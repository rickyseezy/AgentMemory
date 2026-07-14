package agentconfigadapter

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	testInstallationID = "018f0c74-7b5d-7cc1-8a2c-123456789abc"
	testEntryID        = "018f0c74-7b5d-7cc2-9a2c-123456789abc"
)

type AgentHost = domain.AgentHost

var (
	DigestBytes       = domain.DigestBytes
	DigestFromHex     = domain.DigestFromHex
	NewTargetForAgent = domain.NewTargetForAgent
)

func PlanMerge(original []byte, existed bool, target Target, expected Digest) (MergePlan, error) {
	return planCodexMerge(original, existed, target, expected)
}

func ValidateDocumentFor(host AgentHost, contents []byte) error {
	if host != AgentHostCodex {
		return ErrInvalidTarget
	}
	_, err := parseCodexDocument(contents)
	return err
}

func VerifyManagedEntry(contents []byte, target Target) error {
	return verifyCodexManagedEntry(contents, target)
}

func TestPF001CodexMergePreservesUnmanagedTOMLExactly(t *testing.T) {
	t.Parallel()
	target := testCodexTarget(t, "/Applications/AgentMemory 世界/agentmemory", strings.Repeat("a", 64))
	original := []byte("# user comment\nmodel = \"gpt-5\"\n\n[mcp_servers.other]\ncommand = \"other\"\nargs = [\"--keep\"]")

	plan, err := PlanMerge(original, true, target, Digest{})
	if err != nil {
		t.Fatalf("PlanMerge() error = %v", err)
	}
	if plan.Action() != MergeActionAdd || !plan.Changed() {
		t.Fatalf("action = %s, changed = %t", plan.Action(), plan.Changed())
	}
	if !bytes.HasPrefix(plan.AfterContent(), append(append([]byte(nil), original...), '\n')) {
		t.Fatal("Codex merge did not preserve every unmanaged byte")
	}
	if err := ValidateDocumentFor(AgentHostCodex, plan.AfterContent()); err != nil {
		t.Fatalf("ValidateDocumentFor() error = %v", err)
	}
	if err := VerifyManagedEntry(plan.AfterContent(), target); err != nil {
		t.Fatalf("VerifyManagedEntry() error = %v", err)
	}
}

func TestPF001CodexMergeIsIdempotentAndReceiptBound(t *testing.T) {
	t.Parallel()
	firstTarget := testCodexTarget(t, `C:\Program Files\AgentMemory\agentmemory.exe`, strings.Repeat("b", 64))
	first, err := PlanMerge(nil, false, firstTarget, Digest{})
	if err != nil {
		t.Fatalf("first PlanMerge() error = %v", err)
	}
	idempotent, err := PlanMerge(first.AfterContent(), true, firstTarget, Digest{})
	if err != nil {
		t.Fatalf("idempotent PlanMerge() error = %v", err)
	}
	if idempotent.Action() != MergeActionNoChange || idempotent.Changed() ||
		!bytes.Equal(idempotent.AfterContent(), first.AfterContent()) {
		t.Fatal("idempotent Codex merge rewrote the configuration")
	}

	updatedTarget := testCodexTarget(t, firstTarget.Command(), strings.Repeat("c", 64))
	if _, err := PlanMerge(first.AfterContent(), true, updatedTarget, Digest{}); !errors.Is(err, ErrManagedEntryConflict) {
		t.Fatalf("update without receipt error = %v", err)
	}
	updated, err := PlanMerge(first.AfterContent(), true, updatedTarget, first.ManagedEntryDigest())
	if err != nil {
		t.Fatalf("receipt-bound update error = %v", err)
	}
	if updated.Action() != MergeActionReplaceManaged || !updated.Changed() {
		t.Fatalf("updated action = %s, changed = %t", updated.Action(), updated.Changed())
	}
	if err := VerifyManagedEntry(updated.AfterContent(), updatedTarget); err != nil {
		t.Fatalf("updated verification error = %v", err)
	}
}

func TestPF001CodexMergeRejectsForeignAndAmbiguousOwnership(t *testing.T) {
	t.Parallel()
	target := testCodexTarget(t, "/opt/agentmemory", strings.Repeat("d", 64))
	tests := map[string][]byte{
		"unowned semantic table": []byte("[mcp_servers.agentmemory]\ncommand = \"foreign\"\n"),
		"marker without table":   []byte(codexManagedBegin + "\n" + codexManagedEnd + "\n"),
		"duplicate table": []byte("[mcp_servers.agentmemory]\ncommand = \"one\"\n" +
			"[mcp_servers.agentmemory]\ncommand = \"two\"\n"),
		"duplicate key": []byte("[mcp_servers.other]\ncommand = \"one\"\ncommand = \"two\"\n"),
		"malformed":     []byte("[mcp_servers.other\n"),
		"invalid UTF-8": {0xff},
	}
	for name, document := range tests {
		document := document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := PlanMerge(document, true, target, Digest{})
			if name == "unowned semantic table" || name == "marker without table" {
				if !errors.Is(err, ErrAmbiguousOwnership) {
					t.Fatalf("PlanMerge() error = %v, want ErrAmbiguousOwnership", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("PlanMerge() error = %v, want ErrInvalidDocument", err)
			}
		})
	}
}

func TestPF001CodexMergeRejectsMarkerAndEntryTampering(t *testing.T) {
	t.Parallel()
	target := testCodexTarget(t, "/opt/agentmemory", strings.Repeat("e", 64))
	created, err := PlanMerge([]byte("# keep\n"), true, target, Digest{})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"command": bytes.Replace(created.AfterContent(), []byte(`command = "/opt/agentmemory"`), []byte(`command = "/tmp/attacker"`), 1),
		"args":    bytes.Replace(created.AfterContent(), []byte(`"codex"]`), []byte(`"claude"]`), 1),
		"marker":  bytes.Replace(created.AfterContent(), []byte("# entry_id"), []byte("# foreign_id"), 1),
		"rename":  bytes.Replace(created.AfterContent(), []byte("[mcp_servers.agentmemory]"), []byte("[mcp_servers.renamed]"), 1),
		"append":  append(created.AfterContent(), []byte("future = true\n")...),
	}
	for name, document := range tests {
		document := document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := VerifyManagedEntry(document, target); err == nil {
				t.Fatal("tampered Codex entry verified")
			}
		})
	}
}

func TestPF001CodexTargetValidationAndEmptyExistingDocument(t *testing.T) {
	t.Parallel()
	digest := DigestBytes([]byte("launcher"))
	if _, err := NewTargetForAgent(AgentHost("unknown"), testInstallationID, testEntryID, "/opt/agentmemory", digest); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("unknown host error = %v", err)
	}
	target := testCodexTarget(t, "/opt/agentmemory", digest.String())
	plan, err := PlanMerge(nil, true, target, Digest{})
	if err != nil {
		t.Fatalf("empty existing Codex document error = %v", err)
	}
	if !plan.OriginalExisted() {
		t.Fatal("empty existing Codex document lost the original-existed state")
	}
	if err := VerifyManagedEntry(plan.AfterContent(), target); err != nil {
		t.Fatalf("empty existing verification error = %v", err)
	}
	if _, err := PlanMerge([]byte("model = \"x\""), false, target, Digest{}); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("absent with contents error = %v", err)
	}
}

func FuzzPF001CodexTOMLPlanNeverPanics(f *testing.F) {
	f.Add([]byte("model = \"gpt-5\"\n"))
	f.Add([]byte("[mcp_servers.other]\ncommand = \"other\"\n"))
	f.Add([]byte("[mcp_servers.agentmemory]\ncommand = \"foreign\"\n"))
	target, err := NewTargetForAgent(
		AgentHostCodex,
		testInstallationID,
		testEntryID,
		"/opt/agentmemory",
		DigestBytes([]byte("fuzz launcher")),
	)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, document []byte) {
		plan, planErr := PlanMerge(document, true, target, Digest{})
		if planErr != nil {
			return
		}
		if err := ValidateDocumentFor(AgentHostCodex, plan.AfterContent()); err != nil {
			t.Fatalf("accepted plan produced invalid TOML: %v", err)
		}
		if err := VerifyManagedEntry(plan.AfterContent(), target); err != nil {
			t.Fatalf("accepted plan produced unverifiable entry: %v", err)
		}
	})
}

func testCodexTarget(t *testing.T, command string, digestHex string) Target {
	t.Helper()
	digest, err := DigestFromHex(digestHex)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewTargetForAgent(AgentHostCodex, testInstallationID, testEntryID, command, digest)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
