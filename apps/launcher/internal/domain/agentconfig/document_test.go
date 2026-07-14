package agentconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	testInstallationID = "018f0c74-7b5d-7cc1-8a2c-123456789abc"
	testEntryID        = "018f0c74-7b5d-7cc2-9a2c-123456789abc"
)

func TestPF001PlanMergeAddsOwnedEntryAndPreservesUnknownJSON(t *testing.T) {
	t.Parallel()
	target := testTarget(t, "1111111111111111111111111111111111111111111111111111111111111111")
	original := []byte(`{
  "theme": "dark",
  "future": {"enabled": true, "items": [1, 2, 3]},
  "mcpServers": {
    "other": {"command": "other-mcp", "env": {"DO_NOT_LOG": "private"}, "future": 42}
  }
}`)

	plan, err := PlanMerge(original, true, target, Digest{})
	if err != nil {
		t.Fatalf("PlanMerge() error = %v", err)
	}
	if plan.Action() != MergeActionAdd || !plan.Changed() || !plan.OriginalExisted() {
		t.Fatalf("PlanMerge() action = %s, changed = %t, existed = %t", plan.Action(), plan.Changed(), plan.OriginalExisted())
	}
	if !bytes.Equal(plan.BeforeContent(), original) || !plan.BeforeDigest().Equal(DigestBytes(original)) {
		t.Fatal("plan did not retain an exact, hash-bound backup input")
	}
	if err := ValidateDocument(plan.AfterContent()); err != nil {
		t.Fatalf("ValidateDocument(after) error = %v", err)
	}
	if err := VerifyManagedEntry(plan.AfterContent(), target); err != nil {
		t.Fatalf("VerifyManagedEntry(after) error = %v", err)
	}
	assertJSONPathEqual(t, original, plan.AfterContent(), "theme")
	assertJSONPathEqual(t, original, plan.AfterContent(), "future")
	assertJSONPathEqual(t, original, plan.AfterContent(), "mcpServers", "other")

	after := plan.AfterContent()
	after[0] ^= 0xff
	if err := ValidateDocument(plan.AfterContent()); err != nil {
		t.Fatalf("plan exposed mutable output bytes: %v", err)
	}
}

func TestPF001PlanMergeRejectsDuplicateKeysAndMalformedJSON(t *testing.T) {
	t.Parallel()
	target := testTarget(t, "2222222222222222222222222222222222222222222222222222222222222222")
	tests := map[string][]byte{
		"duplicate root":        []byte(`{"mcpServers":{},"mcpServers":{}}`),
		"duplicate server":      []byte(`{"mcpServers":{"agentmemory":{},"agentmemory":{}}}`),
		"duplicate marker":      []byte(`{"mcpServers":{"agentmemory":{"_agentmemory":{"managed_by":"agentmemory","managed_by":"other"}}}}`),
		"trailing document":     []byte(`{} {}`),
		"comment":               []byte(`{"mcpServers":{/* unsupported */}}`),
		"non-object root":       []byte(`[]`),
		"non-object collection": []byte(`{"mcpServers":[]}`),
		"invalid UTF-8":         append([]byte(`{"key":"`), 0xff, '"', '}'),
	}
	for name, document := range tests {
		document := document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := PlanMerge(document, true, target, Digest{})
			if !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("PlanMerge() error = %v, want ErrInvalidDocument", err)
			}
		})
	}

	oversized := bytes.Repeat([]byte{' '}, MaxDocumentBytes+1)
	if _, err := PlanMerge(oversized, true, target, Digest{}); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("PlanMerge(oversized) error = %v, want ErrInvalidDocument", err)
	}
}

func TestPF001PlanMergeRefusesAmbiguousAgentMemoryOwnership(t *testing.T) {
	t.Parallel()
	target := testTarget(t, "3333333333333333333333333333333333333333333333333333333333333333")
	tests := map[string]string{
		"unmarked entry":     `{"mcpServers":{"agentmemory":{"command":"someone-else"}}}`,
		"foreign owner":      `{"mcpServers":{"agentmemory":{"command":"someone-else","_agentmemory":{"managed_by":"other","schema_version":1,"installation_id":"018f0c74-7b5d-7cc1-8a2c-123456789abc","entry_id":"018f0c74-7b5d-7cc2-9a2c-123456789abc","launcher_sha256":"3333333333333333333333333333333333333333333333333333333333333333"}}}}`,
		"other installation": `{"mcpServers":{"agentmemory":{"command":"someone-else","_agentmemory":{"managed_by":"agentmemory","schema_version":1,"installation_id":"018f0c74-7b5d-7cc3-8a2c-123456789abc","entry_id":"018f0c74-7b5d-7cc2-9a2c-123456789abc","launcher_sha256":"3333333333333333333333333333333333333333333333333333333333333333"}}}}`,
		"malformed marker":   `{"mcpServers":{"agentmemory":{"command":"someone-else","_agentmemory":{"managed_by":"agentmemory"}}}}`,
		"non-object entry":   `{"mcpServers":{"agentmemory":"someone-else"}}`,
	}
	for name, document := range tests {
		document := document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := PlanMerge([]byte(document), true, target, Digest{})
			if !errors.Is(err, ErrAmbiguousOwnership) {
				t.Fatalf("PlanMerge() error = %v, want ErrAmbiguousOwnership", err)
			}
		})
	}
	owned, err := PlanMerge(nil, false, target, Digest{})
	if err != nil {
		t.Fatal(err)
	}
	var renamed map[string]any
	if err := json.Unmarshal(owned.AfterContent(), &renamed); err != nil {
		t.Fatal(err)
	}
	servers := renamed["mcpServers"].(map[string]any)
	servers["legacy-agentmemory"] = servers[managedServerName]
	delete(servers, managedServerName)
	renamedBytes, err := json.Marshal(renamed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanMerge(renamedBytes, true, target, Digest{}); !errors.Is(err, ErrAmbiguousOwnership) {
		t.Fatalf("PlanMerge(renamed owned entry) error = %v, want ErrAmbiguousOwnership", err)
	}
}

func TestPF001PlanMergeIsIdempotentAndRequiresPriorReceiptForManagedUpdate(t *testing.T) {
	t.Parallel()
	firstTarget := testTarget(t, "4444444444444444444444444444444444444444444444444444444444444444")
	first, err := PlanMerge([]byte(`{"future":true}`), true, firstTarget, Digest{})
	if err != nil {
		t.Fatalf("first PlanMerge() error = %v", err)
	}

	idempotent, err := PlanMerge(first.AfterContent(), true, firstTarget, Digest{})
	if err != nil {
		t.Fatalf("idempotent PlanMerge() error = %v", err)
	}
	if idempotent.Action() != MergeActionNoChange || idempotent.Changed() {
		t.Fatalf("idempotent action = %s, changed = %t", idempotent.Action(), idempotent.Changed())
	}
	if !bytes.Equal(idempotent.AfterContent(), first.AfterContent()) {
		t.Fatal("idempotent plan rewrote the host configuration")
	}

	updatedTarget := testTarget(t, "5555555555555555555555555555555555555555555555555555555555555555")
	if _, err := PlanMerge(first.AfterContent(), true, updatedTarget, Digest{}); !errors.Is(err, ErrManagedEntryConflict) {
		t.Fatalf("update without receipt error = %v, want ErrManagedEntryConflict", err)
	}
	wrong := DigestBytes([]byte("wrong prior entry"))
	if _, err := PlanMerge(first.AfterContent(), true, updatedTarget, wrong); !errors.Is(err, ErrManagedEntryConflict) {
		t.Fatalf("update with wrong receipt error = %v, want ErrManagedEntryConflict", err)
	}

	updated, err := PlanMerge(first.AfterContent(), true, updatedTarget, first.ManagedEntryDigest())
	if err != nil {
		t.Fatalf("managed update PlanMerge() error = %v", err)
	}
	if updated.Action() != MergeActionReplaceManaged || !updated.Changed() {
		t.Fatalf("managed update action = %s, changed = %t", updated.Action(), updated.Changed())
	}
	if err := VerifyManagedEntry(updated.AfterContent(), updatedTarget); err != nil {
		t.Fatalf("updated entry verification error = %v", err)
	}
}

func TestPF001TargetAndPlanValidationFailClosed(t *testing.T) {
	t.Parallel()
	digest := DigestBytes([]byte("launcher"))
	if _, err := PlanMerge(nil, false, Target{}, Digest{}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("PlanMerge(zero target) error = %v, want ErrInvalidTarget", err)
	}
	for _, encoded := range []string{strings.Repeat("A", 64), strings.Repeat("g", 64), "short"} {
		if _, err := DigestFromHex(encoded); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("DigestFromHex(%q) error = %v", encoded, err)
		}
	}
	deepDocument := []byte(strings.Repeat(`{"nested":`, maximumJSONDepth+1) + `0` + strings.Repeat(`}`, maximumJSONDepth+1))
	if err := ValidateDocument(deepDocument); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("ValidateDocument(deep) error = %v", err)
	}
	tests := []struct {
		name           string
		installation   string
		entry          string
		command        string
		launcherDigest Digest
	}{
		{name: "installation not UUIDv7", installation: "not-a-uuid", entry: testEntryID, command: "/opt/agentmemory", launcherDigest: digest},
		{name: "entry not UUIDv7", installation: testInstallationID, entry: "018f0c74-7b5d-6cc2-9a2c-123456789abc", command: "/opt/agentmemory", launcherDigest: digest},
		{name: "empty command", installation: testInstallationID, entry: testEntryID, launcherDigest: digest},
		{name: "command contains NUL", installation: testInstallationID, entry: testEntryID, command: "bad\x00command", launcherDigest: digest},
		{name: "missing digest", installation: testInstallationID, entry: testEntryID, command: "/opt/agentmemory"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewTarget(test.installation, test.entry, test.command, test.launcherDigest); !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("NewTarget() error = %v, want ErrInvalidTarget", err)
			}
		})
	}

	target := testTarget(t, "6666666666666666666666666666666666666666666666666666666666666666")
	if _, err := PlanMerge([]byte(`{}`), false, target, Digest{}); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("PlanMerge(absent with contents) error = %v, want ErrInvalidDocument", err)
	}
	if _, err := PlanMerge(nil, true, target, Digest{}); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("PlanMerge(nil existing) error = %v, want ErrInvalidDocument", err)
	}
	created, err := PlanMerge(nil, false, target, Digest{})
	if err != nil {
		t.Fatalf("PlanMerge(absent) error = %v", err)
	}
	if created.OriginalExisted() || created.Action() != MergeActionAdd {
		t.Fatalf("absent plan existed = %t, action = %s", created.OriginalExisted(), created.Action())
	}
	if !created.AfterDigest().Equal(DigestBytes(created.AfterContent())) ||
		created.Target().InstallationID() != target.InstallationID() {
		t.Fatal("merge plan lost its replacement digest or immutable target")
	}
	if err := VerifyManagedEntry([]byte(`not-json`), target); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("VerifyManagedEntry(invalid JSON) error = %v", err)
	}
	if err := VerifyManagedEntry([]byte(`{}`), target); !errors.Is(err, ErrManagedEntryConflict) {
		t.Fatalf("VerifyManagedEntry(missing entry) error = %v", err)
	}
	otherTarget, err := NewTarget(
		testInstallationID,
		"018f0c74-7b5d-7cc3-aa2c-123456789abc",
		target.Command(),
		target.LauncherDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManagedEntry(created.AfterContent(), otherTarget); !errors.Is(err, ErrAmbiguousOwnership) {
		t.Fatalf("VerifyManagedEntry(other owner) error = %v", err)
	}
	tampered := bytes.Replace(created.AfterContent(), []byte(target.Command()), []byte("/opt/substituted"), 1)
	if err := VerifyManagedEntry(tampered, target); !errors.Is(err, ErrManagedEntryConflict) {
		t.Fatalf("VerifyManagedEntry(tampered command) error = %v", err)
	}
}

func TestPF001MergeActionStringsAreStable(t *testing.T) {
	t.Parallel()
	tests := map[MergeAction]string{
		MergeActionUnknown:        "unknown",
		MergeActionAdd:            "add",
		MergeActionNoChange:       "no_change",
		MergeActionReplaceManaged: "replace_managed",
		MergeAction(255):          "unknown",
	}
	for action, expected := range tests {
		if actual := action.String(); actual != expected {
			t.Fatalf("MergeAction(%d).String() = %q, want %q", action, actual, expected)
		}
	}
}

func FuzzPF001HostNeutralJSONPlanNeverPanics(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"mcpServers":{"other":{"command":"other"}}}`))
	f.Add([]byte(`{"mcpServers":{"agentmemory":{"command":"foreign"}}}`))
	target, err := NewTarget(
		testInstallationID,
		testEntryID,
		"/opt/agentmemory",
		DigestBytes([]byte("fuzz launcher")),
	)
	if err != nil {
		f.Fatalf("NewTarget() error = %v", err)
	}
	f.Fuzz(func(t *testing.T, document []byte) {
		plan, planErr := PlanMerge(document, true, target, Digest{})
		if planErr != nil {
			return
		}
		if err := ValidateDocument(plan.AfterContent()); err != nil {
			t.Fatalf("accepted plan produced invalid JSON: %v", err)
		}
		if err := VerifyManagedEntry(plan.AfterContent(), target); err != nil {
			t.Fatalf("accepted plan produced unverifiable entry: %v", err)
		}
	})
}

func testTarget(t *testing.T, digestHex string) Target {
	t.Helper()
	digest, err := DigestFromHex(digestHex)
	if err != nil {
		t.Fatalf("DigestFromHex() error = %v", err)
	}
	target, err := NewTarget(testInstallationID, testEntryID, "/opt/AgentMemory/agentmemory", digest)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}
	return target
}

func assertJSONPathEqual(t *testing.T, before []byte, after []byte, path ...string) {
	t.Helper()
	left := decodeJSON(t, before)
	right := decodeJSON(t, after)
	for _, key := range path {
		leftObject, leftOK := left.(map[string]any)
		rightObject, rightOK := right.(map[string]any)
		if !leftOK || !rightOK {
			t.Fatalf("JSON path %s is not an object", strings.Join(path, "."))
		}
		left = leftObject[key]
		right = rightObject[key]
	}
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	if !bytes.Equal(leftBytes, rightBytes) {
		t.Fatalf("JSON path %s changed: before %s, after %s", strings.Join(path, "."), leftBytes, rightBytes)
	}
}

func decodeJSON(t *testing.T, document []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return value
}
