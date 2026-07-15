package rebootcontinuation

import (
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ContinuationContainsOnlyBoundNonSecretResumeFacts(t *testing.T) {
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	nonce := NonceBytes([]byte("one-use non-secret nonce"))
	record, err := NewRecord(RecordInput{
		LauncherPath:   "/Applications/AgentMemory.app/Contents/MacOS/agentmemory",
		LauncherDigest: install.DigestBytes([]byte("launcher")),
		OperationID:    operationID,
		JournalPath:    "/Users/owner/Library/Application Support/AgentMemory/install-operation.json",
		JournalDigest:  install.DigestBytes([]byte("journal")),
		ExpiresAt:      now.Add(MaximumLifetime),
		Nonce:          nonce,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if record.LauncherPath() == "" || record.LauncherDigest().IsZero() ||
		record.OperationID() != operationID || record.JournalPath() == "" ||
		record.JournalDigest().IsZero() || !record.ExpiresAt().Equal(now.Add(MaximumLifetime)) ||
		record.Nonce() != nonce {
		t.Fatalf("record did not preserve the exact continuation binding: %+v", record)
	}
	if record.Expired(now) || !record.Expired(record.ExpiresAt()) {
		t.Fatal("continuation expiry is not closed at the exact boundary")
	}
	if err := record.Verify(Verification{
		OperationID: operationID, LauncherPath: record.LauncherPath(),
		LauncherDigest: record.LauncherDigest(), JournalPath: record.JournalPath(),
		JournalDigest: record.JournalDigest(),
	}, now); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestPF001ContinuationRejectsIncompleteUnsafeOrOverlongBindings(t *testing.T) {
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	valid := RecordInput{
		LauncherPath: "/opt/agentmemory/bin/agentmemory", LauncherDigest: install.DigestBytes([]byte("launcher")),
		OperationID: operationID, JournalPath: "/home/owner/.config/AgentMemory/journal",
		JournalDigest: install.DigestBytes([]byte("journal")), ExpiresAt: now.Add(time.Hour),
		Nonce: NonceBytes([]byte("nonce")),
	}
	tests := map[string]func(*RecordInput){
		"relative launcher":   func(value *RecordInput) { value.LauncherPath = "agentmemory" },
		"unclean launcher":    func(value *RecordInput) { value.LauncherPath += "/../agentmemory" },
		"launcher digest":     func(value *RecordInput) { value.LauncherDigest = install.Digest{} },
		"operation":           func(value *RecordInput) { value.OperationID = install.OperationID{} },
		"relative journal":    func(value *RecordInput) { value.JournalPath = "journal" },
		"unclean journal":     func(value *RecordInput) { value.JournalPath += "/../journal" },
		"journal digest":      func(value *RecordInput) { value.JournalDigest = install.Digest{} },
		"expired":             func(value *RecordInput) { value.ExpiresAt = now },
		"overlong":            func(value *RecordInput) { value.ExpiresAt = now.Add(MaximumLifetime + time.Nanosecond) },
		"non UTC":             func(value *RecordInput) { value.ExpiresAt = value.ExpiresAt.In(time.FixedZone("foreign", 3600)) },
		"nonce":               func(value *RecordInput) { value.Nonce = Nonce{} },
		"nul launcher":        func(value *RecordInput) { value.LauncherPath += "\x00foreign" },
		"same protected file": func(value *RecordInput) { value.JournalPath = value.LauncherPath },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewRecord(candidate, now); err == nil {
				t.Fatal("invalid continuation accepted")
			}
		})
	}
}

func TestPF001ContinuationVerificationRejectsEverySubstitutionAndExpiry(t *testing.T) {
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	record := recordFixture(t, now)
	valid := Verification{
		OperationID: record.OperationID(), LauncherPath: record.LauncherPath(),
		LauncherDigest: record.LauncherDigest(), JournalPath: record.JournalPath(),
		JournalDigest: record.JournalDigest(),
	}
	foreignOperation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	tests := map[string]func(*Verification, *time.Time){
		"operation":       func(value *Verification, _ *time.Time) { value.OperationID = foreignOperation },
		"launcher path":   func(value *Verification, _ *time.Time) { value.LauncherPath += "-foreign" },
		"launcher digest": func(value *Verification, _ *time.Time) { value.LauncherDigest = install.DigestBytes([]byte("foreign")) },
		"journal path":    func(value *Verification, _ *time.Time) { value.JournalPath += "-foreign" },
		"journal digest":  func(value *Verification, _ *time.Time) { value.JournalDigest = install.DigestBytes([]byte("foreign")) },
		"expiry":          func(_ *Verification, at *time.Time) { *at = record.ExpiresAt() },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate, at := valid, now
			mutate(&candidate, &at)
			if err := record.Verify(candidate, at); err == nil {
				t.Fatal("substituted continuation evidence accepted")
			}
		})
	}
}

func TestPF001ContinuationNonceAndNativePathEdgeContracts(t *testing.T) {
	raw := make([]byte, 32)
	raw[31] = 7
	nonce, err := NewNonce(raw)
	if err != nil || nonce.IsZero() || len(nonce.Bytes()) != 32 {
		t.Fatalf("NewNonce() = (%x, %v)", nonce, err)
	}
	copyBytes := nonce.Bytes()
	copyBytes[31]++
	if nonce.Bytes()[31] != 7 {
		t.Fatal("nonce exposed mutable storage")
	}
	for _, candidate := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33)} {
		if _, candidateError := NewNonce(candidate); candidateError == nil {
			t.Fatalf("NewNonce(%d zero/invalid bytes) accepted", len(candidate))
		}
	}
	for _, path := range []string{
		`C:\Program Files\AgentMemory\agentmemory.exe`,
		`C:/Program Files/AgentMemory/agentmemory.exe`,
		`\\server\private\AgentMemory\agentmemory.exe`,
		"/home/owner/Agent Memory/agentmemory",
	} {
		if !validNativeAbsolutePath(path) {
			t.Fatalf("valid native path %q rejected", path)
		}
	}
	for _, path := range []string{"", " relative", "relative ", `C:relative`, `/opt/./agentmemory`, `C:\\..\\foreign`} {
		if validNativeAbsolutePath(path) {
			t.Fatalf("unsafe native path %q accepted", path)
		}
	}
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	token, err := TokenFor(operationID)
	if err != nil || len(token) != 64 {
		t.Fatalf("TokenFor() = (%q, %v)", token, err)
	}
	if repeated, _ := TokenFor(operationID); repeated != token {
		t.Fatal("continuation token is not deterministic")
	}
	if _, err := TokenFor(install.OperationID{}); err == nil {
		t.Fatal("zero operation token accepted")
	}
}

func TestPF001ContinuationRejectsInvalidCaptureClock(t *testing.T) {
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	record := recordFixture(t, now)
	input := RecordInput{
		LauncherPath: record.LauncherPath(), LauncherDigest: record.LauncherDigest(),
		OperationID: record.OperationID(), JournalPath: record.JournalPath(),
		JournalDigest: record.JournalDigest(), ExpiresAt: record.ExpiresAt(), Nonce: record.Nonce(),
	}
	for _, invalidNow := range []time.Time{{}, now.In(time.FixedZone("foreign", 3600))} {
		if _, err := NewRecord(input, invalidNow); err == nil {
			t.Fatal("invalid capture clock accepted")
		}
	}
	if !record.Expired(time.Time{}) {
		t.Fatal("zero verification clock was not closed")
	}
}

func recordFixture(t testing.TB, now time.Time) Record {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	record, err := NewRecord(RecordInput{
		LauncherPath: "/opt/agentmemory/bin/agentmemory", LauncherDigest: install.DigestBytes([]byte("launcher")),
		OperationID: operationID, JournalPath: "/home/owner/.config/AgentMemory/journal",
		JournalDigest: install.DigestBytes([]byte("journal")), ExpiresAt: now.Add(time.Hour),
		Nonce: NonceBytes([]byte("nonce")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
