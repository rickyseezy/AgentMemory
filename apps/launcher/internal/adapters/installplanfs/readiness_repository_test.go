package installplanfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

func TestPF001ReadinessRepositoryAuthenticatesRoundTripsAndReplaysReceipt(t *testing.T) {
	t.Parallel()
	root := filepath.Join(filesystemTestDirectory(t), "receipts")
	keys := &readinessKeySource{key: []byte("01234567890123456789012345678901")}
	repository, err := NewReadinessRepository(context.Background(), root, "/protected/root-key", keys)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repository.Close() }()
	receipt := repositoryReceipt(t)
	if err := repository.SaveReadinessReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveReadinessReceipt(context.Background(), receipt); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}
	restored, err := repository.LoadReadinessReceipt(context.Background(), receipt.Digest())
	if err != nil || !restored.Digest().Equal(receipt.Digest()) ||
		restored.OperationID() != receipt.OperationID() || len(restored.Results()) != len(receipt.Results()) {
		t.Fatalf("LoadReadinessReceipt() = %#v/%v", restored, err)
	}
	if keys.lastPath != "/protected/root-key" || keys.reads < 3 {
		t.Fatalf("key source path/reads = %q/%d", keys.lastPath, keys.reads)
	}
}

func TestPF001ReadinessRepositoryRejectsTamperWrongKeyAndClosedState(t *testing.T) {
	t.Parallel()
	root := filepath.Join(filesystemTestDirectory(t), "receipts")
	keys := &readinessKeySource{key: []byte("01234567890123456789012345678901")}
	repository, err := NewReadinessRepository(context.Background(), root, "/protected/root-key", keys)
	if err != nil {
		t.Fatal(err)
	}
	receipt := repositoryReceipt(t)
	if err := repository.SaveReadinessReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, readinessFilename(receipt.Digest()))
	raw, err := os.ReadFile(path) //nolint:gosec // G304: generated test repository path.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil { //nolint:gosec // G703: generated test repository path.
		t.Fatal(err)
	}
	if _, err := repository.LoadReadinessReceipt(context.Background(), receipt.Digest()); !errors.Is(err, errReadinessRepositoryIntegrity) {
		t.Fatalf("tampered load error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LoadReadinessReceipt(context.Background(), receipt.Digest()); err == nil {
		t.Fatal("closed repository returned a receipt")
	}
	if err := repository.SaveReadinessReceipt(context.Background(), receipt); err == nil {
		t.Fatal("closed repository saved a receipt")
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestPF001ReadinessRepositoryRejectsInvalidConstructionAndKeyFailure(t *testing.T) {
	t.Parallel()
	keys := &readinessKeySource{key: []byte("short")}
	if _, err := NewReadinessRepository(context.Background(), "relative", "/key", keys); err == nil {
		t.Fatal("constructor accepted relative root")
	}
	if _, err := NewReadinessRepository(context.Background(), filepath.Join(filesystemTestDirectory(t), "root"), "", keys); err == nil {
		t.Fatal("constructor accepted empty key path")
	}
	if _, err := NewReadinessRepository(context.Background(), filepath.Join(filesystemTestDirectory(t), "root"), "/key", nil); err == nil {
		t.Fatal("constructor accepted nil key source")
	}
	repository, err := NewReadinessRepository(
		context.Background(), filepath.Join(filesystemTestDirectory(t), "root"), "/key", keys,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repository.Close() }()
	if err := repository.SaveReadinessReceipt(context.Background(), repositoryReceipt(t)); !errors.Is(err, errReadinessRepositoryIntegrity) {
		t.Fatalf("short key save error = %v", err)
	}
	keys.key = []byte("01234567890123456789012345678901")
	keys.err = errors.New("private")
	if err := repository.SaveReadinessReceipt(context.Background(), repositoryReceipt(t)); !errors.Is(err, errReadinessRepositoryIntegrity) {
		t.Fatalf("key source save error = %v", err)
	}
	if err := (*ReadinessRepository)(nil).SaveReadinessReceipt(context.Background(), repositoryReceipt(t)); err == nil {
		t.Fatal("nil repository saved receipt")
	}
	if _, err := (*ReadinessRepository)(nil).LoadReadinessReceipt(context.Background(), install.Digest{}); err == nil {
		t.Fatal("nil repository loaded receipt")
	}
	var nilContext context.Context
	if _, err := NewReadinessRepository(nilContext, "/root", "/key", keys); err == nil {
		t.Fatal("constructor accepted nil context")
	}
	var typedNil *readinessKeySource
	if _, err := NewReadinessRepository(context.Background(), filepath.Join(filesystemTestDirectory(t), "root"), "/key", typedNil); err == nil {
		t.Fatal("constructor accepted typed nil key source")
	}
}

type readinessKeySource struct {
	key      []byte
	err      error
	lastPath string
	reads    int
}

func (s *readinessKeySource) ReadCredential(_ context.Context, path string) ([]byte, error) {
	s.reads++
	s.lastPath = path
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.key...), nil
}

func repositoryReceipt(t testing.TB) readiness.Receipt {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	manifest := install.DigestBytes([]byte("manifest"))
	compose := install.DigestBytes([]byte("normalized compose"))
	now := time.Date(2026, 7, 13, 12, 0, 0, 123456000, time.UTC)
	results := make([]readiness.Result, 0, len(readiness.RequiredProbes()))
	for _, probe := range readiness.RequiredProbes() {
		result, err := readiness.NewResult(readiness.ResultInput{
			Probe: probe, Status: readiness.StatusPassed, OperationID: operationID, PlanDigest: plan,
			ReleaseID: "agentmemory-1.0.0", GenerationID: "019f5f21-5678-7def-9123-abcdef012345",
			ManifestDigest: manifest, ComposeDigest: compose,
			EvidenceDigest: install.DigestBytes([]byte(probe.String())), ObservedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	receipt, failures := readiness.NewGate().Evaluate(readiness.GateInput{
		OperationID: operationID, PlanDigest: plan, ReleaseID: "agentmemory-1.0.0",
		GenerationID: "019f5f21-5678-7def-9123-abcdef012345", ManifestDigest: manifest,
		ComposeDigest: compose, EvaluatedAt: now, Results: results,
	})
	if len(failures) != 0 {
		t.Fatal(failures)
	}
	return receipt
}
