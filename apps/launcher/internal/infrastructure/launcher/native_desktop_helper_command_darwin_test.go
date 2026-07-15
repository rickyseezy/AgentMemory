//go:build darwin

package launcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001DarwinDesktopHelperExchangeReadsAndAtomicallyPublishesForExactOwner(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	uid := uint32(os.Geteuid()) // #nosec G115 -- test process uid is a Darwin uid_t.
	gid := uint32(os.Getegid()) // #nosec G115 -- test process gid is a Darwin gid_t.
	if uid == 0 || gid == 0 {
		t.Skip("owner-bound exchange test requires a non-root test process")
	}
	plan := runtimeinstall.Sum([]byte("plan"))
	request := runtimeinstall.Sum([]byte("request"))
	directory := filepath.Join(
		home, "Library", "Application Support", "AgentMemory", "bootstrap", plan.String(), "native",
	)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- private directory fixture, not a regular file.
		t.Fatal(err)
	}
	requestPath := filepath.Join(directory, "request-"+request.String()+".json")
	if err := os.WriteFile(requestPath, []byte(`{"request":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	exchange := darwinDesktopHelperExchange{uid: uid, gid: gid, home: home}
	if exchange.PrincipalID() != "uid:"+strconv.FormatUint(uint64(uid), 10) {
		t.Fatalf("PrincipalID() = %q", exchange.PrincipalID())
	}
	raw, receiptPath, err := exchange.ReadDesktopMutationRequest(context.Background(), requestPath)
	if err != nil || string(raw) != `{"request":true}` {
		t.Fatalf("ReadDesktopMutationRequest() raw=%q error=%v", raw, err)
	}
	wantReceipt := filepath.Join(directory, "request-"+request.String()+".receipt.json")
	if receiptPath != wantReceipt {
		t.Fatalf("receipt path = %q, want %q", receiptPath, wantReceipt)
	}
	if err := exchange.WriteDesktopMutationReceipt(context.Background(), receiptPath, []byte(`{"receipt":true}`)); err != nil {
		t.Fatalf("WriteDesktopMutationReceipt() error = %v", err)
	}
	if err := exchange.WriteDesktopMutationReceipt(context.Background(), receiptPath, []byte(`{"replacement":true}`)); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("existing receipt replacement error=%v", err)
	}
	stored, err := os.ReadFile(receiptPath) // #nosec G304 -- receiptPath is digest-derived under the test's private root.
	if err != nil || string(stored) != `{"receipt":true}` {
		t.Fatalf("stored receipt=%q error=%v", stored, err)
	}
	info, err := os.Lstat(receiptPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode=%v error=%v", info, err)
	}
}

func TestPF001DarwinDesktopHelperExchangeRejectsPathAndObjectSubstitution(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	uid := uint32(os.Geteuid()) // #nosec G115 -- test process uid is a Darwin uid_t.
	gid := uint32(os.Getegid()) // #nosec G115 -- test process gid is a Darwin gid_t.
	if uid == 0 || gid == 0 {
		t.Skip("owner-bound exchange test requires a non-root test process")
	}
	exchange := darwinDesktopHelperExchange{uid: uid, gid: gid, home: home}
	plan := runtimeinstall.Sum([]byte("plan"))
	request := runtimeinstall.Sum([]byte("request"))
	directory := filepath.Join(
		home, "Library", "Application Support", "AgentMemory", "bootstrap", plan.String(), "native",
	)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- private directory fixture, not a regular file.
		t.Fatal(err)
	}
	valid := filepath.Join(directory, "request-"+request.String()+".json")
	if err := os.WriteFile(valid, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"relative":       filepath.Base(valid),
		"wrong base":     filepath.Join(t.TempDir(), filepath.Base(valid)),
		"wrong plan":     filepath.Join(filepath.Dir(directory), "not-a-digest", "native", filepath.Base(valid)),
		"receipt input":  filepath.Join(directory, "request-"+request.String()+".receipt.json"),
		"traversal name": filepath.Join(directory, "..", filepath.Base(valid)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := exchange.ReadDesktopMutationRequest(context.Background(), path); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
				t.Fatalf("ReadDesktopMutationRequest(%q) error=%v", path, err)
			}
		})
	}
	if err := os.Chmod(valid, 0o644); err != nil { // #nosec G302 -- deliberately unsafe request-mode rejection fixture.
		t.Fatal(err)
	}
	if _, _, err := exchange.ReadDesktopMutationRequest(context.Background(), valid); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("world-readable request error=%v", err)
	}
	if err := exchange.WriteDesktopMutationReceipt(context.Background(), valid, []byte("receipt")); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("request-name receipt error=%v", err)
	}
}

func TestPF001DarwinDesktopHelperExchangeRejectsMissingAndCancelledAuthority(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	uid := uint32(os.Geteuid()) // #nosec G115 -- test process uid is a Darwin uid_t.
	gid := uint32(os.Getegid()) // #nosec G115 -- test process gid is a Darwin gid_t.
	if uid == 0 || gid == 0 {
		t.Skip("owner-bound exchange test requires a non-root test process")
	}
	plan := runtimeinstall.Sum([]byte("plan"))
	request := runtimeinstall.Sum([]byte("request"))
	directory := filepath.Join(
		home, "Library", "Application Support", "AgentMemory", "bootstrap", plan.String(), "native",
	)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(directory, "request-"+request.String()+".json")
	if err := os.WriteFile(requestPath, []byte("request"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "request-"+request.String()+".receipt.json")
	exchange := darwinDesktopHelperExchange{uid: uid, gid: gid, home: home}

	//lint:ignore SA1012 Deliberate nil-context privileged-exchange regression fixture.
	if _, _, err := exchange.ReadDesktopMutationRequest(nil, requestPath); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil-context read error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := exchange.ReadDesktopMutationRequest(cancelled, requestPath); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context privileged-exchange regression fixture.
	if err := exchange.WriteDesktopMutationReceipt(nil, receiptPath, []byte("receipt")); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil-context write error=%v", err)
	}
	if err := exchange.WriteDesktopMutationReceipt(cancelled, receiptPath, []byte("receipt")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write error=%v", err)
	}
	if _, err := os.Lstat(receiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled writer created receipt: %v", err)
	}
	if err := exchange.WriteDesktopMutationReceipt(context.Background(), receiptPath, nil); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("empty receipt error=%v", err)
	}
	if err := exchange.WriteDesktopMutationReceipt(context.Background(), receiptPath, make([]byte, 64*1024+1)); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("oversized receipt error=%v", err)
	}
}

func TestPF001DarwinDesktopHelperExchangeRejectsInvalidExchangeDirectory(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	uid := uint32(os.Geteuid()) // #nosec G115 -- test process uid is a Darwin uid_t.
	gid := uint32(os.Getegid()) // #nosec G115 -- test process gid is a Darwin gid_t.
	if uid == 0 || gid == 0 {
		t.Skip("owner-bound exchange test requires a non-root test process")
	}
	exchange := darwinDesktopHelperExchange{uid: uid, gid: gid, home: home}
	missing := filepath.Join(home, "missing")
	if opened, err := exchange.openDirectory(missing); opened != nil || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("missing directory opened=%v error=%v", opened, err)
	}
	regular := filepath.Join(home, "regular")
	if err := os.WriteFile(regular, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if opened, err := exchange.openDirectory(regular); opened != nil || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("regular file opened=%v error=%v", opened, err)
	}
	wrongMode := filepath.Join(home, "wrong-mode")
	if err := os.Mkdir(wrongMode, 0o755); err != nil { // #nosec G301 -- deliberately permissive directory rejection fixture.
		t.Fatal(err)
	}
	if opened, err := exchange.openDirectory(wrongMode); opened != nil || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("wrong-mode directory opened=%v error=%v", opened, err)
	}
}

func TestPF001DesktopHelperContextFallbacksPreserveCancellation(t *testing.T) {
	t.Parallel()
	for name, fallback := range map[string]func(context.Context) error{
		"authority": nativeDesktopHelperContextOrIntegrity,
		"command":   desktopHelperCommandContextOrIntegrity,
	} {
		t.Run(name, func(t *testing.T) {
			if err := fallback(context.Background()); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
				t.Fatalf("background fallback error=%v", err)
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if err := fallback(cancelled); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled fallback error=%v", err)
			}
		})
	}
}

func TestPF001DesktopHelperCommandRejectsUnelevatedAndMalformedInvocation(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("unelevated boundary test requires a non-root test process")
	}
	for _, arguments := range [][]string{
		nil,
		{"--execute-desktop-mutation"},
		{"--wrong", "/tmp/request.json"},
		{"--execute-desktop-mutation", "/tmp/request.json"},
	} {
		if err := RunNativeDesktopMutationHelper(context.Background(), arguments); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
			t.Fatalf("RunNativeDesktopMutationHelper(%q) error=%v", arguments, err)
		}
	}
	if root, exchange, err := nativeDesktopHelperPlatformBoundaries("/tmp/request.json"); root != "" || exchange != nil ||
		!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("unelevated boundaries root=%q exchange=%T error=%v", root, exchange, err)
	}
	if root, err := nativeDesktopHelperReleaseBundleRoot(); err != nil ||
		root != "/Library/Application Support/AgentMemory/resources/bundle" {
		t.Fatalf("bundle root=%q error=%v", root, err)
	}
	if application, release, closers, err := newNativeDesktopMutationHelperApplication(
		t.Context(), t.TempDir(), "uid:501",
	); application != nil || release != nil || len(closers) != 0 || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("unelevated application=%T release=%T closers=%d error=%v", application, release, len(closers), err)
	}
}
