//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPF001LinuxEndpointProcessProofTraversesTheExactLivePeerTree(t *testing.T) {
	uid := mustTestUint32(t, os.Getuid())
	pid := mustTestUint32(t, os.Getpid())
	path := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan *net.UnixConn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			acceptError <- acceptErr
			return
		}
		accepted <- connection
	}()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		t.Fatalf("socket stat=%T %+v", info.Sys(), info.Sys())
	}
	if noTCP, proofError := endpointProcessTreeHasNoTCP(
		context.Background(), path, uid, stat.Ino,
	); proofError != nil || !noTCP {
		t.Fatalf("endpoint process proof=(%t,%v)", noTCP, proofError)
	}
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case acceptErr := <-acceptError:
		t.Fatal(acceptErr)
	case <-time.After(time.Second):
		t.Fatal("endpoint proof did not establish the peer connection")
	}

	processes, err := sameUserProcessTree(context.Background(), pid, uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := processes[pid]; !present {
		t.Fatalf("peer process absent from exact tree: %v", processes)
	}
	if sockets, socketError := processSocketInodes(context.Background(), processes); socketError != nil || sockets == nil {
		t.Fatalf("process sockets=(%v,%v)", sockets, socketError)
	}
}

func TestPF001LinuxEndpointProcessProofFailsClosedForInvalidOrCancelledAuthority(t *testing.T) {
	uid := mustTestUint32(t, os.Getuid())
	pid := mustTestUint32(t, os.Getpid())
	if noTCP, err := endpointProcessTreeHasNoTCP(
		context.Background(), filepath.Join(t.TempDir(), "missing.sock"), uid, 1,
	); noTCP || err == nil {
		t.Fatalf("missing endpoint proof=(%t,%v)", noTCP, err)
	}
	if processes, err := sameUserProcessTree(
		context.Background(), pid, uid+1,
	); processes != nil || !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("foreign process tree=(%v,%v)", processes, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if processes, err := sameUserProcessTree(cancelled, pid, uid); processes != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled process tree=(%v,%v)", processes, err)
	}
	if sockets, err := processSocketInodes(cancelled, map[uint32]struct{}{pid: {}}); sockets != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled socket inventory=(%v,%v)", sockets, err)
	}
}

func mustTestUint32(t *testing.T, value int) uint32 {
	t.Helper()
	if value < 0 || uint64(value) > math.MaxUint32 {
		t.Fatalf("test operating-system identifier is outside uint32: %d", value)
	}
	//nolint:gosec // The preceding bounds check proves G115 cannot occur.
	return uint32(value)
}
