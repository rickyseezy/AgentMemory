//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPF001LinuxEndpointProcessProofTraversesTheExactLivePeerTree(t *testing.T) {
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
		context.Background(), path, uint32(os.Getuid()), stat.Ino,
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

	processes, err := sameUserProcessTree(context.Background(), uint32(os.Getpid()), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := processes[uint32(os.Getpid())]; !present {
		t.Fatalf("peer process absent from exact tree: %v", processes)
	}
	if sockets, socketError := processSocketInodes(context.Background(), processes); socketError != nil || sockets == nil {
		t.Fatalf("process sockets=(%v,%v)", sockets, socketError)
	}
}

func TestPF001LinuxEndpointProcessProofFailsClosedForInvalidOrCancelledAuthority(t *testing.T) {
	if noTCP, err := endpointProcessTreeHasNoTCP(
		context.Background(), filepath.Join(t.TempDir(), "missing.sock"), uint32(os.Getuid()), 1,
	); noTCP || err == nil {
		t.Fatalf("missing endpoint proof=(%t,%v)", noTCP, err)
	}
	if processes, err := sameUserProcessTree(
		context.Background(), uint32(os.Getpid()), uint32(os.Getuid())+1,
	); processes != nil || !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("foreign process tree=(%v,%v)", processes, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if processes, err := sameUserProcessTree(cancelled, uint32(os.Getpid()), uint32(os.Getuid())); processes != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled process tree=(%v,%v)", processes, err)
	}
	if sockets, err := processSocketInodes(cancelled, map[uint32]struct{}{uint32(os.Getpid()): {}}); sockets != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled socket inventory=(%v,%v)", sockets, err)
	}
}
