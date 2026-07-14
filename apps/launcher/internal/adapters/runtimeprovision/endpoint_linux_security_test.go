//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"fmt"
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
	procRoot := endpointTestProcRoot(t, pid, uid)
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
	if noTCP, proofError := endpointProcessTreeHasNoTCPAt(
		context.Background(), path, uid, stat.Ino, procRoot,
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

	processes, err := sameUserProcessTreeAt(context.Background(), pid, uid, procRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := processes[pid]; !present {
		t.Fatalf("peer process absent from exact tree: %v", processes)
	}
	if sockets, socketError := processSocketInodesAt(context.Background(), processes, procRoot); socketError != nil || sockets == nil {
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

func endpointTestProcRoot(t *testing.T, pid, uid uint32) string {
	t.Helper()
	root := t.TempDir()
	processRoot := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(filepath.Join(processRoot, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\tagentmemory-test\nPPid:\t1\nUid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid)
	if err := os.WriteFile(filepath.Join(processRoot, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	header := []byte("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	for _, name := range []string{"tcp", "tcp6"} {
		if err := os.WriteFile(filepath.Join(root, "net", name), header, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
