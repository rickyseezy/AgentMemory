//go:build linux

package launcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestPF006LinuxPrivilegeHelperCommandOwnsClosedLifecycle(t *testing.T) {
	t.Parallel()
	lock := &launcherPrivilegeCommandLock{}
	release := &launcherPrivilegeCommandRelease{}
	application := &launcherPrivilegeCommandApplication{receipt: []byte("canonical receipt")}
	port := &launcherPrivilegeCommandLockPort{lock: lock}
	var output bytes.Buffer
	var lockPath string

	err := runNativeLinuxPrivilegeHelperUsing(
		t.Context(), []string{"--request-stdin"}, bytes.NewBufferString("canonical request"), &output,
		func() int { return 0 },
		func(path string) (installapp.InstallationLockPort, error) {
			lockPath = path
			return port, nil
		},
		func(context.Context) (
			nativePrivilegeHelperRequestExecutor,
			nativePrivilegeHelperRelease,
			error,
		) {
			return application, release, nil
		},
	)
	if err != nil || output.String() != "canonical receipt" ||
		lockPath != nativePrivilegeHelperStateRoot+"/execution.lock" ||
		port.acquisitions != 1 || lock.releases != 1 || release.closes != 1 || application.executions != 1 {
		t.Fatalf(
			"output=%q path=%q acquisitions=%d releases=%d closes=%d executions=%d error=%v",
			output.String(), lockPath, port.acquisitions, lock.releases, release.closes,
			application.executions, err,
		)
	}
	for _, value := range application.request {
		if value != 0 {
			t.Fatal("privileged request bytes were retained after execution")
		}
	}
}

func TestPF006LinuxPrivilegeHelperCommandFailsClosedAtEveryLifecycleBoundary(t *testing.T) {
	t.Parallel()
	privateFailure := errors.New("private helper failure")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	tests := map[string]struct {
		ctx                context.Context
		arguments          []string
		input              io.Reader
		output             io.Writer
		effectiveUserID    func() int
		lockFactoryError   error
		nilLockPort        bool
		lockAcquisitionErr error
		nilLock            bool
		applicationError   error
		nilApplication     bool
		executionError     error
		closeError         error
		releaseError       error
		receipt            []byte
		want               error
	}{
		"cancelled context": {
			ctx: cancelled, arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, receipt: []byte("receipt"),
			want: context.Canceled,
		},
		"input read": {
			arguments: []string{"--request-stdin"}, input: launcherPrivilegeCommandErrorReader{},
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, receipt: []byte("receipt"),
			want: runtimeport.ErrPrivilegeIntegrity,
		},
		"empty input": {
			arguments: []string{"--request-stdin"}, input: bytes.NewReader(nil),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, receipt: []byte("receipt"),
			want: runtimeport.ErrPrivilegeIntegrity,
		},
		"lock construction": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, lockFactoryError: privateFailure,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"lock acquisition": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, lockAcquisitionErr: privateFailure,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"nil lock port": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, nilLockPort: true,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"nil acquired lock": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, nilLock: true,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"application composition": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, applicationError: privateFailure,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"nil application": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, nilApplication: true,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"request execution": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, executionError: privateFailure,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"release close": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, closeError: privateFailure,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"lock release": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 }, releaseError: privateFailure,
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"empty receipt": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 0 },
			want: runtimeport.ErrPrivilegeIntegrity,
		},
		"output write": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: launcherPrivilegeCommandErrorWriter{}, effectiveUserID: func() int { return 0 },
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
		"ambient identity": {
			arguments: []string{"--request-stdin"}, input: bytes.NewBufferString("request"),
			output: &bytes.Buffer{}, effectiveUserID: func() int { return 1000 },
			receipt: []byte("receipt"), want: runtimeport.ErrPrivilegeIntegrity,
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := test.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			lock := &launcherPrivilegeCommandLock{err: test.releaseError}
			var acquiredLock installapp.InstallationLock = lock
			if test.nilLock {
				acquiredLock = nil
			}
			port := &launcherPrivilegeCommandLockPort{lock: acquiredLock, err: test.lockAcquisitionErr}
			application := &launcherPrivilegeCommandApplication{
				receipt: test.receipt, err: test.executionError,
			}
			release := &launcherPrivilegeCommandRelease{err: test.closeError}
			err := runNativeLinuxPrivilegeHelperUsing(
				ctx, test.arguments, test.input, test.output, test.effectiveUserID,
				func(string) (installapp.InstallationLockPort, error) {
					if test.nilLockPort {
						return nil, test.lockFactoryError
					}
					return port, test.lockFactoryError
				},
				func(context.Context) (
					nativePrivilegeHelperRequestExecutor,
					nativePrivilegeHelperRelease,
					error,
				) {
					if test.nilApplication {
						return nil, nil, test.applicationError
					}
					return application, release, test.applicationError
				},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}

	if err := runNativeLinuxPrivilegeHelperUsing(
		t.Context(), []string{"--request-stdin"}, bytes.NewBufferString("request"), &bytes.Buffer{},
		nil, nil, nil,
	); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("nil production capabilities error=%v", err)
	}
}

type launcherPrivilegeCommandLockPort struct {
	lock         installapp.InstallationLock
	err          error
	acquisitions int
}

func (p *launcherPrivilegeCommandLockPort) Acquire(context.Context) (installapp.InstallationLock, error) {
	p.acquisitions++
	return p.lock, p.err
}

type launcherPrivilegeCommandLock struct {
	err      error
	releases int
}

func (l *launcherPrivilegeCommandLock) Release(context.Context) error {
	l.releases++
	return l.err
}

type launcherPrivilegeCommandApplication struct {
	receipt    []byte
	err        error
	request    []byte
	executions int
}

func (a *launcherPrivilegeCommandApplication) ExecutePrivilegeRequest(
	_ context.Context,
	raw []byte,
) ([]byte, error) {
	a.executions++
	a.request = raw
	return append([]byte(nil), a.receipt...), a.err
}

type launcherPrivilegeCommandRelease struct {
	err    error
	closes int
}

func (r *launcherPrivilegeCommandRelease) Close(context.Context) error {
	r.closes++
	return r.err
}

type launcherPrivilegeCommandErrorReader struct{}

func (launcherPrivilegeCommandErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("private reader failure")
}

type launcherPrivilegeCommandErrorWriter struct{}

func (launcherPrivilegeCommandErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("private writer failure")
}
