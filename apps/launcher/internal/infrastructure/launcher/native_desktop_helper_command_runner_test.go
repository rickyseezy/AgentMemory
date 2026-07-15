package launcher

import (
	"context"
	"errors"
	"io"
	"runtime"
	"slices"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestPF001NativeDesktopMutationHelperCompositionBuildsCompleteVerifiedApplication(t *testing.T) {
	t.Parallel()
	fixture := nativeReleaseStackFixture(t)
	binding := &nativeDesktopHelperCompositionBindingStub{}
	principal := nativeDesktopCompositionTestPrincipal()
	authority := nativeDesktopMutationHelperCompositionAuthority{
		elevated:   func() bool { return true },
		bundleRoot: func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
		trust:      func() (nativeReleaseTrustMaterial, error) { return fixture.Trust, nil },
		binding: func(candidate string) (runtimeprovision.DesktopHostBindingProvider, error) {
			if candidate != principal {
				t.Fatalf("principal=%q", candidate)
			}
			return binding, nil
		},
		journals: func(string, string) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		},
	}
	application, release, closers, err := newNativeDesktopMutationHelperApplicationWithAuthority(
		t.Context(), t.TempDir(), principal, authority,
	)
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		if application != nil || release != nil || len(closers) != 0 ||
			!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
			t.Fatalf("foreign desktop application=%T release=%T closers=%d error=%v", application, release, len(closers), err)
		}
		return
	}
	if err != nil || application == nil || release == nil {
		t.Fatalf("application=%T release=%T closers=%d error=%v", application, release, len(closers), err)
	}
	if err := closeNativeRuntimeResources(t.Context(), closers); err != nil {
		t.Fatal(err)
	}
	if err := release.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	authority.elevated = nil
	if application, release, closers, err := newNativeDesktopMutationHelperApplicationWithAuthority(
		t.Context(), t.TempDir(), principal, authority,
	); application != nil || release != nil || len(closers) != 0 || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("incomplete authority application=%T release=%T closers=%d error=%v", application, release, len(closers), err)
	}
}

func nativeDesktopCompositionTestPrincipal() string {
	if runtime.GOOS == "windows" {
		return "sid:S-1-5-21-1000-1001-1002-1003"
	}
	return "uid:501"
}

func TestPF001NativeDesktopMutationHelperCompositionContainsAuthorityFailures(t *testing.T) {
	t.Parallel()
	private := errors.New("private")
	valid := func() nativeDesktopMutationHelperCompositionAuthority {
		fixture := nativeReleaseStackFixture(t)
		return nativeDesktopMutationHelperCompositionAuthority{
			elevated:   func() bool { return true },
			bundleRoot: func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
			trust:      func() (nativeReleaseTrustMaterial, error) { return fixture.Trust, nil },
			binding: func(string) (runtimeprovision.DesktopHostBindingProvider, error) {
				return &nativeDesktopHelperCompositionBindingStub{}, nil
			},
			journals: func(string, string) (filesystem.OperationJournalProvider, error) {
				return nativeMissingJournalProvider{}, nil
			},
		}
	}
	for name, mutate := range map[string]func(*nativeDesktopMutationHelperCompositionAuthority){
		"journal": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			a.journals = func(string, string) (filesystem.OperationJournalProvider, error) { return nil, private }
		},
		"catalog journal": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			calls := 0
			a.journals = func(string, string) (filesystem.OperationJournalProvider, error) {
				calls++
				if calls == 2 {
					return nil, private
				}
				return nativeMissingJournalProvider{}, nil
			}
		},
		"replay journal": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			calls := 0
			a.journals = func(string, string) (filesystem.OperationJournalProvider, error) {
				calls++
				if calls == 3 {
					return nil, private
				}
				return nativeMissingJournalProvider{}, nil
			}
		},
		"release anchor": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			a.journals = func(string, string) (filesystem.OperationJournalProvider, error) { return nil, nil }
		},
		"catalog anchor": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			calls := 0
			a.journals = func(string, string) (filesystem.OperationJournalProvider, error) {
				calls++
				if calls == 2 {
					return nil, nil
				}
				return nativeMissingJournalProvider{}, nil
			}
		},
		"replay repository": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			calls := 0
			a.journals = func(string, string) (filesystem.OperationJournalProvider, error) {
				calls++
				if calls == 3 {
					return nil, nil
				}
				return nativeMissingJournalProvider{}, nil
			}
		},
		"bundle": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			a.bundleRoot = func() (string, error) { return "", private }
		},
		"trust": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			a.trust = func() (nativeReleaseTrustMaterial, error) { return nativeReleaseTrustMaterial{}, private }
		},
		"binding": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			a.binding = func(string) (runtimeprovision.DesktopHostBindingProvider, error) { return nil, private }
		},
		"typed nil binding": func(a *nativeDesktopMutationHelperCompositionAuthority) {
			a.binding = func(string) (runtimeprovision.DesktopHostBindingProvider, error) { return nil, nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			authority := valid()
			mutate(&authority)
			application, release, closers, err := newNativeDesktopMutationHelperApplicationWithAuthority(
				t.Context(), t.TempDir(), "uid:501", authority,
			)
			if application != nil || release != nil || len(closers) != 0 ||
				!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
				t.Fatalf("application=%T release=%T closers=%d error=%v", application, release, len(closers), err)
			}
		})
	}
}

func TestPF001NativeDesktopHelperCommandExecutesUnderExclusiveStateLock(t *testing.T) {
	t.Parallel()
	exchange := &nativeDesktopHelperCommandExchangeStub{raw: []byte(`{"request":true}`), receiptPath: "/owner/request.receipt.json"}
	application := &nativeDesktopHelperCommandApplicationStub{receipt: []byte(`{"receipt":true}`)}
	release := &nativeDesktopHelperCommandReleaseStub{}
	closer := &nativeRuntimeCloserStub{}
	dependencies := nativeDesktopHelperCommandDependencies{
		elevated: func() bool { return true },
		boundaries: func(string) (string, nativeDesktopHelperExchange, error) {
			return t.TempDir(), exchange, nil
		},
		application: func(
			context.Context,
			string,
			string,
		) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error) {
			return application, release, []nativeRuntimeResourceCloser{closer}, nil
		},
	}
	if err := runNativeDesktopMutationHelper(
		t.Context(), []string{"--execute-desktop-mutation", "/owner/request.json"}, dependencies,
	); err != nil {
		t.Fatal(err)
	}
	if application.calls != 1 || exchange.reads != 1 || exchange.writes != 1 ||
		!slices.Equal(exchange.receipt, []byte(`{"receipt":true}`)) || release.calls != 1 || closer.calls != 1 {
		t.Fatalf("calls application/read/write/release/close=%d/%d/%d/%d/%d receipt=%q",
			application.calls, exchange.reads, exchange.writes, release.calls, closer.calls, exchange.receipt)
	}
}

func TestPF001NativeDesktopHelperCommandContainsEveryBoundaryFailure(t *testing.T) {
	t.Parallel()
	private := errors.New("private")
	valid := func() (nativeDesktopHelperCommandDependencies, *nativeDesktopHelperCommandExchangeStub) {
		exchange := &nativeDesktopHelperCommandExchangeStub{raw: []byte(`{}`), receiptPath: "/owner/request.receipt.json"}
		dependencies := nativeDesktopHelperCommandDependencies{
			elevated: func() bool { return true },
			boundaries: func(string) (string, nativeDesktopHelperExchange, error) {
				return t.TempDir(), exchange, nil
			},
			application: func(
				context.Context,
				string,
				string,
			) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error) {
				return &nativeDesktopHelperCommandApplicationStub{receipt: []byte(`{}`)},
					&nativeDesktopHelperCommandReleaseStub{}, nil, nil
			},
		}
		return dependencies, exchange
	}
	for name, mutate := range map[string]func(*nativeDesktopHelperCommandDependencies, *nativeDesktopHelperCommandExchangeStub){
		"platform": func(d *nativeDesktopHelperCommandDependencies, _ *nativeDesktopHelperCommandExchangeStub) {
			d.boundaries = func(string) (string, nativeDesktopHelperExchange, error) { return "", nil, private }
		},
		"request": func(_ *nativeDesktopHelperCommandDependencies, e *nativeDesktopHelperCommandExchangeStub) {
			e.readErr = private
		},
		"application": func(d *nativeDesktopHelperCommandDependencies, _ *nativeDesktopHelperCommandExchangeStub) {
			d.application = func(
				context.Context, string, string,
			) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error) {
				return nil, nil, nil, private
			}
		},
		"execution": func(d *nativeDesktopHelperCommandDependencies, _ *nativeDesktopHelperCommandExchangeStub) {
			d.application = func(
				context.Context, string, string,
			) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error) {
				return &nativeDesktopHelperCommandApplicationStub{err: private}, &nativeDesktopHelperCommandReleaseStub{}, nil, nil
			}
		},
		"resource close": func(d *nativeDesktopHelperCommandDependencies, _ *nativeDesktopHelperCommandExchangeStub) {
			d.application = func(
				context.Context, string, string,
			) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error) {
				return &nativeDesktopHelperCommandApplicationStub{receipt: []byte(`{}`)},
					&nativeDesktopHelperCommandReleaseStub{}, []nativeRuntimeResourceCloser{&nativeRuntimeCloserStub{err: private}}, nil
			}
		},
		"release close": func(d *nativeDesktopHelperCommandDependencies, _ *nativeDesktopHelperCommandExchangeStub) {
			d.application = func(
				context.Context, string, string,
			) (nativeDesktopHelperCommandApplication, nativeDesktopHelperCommandRelease, []nativeRuntimeResourceCloser, error) {
				return &nativeDesktopHelperCommandApplicationStub{receipt: []byte(`{}`)},
					&nativeDesktopHelperCommandReleaseStub{err: private}, nil, nil
			}
		},
		"receipt write": func(_ *nativeDesktopHelperCommandDependencies, e *nativeDesktopHelperCommandExchangeStub) {
			e.writeErr = private
		},
	} {
		t.Run(name, func(t *testing.T) {
			dependencies, exchange := valid()
			mutate(&dependencies, exchange)
			if err := runNativeDesktopMutationHelper(
				t.Context(), []string{"--execute-desktop-mutation", "/owner/request.json"}, dependencies,
			); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) || errors.Is(err, private) {
				t.Fatalf("contained error=%v", err)
			}
		})
	}
	dependencies, _ := valid()
	dependencies.elevated = nil
	if err := runNativeDesktopMutationHelper(t.Context(), []string{"--execute-desktop-mutation", "/owner/request.json"}, dependencies); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("missing authority error=%v", err)
	}
}

func TestPF001NativeDesktopMutationCommandRunnerRejectsUntrustedBoundaryInputs(t *testing.T) {
	t.Parallel()
	runner := nativeDesktopMutationCommandRunner{}
	//lint:ignore SA1012 Deliberate nil-context process-runner regression fixture.
	if code, err := runner.RunDesktopMutationCommand(nil, runtimeprovision.DesktopMutationCommand{}); code != 0 || //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("nil context code=%d error=%v", code, err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if code, err := runner.RunDesktopMutationCommand(cancelled, runtimeprovision.DesktopMutationCommand{}); code != 0 ||
		!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("zero command code=%d error=%v", code, err)
	}
}

func TestPF001NativeDesktopMutationCommandOutputIsStrictlyBounded(t *testing.T) {
	t.Parallel()
	var absent *nativeDesktopMutationBoundedWriter
	if written, err := absent.Write([]byte("x")); written != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("absent writer bytes=%d error=%v", written, err)
	}

	writer := &nativeDesktopMutationBoundedWriter{remaining: 4}
	if written, err := writer.Write([]byte("ab")); err != nil || written != 2 || writer.remaining != 2 || writer.exceeded {
		t.Fatalf("bounded write bytes=%d remaining=%d exceeded=%t error=%v", written, writer.remaining, writer.exceeded, err)
	}
	if written, err := writer.Write([]byte("cdef")); err != nil || written != 4 || writer.remaining != 0 ||
		!writer.exceeded || writer.buffer.String() != "abcd" {
		t.Fatalf("overflow bytes=%d buffer=%q remaining=%d exceeded=%t error=%v",
			written, writer.buffer.String(), writer.remaining, writer.exceeded, err)
	}
}

func TestPF001NativeDesktopMutationExitCodeAcceptsOnlyUint32ProcessStatus(t *testing.T) {
	t.Parallel()
	for _, expected := range []int{0, 17} {
		actual, ok := nativeDesktopMutationExitCode(nativeDesktopExitError(expected))
		if !ok || actual != uint32(expected) { // #nosec G115 -- fixture values are fixed non-negative uint32 values.
			t.Fatalf("exit code %d mapped to (%d, %t)", expected, actual, ok)
		}
	}
	for _, failure := range []error{errors.New("not an exit status"), nativeDesktopExitError(-1)} {
		if actual, ok := nativeDesktopMutationExitCode(failure); ok || actual != 0 {
			t.Fatalf("invalid exit error %v mapped to (%d, %t)", failure, actual, ok)
		}
	}
}

type nativeDesktopExitError int

func (e nativeDesktopExitError) Error() string { return "native desktop test exit" }

func (e nativeDesktopExitError) ExitCode() int { return int(e) }

type nativeDesktopHelperCommandExchangeStub struct {
	raw         []byte
	receipt     []byte
	receiptPath string
	readErr     error
	writeErr    error
	reads       int
	writes      int
}

func (s *nativeDesktopHelperCommandExchangeStub) ReadDesktopMutationRequest(
	context.Context,
	string,
) ([]byte, string, error) {
	s.reads++
	return slices.Clone(s.raw), s.receiptPath, s.readErr
}

func (s *nativeDesktopHelperCommandExchangeStub) WriteDesktopMutationReceipt(
	_ context.Context,
	_ string,
	receipt []byte,
) error {
	s.writes++
	s.receipt = slices.Clone(receipt)
	return s.writeErr
}

func (*nativeDesktopHelperCommandExchangeStub) PrincipalID() string { return "uid:501" }

type nativeDesktopHelperCommandApplicationStub struct {
	receipt []byte
	err     error
	calls   int
}

func (s *nativeDesktopHelperCommandApplicationStub) ExecuteDesktopMutationRequest(
	context.Context,
	[]byte,
) ([]byte, error) {
	s.calls++
	return slices.Clone(s.receipt), s.err
}

type nativeDesktopHelperCommandReleaseStub struct {
	err   error
	calls int
}

func (s *nativeDesktopHelperCommandReleaseStub) Close(context.Context) error {
	s.calls++
	return s.err
}

type nativeDesktopHelperCompositionBindingStub struct{}

func (*nativeDesktopHelperCompositionBindingStub) CurrentDesktopHostBinding(
	context.Context,
	runtimecatalog.Digest,
	string,
) (runtimecatalogapp.DesktopHostBinding, error) {
	return runtimecatalogapp.DesktopHostBinding{}, nil
}
