package launcher

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001NativeCommandInstallerBuildsOnlyFromAuthenticatedCommandAuthority(t *testing.T) {
	t.Parallel()
	command := nativeInstallerCommandFixture(t)
	wantResult := installapp.InstallResult{OperationID: command.OperationID}
	application := &nativeInstallApplicationStub{result: wantResult}
	var built nativeInstallAuthority
	installer, err := newNativeCommandInstallerWithAuthenticator(func(
		_ context.Context,
		authority nativeInstallAuthority,
	) (nativeInstallApplication, error) {
		built = authority
		return application, nil
	}, nativeInstallerAuthenticatorFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := installer.Install(t.Context(), command)
	if err != nil || result.OperationID != wantResult.OperationID || application.calls != 1 {
		t.Fatalf("Install()=(%+v,%v) calls=%d", result, err, application.calls)
	}
	operationID, _ := install.NewOperationID(command.OperationID)
	digest, _ := install.BindPlan(command.CanonicalPlan)
	if built.OperationID != operationID || !built.PlanDigest.Equal(digest) ||
		string(built.CanonicalPlan) != string(command.CanonicalPlan) {
		t.Fatalf("built authority=%+v", built)
	}
	command.CanonicalPlan[0] ^= 0xff
	if string(application.command.CanonicalPlan) != string(built.CanonicalPlan) {
		t.Fatal("application command aliases caller-owned plan bytes")
	}
}

func TestPF001NativeCommandInstallerRejectsSubstitutionBeforeComposition(t *testing.T) {
	t.Parallel()
	command := nativeInstallerCommandFixture(t)
	builds := 0
	installer, err := newNativeCommandInstaller(func(
		context.Context,
		nativeInstallAuthority,
	) (nativeInstallApplication, error) {
		builds++
		return &nativeInstallApplicationStub{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	foreign := command
	foreign.OperationID = "019f5f23-5678-7def-9123-abcdef012399"
	nonCanonical := command
	nonCanonical.CanonicalPlan = append(append([]byte(nil), command.CanonicalPlan...), '\n')
	missingPlan := command
	missingPlan.CanonicalPlan = nil
	invalidID := command
	invalidID.OperationID = "invalid"
	for name, candidate := range map[string]installapp.InstallCommand{
		"foreign operation": foreign,
		"non canonical":     nonCanonical,
		"missing plan":      missingPlan,
		"invalid operation": invalidID,
	} {
		if _, installError := installer.Install(t.Context(), candidate); !errors.Is(installError, errNativeInstallerIntegrity) {
			t.Fatalf("%s error=%v", name, installError)
		}
	}
	//lint:ignore SA1012 Deliberate nil-context boundary attack.
	if _, installError := installer.Install(nil, command); !errors.Is(installError, errNativeInstallerIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", installError)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, installError := installer.Install(cancelled, command); !errors.Is(installError, context.Canceled) {
		t.Fatalf("cancelled context error=%v", installError)
	}
	if builds != 0 {
		t.Fatalf("invalid commands reached graph composition: %d", builds)
	}
}

func TestPF001NativeCommandInstallerFailsClosedOnCompositionFailure(t *testing.T) {
	t.Parallel()
	command := nativeInstallerCommandFixture(t)
	var typedNil *nativeInstallApplicationStub
	for name, factory := range map[string]nativeInstallApplicationFactory{
		"nil factory": nil,
		"factory error": func(context.Context, nativeInstallAuthority) (nativeInstallApplication, error) {
			return nil, errors.New("private")
		},
		"nil application": func(context.Context, nativeInstallAuthority) (nativeInstallApplication, error) {
			return nil, nil
		},
		"typed nil application": func(context.Context, nativeInstallAuthority) (nativeInstallApplication, error) {
			return typedNil, nil
		},
	} {
		installer, constructError := newNativeCommandInstallerWithAuthenticator(
			factory, nativeInstallerAuthenticatorFixture(t),
		)
		if name == "nil factory" {
			if installer != nil || !errors.Is(constructError, errNativeInstallerIntegrity) {
				t.Fatalf("%s constructor=(%v,%v)", name, installer, constructError)
			}
			continue
		}
		if constructError != nil {
			t.Fatalf("%s constructor error=%v", name, constructError)
		}
		if _, installError := installer.Install(t.Context(), command); !errors.Is(installError, errNativeInstallerUnavailable) {
			t.Fatalf("%s install error=%v", name, installError)
		}
	}
}

func TestPF001NativeCommandInstallerClosesOperationScopedApplication(t *testing.T) {
	t.Parallel()
	command := nativeInstallerCommandFixture(t)
	application := &nativeInstallApplicationStub{}
	installer, err := newNativeCommandInstallerWithAuthenticator(
		func(context.Context, nativeInstallAuthority) (nativeInstallApplication, error) {
			return application, nil
		}, nativeInstallerAuthenticatorFixture(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(t.Context(), command); err != nil || application.closed != 1 {
		t.Fatalf("install error=%v closes=%d", err, application.closed)
	}
	application.closeError = errors.New("private close error")
	if _, err := installer.Install(t.Context(), command); !errors.Is(err, errNativeInstallerUnavailable) ||
		application.closed != 2 {
		t.Fatalf("close failure error=%v closes=%d", err, application.closed)
	}
}

type nativeInstallApplicationStub struct {
	result     installapp.InstallResult
	err        error
	command    installapp.InstallCommand
	calls      int
	closed     int
	closeError error
}

func (s *nativeInstallApplicationStub) Close(context.Context) error {
	s.closed++
	return s.closeError
}

func (s *nativeInstallApplicationStub) Install(
	_ context.Context,
	command installapp.InstallCommand,
) (installapp.InstallResult, error) {
	s.calls++
	s.command = command
	return s.result, s.err
}

func nativeInstallerCommandFixture(t testing.TB) installapp.InstallCommand {
	t.Helper()
	operationID := "019f5f23-5678-7def-9123-abcdef012347"
	return installapp.InstallCommand{
		OperationID: operationID, CanonicalPlan: []byte("authenticated canonical plan"),
	}
}

func nativeInstallerAuthenticatorFixture(t testing.TB) nativeInstallAuthenticator {
	t.Helper()
	return func(command installapp.InstallCommand) (nativeInstallAuthority, error) {
		operationID, err := install.NewOperationID(command.OperationID)
		digest, digestError := install.BindPlan(command.CanonicalPlan)
		if err != nil || digestError != nil {
			return nativeInstallAuthority{}, errNativeInstallerIntegrity
		}
		return nativeInstallAuthority{
			OperationID: operationID, PlanDigest: digest,
			CanonicalPlan: append([]byte(nil), command.CanonicalPlan...),
		}, nil
	}
}
