package launcher

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
)

func TestPF001ProductionFirstStartUsesVerifiedReleaseAndOneSupervisor(t *testing.T) {
	t.Parallel()
	releaseFixture := nativeReleaseStackFixture(t)
	firstStart := nativeFirstStartFixture()
	applications := firstStart.Applications
	firstStart.Templates = nil
	firstStart.Applications = nil
	composition, err := composeNativeProductionFirstStart(t.Context(), nativeProductionFirstStartDependencies{
		Release: nativeReleaseAuthorityDependencies{
			BundleRoot: func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
			Trust:      func() (nativeReleaseTrustMaterial, error) { return releaseFixture.Trust, nil },
			Clock:      releaseFixture.Clock, AntiRollback: releaseFixture.AntiRollback,
		},
		Applications: func(context.Context, *nativeReleaseAuthority) (nativeInstallApplicationFactory, error) {
			return applications, nil
		},
		FirstStart: firstStart,
	})
	if err != nil || composition.Factory == nil || composition.Supervisor == nil ||
		composition.Release == nil || firstStart.Runtime.supervisor != composition.Supervisor {
		t.Fatalf("composition=%#v error=%v", composition, err)
	}
	if err := composition.Supervisor.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := composition.Release.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestPF001ProductionFirstStartDoesNotExposePartialAuthority(t *testing.T) {
	t.Parallel()
	releaseFixture := nativeReleaseStackFixture(t)
	valid := nativeProductionFirstStartDependencies{
		Release: nativeReleaseAuthorityDependencies{
			BundleRoot: func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
			Trust:      func() (nativeReleaseTrustMaterial, error) { return releaseFixture.Trust, nil },
			Clock:      releaseFixture.Clock, AntiRollback: releaseFixture.AntiRollback,
		},
		Applications: func(context.Context, *nativeReleaseAuthority) (nativeInstallApplicationFactory, error) {
			return nativeFirstStartFixture().Applications, nil
		},
		FirstStart: nativeFirstStartFixture(),
	}
	for _, test := range []struct {
		name   string
		mutate func(*nativeProductionFirstStartDependencies)
		want   error
	}{
		{name: "release", mutate: func(d *nativeProductionFirstStartDependencies) { d.Release.Trust = nil }, want: firststartapp.ErrIntegrity},
		{name: "applications", mutate: func(d *nativeProductionFirstStartDependencies) { d.Applications = nil }, want: errNativeInstallerIntegrity},
		{name: "application failure", mutate: func(d *nativeProductionFirstStartDependencies) {
			d.Applications = func(context.Context, *nativeReleaseAuthority) (nativeInstallApplicationFactory, error) {
				return nil, errors.New("private graph")
			}
		}, want: errNativeInstallerIntegrity},
		{name: "resolver", mutate: func(d *nativeProductionFirstStartDependencies) { d.FirstStart.Resolver = nil }, want: errNativeInstallerIntegrity},
		{name: "plans", mutate: func(d *nativeProductionFirstStartDependencies) { d.FirstStart.Plans = nil }, want: errNativeInstallerIntegrity},
		{name: "operations", mutate: func(d *nativeProductionFirstStartDependencies) { d.FirstStart.Operations = nil }, want: errNativeInstallerIntegrity},
		{name: "preparations", mutate: func(d *nativeProductionFirstStartDependencies) { d.FirstStart.Preparations = nil }, want: errNativeInstallerIntegrity},
		{name: "binder", mutate: func(d *nativeProductionFirstStartDependencies) { d.FirstStart.Binder = nil }, want: errNativeInstallerIntegrity},
		{name: "runtime", mutate: func(d *nativeProductionFirstStartDependencies) { d.FirstStart.Runtime = nil }, want: errNativeInstallerIntegrity},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			composition, err := composeNativeProductionFirstStart(t.Context(), candidate)
			if composition.Factory != nil || composition.Supervisor != nil || composition.Release != nil ||
				!errors.Is(err, test.want) {
				t.Fatalf("composition=%#v error=%v want=%v", composition, err, test.want)
			}
		})
	}
	//lint:ignore SA1012 Deliberate absent-context production boundary.
	if composition, err := composeNativeProductionFirstStart(nil, valid); composition.Factory != nil || //nolint:staticcheck
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil context composition=%#v error=%v", composition, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if composition, err := composeNativeProductionFirstStart(canceled, valid); composition.Factory != nil ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("canceled composition=%#v error=%v", composition, err)
	}
}
