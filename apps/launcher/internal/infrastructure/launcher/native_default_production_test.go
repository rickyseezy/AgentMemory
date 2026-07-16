package launcher

import (
	"context"
	"errors"
	"testing"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
)

func TestPF001DefaultNativeProductionRequiresCompleteLocalComposition(t *testing.T) {
	t.Parallel()
	installed := newInstalledNativeFactory()
	if installed == nil || installed.roots == nil || installed.journals == nil ||
		nilCapability(installed.ready) || installed.production == nil {
		t.Fatalf("installed native factory=%+v", installed)
	}
	if production, err := composeDefaultNativeProduction(t.Context(), nil); !errors.Is(err, errNativeInstallerIntegrity) ||
		production.Factory != nil || production.Supervisor != nil || production.Release != nil {
		t.Fatalf("nil composition=%+v error=%v", production, err)
	}
	if production, err := composeDefaultNativeProduction(t.Context(), &nativeComposition{}); !errors.Is(err, errNativeInstallerIntegrity) ||
		production.Factory != nil || production.Supervisor != nil || production.Release != nil {
		t.Fatalf("incomplete composition=%+v error=%v", production, err)
	}
	//lint:ignore SA1012 Deliberate nil-context production boundary attack.
	if production, err := composeDefaultNativeProduction(nil, &nativeComposition{}); !errors.Is(err, errNativeInstallerIntegrity) || //nolint:staticcheck // Security regression fixture; owner=security expiry=2027-07-14.
		production.Factory != nil || production.Supervisor != nil || production.Release != nil {
		t.Fatalf("nil context production=%+v error=%v", production, err)
	}
	if production, err := composeInstalledNativeProduction(t.Context(), nil); !errors.Is(err, errNativeInstallerIntegrity) ||
		production.Factory != nil || production.Supervisor != nil || production.Release != nil {
		t.Fatalf("nil installed composition=%+v error=%v", production, err)
	}
}

func TestPF001DefaultNativeProductionFailsClosedWithoutPackagedRelease(t *testing.T) {
	t.Parallel()
	composition, err := composeNative(
		t.Context(), nativeTestRoots(t.TempDir()),
		func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		},
		pendingReadySurface{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = composition.resources.Close(context.Background()) })
	production, err := composeDefaultNativeProduction(t.Context(), &composition)
	if err == nil || production.Factory != nil || production.Supervisor != nil || production.Release != nil {
		t.Fatalf("unpackaged production=%+v error=%v", production, err)
	}
}
