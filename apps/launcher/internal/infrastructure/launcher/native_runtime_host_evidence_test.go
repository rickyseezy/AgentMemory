package launcher

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestNativeRuntimeHostReattestorRequiresExactCommittedReceipt(t *testing.T) {
	t.Parallel()
	request := nativeRuntimeEvidenceRequest(t)
	observation, err := hostverification.NewObservation(hostverification.ObservationInput{
		Platform: request.SignedHostPlan.Plan().Platform(), CPUCores: 8,
		MemoryBytes: 32 << 30, FreeDiskBytes: 100 << 30,
		StorageTarget:  request.HostStorageTarget,
		Virtualization: hostverification.VirtualizationHypervisorFramework,
		Encryption:     hostverification.EncryptionFileVault,
		AvailablePorts: request.SignedHostPlan.Plan().RequiredPorts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := hostverification.NewObservedResult(observation)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := hostverifyapp.NewApplication(hostverifyapp.Dependencies{
		Signature: nativeRuntimeHostSignature{}, Probe: nativeRuntimeHostProbe{result: result},
	})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := verifier.Verify(t.Context(), hostverifyapp.Command{
		OperationID: request.OperationID, ParentPlanDigest: request.ParentPlanDigest,
		SignedPlan: request.SignedHostPlan, StorageTarget: request.HostStorageTarget,
	})
	if err != nil {
		t.Fatal(err)
	}
	request.HostEvidenceDigest = verification.EvidenceDigest()
	attestor := nativeRuntimeHostReattestor{verifier: verifier}
	if err := attestor.ReattestHost(t.Context(), request); err != nil {
		t.Fatalf("exact receipt error=%v", err)
	}
	request.HostEvidenceDigest = install.DigestBytes([]byte("foreign receipt"))
	if err := attestor.ReattestHost(t.Context(), request); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("foreign receipt error=%v", err)
	}
	if err := (nativeRuntimeHostReattestor{}).ReattestHost(t.Context(), request); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil verifier error=%v", err)
	}
}

type nativeRuntimeHostSignature struct{}

func (nativeRuntimeHostSignature) VerifyHostPlanSignature(context.Context, hostverification.SignedPlan) error {
	return nil
}

type nativeRuntimeHostProbe struct {
	result hostverification.ProbeResult
}

func (p nativeRuntimeHostProbe) ProbeHost(
	context.Context,
	hostverification.Plan,
	string,
) (hostverification.ProbeResult, error) {
	return p.result, nil
}

var _ interface {
	ReattestHost(context.Context, installplanapp.RuntimeEvidenceRequest) error
} = nativeRuntimeHostReattestor{}
