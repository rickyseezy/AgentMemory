package secretprojector

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func TestPF001DefaultProjectionContractIsClosedAndLeastPrivilege(t *testing.T) {
	t.Parallel()

	contract := defaultContract()
	if len(contract) != 6 || contract[0].purpose != purposeCore || len(contract[0].files) != 8 {
		t.Fatalf("default contract = %#v", contract)
	}
	if contract[1].files[0].userID != 10_001 || contract[2].files[0].userID != 7474 ||
		contract[2].files[0].groupID != 7474 || contract[0].files[7].maxBytes != maximumAttestationBytes {
		t.Fatalf("projection ownership/length contract = %#v", contract)
	}
	seen := make(map[string]struct{}, len(contract))
	for _, volume := range contract {
		if volume.purpose == "" || len(volume.files) == 0 {
			t.Fatalf("empty projection contract = %#v", volume)
		}
		if _, duplicate := seen[volume.purpose]; duplicate {
			t.Fatalf("duplicate projection purpose %q", volume.purpose)
		}
		seen[volume.purpose] = struct{}{}
		for _, file := range volume.files {
			if file.name == "" || file.maxBytes == 0 || inputPath(file.name) == inputRoot ||
				outputPath(volume.purpose) == outputRoot {
				t.Fatalf("invalid projection file = %#v", file)
			}
		}
	}
}

func TestPRO009RemoteProjectionSeparatesCoreGatewayAndAdapterAuthority(t *testing.T) {
	t.Parallel()
	contract := remoteContract()
	if len(contract) != 9 {
		t.Fatalf("remote projection count=%d", len(contract))
	}
	byPurpose := make(map[string]volumeContract, len(contract))
	for _, volume := range contract {
		byPurpose[volume.purpose] = volume
	}
	core := byPurpose[purposeProviderCoreEgress]
	gateway := byPurpose[purposeProviderGateway]
	adapter := byPurpose[purposeProviderAdapterEgress]
	if len(core.files) != 2 || len(gateway.files) != 5 || len(adapter.files) != 1 ||
		adapter.files[0].name != composeplan.SecretProviderGatewayClientCapability ||
		adapter.files[0].userID != 65_532 ||
		gateway.files[2].name != composeplan.SecretProviderGatewayCredentialVault ||
		gateway.files[2].maxBytes != maximumCredentialVaultBytes {
		t.Fatalf("remote authority escaped projection: %#v", contract)
	}
	for _, file := range adapter.files {
		if file.name == composeplan.SecretProviderGatewayPermitHMACKey ||
			file.name == composeplan.SecretProviderGatewayCredentialVault ||
			file.name == composeplan.SecretProviderGatewayCredentialVaultHMACKey {
			t.Fatalf("custom adapter received gateway authority: %#v", file)
		}
	}
}
