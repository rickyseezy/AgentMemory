package installplan

import (
	"bytes"
	"testing"

	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ReleaseTemplateRebindsOnlyPerHostAuthority(t *testing.T) {
	t.Parallel()
	templateInput := validPlanInput(t)
	policy := templateInput.SignedHostPlan.Plan()
	ownerPolicy, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: policy.PolicyID(), SigningKeyID: policy.SigningKeyID(), Platform: policy.Platform(),
		MinimumCPUCores: policy.MinimumCPUCores(), MinimumMemoryBytes: policy.MinimumMemoryBytes(),
		MinimumFreeDiskBytes: policy.MinimumFreeDiskBytes(), StorageTargetMode: hostverification.StorageTargetOwnerSelected,
		RequiredPorts: policy.RequiredPorts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	templateInput.SignedHostPlan, err = hostverification.NewSignedPlan(
		ownerPolicy, ownerPolicy.SigningKeyID(), bytes.Repeat([]byte{0x24}, 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	templateInput.HostStorageTarget = "/home/template/.agentmemory"
	templateInput.Product = productInputAt("/home/template/.agentmemory")
	templateInput.Artifacts.Capacity.HostRelease = templateInput.Product.ReleaseDirectory
	template, err := NewV1(templateInput)
	if err != nil {
		t.Fatal(err)
	}

	operation, _ := install.NewOperationID("019f6f1f-0000-7abc-8123-0123456789ab")
	product := productInputAt("/home/owner/.agentmemory")
	rebound, err := RebindV1(template, RebindInput{
		OperationID: operation, InstallationID: "019f6f20-1234-7abc-8123-0123456789ab",
		GenerationID: "019f6f21-5678-7def-9123-abcdef012345", RuntimeEndpoint: "unix:///var/run/docker.sock",
		SecurityEpoch: 1, HostStorageTarget: "/home/owner/.agentmemory", Product: product,
		Capacity: CapacityInput{HostCAS: "/home/owner/.agentmemory/cas", HostRelease: product.ReleaseDirectory,
			DockerEngine: "unix:///var/run/docker.sock", DockerDataVolume: "agentmemory-core-data"},
		AgentConfiguration: AgentConfigurationInput{AgentHost: agentconfigdomain.AgentHostCodex,
			ConfigLocation: "/home/owner/.codex/config.toml", EntryID: "019f6f22-5678-7def-9123-abcdef012346",
			LauncherDigest: template.AgentConfiguration().LauncherDigest(), LauncherPath: "/opt/agentmemory/bin/agentmemory"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rebound.OperationID() != operation || rebound.HostStorageTarget() != "/home/owner/.agentmemory" ||
		rebound.RuntimeOwnership() != install.RuntimeOwnershipUndetermined ||
		rebound.AgentConfiguration().AgentHost() != agentconfigdomain.AgentHostCodex ||
		!bytes.Equal(rebound.SignedRelease().SignaturePayload(), template.SignedRelease().SignaturePayload()) ||
		!bytes.Equal(rebound.SignedHostPlan().Signature(), template.SignedHostPlan().Signature()) {
		t.Fatal("rebound plan lost a dynamic or signed binding")
	}
	if bytes.Equal(rebound.CanonicalBytes(), template.CanonicalBytes()) || rebound.Digest().Equal(template.Digest()) {
		t.Fatal("per-host rebind reused template identity")
	}
}

func productInputAt(root string) ProductInput {
	product := testProductInput()
	oldRoot := "/home/user/.agentmemory"
	replace := func(value string) string { return root + value[len(oldRoot):] }
	product.ReleaseDirectory = replace(product.ReleaseDirectory)
	product.ConfigurationDirectory = replace(product.ConfigurationDirectory)
	product.RuntimeDirectory = replace(product.RuntimeDirectory)
	product.SecretDirectory = replace(product.SecretDirectory)
	product.BackupDirectory = replace(product.BackupDirectory)
	product.ComposeProjectDirectory = replace(product.ComposeProjectDirectory)
	product.ComposeConfigurationPath = replace(product.ComposeConfigurationPath)
	product.EmptyEnvironmentPath = replace(product.EmptyEnvironmentPath)
	product.EgressAttestationPath = replace(product.EgressAttestationPath)
	for index := range product.SecretFiles {
		product.SecretFiles[index].Path = replace(product.SecretFiles[index].Path)
	}
	return product
}
