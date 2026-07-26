package composeplan

import (
	"strings"
	"testing"
)

func TestPRO009RemoteReleaseHasExactlyOneDualHomedCredentialIsolatedGateway(t *testing.T) {
	t.Parallel()
	input := validRemoteReleaseInput()
	plan, err := NewRemoteReleasePlan(input)
	if err != nil || !plan.Valid() {
		t.Fatalf("NewRemoteReleasePlan() = %#v/%v", plan, err)
	}
	model, ok := plan.CanonicalModel()
	gateway := model.Services[ServiceProviderGateway]
	core := model.Services[ServiceCore]
	projector := model.Services[ServiceSecretProjector]
	secretFiles, secretFilesOK := plan.SecretFiles()
	projections, projectionsOK := plan.SecretProjectionVolumes()
	if !ok || len(NewRemotePolicy().Validate(model)) != 0 ||
		len(NewPolicy().Validate(model)) == 0 || len(model.Services) != 8 ||
		len(model.Networks) != 2 || model.Networks[NetworkEgress].Internal ||
		len(gateway.Networks) != 2 || gateway.Networks[0] != NetworkEgress ||
		gateway.Networks[1] != NetworkInternal || len(gateway.Mounts) != 2 ||
		len(gateway.Ports) != 0 || len(gateway.Environment) != 0 ||
		len(core.Networks) != 1 || core.Networks[0] != NetworkInternal ||
		len(core.DependsOn) != 6 || len(core.Mounts) != 6 ||
		!secretFilesOK || len(secretFiles) != 13 ||
		!projectionsOK || len(projections) != 9 ||
		len(projector.Mounts) != 22 || len(model.Volumes) != 15 {
		t.Fatalf("remote release model = %#v", model)
	}
	for name, service := range model.Services {
		if name != ServiceProviderGateway && len(service.Networks) > 0 &&
			(len(service.Networks) != 1 || service.Networks[0] != NetworkInternal) {
			t.Fatalf("%s escaped internal network: %#v", name, service.Networks)
		}
	}
}

func TestPRO009RemotePolicyRejectsEveryGatewayIsolationRegression(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*Model)
	}{
		{name: "missing gateway", mutate: func(model *Model) {
			delete(model.Services, ServiceProviderGateway)
		}},
		{name: "gateway internal only", mutate: func(model *Model) {
			service := model.Services[ServiceProviderGateway]
			service.Networks = []NetworkName{NetworkInternal}
			model.Services[ServiceProviderGateway] = service
		}},
		{name: "core egress", mutate: func(model *Model) {
			service := model.Services[ServiceCore]
			service.Networks = []NetworkName{NetworkEgress, NetworkInternal}
			model.Services[ServiceCore] = service
		}},
		{name: "internal externally routed", mutate: func(model *Model) {
			network := model.Networks[NetworkInternal]
			network.Internal = false
			model.Networks[NetworkInternal] = network
		}},
		{name: "gateway port", mutate: func(model *Model) {
			service := model.Services[ServiceProviderGateway]
			service.Ports = []Port{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 8080}}
			model.Services[ServiceProviderGateway] = service
		}},
		{name: "gateway state", mutate: func(model *Model) {
			service := model.Services[ServiceProviderGateway]
			service.Mounts = append(service.Mounts, Mount{
				Kind: MountVolume, Source: model.Identity.VolumeName("state"),
				Target: "/var/lib/agentmemory/state",
			})
			model.Services[ServiceProviderGateway] = service
		}},
		{name: "gateway secret volume writable", mutate: func(model *Model) {
			service := model.Services[ServiceProviderGateway]
			service.Mounts[0].ReadOnly = false
			model.Services[ServiceProviderGateway] = service
		}},
		{name: "docker socket", mutate: func(model *Model) {
			service := model.Services[ServiceProviderGateway]
			service.Mounts[0].Target = "/var/run/docker.sock"
			model.Services[ServiceProviderGateway] = service
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, err := NewRemoteReleasePlan(validRemoteReleaseInput())
			if err != nil {
				t.Fatal(err)
			}
			model, _ := plan.CanonicalModel()
			test.mutate(&model)
			if len(NewRemotePolicy().Validate(model)) == 0 {
				t.Fatalf("unsafe remote topology passed: %#v", model)
			}
		})
	}
}

func TestPRO009RemoteReleaseRejectsMutableOrMissingGatewayAuthority(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*RemoteReleaseInput){
		func(input *RemoteReleaseInput) { input.GatewayImage = "gateway:latest" },
		func(input *RemoteReleaseInput) { input.GatewayImage = "" },
		func(input *RemoteReleaseInput) { input.GatewayLimits = Limits{} },
		func(input *RemoteReleaseInput) {
			delete(input.EgressSecretFiles, SecretProviderGatewayClientCapability)
		},
		func(input *RemoteReleaseInput) {
			input.EgressSecretFiles["ambient"] = "/managed/ambient"
		},
		func(input *RemoteReleaseInput) {
			input.EgressSecretFiles[SecretProviderGatewayClientCapability] = "relative"
		},
	} {
		input := validRemoteReleaseInput()
		mutate(&input)
		if plan, err := NewRemoteReleasePlan(input); err == nil || plan.Valid() {
			t.Fatalf("unsafe remote input produced %#v/%v", plan, err)
		}
	}
}

func validRemoteReleaseInput() RemoteReleaseInput {
	return RemoteReleaseInput{
		Default: validDefaultReleaseInput(),
		GatewayImage: "ghcr.io/agentmemory/provider-gateway@sha256:" +
			strings.Repeat("e", 64),
		GatewayLimits: Limits{
			CPUsMilli: 500, MemoryBytes: 256 * 1024 * 1024, PIDs: 64,
		},
		EgressSecretFiles: map[string]string{
			SecretProviderGatewayClientCapability:       "/managed/provider-client-capability",
			SecretProviderGatewayPermitHMACKey:          "/managed/provider-permit-hmac-key",
			SecretProviderGatewayCredentialVault:        "/managed/provider-credential-vault",
			SecretProviderGatewayCredentialVaultKey:     "/managed/provider-credential-vault-key",
			SecretProviderGatewayCredentialVaultHMACKey: "/managed/provider-credential-vault-hmac-key",
		},
	}
}
