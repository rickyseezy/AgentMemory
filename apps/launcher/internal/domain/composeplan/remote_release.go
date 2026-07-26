package composeplan

import "time"

// RemoteReleaseInput adds only the signed gateway image and limits to an
// already closed default release input. Credential material is provisioned
// separately into gateway-only engine volumes and is never represented here.
type RemoteReleaseInput struct {
	Default           DefaultReleaseInput
	GatewayImage      string
	GatewayLimits     Limits
	EgressSecretFiles map[string]string
}

// NewRemoteReleasePlan constructs the exact optional dual-network topology.
func NewRemoteReleasePlan(input RemoteReleaseInput) (PolicyPlan, error) {
	base, err := NewDefaultReleasePlan(input.Default)
	if err != nil || input.GatewayImage == "" || input.GatewayLimits == (Limits{}) ||
		len(input.EgressSecretFiles) != len(requiredRemoteSecrets) {
		return PolicyPlan{}, errInvalidPolicyPlan
	}
	for _, name := range requiredRemoteSecrets {
		if !validSecretFile(input.EgressSecretFiles[name]) {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	for name := range input.EgressSecretFiles {
		if !requiredRemoteSecret(name) {
			return PolicyPlan{}, errInvalidPolicyPlan
		}
	}
	model, ok := base.CanonicalModel()
	if !ok {
		return PolicyPlan{}, errInvalidPolicyPlan
	}
	labels := func(purpose string, generation string) map[string]string {
		return map[string]string{
			LabelInstallation: model.Identity.InstallationID(),
			LabelRelease:      model.Release,
			LabelGeneration:   generation,
			LabelPurpose:      purpose,
			LabelManaged:      "true",
		}
	}
	model.Networks[NetworkEgress] = Network{
		Name:     model.Identity.NetworkName("egress"),
		Internal: false,
		Labels:   labels("egress", model.Identity.Generation()),
	}
	for _, purpose := range []string{
		"provider-core-egress",
		"provider-gateway-secrets",
		"provider-adapter-egress",
	} {
		name := model.Identity.StableVolumeName(purpose)
		model.Volumes[name] = Volume{
			Name: name, Labels: labels(purpose, "stable"),
		}
	}
	for _, name := range requiredRemoteSecrets {
		model.Secrets[name] = Secret{
			Name: model.Identity.StableVolumeName(name),
			File: input.EgressSecretFiles[name],
		}
	}
	core := model.Services[ServiceCore]
	core.DependsOn = append(core.DependsOn, Dependency{
		Service: ServiceProviderGateway, Condition: "service_healthy", Required: true,
	})
	core.Mounts = append(core.Mounts, Mount{
		Kind: MountVolume, Source: model.Identity.StableVolumeName("provider-core-egress"),
		Target: "/run/provider-egress", ReadOnly: true,
	})
	model.Services[ServiceCore] = core
	projector := model.Services[ServiceSecretProjector]
	projector.Command = []string{"remote"}
	for _, purpose := range []string{
		"provider-core-egress",
		"provider-gateway-secrets",
		"provider-adapter-egress",
	} {
		projector.Mounts = append(projector.Mounts, Mount{
			Kind: MountVolume, Source: model.Identity.StableVolumeName(purpose),
			Target: "/run/outputs/" + purpose,
		})
	}
	for _, name := range requiredRemoteSecrets {
		projector.Mounts = append(projector.Mounts, Mount{
			Kind: MountSecret, Source: name, Target: "/run/inputs/" + name,
			ReadOnly: true,
		})
	}
	model.Services[ServiceSecretProjector] = projector
	model.Services[ServiceProviderGateway] = Service{
		Name: ServiceProviderGateway, Image: input.GatewayImage,
		User: "10001:10001", ReadOnly: true, CapDropAll: true,
		NoNewPrivileges: true, Restart: "unless-stopped",
		Networks: []NetworkName{NetworkEgress, NetworkInternal},
		Healthcheck: []string{
			"CMD", "/usr/local/bin/agentmemory-provider-gateway", "healthcheck",
		},
		HealthTiming: HealthcheckTiming{
			Interval: 10 * time.Second, Timeout: 5 * time.Second, Retries: 6,
			StartPeriod: 30 * time.Second, StartInterval: 2 * time.Second,
		},
		StopGracePeriod: 30 * time.Second,
		Limits:          input.GatewayLimits,
		Tmpfs: []Tmpfs{{
			Target: "/tmp", SizeBytes: 64 * 1024 * 1024, Mode: 0o1777,
		}},
		Mounts: []Mount{
			{
				Kind:   MountVolume,
				Source: model.Identity.StableVolumeName("provider-gateway-secrets"),
				Target: "/run/secrets", ReadOnly: true,
			},
			{
				Kind: MountVolume, Source: model.Identity.StableVolumeName("telemetry"),
				Target: "/var/lib/agentmemory/telemetry",
			},
		},
		Environment: map[string]string{},
		Labels:      labels(string(ServiceProviderGateway), model.Identity.Generation()),
	}
	return NewPolicyPlan(model)
}
