package composeplan

import "sort"

// RemotePolicy validates the closed optional provider-egress topology. The
// default Policy remains offline-only and continues to reject this profile.
type RemotePolicy struct{}

// NewRemotePolicy constructs the stateless remote-profile policy.
func NewRemotePolicy() RemotePolicy { return RemotePolicy{} }

// RequiredRemoteServices returns the complete closed remote-profile inventory.
func RequiredRemoteServices() []ServiceName {
	return append(RequiredDefaultServices(), ServiceProviderGateway)
}

// Validate returns deterministic violations for the exact dual-homed topology.
func (RemotePolicy) Validate(model Model) []Violation {
	violations := make([]Violation, 0)
	if !validReleaseIdentity(model.Release) {
		violations = append(violations, Violation{Code: ViolationLabels, Resource: "release"})
	}
	requiredServices := RequiredRemoteServices()
	for _, required := range requiredServices {
		if _, exists := model.Services[required]; !exists {
			violations = append(violations, Violation{
				Code: ViolationRequiredService, Resource: string(required),
			})
		}
	}
	serviceNames := make([]string, 0, len(model.Services))
	for name := range model.Services {
		serviceNames = append(serviceNames, string(name))
	}
	sort.Strings(serviceNames)
	for _, rawName := range serviceNames {
		name := ServiceName(rawName)
		if !remoteService(name) {
			violations = append(violations, Violation{
				Code: ViolationClosedInventory, Resource: rawName,
			})
			continue
		}
		violations = append(violations, validateService(model, name, model.Services[name])...)
	}
	internal, internalExists := model.Networks[NetworkInternal]
	if !internalExists || !internal.Internal ||
		internal.Name != model.Identity.NetworkName("internal") ||
		!validLabels(internal.Labels, model, "internal", model.Identity.Generation()) {
		violations = append(violations, Violation{
			Code: ViolationNetworkIsolation, Resource: string(NetworkInternal),
		})
	}
	egress, egressExists := model.Networks[NetworkEgress]
	if !egressExists || egress.Internal ||
		egress.Name != model.Identity.NetworkName("egress") ||
		!validLabels(egress.Labels, model, "egress", model.Identity.Generation()) {
		violations = append(violations, Violation{
			Code: ViolationNetworkIsolation, Resource: string(NetworkEgress),
		})
	}
	if len(model.Networks) != 2 {
		violations = append(violations, Violation{
			Code: ViolationClosedInventory, Resource: "networks",
		})
	}
	requiredVolumeNames := append(requiredVolumes(model.Identity),
		model.Identity.StableVolumeName("provider-core-egress"),
		model.Identity.StableVolumeName("provider-gateway-secrets"),
		model.Identity.StableVolumeName("provider-adapter-egress"),
	)
	if len(model.Volumes) != len(requiredVolumeNames) {
		violations = append(violations, Violation{
			Code: ViolationClosedInventory, Resource: "volumes",
		})
	}
	for _, required := range requiredVolumeNames {
		if _, exists := model.Volumes[required]; !exists {
			violations = append(violations, Violation{
				Code: ViolationClosedInventory, Resource: required,
			})
		}
	}
	for key, volume := range model.Volumes {
		if key != volume.Name || !validVolume(volume, model) {
			violations = append(violations, Violation{
				Code: ViolationLabels, Resource: volume.Name,
			})
		}
	}
	if len(model.Secrets) != len(requiredDefaultSecrets)+len(requiredRemoteSecrets) {
		violations = append(violations, Violation{
			Code: ViolationClosedInventory, Resource: "secrets",
		})
	}
	for _, name := range requiredDefaultSecrets {
		secret, exists := model.Secrets[name]
		if !exists || secret.Name != model.Identity.StableVolumeName(name) ||
			!validSecretFile(secret.File) {
			violations = append(violations, Violation{
				Code: ViolationClosedInventory, Resource: name,
			})
		}
	}
	for _, name := range requiredRemoteSecrets {
		secret, exists := model.Secrets[name]
		if !exists || secret.Name != model.Identity.StableVolumeName(name) ||
			!validSecretFile(secret.File) {
			violations = append(violations, Violation{
				Code: ViolationClosedInventory, Resource: name,
			})
		}
	}
	for name := range model.Secrets {
		if !requiredDefaultSecret(name) && !requiredRemoteSecret(name) {
			violations = append(violations, Violation{
				Code: ViolationClosedInventory, Resource: name,
			})
		}
	}
	return violations
}

func remoteService(name ServiceName) bool {
	for _, required := range RequiredRemoteServices() {
		if name == required {
			return true
		}
	}
	return false
}

func validateTopology(model Model) []Violation {
	if remoteTopology(model) {
		return NewRemotePolicy().Validate(model)
	}
	return NewPolicy().Validate(model)
}
