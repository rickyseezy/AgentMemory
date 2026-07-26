package composeplan

import (
	"errors"
	"reflect"
	"sort"
)

const (
	// SecretProjectionVolumeReservationBytes is the signed conservative engine
	// allocation reserved for each tiny protected projection volume. Capacity
	// planning must never infer filesystem allocation from raw secret length.
	SecretProjectionVolumeReservationBytes uint64 = 1024 * 1024
	maximumProjectedAttestationBytes              = 64 * 1024
	maximumProviderCredentialVaultBytes           = 4 * 1024 * 1024
)

// ProjectedSecret is one immutable protected-file copy contract. SourceFile
// is a protected path reference and never contains secret bytes.
type ProjectedSecret struct {
	name       string
	sourceFile string
	uid        uint32
	gid        uint32
	mode       uint32
	maxBytes   uint64
}

// Name returns the fixed file name within the consumer projection volume.
func (s ProjectedSecret) Name() string { return s.name }

// SourceFile returns the authenticated host protected-file reference.
func (s ProjectedSecret) SourceFile() string { return s.sourceFile }

// UserID returns the exact projected owner UID.
func (s ProjectedSecret) UserID() uint32 { return s.uid }

// GroupID returns the exact projected owner GID.
func (s ProjectedSecret) GroupID() uint32 { return s.gid }

// Mode returns the exact projected permission bits.
func (s ProjectedSecret) Mode() uint32 { return s.mode }

// MaximumBytes returns the closed input/output length bound.
func (s ProjectedSecret) MaximumBytes() uint64 { return s.maxBytes }

// SecretProjectionVolume is one engine-managed, per-consumer projection.
type SecretProjectionVolume struct {
	name          string
	purpose       string
	reservedBytes uint64
	files         []ProjectedSecret
}

// SecretProjectionCapacity is the file-content-free capacity projection used
// before protected sources or the complete Compose plan are available.
type SecretProjectionCapacity struct {
	name          string
	purpose       string
	reservedBytes uint64
}

// Name returns the exact generation-pinned Docker volume identity.
func (c SecretProjectionCapacity) Name() string { return c.name }

// Purpose returns the closed ownership-label purpose.
func (c SecretProjectionCapacity) Purpose() string { return c.purpose }

// ReservedBytes returns the signed conservative allocation.
func (c SecretProjectionCapacity) ReservedBytes() uint64 { return c.reservedBytes }

// Name returns the exact physical Docker volume identity.
func (v SecretProjectionVolume) Name() string { return v.name }

// Purpose returns the closed resource-purpose label.
func (v SecretProjectionVolume) Purpose() string { return v.purpose }

// ReservedBytes returns signed capacity authority for this volume.
func (v SecretProjectionVolume) ReservedBytes() uint64 { return v.reservedBytes }

// Files returns an immutable-by-copy target inventory.
func (v SecretProjectionVolume) Files() []ProjectedSecret {
	return append([]ProjectedSecret(nil), v.files...)
}

// SecretProjectionCapacities derives the exact six capacity leases from an
// already validated installation identity without requiring secret paths.
func (i Identity) SecretProjectionCapacities() ([]SecretProjectionCapacity, bool) {
	if !validUUID(i.installationID) || !validUUIDv7(i.generation) || i.ProjectName() == "agentmemory_" {
		return nil, false
	}
	capacities := make([]SecretProjectionCapacity, 0, len(requiredProjectionPurposes()))
	for _, purpose := range requiredProjectionPurposes() {
		capacities = append(capacities, SecretProjectionCapacity{
			name: i.VolumeName(purpose), purpose: purpose,
			reservedBytes: SecretProjectionVolumeReservationBytes,
		})
	}
	return capacities, len(capacities) == 6
}

var errInvalidPolicyPlan = errors.New("compose policy plan is invalid")

// PolicyPlan is an immutable, canonical projection of the authenticated
// release topology. The application layer must construct it only from the
// verified release and runtime composition inputs, never from rendered Docker
// output.
type PolicyPlan struct {
	model Model
}

// NewPolicyPlan validates and snapshots the authenticated topology projection.
func NewPolicyPlan(model Model) (PolicyPlan, error) {
	canonical := canonicalModel(model)
	if len(validateTopology(canonical)) != 0 {
		return PolicyPlan{}, errInvalidPolicyPlan
	}
	return PolicyPlan{model: canonical}, nil
}

// Valid reports whether the plan contains valid execution authority.
func (p PolicyPlan) Valid() bool {
	return len(p.model.Services) != 0 && len(validateTopology(p.model)) == 0
}

// Matches compares a rendered policy model with the immutable release plan.
// Only collection ordering is normalized; no values are defaulted or dropped.
func (p PolicyPlan) Matches(model Model) bool {
	if !p.Valid() {
		return false
	}
	candidate := canonicalModel(model)
	return len(validateTopology(candidate)) == 0 && reflect.DeepEqual(p.model, candidate)
}

// CanonicalModel returns a deep caller-owned snapshot for deterministic
// release-bundle rendering. Mutating the returned model cannot alter the plan.
func (p PolicyPlan) CanonicalModel() (Model, bool) {
	if !p.Valid() {
		return Model{}, false
	}
	return canonicalModel(p.model), true
}

// SecretFiles returns a caller-owned closed map of authenticated protected-file
// sources. Values are path references, never secret bytes.
func (p PolicyPlan) SecretFiles() (map[string]string, bool) {
	if !p.Valid() {
		return nil, false
	}
	files := make(map[string]string, len(p.model.Secrets))
	for name, secret := range p.model.Secrets {
		if secret.File == "" {
			return nil, false
		}
		files[name] = secret.File
	}
	expected := len(requiredDefaultSecrets)
	if remoteTopology(p.model) {
		expected += len(requiredRemoteSecrets)
	}
	return files, len(files) == expected
}

// InstallationKeyFile returns the installation-root-key source for legacy
// callers. New execution code must snapshot every path returned by SecretFiles.
func (p PolicyPlan) InstallationKeyFile() (string, bool) {
	if !p.Valid() {
		return "", false
	}
	secret, exists := p.model.Secrets[SecretInstallationRootKey]
	return secret.File, exists && secret.File != ""
}

// SecretProjectionVolumes returns the exact six least-privilege projection
// volumes consumed by the production stack. It is also the sole signed
// capacity authority for these resources.
func (p PolicyPlan) SecretProjectionVolumes() ([]SecretProjectionVolume, bool) {
	if !p.Valid() {
		return nil, false
	}
	secret := func(name string, uid uint32, gid uint32) ProjectedSecret {
		maximum := uint64(32)
		switch name {
		case SecretEgressAttestation:
			maximum = maximumProjectedAttestationBytes
		case SecretProviderGatewayCredentialVault:
			maximum = maximumProviderCredentialVaultBytes
		}
		return ProjectedSecret{
			name: name, sourceFile: p.model.Secrets[name].File, uid: uid, gid: gid,
			mode: 0o400, maxBytes: maximum,
		}
	}
	allCore := make([]ProjectedSecret, 0, len(requiredDefaultSecrets))
	for _, name := range requiredDefaultSecrets {
		allCore = append(allCore, secret(name, 10_001, 10_001))
	}
	type projectionDefinition struct {
		purpose string
		stable  bool
		files   []ProjectedSecret
	}
	definitions := []projectionDefinition{
		{purpose: projectionPurposeCore, files: allCore},
		{purpose: projectionPurposeMigrate, files: []ProjectedSecret{secret(SecretNeo4jPassword, 10_001, 10_001)}},
		{purpose: projectionPurposeNeo4j, files: []ProjectedSecret{secret(SecretNeo4jPassword, 7474, 7474)}},
		{purpose: projectionPurposeEmbedding, files: []ProjectedSecret{secret(SecretEmbeddingCapability, 10_001, 10_001)}},
		{purpose: projectionPurposeReranking, files: []ProjectedSecret{secret(SecretRerankingCapability, 10_001, 10_001)}},
		{purpose: projectionPurposeExtraction, files: []ProjectedSecret{secret(SecretExtractionCapability, 10_001, 10_001)}},
	}
	if remoteTopology(p.model) {
		definitions = append(definitions,
			projectionDefinition{
				purpose: "provider-core-egress", stable: true,
				files: []ProjectedSecret{
					secret(SecretProviderGatewayClientCapability, 10_001, 10_001),
					secret(SecretProviderGatewayPermitHMACKey, 10_001, 10_001),
				},
			},
			projectionDefinition{
				purpose: "provider-gateway-secrets", stable: true,
				files: []ProjectedSecret{
					secret(SecretProviderGatewayClientCapability, 10_001, 10_001),
					secret(SecretProviderGatewayPermitHMACKey, 10_001, 10_001),
					secret(SecretProviderGatewayCredentialVault, 10_001, 10_001),
					secret(SecretProviderGatewayCredentialVaultKey, 10_001, 10_001),
					secret(SecretProviderGatewayCredentialVaultHMACKey, 10_001, 10_001),
				},
			},
			projectionDefinition{
				purpose: "provider-adapter-egress", stable: true,
				files: []ProjectedSecret{
					secret(SecretProviderGatewayClientCapability, 65_532, 65_532),
				},
			},
		)
	}
	volumes := make([]SecretProjectionVolume, 0, len(definitions))
	for _, definition := range definitions {
		name := p.model.Identity.VolumeName(definition.purpose)
		if definition.stable {
			name = p.model.Identity.StableVolumeName(definition.purpose)
		}
		volumes = append(volumes, SecretProjectionVolume{
			name: name, purpose: definition.purpose,
			reservedBytes: SecretProjectionVolumeReservationBytes,
			files:         append([]ProjectedSecret(nil), definition.files...),
		})
	}
	expected := 6
	if remoteTopology(p.model) {
		expected = 9
	}
	return volumes, len(volumes) == expected
}

func canonicalModel(model Model) Model {
	canonical := Model{
		Identity: model.Identity,
		Release:  model.Release,
		Services: make(map[ServiceName]Service, len(model.Services)),
		Networks: make(map[NetworkName]Network, len(model.Networks)),
		Volumes:  make(map[string]Volume, len(model.Volumes)),
		Secrets:  make(map[string]Secret, len(model.Secrets)),
	}
	for name, service := range model.Services {
		service.CapAdd = append([]string(nil), service.CapAdd...)
		sort.Strings(service.CapAdd)
		service.Networks = append([]NetworkName(nil), service.Networks...)
		sort.Slice(service.Networks, func(left int, right int) bool { return service.Networks[left] < service.Networks[right] })
		service.Healthcheck = append([]string(nil), service.Healthcheck...)
		service.Command = append([]string(nil), service.Command...)
		service.Tmpfs = append([]Tmpfs(nil), service.Tmpfs...)
		sort.Slice(service.Tmpfs, func(left int, right int) bool { return service.Tmpfs[left].Target < service.Tmpfs[right].Target })
		service.Ports = append([]Port(nil), service.Ports...)
		sort.Slice(service.Ports, func(left int, right int) bool {
			if service.Ports[left].HostIP == service.Ports[right].HostIP {
				return service.Ports[left].HostPort < service.Ports[right].HostPort
			}
			return service.Ports[left].HostIP < service.Ports[right].HostIP
		})
		service.Mounts = append([]Mount(nil), service.Mounts...)
		sort.Slice(service.Mounts, func(left int, right int) bool { return service.Mounts[left].Target < service.Mounts[right].Target })
		service.DependsOn = append([]Dependency(nil), service.DependsOn...)
		sort.Slice(service.DependsOn, func(left int, right int) bool {
			return service.DependsOn[left].Service < service.DependsOn[right].Service
		})
		service.Environment = cloneLabels(service.Environment)
		service.Labels = cloneLabels(service.Labels)
		canonical.Services[name] = service
	}
	for name, network := range model.Networks {
		network.Labels = cloneLabels(network.Labels)
		canonical.Networks[name] = network
	}
	for name, volume := range model.Volumes {
		volume.Labels = cloneLabels(volume.Labels)
		canonical.Volumes[name] = volume
	}
	for name, secret := range model.Secrets {
		canonical.Secrets[name] = secret
	}
	return canonical
}

func cloneLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}
