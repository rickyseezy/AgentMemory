package releaseinventory

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

const maximumTopologyEntries = 256

// TopologyLabelInput is one signed Docker resource label.
type TopologyLabelInput struct {
	Key   string
	Value string
}

// TopologyLabel is one immutable AgentMemory-owned resource label.
type TopologyLabel struct {
	key   string
	value string
}

// Key returns the signed label key.
func (l TopologyLabel) Key() string { return l.key }

// Value returns the signed label value.
func (l TopologyLabel) Value() string { return l.value }

// DockerNetworkInput declares one closed Compose network.
type DockerNetworkInput struct {
	ID       string
	Internal bool
	Labels   []TopologyLabelInput
}

// DockerNetwork is one immutable network definition.
type DockerNetwork struct {
	id       string
	internal bool
	labels   []TopologyLabel
}

// ID returns the logical network identifier.
func (n DockerNetwork) ID() string { return n.id }

// Internal reports whether Docker must deny external routing on this network.
func (n DockerNetwork) Internal() bool { return n.internal }

// Labels returns a copy of signed ownership labels.
func (n DockerNetwork) Labels() []TopologyLabel { return append([]TopologyLabel(nil), n.labels...) }

// DockerVolumeInput declares one named persistent volume.
type DockerVolumeInput struct {
	ID      string
	Purpose string
	Labels  []TopologyLabelInput
}

// DockerVolume is one immutable persistent-volume definition.
type DockerVolume struct {
	id      string
	purpose string
	labels  []TopologyLabel
}

// ID returns the logical volume identifier.
func (v DockerVolume) ID() string { return v.id }

// Purpose returns the signed volume purpose.
func (v DockerVolume) Purpose() string { return v.purpose }

// Labels returns a copy of signed ownership labels.
func (v DockerVolume) Labels() []TopologyLabel { return append([]TopologyLabel(nil), v.labels...) }

// HealthProbeKind is the closed, non-shell health-probe vocabulary.
type HealthProbeKind string

// Supported health-probe kinds.
const (
	HealthProbeKindHTTP HealthProbeKind = "http"
	HealthProbeKindExec HealthProbeKind = "exec"
)

// HealthProbeInput declares one bounded health probe.
type HealthProbeInput struct {
	ID              string
	Kind            HealthProbeKind
	HTTPPath        string
	Arguments       []string
	Port            uint16
	IntervalSeconds uint32
	TimeoutSeconds  uint32
	Retries         uint32
}

// HealthProbe is one immutable HTTP-path or argv health check.
type HealthProbe struct {
	id              string
	kind            HealthProbeKind
	httpPath        string
	arguments       []string
	port            uint16
	intervalSeconds uint32
	timeoutSeconds  uint32
	retries         uint32
}

// ID returns the health-probe identifier.
func (p HealthProbe) ID() string { return p.id }

// Kind returns the non-shell probe kind.
func (p HealthProbe) Kind() HealthProbeKind { return p.kind }

// HTTPPath returns the container-local path for an HTTP probe.
func (p HealthProbe) HTTPPath() string { return p.httpPath }

// Arguments returns a copy of exact exec-probe argv.
func (p HealthProbe) Arguments() []string { return append([]string(nil), p.arguments...) }

// Port returns the container-local HTTP port, or zero for an exec probe.
func (p HealthProbe) Port() uint16 { return p.port }

// IntervalSeconds returns the signed probe interval.
func (p HealthProbe) IntervalSeconds() uint32 { return p.intervalSeconds }

// TimeoutSeconds returns the signed per-probe timeout.
func (p HealthProbe) TimeoutSeconds() uint32 { return p.timeoutSeconds }

// Retries returns the signed failure threshold.
func (p HealthProbe) Retries() uint32 { return p.retries }

// VolumeMountInput binds a declared volume to an absolute container path.
type VolumeMountInput struct {
	VolumeID string
	Target   string
	ReadOnly bool
}

// VolumeMount is one immutable volume permission.
type VolumeMount struct {
	volumeID string
	target   string
	readOnly bool
}

// VolumeID returns the declared volume identifier.
func (m VolumeMount) VolumeID() string { return m.volumeID }

// Target returns the absolute container mount target.
func (m VolumeMount) Target() string { return m.target }

// ReadOnly reports whether the service may mutate the mounted volume.
func (m VolumeMount) ReadOnly() bool { return m.readOnly }

// PortBindingInput declares one loopback-only published TCP port.
type PortBindingInput struct {
	Host          string
	HostPort      uint16
	ContainerPort uint16
}

// PortBinding is one immutable loopback-only TCP binding.
type PortBinding struct {
	host          string
	hostPort      uint16
	containerPort uint16
}

// Host returns the literal loopback address.
func (b PortBinding) Host() string { return b.host }

// HostPort returns the signed host port.
func (b PortBinding) HostPort() uint16 { return b.hostPort }

// ContainerPort returns the signed container port.
func (b PortBinding) ContainerPort() uint16 { return b.containerPort }

// DockerServiceInput declares one least-privileged Compose service.
type DockerServiceInput struct {
	ID                     string
	ImageResourceIDs       []string
	Profiles               []string
	NetworkIDs             []string
	VolumeMounts           []VolumeMountInput
	HealthProbeID          string
	UserID                 uint32
	GroupID                uint32
	Privileged             bool
	ReadOnlyRootFilesystem bool
	NoNewPrivileges        bool
	Capabilities           []string
	PublishedPorts         []PortBindingInput
	Labels                 []TopologyLabelInput
}

// DockerService is one immutable service execution and permission plan.
type DockerService struct {
	id                     string
	imageResourceIDs       []string
	profiles               []string
	networkIDs             []string
	volumeMounts           []VolumeMount
	healthProbeID          string
	userID                 uint32
	groupID                uint32
	privileged             bool
	readOnlyRootFilesystem bool
	noNewPrivileges        bool
	capabilities           []string
	publishedPorts         []PortBinding
	labels                 []TopologyLabel
}

// ID returns the logical service identifier.
func (s DockerService) ID() string { return s.id }

// ImageResourceIDs returns exact platform image candidates from the manifest.
func (s DockerService) ImageResourceIDs() []string {
	return append([]string(nil), s.imageResourceIDs...)
}

// Profiles returns a copy of allowed Compose profiles.
func (s DockerService) Profiles() []string { return append([]string(nil), s.profiles...) }

// NetworkIDs returns a copy of allowed network memberships.
func (s DockerService) NetworkIDs() []string { return append([]string(nil), s.networkIDs...) }

// VolumeMounts returns a copy of signed volume permissions.
func (s DockerService) VolumeMounts() []VolumeMount {
	return append([]VolumeMount(nil), s.volumeMounts...)
}

// HealthProbeID returns the required health probe.
func (s DockerService) HealthProbeID() string { return s.healthProbeID }

// UserID returns the required non-root container user.
func (s DockerService) UserID() uint32 { return s.userID }

// GroupID returns the required non-root container group.
func (s DockerService) GroupID() uint32 { return s.groupID }

// Privileged reports whether privileged execution was declared. Valid v1 manifests always return false.
func (s DockerService) Privileged() bool { return s.privileged }

// ReadOnlyRootFilesystem reports the signed root-filesystem policy.
func (s DockerService) ReadOnlyRootFilesystem() bool { return s.readOnlyRootFilesystem }

// NoNewPrivileges reports the signed privilege-escalation policy.
func (s DockerService) NoNewPrivileges() bool { return s.noNewPrivileges }

// Capabilities returns the closed Linux capability set. Valid v1 manifests return an empty set.
func (s DockerService) Capabilities() []string {
	return append([]string(nil), s.capabilities...)
}

// PublishedPorts returns a copy of loopback-only port bindings.
func (s DockerService) PublishedPorts() []PortBinding {
	return append([]PortBinding(nil), s.publishedPorts...)
}

// Labels returns a copy of signed ownership labels.
func (s DockerService) Labels() []TopologyLabel { return append([]TopologyLabel(nil), s.labels...) }

// DockerTopologyInput contains the complete renderable Docker inventory.
type DockerTopologyInput struct {
	Profiles     []string
	Networks     []DockerNetworkInput
	Volumes      []DockerVolumeInput
	HealthProbes []HealthProbeInput
	Services     []DockerServiceInput
}

// DockerTopology is the closed immutable Docker execution inventory.
type DockerTopology struct {
	profiles     []string
	networks     []DockerNetwork
	volumes      []DockerVolume
	healthProbes []HealthProbe
	services     []DockerService
}

// NewDockerTopology validates references, ownership labels, permissions, and port isolation.
func NewDockerTopology(input DockerTopologyInput) (DockerTopology, error) {
	if len(input.Profiles) == 0 || len(input.Networks) == 0 || len(input.HealthProbes) == 0 ||
		len(input.Services) == 0 || len(input.Profiles) > maximumTopologyEntries ||
		len(input.Networks) > maximumTopologyEntries || len(input.Volumes) > maximumTopologyEntries ||
		len(input.HealthProbes) > maximumTopologyEntries || len(input.Services) > maximumTopologyEntries {
		return DockerTopology{}, errors.New("docker topology inventory size is invalid")
	}
	profiles, err := validatedIdentifierSet(input.Profiles, true)
	if err != nil {
		return DockerTopology{}, errors.New("docker topology profile set is invalid")
	}
	networks, networkIDs, err := buildNetworks(input.Networks)
	if err != nil {
		return DockerTopology{}, err
	}
	volumes, volumeIDs, err := buildVolumes(input.Volumes)
	if err != nil {
		return DockerTopology{}, err
	}
	probes, probeIDs, err := buildHealthProbes(input.HealthProbes)
	if err != nil {
		return DockerTopology{}, err
	}
	services, err := buildServices(input.Services, profiles, networkIDs, volumeIDs, probeIDs)
	if err != nil {
		return DockerTopology{}, err
	}
	if err := rejectUnusedTopologyEntries(profiles, networks, volumes, probes, services); err != nil {
		return DockerTopology{}, err
	}
	return DockerTopology{
		profiles: profiles, networks: networks, volumes: volumes,
		healthProbes: probes, services: services,
	}, nil
}

// Valid reports whether the topology is usable as an execution authority.
func (t DockerTopology) Valid() bool {
	return len(t.services) > 0 && len(t.networks) > 0 && len(t.healthProbes) > 0
}

// Profiles returns a copy of the closed profile set.
func (t DockerTopology) Profiles() []string { return append([]string(nil), t.profiles...) }

// Networks returns a copy of the closed network inventory.
func (t DockerTopology) Networks() []DockerNetwork {
	return append([]DockerNetwork(nil), t.networks...)
}

// Volumes returns a copy of the closed volume inventory.
func (t DockerTopology) Volumes() []DockerVolume { return append([]DockerVolume(nil), t.volumes...) }

// HealthProbes returns a copy of the closed probe inventory.
func (t DockerTopology) HealthProbes() []HealthProbe {
	return append([]HealthProbe(nil), t.healthProbes...)
}

// Services returns a copy of the closed service inventory.
func (t DockerTopology) Services() []DockerService {
	return append([]DockerService(nil), t.services...)
}

func buildNetworks(inputs []DockerNetworkInput) ([]DockerNetwork, map[string]struct{}, error) {
	result := make([]DockerNetwork, 0, len(inputs))
	ids := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		labels, err := validatedLabels(input.Labels)
		if !validIdentifier(input.ID) || err != nil {
			return nil, nil, errors.New("docker network definition is invalid")
		}
		if _, duplicate := ids[input.ID]; duplicate {
			return nil, nil, errors.New("docker network definition is duplicated")
		}
		ids[input.ID] = struct{}{}
		result = append(result, DockerNetwork{id: input.ID, internal: input.Internal, labels: labels})
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].id < result[right].id })
	return result, ids, nil
}

func buildVolumes(inputs []DockerVolumeInput) ([]DockerVolume, map[string]struct{}, error) {
	result := make([]DockerVolume, 0, len(inputs))
	ids := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		labels, err := validatedLabels(input.Labels)
		if !validIdentifier(input.ID) || !validIdentifier(input.Purpose) || err != nil {
			return nil, nil, errors.New("docker volume definition is invalid")
		}
		if _, duplicate := ids[input.ID]; duplicate {
			return nil, nil, errors.New("docker volume definition is duplicated")
		}
		ids[input.ID] = struct{}{}
		result = append(result, DockerVolume{id: input.ID, purpose: input.Purpose, labels: labels})
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].id < result[right].id })
	return result, ids, nil
}

func buildHealthProbes(inputs []HealthProbeInput) ([]HealthProbe, map[string]struct{}, error) {
	result := make([]HealthProbe, 0, len(inputs))
	ids := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if !validIdentifier(input.ID) || input.IntervalSeconds == 0 || input.IntervalSeconds > 300 ||
			input.TimeoutSeconds == 0 || input.TimeoutSeconds > input.IntervalSeconds ||
			input.Retries == 0 || input.Retries > 10 || !validProbeTarget(input) {
			return nil, nil, errors.New("docker health probe is invalid")
		}
		if _, duplicate := ids[input.ID]; duplicate {
			return nil, nil, errors.New("docker health probe is duplicated")
		}
		arguments := append([]string(nil), input.Arguments...)
		ids[input.ID] = struct{}{}
		result = append(result, HealthProbe{
			id: input.ID, kind: input.Kind, httpPath: input.HTTPPath, arguments: arguments, port: input.Port,
			intervalSeconds: input.IntervalSeconds, timeoutSeconds: input.TimeoutSeconds,
			retries: input.Retries,
		})
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].id < result[right].id })
	return result, ids, nil
}

func validProbeTarget(input HealthProbeInput) bool {
	switch input.Kind {
	case HealthProbeKindHTTP:
		return len(input.Arguments) == 0 && input.Port != 0 && validContainerPath(input.HTTPPath)
	case HealthProbeKindExec:
		if input.HTTPPath != "" || input.Port != 0 || len(input.Arguments) == 0 ||
			len(input.Arguments) > 32 || !validContainerPath(input.Arguments[0]) {
			return false
		}
		for _, argument := range input.Arguments {
			if !validSafeText(argument, 512) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func buildServices(
	inputs []DockerServiceInput,
	profiles []string,
	networkIDs map[string]struct{},
	volumeIDs map[string]struct{},
	probeIDs map[string]struct{},
) ([]DockerService, error) {
	profileIDs := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		profileIDs[profile] = struct{}{}
	}
	result := make([]DockerService, 0, len(inputs))
	serviceIDs := make(map[string]struct{}, len(inputs))
	publishedPorts := make(map[string]struct{})
	for _, input := range inputs {
		service, err := buildService(input, profileIDs, networkIDs, volumeIDs, probeIDs, publishedPorts)
		if err != nil {
			return nil, err
		}
		if _, duplicate := serviceIDs[service.id]; duplicate {
			return nil, errors.New("docker service definition is duplicated")
		}
		serviceIDs[service.id] = struct{}{}
		result = append(result, service)
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].id < result[right].id })
	return result, nil
}

func buildService(
	input DockerServiceInput,
	profileIDs map[string]struct{},
	networkIDs map[string]struct{},
	volumeIDs map[string]struct{},
	probeIDs map[string]struct{},
	publishedPorts map[string]struct{},
) (DockerService, error) {
	images, imageError := validatedIdentifierSet(input.ImageResourceIDs, true)
	profiles, profileError := validatedReferenceSet(input.Profiles, profileIDs)
	networks, networkError := validatedReferenceSet(input.NetworkIDs, networkIDs)
	labels, labelError := validatedLabels(input.Labels)
	if !validIdentifier(input.ID) || imageError != nil || profileError != nil || networkError != nil ||
		labelError != nil || input.UserID == 0 || input.GroupID == 0 || input.Privileged ||
		!input.ReadOnlyRootFilesystem || !input.NoNewPrivileges || len(input.Capabilities) != 0 {
		return DockerService{}, errors.New("docker service permission plan is invalid")
	}
	if _, exists := probeIDs[input.HealthProbeID]; !exists {
		return DockerService{}, errors.New("docker service health probe is not declared")
	}
	mounts, err := validatedVolumeMounts(input.VolumeMounts, volumeIDs)
	if err != nil {
		return DockerService{}, err
	}
	ports, err := validatedPortBindings(input.PublishedPorts, publishedPorts)
	if err != nil {
		return DockerService{}, err
	}
	return DockerService{
		id: input.ID, imageResourceIDs: images, profiles: profiles, networkIDs: networks,
		volumeMounts: mounts, healthProbeID: input.HealthProbeID, userID: input.UserID,
		groupID: input.GroupID, privileged: false, readOnlyRootFilesystem: true,
		noNewPrivileges: true, capabilities: []string{}, publishedPorts: ports, labels: labels,
	}, nil
}

func validatedVolumeMounts(inputs []VolumeMountInput, volumeIDs map[string]struct{}) ([]VolumeMount, error) {
	result := make([]VolumeMount, 0, len(inputs))
	targets := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if _, exists := volumeIDs[input.VolumeID]; !exists || !validContainerPath(input.Target) {
			return nil, errors.New("docker service volume mount is invalid")
		}
		if _, duplicate := targets[input.Target]; duplicate {
			return nil, errors.New("docker service mount target is duplicated")
		}
		targets[input.Target] = struct{}{}
		result = append(result, VolumeMount{volumeID: input.VolumeID, target: input.Target, readOnly: input.ReadOnly})
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].target < result[right].target })
	return result, nil
}

func validatedPortBindings(inputs []PortBindingInput, allPorts map[string]struct{}) ([]PortBinding, error) {
	result := make([]PortBinding, 0, len(inputs))
	for _, input := range inputs {
		if input.Host != "127.0.0.1" && input.Host != "::1" || input.HostPort == 0 || input.ContainerPort == 0 {
			return nil, errors.New("docker service published port is not loopback-only")
		}
		key := input.Host + ":" + strconv.FormatUint(uint64(input.HostPort), 10)
		if _, duplicate := allPorts[key]; duplicate {
			return nil, errors.New("docker published host port is duplicated")
		}
		allPorts[key] = struct{}{}
		result = append(result, PortBinding{
			host: input.Host, hostPort: input.HostPort, containerPort: input.ContainerPort,
		})
	}
	sort.Slice(result, func(left int, right int) bool {
		if result[left].host == result[right].host {
			return result[left].hostPort < result[right].hostPort
		}
		return result[left].host < result[right].host
	})
	return result, nil
}

func validatedLabels(inputs []TopologyLabelInput) ([]TopologyLabel, error) {
	if len(inputs) == 0 || len(inputs) > 32 {
		return nil, errors.New("docker resource labels are required")
	}
	result := make([]TopologyLabel, 0, len(inputs))
	keys := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if !strings.HasPrefix(input.Key, "com.agentmemory.") || !validLabelKey(input.Key) ||
			!validSafeText(input.Value, 128) {
			return nil, errors.New("docker resource label is invalid")
		}
		if _, duplicate := keys[input.Key]; duplicate {
			return nil, errors.New("docker resource label is duplicated")
		}
		keys[input.Key] = struct{}{}
		result = append(result, TopologyLabel{key: input.Key, value: input.Value})
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].key < result[right].key })
	return result, nil
}

func validLabelKey(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validatedIdentifierSet(values []string, required bool) ([]string, error) {
	if required && len(values) == 0 || len(values) > maximumTopologyEntries {
		return nil, errors.New("identifier set size is invalid")
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if !validIdentifier(value) || index > 0 && result[index-1] == value {
			return nil, errors.New("identifier set is invalid")
		}
	}
	return result, nil
}

func validatedReferenceSet(values []string, allowed map[string]struct{}) ([]string, error) {
	result, err := validatedIdentifierSet(values, true)
	if err != nil {
		return nil, err
	}
	for _, value := range result {
		if _, exists := allowed[value]; !exists {
			return nil, errors.New("topology reference is not declared")
		}
	}
	return result, nil
}

func validContainerPath(value string) bool {
	if len(value) < 2 || len(value) > 256 || value[0] != '/' || strings.Contains(value, "\\") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." || segment == "." {
			return false
		}
	}
	return validSafeText(value, 256)
}

func rejectUnusedTopologyEntries(
	profiles []string,
	networks []DockerNetwork,
	volumes []DockerVolume,
	probes []HealthProbe,
	services []DockerService,
) error {
	usedProfiles := make(map[string]struct{})
	usedNetworks := make(map[string]struct{})
	usedVolumes := make(map[string]struct{})
	usedProbes := make(map[string]struct{})
	for _, service := range services {
		for _, profile := range service.profiles {
			usedProfiles[profile] = struct{}{}
		}
		for _, network := range service.networkIDs {
			usedNetworks[network] = struct{}{}
		}
		for _, mount := range service.volumeMounts {
			usedVolumes[mount.volumeID] = struct{}{}
		}
		usedProbes[service.healthProbeID] = struct{}{}
	}
	if len(usedProfiles) != len(profiles) || len(usedNetworks) != len(networks) ||
		len(usedVolumes) != len(volumes) || len(usedProbes) != len(probes) {
		return errors.New("docker topology contains an unused declared resource")
	}
	return nil
}

func cloneDockerTopology(topology DockerTopology) DockerTopology {
	cloned := DockerTopology{profiles: append([]string(nil), topology.profiles...)}
	cloned.networks = make([]DockerNetwork, 0, len(topology.networks))
	for _, network := range topology.networks {
		network.labels = append([]TopologyLabel(nil), network.labels...)
		cloned.networks = append(cloned.networks, network)
	}
	cloned.volumes = make([]DockerVolume, 0, len(topology.volumes))
	for _, volume := range topology.volumes {
		volume.labels = append([]TopologyLabel(nil), volume.labels...)
		cloned.volumes = append(cloned.volumes, volume)
	}
	cloned.healthProbes = make([]HealthProbe, 0, len(topology.healthProbes))
	for _, probe := range topology.healthProbes {
		probe.arguments = append([]string(nil), probe.arguments...)
		cloned.healthProbes = append(cloned.healthProbes, probe)
	}
	cloned.services = make([]DockerService, 0, len(topology.services))
	for _, service := range topology.services {
		service.imageResourceIDs = append([]string(nil), service.imageResourceIDs...)
		service.profiles = append([]string(nil), service.profiles...)
		service.networkIDs = append([]string(nil), service.networkIDs...)
		service.volumeMounts = append([]VolumeMount(nil), service.volumeMounts...)
		service.capabilities = append([]string(nil), service.capabilities...)
		service.publishedPorts = append([]PortBinding(nil), service.publishedPorts...)
		service.labels = append([]TopologyLabel(nil), service.labels...)
		cloned.services = append(cloned.services, service)
	}
	return cloned
}
