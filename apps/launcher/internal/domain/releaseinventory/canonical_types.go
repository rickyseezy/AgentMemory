package releaseinventory

type canonicalVersionRange struct {
	Maximum string `json:"maximum"`
	Minimum string `json:"minimum"`
}

type canonicalCompatibility struct {
	Compose        canonicalVersionRange `json:"compose"`
	CoreAPI        canonicalVersionRange `json:"core_api"`
	Launcher       canonicalVersionRange `json:"launcher"`
	MCP            canonicalVersionRange `json:"mcp"`
	Neo4j          canonicalVersionRange `json:"neo4j"`
	Provider       canonicalVersionRange `json:"provider"`
	RuntimeCatalog canonicalVersionRange `json:"runtime_catalog"`
	Schema         canonicalVersionRange `json:"schema"`
	SQLite         canonicalVersionRange `json:"sqlite"`
}

type canonicalPriorRelease struct {
	ManifestDigest        string `json:"manifest_digest"`
	MaximumDataGeneration uint64 `json:"maximum_data_generation"`
	MinimumDataGeneration uint64 `json:"minimum_data_generation"`
	ReleaseID             string `json:"release_id"`
}

type canonicalRollbackRelease struct {
	DataGeneration uint64 `json:"data_generation"`
	ManifestDigest string `json:"manifest_digest"`
	ReleaseID      string `json:"release_id"`
}

type canonicalDockerTopology struct {
	HealthProbes []canonicalHealthProbe   `json:"health_probes"`
	Networks     []canonicalDockerNetwork `json:"networks"`
	Profiles     []string                 `json:"profiles"`
	Services     []canonicalDockerService `json:"services"`
	Volumes      []canonicalDockerVolume  `json:"volumes"`
}

type canonicalTopologyLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type canonicalDockerNetwork struct {
	ID       string                   `json:"id"`
	Internal bool                     `json:"internal"`
	Labels   []canonicalTopologyLabel `json:"labels"`
}

type canonicalDockerVolume struct {
	ID      string                   `json:"id"`
	Labels  []canonicalTopologyLabel `json:"labels"`
	Purpose string                   `json:"purpose"`
}

type canonicalHealthProbe struct {
	Arguments       []string `json:"arguments"`
	HTTPPath        string   `json:"http_path"`
	ID              string   `json:"id"`
	IntervalSeconds uint32   `json:"interval_seconds"`
	Kind            string   `json:"kind"`
	Port            uint16   `json:"port"`
	Retries         uint32   `json:"retries"`
	TimeoutSeconds  uint32   `json:"timeout_seconds"`
}

type canonicalVolumeMount struct {
	ReadOnly bool   `json:"read_only"`
	Target   string `json:"target"`
	VolumeID string `json:"volume_id"`
}

type canonicalPortBinding struct {
	ContainerPort uint16 `json:"container_port"`
	Host          string `json:"host"`
	HostPort      uint16 `json:"host_port"`
}

type canonicalDockerService struct {
	Capabilities           []string                 `json:"capabilities"`
	GroupID                uint32                   `json:"group_id"`
	HealthProbeID          string                   `json:"health_probe_id"`
	ID                     string                   `json:"id"`
	ImageResourceIDs       []string                 `json:"image_resource_ids"`
	Labels                 []canonicalTopologyLabel `json:"labels"`
	NetworkIDs             []string                 `json:"network_ids"`
	NoNewPrivileges        bool                     `json:"no_new_privileges"`
	Privileged             bool                     `json:"privileged"`
	Profiles               []string                 `json:"profiles"`
	PublishedPorts         []canonicalPortBinding   `json:"published_ports"`
	ReadOnlyRootFilesystem bool                     `json:"read_only_root_filesystem"`
	UserID                 uint32                   `json:"user_id"`
	VolumeMounts           []canonicalVolumeMount   `json:"volume_mounts"`
}

func canonicalCompatibilityFrom(value Compatibility) canonicalCompatibility {
	return canonicalCompatibility{
		Compose:        canonicalVersionRangeFrom(value.Compose()),
		CoreAPI:        canonicalVersionRangeFrom(value.CoreAPI()),
		Launcher:       canonicalVersionRangeFrom(value.Launcher()),
		MCP:            canonicalVersionRangeFrom(value.MCP()),
		Neo4j:          canonicalVersionRangeFrom(value.Neo4j()),
		Provider:       canonicalVersionRangeFrom(value.Provider()),
		RuntimeCatalog: canonicalVersionRangeFrom(value.RuntimeCatalog()),
		Schema:         canonicalVersionRangeFrom(value.Schema()),
		SQLite:         canonicalVersionRangeFrom(value.SQLite()),
	}
}

func canonicalVersionRangeFrom(value VersionRange) canonicalVersionRange {
	return canonicalVersionRange{Maximum: value.Maximum(), Minimum: value.Minimum()}
}

func canonicalPriorReleasesFrom(history ReleaseHistory) []canonicalPriorRelease {
	result := make([]canonicalPriorRelease, 0, len(history.prior))
	for _, prior := range history.prior {
		result = append(result, canonicalPriorRelease{
			ManifestDigest: prior.manifestDigest.Hex(), MaximumDataGeneration: prior.maximumDataGeneration,
			MinimumDataGeneration: prior.minimumDataGeneration, ReleaseID: prior.releaseID,
		})
	}
	return result
}

func canonicalRollbackReleasesFrom(history ReleaseHistory) []canonicalRollbackRelease {
	result := make([]canonicalRollbackRelease, 0, len(history.rollback))
	for _, rollback := range history.rollback {
		result = append(result, canonicalRollbackRelease{
			DataGeneration: rollback.dataGeneration, ManifestDigest: rollback.manifestDigest.Hex(),
			ReleaseID: rollback.releaseID,
		})
	}
	return result
}

func canonicalDockerTopologyFrom(topology DockerTopology) canonicalDockerTopology {
	probes := make([]canonicalHealthProbe, 0, len(topology.healthProbes))
	for _, probe := range topology.healthProbes {
		probes = append(probes, canonicalHealthProbe{
			Arguments: append([]string(nil), probe.arguments...), HTTPPath: probe.httpPath,
			ID: probe.id, IntervalSeconds: probe.intervalSeconds, Kind: string(probe.kind),
			Port: probe.port, Retries: probe.retries, TimeoutSeconds: probe.timeoutSeconds,
		})
	}
	networks := make([]canonicalDockerNetwork, 0, len(topology.networks))
	for _, network := range topology.networks {
		networks = append(networks, canonicalDockerNetwork{
			ID: network.id, Internal: network.internal, Labels: canonicalLabelsFrom(network.labels),
		})
	}
	services := make([]canonicalDockerService, 0, len(topology.services))
	for _, service := range topology.services {
		services = append(services, canonicalDockerService{
			Capabilities: append([]string(nil), service.capabilities...), GroupID: service.groupID,
			HealthProbeID: service.healthProbeID, ID: service.id,
			ImageResourceIDs: append([]string(nil), service.imageResourceIDs...),
			Labels:           canonicalLabelsFrom(service.labels), NetworkIDs: append([]string(nil), service.networkIDs...),
			NoNewPrivileges: service.noNewPrivileges, Privileged: service.privileged,
			Profiles:               append([]string(nil), service.profiles...),
			PublishedPorts:         canonicalPortBindingsFrom(service.publishedPorts),
			ReadOnlyRootFilesystem: service.readOnlyRootFilesystem, UserID: service.userID,
			VolumeMounts: canonicalVolumeMountsFrom(service.volumeMounts),
		})
	}
	volumes := make([]canonicalDockerVolume, 0, len(topology.volumes))
	for _, volume := range topology.volumes {
		volumes = append(volumes, canonicalDockerVolume{
			ID: volume.id, Labels: canonicalLabelsFrom(volume.labels), Purpose: volume.purpose,
		})
	}
	return canonicalDockerTopology{
		HealthProbes: probes, Networks: networks, Profiles: append([]string(nil), topology.profiles...),
		Services: services, Volumes: volumes,
	}
}

func canonicalLabelsFrom(labels []TopologyLabel) []canonicalTopologyLabel {
	result := make([]canonicalTopologyLabel, 0, len(labels))
	for _, label := range labels {
		result = append(result, canonicalTopologyLabel{Key: label.key, Value: label.value})
	}
	return result
}

func canonicalPortBindingsFrom(bindings []PortBinding) []canonicalPortBinding {
	result := make([]canonicalPortBinding, 0, len(bindings))
	for _, binding := range bindings {
		result = append(result, canonicalPortBinding{
			ContainerPort: binding.containerPort, Host: binding.host, HostPort: binding.hostPort,
		})
	}
	return result
}

func canonicalVolumeMountsFrom(mounts []VolumeMount) []canonicalVolumeMount {
	result := make([]canonicalVolumeMount, 0, len(mounts))
	for _, mount := range mounts {
		result = append(result, canonicalVolumeMount{
			ReadOnly: mount.readOnly, Target: mount.target, VolumeID: mount.volumeID,
		})
	}
	return result
}
