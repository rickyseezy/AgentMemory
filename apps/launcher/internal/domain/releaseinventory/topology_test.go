package releaseinventory

import "testing"

func TestDockerTopologyClosesReferencesPermissionsAndMutableStorage(t *testing.T) {
	t.Parallel()

	input := validDockerTopologyInput()
	topology, err := NewDockerTopology(input)
	if err != nil {
		t.Fatalf("NewDockerTopology() error = %v", err)
	}
	if !topology.Valid() || len(topology.Services()) != 1 || topology.Services()[0].ID() != "core" ||
		topology.Services()[0].Privileged() || !topology.Services()[0].ReadOnlyRootFilesystem() ||
		!topology.Services()[0].NoNewPrivileges() || topology.Services()[0].UserID() == 0 ||
		len(topology.Services()[0].PublishedPorts()) != 1 || !topology.Networks()[0].Internal() {
		t.Fatal("topology accessors lost its closed permission plan")
	}
	network := topology.Networks()[0]
	volume := topology.Volumes()[0]
	probe := topology.HealthProbes()[0]
	service := topology.Services()[0]
	mount := service.VolumeMounts()[0]
	port := service.PublishedPorts()[0]
	if network.ID() != "internal" || network.Labels()[0].Key() != "com.agentmemory.managed" ||
		network.Labels()[0].Value() != "true" || volume.ID() != "core-data" ||
		volume.Purpose() != "canonical-data" || len(volume.Labels()) != 1 ||
		probe.ID() != "core-ready" || probe.Kind() != HealthProbeKindHTTP || probe.HTTPPath() != "/ready" ||
		len(probe.Arguments()) != 0 || probe.Port() != 8080 || probe.IntervalSeconds() != 10 || probe.TimeoutSeconds() != 3 ||
		probe.Retries() != 5 || len(service.Profiles()) != 1 || len(service.NetworkIDs()) != 1 ||
		service.HealthProbeID() != "core-ready" || service.GroupID() != 1000 ||
		len(service.Capabilities()) != 0 || len(service.Labels()) != 1 ||
		mount.VolumeID() != "core-data" || mount.Target() != "/var/lib/agentmemory" || mount.ReadOnly() ||
		port.Host() != "127.0.0.1" || port.HostPort() != 38765 || port.ContainerPort() != 8080 ||
		len(topology.Profiles()) != 1 {
		t.Fatal("topology nested accessors lost signed values")
	}
	input.Services[0].ImageResourceIDs[0] = "tampered"
	services := topology.Services()
	images := services[0].ImageResourceIDs()
	images[0] = "tampered"
	if topology.Services()[0].ImageResourceIDs()[0] != "image" {
		t.Fatal("DockerTopology retained caller-owned mutable storage")
	}
}

func TestDockerTopologyRejectsPrivilegeNetworkAndReferenceExpansion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*DockerTopologyInput)
	}{
		{name: "privileged", mutate: func(input *DockerTopologyInput) { input.Services[0].Privileged = true }},
		{name: "root user", mutate: func(input *DockerTopologyInput) { input.Services[0].UserID = 0 }},
		{name: "writable root", mutate: func(input *DockerTopologyInput) { input.Services[0].ReadOnlyRootFilesystem = false }},
		{name: "new privileges", mutate: func(input *DockerTopologyInput) { input.Services[0].NoNewPrivileges = false }},
		{name: "capability", mutate: func(input *DockerTopologyInput) { input.Services[0].Capabilities = []string{"SYS_ADMIN"} }},
		{name: "public listener", mutate: func(input *DockerTopologyInput) { input.Services[0].PublishedPorts[0].Host = "0.0.0.0" }},
		{name: "undeclared network", mutate: func(input *DockerTopologyInput) { input.Services[0].NetworkIDs = []string{"outside"} }},
		{name: "unsafe mount", mutate: func(input *DockerTopologyInput) { input.Services[0].VolumeMounts[0].Target = "/data/../host" }},
		{name: "shell health probe", mutate: func(input *DockerTopologyInput) {
			input.HealthProbes[0].Arguments = []string{"sh", "-c", "curl localhost"}
		}},
		{
			name: "explicit shell exec probe",
			mutate: func(input *DockerTopologyInput) {
				input.HealthProbes[0].Kind = HealthProbeKindExec
				input.HealthProbes[0].HTTPPath = ""
				input.HealthProbes[0].Port = 0
				input.HealthProbes[0].Arguments = []string{"sh", "-c", "true"}
			},
		},
		{name: "unused volume", mutate: func(input *DockerTopologyInput) { input.Services[0].VolumeMounts = nil }},
		{name: "foreign label", mutate: func(input *DockerTopologyInput) { input.Services[0].Labels[0].Key = "com.other.owner" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validDockerTopologyInput()
			test.mutate(&input)
			if _, err := NewDockerTopology(input); err == nil {
				t.Fatal("NewDockerTopology() accepted expanded or ambiguous authority")
			}
		})
	}
}

func validDockerTopologyInput() DockerTopologyInput {
	labels := []TopologyLabelInput{{Key: "com.agentmemory.managed", Value: "true"}}
	return DockerTopologyInput{
		Profiles: []string{"default"},
		Networks: []DockerNetworkInput{{ID: "internal", Internal: true, Labels: labels}},
		Volumes:  []DockerVolumeInput{{ID: "core-data", Purpose: "canonical-data", Labels: labels}},
		HealthProbes: []HealthProbeInput{{
			ID: "core-ready", Kind: HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080,
			IntervalSeconds: 10, TimeoutSeconds: 3, Retries: 5,
		}},
		Services: []DockerServiceInput{{
			ID: "core", ImageResourceIDs: []string{"image"}, Profiles: []string{"default"},
			NetworkIDs:    []string{"internal"},
			VolumeMounts:  []VolumeMountInput{{VolumeID: "core-data", Target: "/var/lib/agentmemory"}},
			HealthProbeID: "core-ready", UserID: 1000, GroupID: 1000,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true,
			PublishedPorts: []PortBindingInput{{Host: "127.0.0.1", HostPort: 38765, ContainerPort: 8080}},
			Labels:         labels,
		}},
	}
}
