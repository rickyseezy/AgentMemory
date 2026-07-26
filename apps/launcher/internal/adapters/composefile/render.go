// Package composefile renders the sole production Compose source from a
// validated composeplan.PolicyPlan. It has no template or interpolation path.
package composefile

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

const maximumComposeSourceBytes = 1024 * 1024

var errInvalidComposeSource = errors.New("production Compose source is invalid")

type document struct {
	Name     string                    `json:"name"`
	Services map[string]service        `json:"services"`
	Networks map[string]network        `json:"networks"`
	Volumes  map[string]volume         `json:"volumes"`
	Secrets  map[string]secretResource `json:"secrets"`
}

type service struct {
	Image           string                `json:"image"`
	User            string                `json:"user"`
	ReadOnly        bool                  `json:"read_only"`
	CapDrop         []string              `json:"cap_drop"`
	CapAdd          []string              `json:"cap_add,omitempty"`
	SecurityOpt     []string              `json:"security_opt"`
	Restart         string                `json:"restart"`
	Networks        []string              `json:"networks,omitempty"`
	NetworkMode     string                `json:"network_mode,omitempty"`
	Healthcheck     *healthcheck          `json:"healthcheck,omitempty"`
	StopGracePeriod string                `json:"stop_grace_period"`
	Deploy          deployment            `json:"deploy"`
	Tmpfs           []string              `json:"tmpfs"`
	Ports           []port                `json:"ports,omitempty"`
	Volumes         []serviceVolume       `json:"volumes,omitempty"`
	Secrets         []serviceSecret       `json:"secrets,omitempty"`
	Environment     map[string]string     `json:"environment"`
	Labels          map[string]string     `json:"labels"`
	DependsOn       map[string]dependency `json:"depends_on,omitempty"`
	PullPolicy      string                `json:"pull_policy"`
}

type healthcheck struct {
	Test          []string `json:"test"`
	Interval      string   `json:"interval"`
	Timeout       string   `json:"timeout"`
	Retries       uint32   `json:"retries"`
	StartPeriod   string   `json:"start_period"`
	StartInterval string   `json:"start_interval"`
}

type deployment struct {
	Resources resources `json:"resources"`
}

type resources struct {
	Limits resourceLimits `json:"limits"`
}

type resourceLimits struct {
	CPUs   string `json:"cpus"`
	Memory string `json:"memory"`
	PIDs   uint32 `json:"pids"`
}

type port struct {
	HostIP    string `json:"host_ip"`
	Target    uint16 `json:"target"`
	Published string `json:"published"`
	Protocol  string `json:"protocol"`
}

type serviceVolume struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

type serviceSecret struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Mode   string `json:"mode,omitempty"`
}

type dependency struct {
	Condition string `json:"condition"`
	Restart   bool   `json:"restart"`
	Required  bool   `json:"required"`
}

type network struct {
	Name     string            `json:"name"`
	Internal bool              `json:"internal"`
	Labels   map[string]string `json:"labels"`
}

type volume struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type secretResource struct {
	Name string `json:"name"`
	File string `json:"file"`
}

// Render returns deterministic JSON accepted by Docker Compose as a source
// document. It contains protected-file references only and never secret bytes.
func Render(plan composeplan.PolicyPlan) ([]byte, error) {
	model, ok := plan.CanonicalModel()
	if !ok || !plan.Valid() {
		return nil, errInvalidComposeSource
	}
	logicalVolumes := make(map[string]string, len(model.Volumes))
	volumes := make(map[string]volume, len(model.Volumes))
	for physical, expected := range model.Volumes {
		logical := expected.Labels[composeplan.LabelPurpose]
		if logical == "" {
			return nil, errInvalidComposeSource
		}
		if _, duplicate := volumes[logical]; duplicate {
			return nil, errInvalidComposeSource
		}
		logicalVolumes[physical] = logical
		volumes[logical] = volume{Name: expected.Name, Labels: clone(expected.Labels)}
	}
	services := make(map[string]service, len(model.Services))
	for name, expected := range model.Services {
		rendered, err := renderService(expected, logicalVolumes)
		if err != nil {
			return nil, err
		}
		services[string(name)] = rendered
	}
	secrets := make(map[string]secretResource, len(model.Secrets))
	for name, expected := range model.Secrets {
		secrets[name] = secretResource{Name: expected.Name, File: expected.File}
	}
	networks := make(map[string]network, len(model.Networks))
	for name, expected := range model.Networks {
		networks[string(name)] = network{
			Name: expected.Name, Internal: expected.Internal, Labels: clone(expected.Labels),
		}
	}
	source := document{
		Name: model.Identity.ProjectName(), Services: services,
		Networks: networks,
		Volumes:  volumes, Secrets: secrets,
	}
	encoded, err := json.Marshal(source)
	if err != nil || len(encoded) == 0 || len(encoded)+1 > maximumComposeSourceBytes {
		return nil, errInvalidComposeSource
	}
	return append(encoded, '\n'), nil
}

func renderService(expected composeplan.Service, logicalVolumes map[string]string) (service, error) {
	rendered := service{
		Image: expected.Image, User: expected.User, ReadOnly: expected.ReadOnly,
		CapDrop: []string{"ALL"}, CapAdd: append([]string(nil), expected.CapAdd...),
		SecurityOpt: []string{"no-new-privileges:true"}, Restart: expected.Restart,
		StopGracePeriod: duration(expected.StopGracePeriod),
		Deploy: deployment{Resources: resources{Limits: resourceLimits{
			CPUs:   formatCPUs(expected.Limits.CPUsMilli),
			Memory: strconv.FormatUint(expected.Limits.MemoryBytes, 10), PIDs: expected.Limits.PIDs,
		}}},
		Environment: clone(expected.Environment), Labels: clone(expected.Labels), PullPolicy: "never",
	}
	if expected.NetworkDisabled {
		rendered.NetworkMode = "none"
	} else {
		rendered.Networks = make([]string, 0, len(expected.Networks))
		for _, name := range expected.Networks {
			rendered.Networks = append(rendered.Networks, string(name))
		}
	}
	if len(expected.Healthcheck) != 0 {
		rendered.Healthcheck = &healthcheck{
			Test:     append([]string(nil), expected.Healthcheck...),
			Interval: duration(expected.HealthTiming.Interval), Timeout: duration(expected.HealthTiming.Timeout),
			Retries: expected.HealthTiming.Retries, StartPeriod: duration(expected.HealthTiming.StartPeriod),
			StartInterval: duration(expected.HealthTiming.StartInterval),
		}
	}
	for _, entry := range expected.Tmpfs {
		options := "size=" + strconv.FormatUint(entry.SizeBytes, 10) +
			",mode=0" + strconv.FormatUint(uint64(entry.Mode), 8)
		if entry.Executable {
			options += ",exec"
		}
		rendered.Tmpfs = append(rendered.Tmpfs, entry.Target+":"+options)
	}
	for _, expectedPort := range expected.Ports {
		rendered.Ports = append(rendered.Ports, port{
			HostIP: expectedPort.HostIP, Target: expectedPort.ContainerPort,
			Published: strconv.FormatUint(uint64(expectedPort.HostPort), 10), Protocol: "tcp",
		})
	}
	for _, mount := range expected.Mounts {
		switch mount.Kind {
		case composeplan.MountVolume:
			logical, exists := logicalVolumes[mount.Source]
			if !exists {
				return service{}, errInvalidComposeSource
			}
			rendered.Volumes = append(rendered.Volumes, serviceVolume{
				Type: "volume", Source: logical, Target: mount.Target, ReadOnly: mount.ReadOnly,
			})
		case composeplan.MountSecret:
			rendered.Secrets = append(rendered.Secrets, serviceSecret{
				Source: mount.Source, Target: mount.Target,
			})
		case composeplan.MountUnknown, composeplan.MountConfig, composeplan.MountBind:
			return service{}, errInvalidComposeSource
		default:
			return service{}, errInvalidComposeSource
		}
	}
	for _, expectedDependency := range expected.DependsOn {
		if rendered.DependsOn == nil {
			rendered.DependsOn = make(map[string]dependency, len(expected.DependsOn))
		}
		rendered.DependsOn[string(expectedDependency.Service)] = dependency{
			Condition: expectedDependency.Condition, Restart: expectedDependency.Restart,
			Required: expectedDependency.Required,
		}
	}
	return rendered, nil
}

func formatCPUs(milli uint32) string {
	return strconv.FormatFloat(float64(milli)/1000, 'f', 3, 64)
}

func duration(value time.Duration) string { return value.String() }

func clone(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
