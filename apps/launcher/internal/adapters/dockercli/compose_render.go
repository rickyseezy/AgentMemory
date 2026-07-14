package dockercli

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

const maximumRenderedEntries = 256

var errRenderedComposePolicy = errors.New("rendered Compose policy is invalid")

type renderedComposeDocument struct {
	Name     string                            `json:"name"`
	Services map[string]renderedComposeService `json:"services"`
	Networks map[string]renderedComposeNetwork `json:"networks,omitempty"`
	Volumes  map[string]renderedComposeVolume  `json:"volumes,omitempty"`
	Secrets  map[string]renderedComposeSecret  `json:"secrets,omitempty"`
}

type renderedComposeService struct {
	Command     []string                             `json:"command"`
	Entrypoint  json.RawMessage                      `json:"entrypoint"`
	Image       string                               `json:"image"`
	User        string                               `json:"user"`
	ReadOnly    bool                                 `json:"read_only"`
	CapAdd      []string                             `json:"cap_add,omitempty"`
	CapDrop     []string                             `json:"cap_drop,omitempty"`
	SecurityOpt []string                             `json:"security_opt,omitempty"`
	Privileged  bool                                 `json:"privileged,omitempty"`
	NetworkMode string                               `json:"network_mode,omitempty"`
	PID         string                               `json:"pid,omitempty"`
	IPC         string                               `json:"ipc,omitempty"`
	Restart     string                               `json:"restart"`
	Networks    map[string]json.RawMessage           `json:"networks"`
	Healthcheck *renderedComposeHealthcheck          `json:"healthcheck,omitempty"`
	StopGrace   string                               `json:"stop_grace_period"`
	Deploy      *renderedComposeDeploy               `json:"deploy"`
	Tmpfs       []string                             `json:"tmpfs,omitempty"`
	Ports       []renderedComposePort                `json:"ports,omitempty"`
	Volumes     []renderedComposeServiceVolume       `json:"volumes,omitempty"`
	Secrets     []renderedComposeServiceSecret       `json:"secrets,omitempty"`
	Environment map[string]string                    `json:"environment,omitempty"`
	Labels      map[string]string                    `json:"labels"`
	DependsOn   map[string]renderedComposeDependency `json:"depends_on,omitempty"`
	PullPolicy  string                               `json:"pull_policy,omitempty"`
}

type renderedComposeHealthcheck struct {
	Test          []string `json:"test"`
	Timeout       string   `json:"timeout"`
	Interval      string   `json:"interval"`
	Retries       uint32   `json:"retries"`
	StartPeriod   string   `json:"start_period"`
	StartInterval string   `json:"start_interval"`
}

type renderedComposeDependency struct {
	Condition string `json:"condition"`
	Restart   bool   `json:"restart,omitempty"`
	Required  bool   `json:"required"`
}

type renderedComposeDeploy struct {
	Resources renderedComposeResources  `json:"resources"`
	Placement *renderedComposePlacement `json:"placement,omitempty"`
}

type renderedComposePlacement struct{}

type renderedComposeResources struct {
	Limits *renderedComposeLimits `json:"limits"`
}

type renderedComposeLimits struct {
	CPUs   json.Number `json:"cpus"`
	Memory string      `json:"memory"`
	PIDs   int64       `json:"pids"`
}

type renderedComposePort struct {
	Name        string `json:"name,omitempty"`
	Mode        string `json:"mode,omitempty"`
	HostIP      string `json:"host_ip,omitempty"`
	Target      uint32 `json:"target"`
	Published   string `json:"published"`
	Protocol    string `json:"protocol,omitempty"`
	AppProtocol string `json:"app_protocol,omitempty"`
}

type renderedComposeServiceVolume struct {
	Type        string                        `json:"type"`
	Source      string                        `json:"source,omitempty"`
	Target      string                        `json:"target"`
	ReadOnly    bool                          `json:"read_only,omitempty"`
	Consistency string                        `json:"consistency,omitempty"`
	Bind        *renderedComposeBindOptions   `json:"bind,omitempty"`
	Volume      *renderedComposeVolumeOptions `json:"volume,omitempty"`
	Tmpfs       *renderedComposeTmpfsOptions  `json:"tmpfs,omitempty"`
}

type renderedComposeBindOptions struct {
	SELinux        string `json:"selinux,omitempty"`
	Propagation    string `json:"propagation,omitempty"`
	CreateHostPath bool   `json:"create_host_path,omitempty"`
	Recursive      string `json:"recursive,omitempty"`
}

type renderedComposeVolumeOptions struct {
	Labels  map[string]string `json:"labels,omitempty"`
	NoCopy  bool              `json:"nocopy,omitempty"`
	Subpath string            `json:"subpath,omitempty"`
}

type renderedComposeTmpfsOptions struct {
	Size string `json:"size"`
	Mode uint32 `json:"mode"`
}

type renderedComposeServiceSecret struct {
	Source string          `json:"source"`
	Target string          `json:"target"`
	UID    string          `json:"uid,omitempty"`
	GID    string          `json:"gid,omitempty"`
	Mode   json.RawMessage `json:"mode,omitempty"`
}

type renderedComposeNetwork struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	IPAM       json.RawMessage   `json:"ipam,omitempty"`
	External   bool              `json:"external,omitempty"`
	Internal   bool              `json:"internal"`
	Attachable bool              `json:"attachable,omitempty"`
	Labels     map[string]string `json:"labels"`
	EnableIPv4 *bool             `json:"enable_ipv4,omitempty"`
	EnableIPv6 *bool             `json:"enable_ipv6,omitempty"`
}

type renderedComposeVolume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	External   bool              `json:"external,omitempty"`
	Labels     map[string]string `json:"labels"`
}

type renderedComposeSecret struct {
	Name           string            `json:"name"`
	File           string            `json:"file,omitempty"`
	Environment    string            `json:"environment,omitempty"`
	Content        string            `json:"content,omitempty"`
	External       bool              `json:"external,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Driver         string            `json:"driver,omitempty"`
	DriverOpts     map[string]string `json:"driver_opts,omitempty"`
	TemplateDriver string            `json:"template_driver,omitempty"`
}

func decodeRenderedPolicy(data []byte, expectedProject string) (composeplan.Model, error) {
	if len(data) == 0 || len(data) > maximumDockerJSON || rejectDuplicateJSONKeys(data) != nil {
		return composeplan.Model{}, errRenderedComposePolicy
	}
	var document renderedComposeDocument
	if err := decodeStrictJSON(data, &document); err != nil || document.Name != expectedProject ||
		len(document.Services) == 0 || tooManyRenderedEntries(document) {
		return composeplan.Model{}, errRenderedComposePolicy
	}
	core, exists := document.Services[string(composeplan.ServiceCore)]
	if !exists {
		return composeplan.Model{}, errRenderedComposePolicy
	}
	identity, err := composeplan.NewIdentity(
		core.Labels[composeplan.LabelInstallation], core.Labels[composeplan.LabelGeneration],
	)
	if err != nil || identity.ProjectName() != document.Name {
		return composeplan.Model{}, errRenderedComposePolicy
	}
	model := composeplan.Model{
		Identity: identity,
		Release:  core.Labels[composeplan.LabelRelease],
		Services: make(map[composeplan.ServiceName]composeplan.Service, len(document.Services)),
		Networks: make(map[composeplan.NetworkName]composeplan.Network, len(document.Networks)),
		Volumes:  make(map[string]composeplan.Volume, len(document.Volumes)),
		Secrets:  make(map[string]composeplan.Secret, len(document.Secrets)),
	}
	logicalVolumes, err := normalizeRenderedResources(document, &model)
	if err != nil {
		return composeplan.Model{}, errRenderedComposePolicy
	}
	for name, raw := range document.Services {
		service, serviceError := normalizeRenderedService(composeplan.ServiceName(name), raw, logicalVolumes)
		if serviceError != nil {
			return composeplan.Model{}, errRenderedComposePolicy
		}
		model.Services[service.Name] = service
	}
	return model, nil
}

func tooManyRenderedEntries(document renderedComposeDocument) bool {
	return len(document.Services) > maximumRenderedEntries || len(document.Networks) > maximumRenderedEntries ||
		len(document.Volumes) > maximumRenderedEntries || len(document.Secrets) > maximumRenderedEntries
}

func normalizeRenderedResources(
	document renderedComposeDocument,
	model *composeplan.Model,
) (map[string]string, error) {
	logicalVolumes := make(map[string]string, len(document.Volumes))
	physicalVolumes := make(map[string]struct{}, len(document.Volumes))
	for logical, raw := range document.Volumes {
		if logical == "" || raw.Name == "" || raw.External || (raw.Driver != "" && raw.Driver != "local") ||
			len(raw.DriverOpts) != 0 {
			return nil, errRenderedComposePolicy
		}
		if _, duplicate := physicalVolumes[raw.Name]; duplicate {
			return nil, errRenderedComposePolicy
		}
		physicalVolumes[raw.Name] = struct{}{}
		logicalVolumes[logical] = raw.Name
		model.Volumes[raw.Name] = composeplan.Volume{Name: raw.Name, Labels: cloneStringMap(raw.Labels)}
	}
	for logical, raw := range document.Networks {
		if logical == "" || raw.Name == "" || raw.External || raw.Attachable ||
			(raw.Driver != "" && raw.Driver != "bridge") || len(raw.DriverOpts) != 0 ||
			!emptyJSONObject(raw.IPAM) || raw.EnableIPv4 != nil || raw.EnableIPv6 != nil {
			return nil, errRenderedComposePolicy
		}
		name := composeplan.NetworkName(logical)
		model.Networks[name] = composeplan.Network{
			Name: raw.Name, Internal: raw.Internal, Labels: cloneStringMap(raw.Labels),
		}
	}
	for logical, raw := range document.Secrets {
		if logical == "" || raw.Name == "" || raw.File == "" || raw.Environment != "" || raw.Content != "" ||
			raw.External || len(raw.Labels) != 0 || raw.Driver != "" || len(raw.DriverOpts) != 0 || raw.TemplateDriver != "" {
			return nil, errRenderedComposePolicy
		}
		model.Secrets[logical] = composeplan.Secret{Name: raw.Name, File: raw.File}
	}
	return logicalVolumes, nil
}

func normalizeRenderedService(
	name composeplan.ServiceName,
	raw renderedComposeService,
	logicalVolumes map[string]string,
) (composeplan.Service, error) {
	projector := name == composeplan.ServiceSecretProjector
	validNetworks := !projector && raw.NetworkMode == "" && len(raw.Networks) > 0 &&
		len(raw.Networks) <= maximumRenderedEntries ||
		projector && raw.NetworkMode == "none" && len(raw.Networks) == 0
	if !nullJSON(raw.Entrypoint) ||
		(raw.PullPolicy != "" && raw.PullPolicy != "never") || raw.Deploy == nil ||
		raw.Deploy.Resources.Limits == nil ||
		!validNetworks || raw.PID != "" || raw.IPC != "" ||
		len(raw.DependsOn) > maximumRenderedEntries || len(raw.Volumes) > maximumRenderedEntries ||
		len(raw.Secrets) > maximumRenderedEntries || len(raw.Tmpfs) > maximumRenderedEntries ||
		len(raw.Ports) > maximumRenderedEntries || len(raw.Environment) > maximumRenderedEntries {
		return composeplan.Service{}, errRenderedComposePolicy
	}
	limits, err := normalizeLimits(*raw.Deploy.Resources.Limits)
	if err != nil {
		return composeplan.Service{}, err
	}
	healthTiming := composeplan.HealthcheckTiming{}
	healthcheck := []string(nil)
	if raw.Healthcheck != nil {
		healthTiming, err = normalizeHealthTiming(*raw.Healthcheck)
		if err != nil {
			return composeplan.Service{}, errRenderedComposePolicy
		}
		healthcheck = append([]string(nil), raw.Healthcheck.Test...)
	}
	stopGrace, err := time.ParseDuration(raw.StopGrace)
	if err != nil {
		return composeplan.Service{}, errRenderedComposePolicy
	}
	service := composeplan.Service{
		Name: name, Image: raw.Image, User: raw.User, ReadOnly: raw.ReadOnly,
		CapDropAll:      len(raw.CapDrop) == 1 && raw.CapDrop[0] == "ALL",
		CapAdd:          append([]string(nil), raw.CapAdd...),
		NoNewPrivileges: noNewPrivileges(raw.SecurityOpt), Privileged: raw.Privileged,
		HostNetwork: raw.NetworkMode != "" && raw.NetworkMode != "none", HostPID: raw.PID != "", HostIPC: raw.IPC != "",
		NetworkDisabled: raw.NetworkMode == "none",
		Restart:         raw.Restart, Healthcheck: healthcheck, Command: append([]string(nil), raw.Command...),
		HealthTiming: healthTiming, StopGracePeriod: stopGrace, Limits: limits,
		Environment: cloneStringMap(raw.Environment), Labels: cloneStringMap(raw.Labels),
	}
	for network, options := range raw.Networks {
		if !nullOrEmptyJSONObject(options) {
			return composeplan.Service{}, errRenderedComposePolicy
		}
		service.Networks = append(service.Networks, composeplan.NetworkName(network))
	}
	for dependencyName, dependency := range raw.DependsOn {
		service.DependsOn = append(service.DependsOn, composeplan.Dependency{
			Service: composeplan.ServiceName(dependencyName), Condition: dependency.Condition,
			Restart: dependency.Restart, Required: dependency.Required,
		})
	}
	for _, value := range raw.Tmpfs {
		tmpfs, parseError := parseRenderedTmpfs(value)
		if parseError != nil {
			return composeplan.Service{}, errRenderedComposePolicy
		}
		service.Tmpfs = append(service.Tmpfs, tmpfs)
	}
	for _, rawPort := range raw.Ports {
		port, portError := normalizeRenderedPort(rawPort)
		if portError != nil {
			return composeplan.Service{}, errRenderedComposePolicy
		}
		service.Ports = append(service.Ports, port)
	}
	for _, rawMount := range raw.Volumes {
		mount, tmpfs, mountError := normalizeRenderedMount(rawMount, logicalVolumes)
		if mountError != nil {
			return composeplan.Service{}, errRenderedComposePolicy
		}
		if tmpfs != nil {
			service.Tmpfs = append(service.Tmpfs, *tmpfs)
		} else {
			service.Mounts = append(service.Mounts, mount)
		}
	}
	for _, rawSecret := range raw.Secrets {
		if rawSecret.Source == "" || rawSecret.Target == "" || rawSecret.UID != "" || rawSecret.GID != "" ||
			!validSecretMode(rawSecret.Mode) {
			return composeplan.Service{}, errRenderedComposePolicy
		}
		service.Mounts = append(service.Mounts, composeplan.Mount{
			Kind: composeplan.MountSecret, Source: rawSecret.Source, Target: rawSecret.Target, ReadOnly: true,
		})
	}
	return service, nil
}

func normalizeHealthTiming(raw renderedComposeHealthcheck) (composeplan.HealthcheckTiming, error) {
	interval, intervalError := time.ParseDuration(raw.Interval)
	timeout, timeoutError := time.ParseDuration(raw.Timeout)
	startPeriod, startPeriodError := time.ParseDuration(raw.StartPeriod)
	startInterval, startIntervalError := time.ParseDuration(raw.StartInterval)
	if intervalError != nil || timeoutError != nil || startPeriodError != nil || startIntervalError != nil {
		return composeplan.HealthcheckTiming{}, errRenderedComposePolicy
	}
	return composeplan.HealthcheckTiming{
		Interval: interval, Timeout: timeout, Retries: raw.Retries,
		StartPeriod: startPeriod, StartInterval: startInterval,
	}, nil
}

func normalizeLimits(raw renderedComposeLimits) (composeplan.Limits, error) {
	value, ok := new(big.Rat).SetString(raw.CPUs.String())
	if !ok || value.Sign() <= 0 {
		return composeplan.Limits{}, errRenderedComposePolicy
	}
	value.Mul(value, big.NewRat(1000, 1))
	if !value.IsInt() || !value.Num().IsUint64() {
		return composeplan.Limits{}, errRenderedComposePolicy
	}
	cpus := value.Num().Uint64()
	memory, memoryError := strconv.ParseUint(raw.Memory, 10, 64)
	if memoryError != nil || cpus == 0 || cpus > uint64(^uint32(0)) || memory == 0 ||
		raw.PIDs <= 0 || raw.PIDs > int64(^uint32(0)) {
		return composeplan.Limits{}, errRenderedComposePolicy
	}
	return composeplan.Limits{CPUsMilli: uint32(cpus), MemoryBytes: memory, PIDs: uint32(raw.PIDs)}, nil
}

func normalizeRenderedPort(raw renderedComposePort) (composeplan.Port, error) {
	port, err := strconv.ParseUint(raw.Published, 10, 16)
	if err != nil || raw.Name != "" || raw.AppProtocol != "" || (raw.Mode != "" && raw.Mode != "ingress") ||
		(raw.Protocol != "" && raw.Protocol != "tcp") || raw.Target == 0 || raw.Target > uint32(^uint16(0)) {
		return composeplan.Port{}, errRenderedComposePolicy
	}
	return composeplan.Port{HostIP: raw.HostIP, HostPort: uint16(port), ContainerPort: uint16(raw.Target)}, nil
}

func normalizeRenderedMount(
	raw renderedComposeServiceVolume,
	logicalVolumes map[string]string,
) (composeplan.Mount, *composeplan.Tmpfs, error) {
	if raw.Target == "" || raw.Consistency != "" {
		return composeplan.Mount{}, nil, errRenderedComposePolicy
	}
	switch raw.Type {
	case "volume":
		physical, exists := logicalVolumes[raw.Source]
		if !exists || raw.Bind != nil || raw.Tmpfs != nil || !emptyVolumeOptions(raw.Volume) {
			return composeplan.Mount{}, nil, errRenderedComposePolicy
		}
		return composeplan.Mount{
			Kind: composeplan.MountVolume, Source: physical, Target: raw.Target, ReadOnly: raw.ReadOnly,
		}, nil, nil
	case "bind":
		return composeplan.Mount{
			Kind: composeplan.MountBind, Source: raw.Source, Target: raw.Target, ReadOnly: raw.ReadOnly,
		}, nil, nil
	case "tmpfs":
		if raw.Source != "" || raw.Bind != nil || raw.Volume != nil || raw.Tmpfs == nil || raw.ReadOnly {
			return composeplan.Mount{}, nil, errRenderedComposePolicy
		}
		size, err := strconv.ParseUint(raw.Tmpfs.Size, 10, 64)
		if err != nil {
			return composeplan.Mount{}, nil, errRenderedComposePolicy
		}
		return composeplan.Mount{}, &composeplan.Tmpfs{
			Target: raw.Target, SizeBytes: size, Mode: raw.Tmpfs.Mode,
		}, nil
	default:
		return composeplan.Mount{}, nil, errRenderedComposePolicy
	}
}

func parseRenderedTmpfs(value string) (composeplan.Tmpfs, error) {
	target, options, found := strings.Cut(value, ":")
	if !found || target == "" {
		return composeplan.Tmpfs{}, errRenderedComposePolicy
	}
	var size uint64
	var mode uint64
	executable := false
	seen := make(map[string]struct{}, 3)
	for _, option := range strings.Split(options, ",") {
		if option == "exec" {
			if _, duplicate := seen[option]; duplicate {
				return composeplan.Tmpfs{}, errRenderedComposePolicy
			}
			seen[option] = struct{}{}
			executable = true
			continue
		}
		key, raw, ok := strings.Cut(option, "=")
		if !ok || raw == "" {
			return composeplan.Tmpfs{}, errRenderedComposePolicy
		}
		if _, duplicate := seen[key]; duplicate {
			return composeplan.Tmpfs{}, errRenderedComposePolicy
		}
		seen[key] = struct{}{}
		var err error
		switch key {
		case "size":
			size, err = strconv.ParseUint(raw, 10, 64)
		case "mode":
			base := 10
			if strings.HasPrefix(raw, "0") {
				base = 8
			}
			mode, err = strconv.ParseUint(raw, base, 32)
		default:
			return composeplan.Tmpfs{}, errRenderedComposePolicy
		}
		if err != nil {
			return composeplan.Tmpfs{}, errRenderedComposePolicy
		}
	}
	if _, exists := seen["size"]; !exists {
		return composeplan.Tmpfs{}, errRenderedComposePolicy
	}
	if _, exists := seen["mode"]; !exists {
		return composeplan.Tmpfs{}, errRenderedComposePolicy
	}
	return composeplan.Tmpfs{Target: target, SizeBytes: size, Mode: uint32(mode), Executable: executable}, nil
}

func validSecretMode(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte(`"0400"`)) ||
		bytes.Equal(trimmed, []byte(`"0444"`)) || bytes.Equal(trimmed, []byte(`292`))
}

func noNewPrivileges(values []string) bool {
	return len(values) == 1 && (values[0] == "no-new-privileges:true" || values[0] == "no-new-privileges=true")
}

func nullJSON(value json.RawMessage) bool {
	return len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func nullOrEmptyJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("{}"))
}

func emptyJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("{}"))
}

func emptyVolumeOptions(value *renderedComposeVolumeOptions) bool {
	return value == nil || len(value.Labels) == 0 && !value.NoCopy && value.Subpath == ""
}

func cloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
