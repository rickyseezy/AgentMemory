package dockercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

// ProviderAdapterRuntime is the closed Compose boundary for custom provider sidecars.
// Its public API cannot express raw Compose fields, Docker flags, mounts, ports, or networks.
type ProviderAdapterRuntime struct {
	executors Executors
	endpoint  containerengine.Endpoint
	mu        sync.Mutex
	active    map[string]providerRuntimeRecord
}

type providerRuntimeRecord struct {
	plan          provideradapter.DeploymentPlan
	configuration []byte
}

// NewProviderAdapterRuntime binds custom adapters to one explicit local engine.
func NewProviderAdapterRuntime(executors Executors, endpoint containerengine.Endpoint) (*ProviderAdapterRuntime, error) {
	if !executors.valid() || endpoint.String() == "" {
		return nil, provideradapterapp.ErrRuntime
	}
	return &ProviderAdapterRuntime{executors: executors, endpoint: endpoint, active: map[string]providerRuntimeRecord{}}, nil
}

// Start renders the closed template, asks Compose to normalize it, and starts only its one service.
func (r *ProviderAdapterRuntime) Start(ctx context.Context, plan provideradapter.DeploymentPlan) (provideradapterapp.RuntimeHandle, error) {
	if r == nil || ctx == nil || !plan.Valid() {
		return provideradapterapp.RuntimeHandle{}, provideradapterapp.ErrRuntime
	}
	configuration, err := renderProviderAdapterCompose(plan)
	if err != nil {
		return provideradapterapp.RuntimeHandle{}, provideradapterapp.ErrRuntime
	}
	handle := provideradapterapp.NewRuntimeHandle(plan.ServiceName(), plan.Digest())
	if !handle.Valid() {
		return provideradapterapp.RuntimeHandle{}, provideradapterapp.ErrRuntime
	}
	r.mu.Lock()
	_, exists := r.active[handle.InstanceID()]
	r.mu.Unlock()
	if exists {
		return provideradapterapp.RuntimeHandle{}, provideradapterapp.ErrRuntime
	}
	deadline := time.Duration(plan.TimeoutMilliseconds()) * time.Millisecond
	operationContext, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if err = r.execute(operationContext, plan, configuration, []string{"config", "--format", "json", "--no-env-resolution"}); err != nil {
		return provideradapterapp.RuntimeHandle{}, err
	}
	if err = r.execute(operationContext, plan, configuration, []string{
		"up", "--detach", "--no-build", "--pull", "never", "--no-deps", plan.ServiceName(),
	}); err != nil {
		// Compose may create a container before returning failure. Return a valid
		// handle so the application is obligated to invoke Stop.
		r.mu.Lock()
		r.active[handle.InstanceID()] = providerRuntimeRecord{plan: plan, configuration: configuration}
		r.mu.Unlock()
		return handle, err
	}
	r.mu.Lock()
	r.active[handle.InstanceID()] = providerRuntimeRecord{plan: plan, configuration: configuration}
	r.mu.Unlock()
	return handle, nil
}

// Stop removes only the previously started service and cannot address another project or container.
func (r *ProviderAdapterRuntime) Stop(ctx context.Context, handle provideradapterapp.RuntimeHandle) error {
	if r == nil || ctx == nil || !handle.Valid() {
		return provideradapterapp.ErrRuntime
	}
	r.mu.Lock()
	record, exists := r.active[handle.InstanceID()]
	r.mu.Unlock()
	if !exists || !record.plan.Digest().Equal(handle.PlanDigest()) || record.plan.ServiceName() != handle.InstanceID() {
		return provideradapterapp.ErrRuntime
	}
	operationContext, cancel := context.WithTimeout(ctx, time.Duration(record.plan.TimeoutMilliseconds())*time.Millisecond)
	defer cancel()
	err := r.execute(operationContext, record.plan, record.configuration, []string{
		"rm", "--stop", "--force", record.plan.ServiceName(),
	})
	if err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.active, handle.InstanceID())
	r.mu.Unlock()
	return nil
}

func (r *ProviderAdapterRuntime) execute(
	ctx context.Context,
	plan provideradapter.DeploymentPlan,
	configuration []byte,
	operation []string,
) error {
	runner, executable, err := r.executors.composeBinding()
	if err != nil {
		return provideradapterapp.ErrRuntime
	}
	arguments := make([]string, 0, 10+len(operation))
	arguments = append(arguments,
		"--host", r.endpoint.String(), "--ansi", "never", "--progress", "quiet",
		"--project-name", plan.ProjectName(), "--file", "-",
	)
	arguments = append(arguments, operation...)
	invocation, err := argvprocess.NewInvocationWithStandardInput(executable, arguments, configuration)
	if err != nil {
		return provideradapterapp.ErrRuntime
	}
	result, err := runner.Run(ctx, invocation)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(provideradapterapp.ErrRuntime, err)
		}
		return provideradapterapp.ErrRuntime
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumDockerJSON || len(result.StandardError) > maximumDockerJSON {
		return provideradapterapp.ErrRuntime
	}
	return nil
}

type providerComposeDocument struct {
	Name     string                            `json:"name"`
	Services map[string]providerComposeService `json:"services"`
	Networks map[string]providerComposeNetwork `json:"networks"`
	Secrets  map[string]providerComposeSecret  `json:"secrets,omitempty"`
}

type providerComposeService struct {
	Image           string                  `json:"image"`
	User            string                  `json:"user"`
	ReadOnly        bool                    `json:"read_only"`
	Init            bool                    `json:"init"`
	Restart         string                  `json:"restart"`
	CapDrop         []string                `json:"cap_drop"`
	SecurityOpt     []string                `json:"security_opt"`
	Tmpfs           []string                `json:"tmpfs"`
	Networks        []string                `json:"networks"`
	CPUs            string                  `json:"cpus"`
	Memory          string                  `json:"mem_limit"`
	PIDs            uint32                  `json:"pids_limit"`
	StopGracePeriod string                  `json:"stop_grace_period"`
	Labels          map[string]string       `json:"labels"`
	Secrets         []providerServiceSecret `json:"secrets,omitempty"`
}

type providerComposeNetwork struct {
	External bool   `json:"external"`
	Name     string `json:"name"`
}

type providerComposeSecret struct {
	External bool   `json:"external"`
	Name     string `json:"name"`
}

type providerServiceSecret struct {
	Source string `json:"source"`
	Target string `json:"target"`
	UID    string `json:"uid"`
	GID    string `json:"gid"`
	Mode   int    `json:"mode"`
}

func renderProviderAdapterCompose(plan provideradapter.DeploymentPlan) ([]byte, error) {
	if !plan.Valid() || !plan.ReadOnlyRootFS() || !plan.NoNewPrivileges() || plan.Privileged() ||
		plan.HostNetwork() || plan.PublishPort() || plan.Network() != "am_internal" ||
		plan.ProjectName() == "" || plan.ExternalNetwork() == "" || plan.ServiceName() == "" ||
		plan.User() != "65532:65532" || plan.ScratchTarget() != "/tmp" || plan.ScratchBytes() == 0 {
		return nil, provideradapter.ErrInvalidDeployment
	}
	tmpfs := fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=65532,gid=65532", plan.ScratchBytes())
	document := providerComposeDocument{
		Name: plan.ProjectName(),
		Services: map[string]providerComposeService{plan.ServiceName(): {
			Image: plan.Image(), User: plan.User(), ReadOnly: true, Init: true, Restart: "no",
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Tmpfs: []string{tmpfs}, Networks: []string{plan.Network()},
			CPUs:   strconv.FormatFloat(float64(plan.CPUsMilli())/1000, 'f', 3, 64),
			Memory: strconv.FormatUint(plan.MemoryBytes(), 10), PIDs: plan.PIDs(),
			StopGracePeriod: "10s", Labels: map[string]string{
				"com.agentmemory.managed": "true", "com.agentmemory.kind": "custom-provider-adapter",
				"com.agentmemory.plan-digest": plan.Digest().Hex(),
			},
		}},
		Networks: map[string]providerComposeNetwork{plan.Network(): {External: true, Name: plan.ExternalNetwork()}},
	}
	if capability := plan.CapabilitySecret(); capability != "" {
		document.Secrets = map[string]providerComposeSecret{
			"provider_gateway_capability": {External: true, Name: capability},
		}
		service := document.Services[plan.ServiceName()]
		service.Secrets = []providerServiceSecret{{
			Source: "provider_gateway_capability", Target: "provider_gateway_capability",
			UID: "65532", GID: "65532", Mode: 0o400,
		}}
		document.Services[plan.ServiceName()] = service
	}
	return json.Marshal(document)
}

var _ provideradapterapp.Runtime = (*ProviderAdapterRuntime)(nil)
