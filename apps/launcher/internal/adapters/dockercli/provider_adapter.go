package dockercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/providerprotocol"
)

const maximumProviderOperationFrameBytes = 8*1024*1024 + 4

var providerOperationPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

const (
	providerManagedLabel         = "com.agentmemory.managed"
	providerKindLabel            = "com.agentmemory.kind"
	providerPlanDigestLabel      = "com.agentmemory.plan-digest"
	providerOperationDigestLabel = "com.agentmemory.operation-digest"
	providerAdapterKind          = "custom-provider-adapter"
	maximumProviderOrphans       = 256
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
	Volumes  map[string]providerComposeVolume  `json:"volumes,omitempty"`
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
	Volumes         []providerServiceVolume `json:"volumes,omitempty"`
}

type providerComposeNetwork struct {
	External bool   `json:"external"`
	Name     string `json:"name"`
}

type providerComposeVolume struct {
	External bool   `json:"external"`
	Name     string `json:"name"`
}

type providerServiceVolume struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

func renderProviderAdapterCompose(plan provideradapter.DeploymentPlan) ([]byte, error) {
	return renderProviderAdapterComposeFor(
		plan,
		plan.ProjectName(),
		plan.ServiceName(),
		"",
	)
}

func renderProviderAdapterComposeFor(
	plan provideradapter.DeploymentPlan,
	projectName string,
	serviceName string,
	operationDigest string,
) ([]byte, error) {
	if !plan.Valid() || !plan.ReadOnlyRootFS() || !plan.NoNewPrivileges() || plan.Privileged() ||
		plan.HostNetwork() || plan.PublishPort() || plan.Network() != "am_internal" ||
		projectName == "" || plan.ExternalNetwork() == "" || serviceName == "" ||
		plan.User() != "65532:65532" || plan.ScratchTarget() != "/tmp" || plan.ScratchBytes() == 0 {
		return nil, provideradapter.ErrInvalidDeployment
	}
	tmpfs := fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=65532,gid=65532", plan.ScratchBytes())
	document := providerComposeDocument{
		Name: projectName,
		Services: map[string]providerComposeService{serviceName: {
			Image: plan.Image(), User: plan.User(), ReadOnly: true, Init: true, Restart: "no",
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Tmpfs: []string{tmpfs}, Networks: []string{plan.Network()},
			CPUs:   strconv.FormatFloat(float64(plan.CPUsMilli())/1000, 'f', 3, 64),
			Memory: strconv.FormatUint(plan.MemoryBytes(), 10), PIDs: plan.PIDs(),
			StopGracePeriod: "10s", Labels: map[string]string{
				providerManagedLabel: "true", providerKindLabel: providerAdapterKind,
				providerPlanDigestLabel: plan.Digest().Hex(),
			},
		}},
		Networks: map[string]providerComposeNetwork{plan.Network(): {External: true, Name: plan.ExternalNetwork()}},
	}
	if operationDigest != "" {
		service := document.Services[serviceName]
		service.Labels[providerOperationDigestLabel] = operationDigest
		document.Services[serviceName] = service
	}
	if capability := plan.CapabilitySecret(); capability != "" && operationDigest != "" {
		document.Volumes = map[string]providerComposeVolume{
			"provider_gateway_capability": {External: true, Name: capability},
		}
		service := document.Services[serviceName]
		service.Volumes = []providerServiceVolume{{
			Type: "volume", Source: "provider_gateway_capability",
			Target: "/run/provider-gateway", ReadOnly: true,
		}}
		document.Services[serviceName] = service
	}
	return json.Marshal(document)
}

// ProviderAdapterOperationSupervisor owns one request/container/configuration
// lifecycle. It never exposes raw Compose, mount, environment, or Docker flags.
type ProviderAdapterOperationSupervisor struct {
	executors        Executors
	endpoint         containerengine.Endpoint
	runtimeDirectory string
	lifecycle        sync.RWMutex
	activeMu         sync.Mutex
	active           map[string]struct{}
}

// NewProviderAdapterOperationSupervisor binds a private existing runtime
// directory and the signed Compose executable used for every operation.
func NewProviderAdapterOperationSupervisor(
	executors Executors,
	endpoint containerengine.Endpoint,
	runtimeDirectory string,
) (*ProviderAdapterOperationSupervisor, error) {
	info, err := os.Lstat(runtimeDirectory)
	if !executors.valid() || endpoint.String() == "" || err != nil ||
		!filepath.IsAbs(runtimeDirectory) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, provideradapterapp.ErrRuntime
	}
	return &ProviderAdapterOperationSupervisor{
		executors: executors, endpoint: endpoint, runtimeDirectory: runtimeDirectory,
		active: map[string]struct{}{},
	}, nil
}

// Execute runs exactly one framed operation through one auto-removed container
// and always reconciles its operation-scoped Compose project.
func (s *ProviderAdapterOperationSupervisor) Execute(
	ctx context.Context,
	plan provideradapter.DeploymentPlan,
	operationID string,
	request []byte,
) ([]byte, error) {
	if s == nil || ctx == nil || !plan.Valid() ||
		!providerOperationPattern.MatchString(operationID) ||
		len(request) < 5 || len(request) > maximumProviderOperationFrameBytes {
		return nil, provideradapterapp.ErrRuntime
	}
	decodedRequest, err := providerprotocol.DecodeRequest(bytes.NewReader(request))
	if err != nil || decodedRequest.ID != operationID ||
		decodedRequest.Params.OperationID != operationID {
		return nil, provideradapterapp.ErrRuntime
	}
	sum := sha256.Sum256([]byte(operationID + "\x00" + plan.Digest().Hex()))
	operationDigest := fmt.Sprintf("%x", sum)
	if !s.begin(operationDigest) {
		return nil, provideradapterapp.ErrRuntime
	}
	defer s.end(operationDigest)
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	projectName := "amop_" + plan.Digest().Hex()[:12] + "_" + operationDigest[:19]
	serviceName := "adapter_" + operationDigest[:20]
	configuration, err := renderProviderAdapterComposeFor(
		plan, projectName, serviceName, operationDigest,
	)
	if err != nil {
		return nil, provideradapterapp.ErrRuntime
	}
	directory, err := openPrivateExecutionDirectory(ctx, s.runtimeDirectory)
	if err != nil {
		return nil, provideradapterapp.ErrRuntime
	}
	defer func() {
		_ = directory.Close()
	}()
	name := projectName + ".json"
	path := filepath.Join(s.runtimeDirectory, name)
	configurationFile, err := ensureExecutionFile(
		ctx, directory, name, path, configuration, false,
	)
	if err != nil {
		return nil, provideradapterapp.ErrRuntime
	}
	defer func() {
		_ = configurationFile.Close()
		_ = os.Remove(path)
	}()
	deadline := time.Duration(plan.TimeoutMilliseconds()) * time.Millisecond
	operationContext, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	cleanupRequired := true
	defer func() {
		if cleanupRequired {
			_ = s.cleanup(context.WithoutCancel(ctx), projectName, path)
		}
	}()
	if err = s.validate(operationContext, projectName, path); err != nil {
		return nil, err
	}
	runner, executable, err := s.executors.composeBinding()
	if err != nil {
		return nil, provideradapterapp.ErrRuntime
	}
	streaming, ok := runner.(argvprocess.StreamingRunner)
	if !ok {
		return nil, provideradapterapp.ErrRuntime
	}
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"--host", s.endpoint.String(), "--ansi", "never", "--progress", "quiet",
		"--project-name", projectName, "--file", path,
		"run", "--rm", "--no-deps", "-T", serviceName,
	})
	if err != nil {
		return nil, provideradapterapp.ErrRuntime
	}
	output := &boundedOperationWriter{maximum: maximumProviderOperationFrameBytes}
	streams, err := argvprocess.NewStreams(bytes.NewReader(request), output, io.Discard)
	if err != nil {
		return nil, provideradapterapp.ErrRuntime
	}
	runErr := streaming.RunStreaming(operationContext, invocation, streams)
	cleanupErr := s.cleanup(context.WithoutCancel(ctx), projectName, path)
	cleanupRequired = false
	if runErr != nil || cleanupErr != nil {
		return nil, errors.Join(provideradapterapp.ErrRuntime, runErr, cleanupErr)
	}
	if output.overflow || output.buffer.Len() < 5 {
		return nil, provideradapterapp.ErrRuntime
	}
	decodedResponse, err := providerprotocol.DecodeResponse(
		bytes.NewReader(output.buffer.Bytes()),
	)
	if err != nil ||
		providerprotocol.ValidateResponseFor(decodedRequest, decodedResponse) != nil {
		return nil, provideradapterapp.ErrRuntime
	}
	return bytes.Clone(output.buffer.Bytes()), nil
}

// Reconcile removes only orphaned operation containers belonging to an exact
// caller-authorized set of immutable adapter plans. It must run before the
// caller accepts new operations after a supervisor restart.
func (s *ProviderAdapterOperationSupervisor) Reconcile(
	ctx context.Context,
	plans []provideradapter.DeploymentPlan,
) error {
	if s == nil || ctx == nil || len(plans) == 0 || len(plans) > maximumProviderOrphans {
		return provideradapterapp.ErrRuntime
	}
	digests := make([]string, 0, len(plans))
	seen := make(map[string]struct{}, len(plans))
	for _, plan := range plans {
		if !plan.Valid() {
			return provideradapterapp.ErrRuntime
		}
		digest := plan.Digest().Hex()
		if _, duplicate := seen[digest]; duplicate {
			return provideradapterapp.ErrRuntime
		}
		seen[digest] = struct{}{}
		digests = append(digests, digest)
	}
	slices.Sort(digests)
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	for _, digest := range digests {
		containers, err := s.listOrphans(ctx, digest)
		if err != nil {
			return err
		}
		for _, containerID := range containers {
			if err := s.verifyAndRemoveOrphan(ctx, containerID, digest); err != nil {
				return err
			}
		}
		remaining, err := s.listOrphans(ctx, digest)
		if err != nil || len(remaining) != 0 {
			return provideradapterapp.ErrRuntime
		}
	}
	return nil
}

func (s *ProviderAdapterOperationSupervisor) begin(operationDigest string) bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if _, exists := s.active[operationDigest]; exists {
		return false
	}
	s.active[operationDigest] = struct{}{}
	return true
}

func (s *ProviderAdapterOperationSupervisor) end(operationDigest string) {
	s.activeMu.Lock()
	delete(s.active, operationDigest)
	s.activeMu.Unlock()
}

func (s *ProviderAdapterOperationSupervisor) listOrphans(
	ctx context.Context,
	planDigest string,
) ([]string, error) {
	result, err := s.runDocker(ctx, []string{
		"--host", s.endpoint.String(), "container", "ls", "--all", "--quiet", "--no-trunc",
		"--filter", "label=" + providerManagedLabel + "=true",
		"--filter", "label=" + providerKindLabel + "=" + providerAdapterKind,
		"--filter", "label=" + providerPlanDigestLabel + "=" + planDigest,
	})
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(string(result.StandardOutput))
	if len(ids) > maximumProviderOrphans {
		return nil, provideradapterapp.ErrRuntime
	}
	unique := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !lowerHexResourceID(id) {
			return nil, provideradapterapp.ErrRuntime
		}
		if _, duplicate := unique[id]; duplicate {
			return nil, provideradapterapp.ErrRuntime
		}
		unique[id] = struct{}{}
	}
	slices.Sort(ids)
	return ids, nil
}

type providerOrphanDocument struct {
	ID     string            `json:"ID"`
	Labels map[string]string `json:"Labels"`
}

func (s *ProviderAdapterOperationSupervisor) verifyAndRemoveOrphan(
	ctx context.Context,
	containerID string,
	planDigest string,
) error {
	result, err := s.runDocker(ctx, []string{
		"--host", s.endpoint.String(), "container", "inspect", "--format",
		`{"ID":{{json .Id}},"Labels":{{json .Config.Labels}}}`, "--", containerID,
	})
	if err != nil || rejectDuplicateJSONKeys(result.StandardOutput) != nil {
		return provideradapterapp.ErrRuntime
	}
	var document providerOrphanDocument
	if decodeStrictJSON(result.StandardOutput, &document) != nil ||
		document.ID != containerID ||
		document.Labels[providerManagedLabel] != "true" ||
		document.Labels[providerKindLabel] != providerAdapterKind ||
		document.Labels[providerPlanDigestLabel] != planDigest ||
		!lowerHexResourceID(document.Labels[providerOperationDigestLabel]) {
		return provideradapterapp.ErrRuntime
	}
	_, err = s.runDocker(ctx, []string{
		"--host", s.endpoint.String(), "container", "rm", "--force", "--", containerID,
	})
	return err
}

func (s *ProviderAdapterOperationSupervisor) runDocker(
	ctx context.Context,
	arguments []string,
) (argvprocess.Result, error) {
	runner, executable, err := s.executors.dockerBinding()
	if err != nil {
		return argvprocess.Result{}, provideradapterapp.ErrRuntime
	}
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		return argvprocess.Result{}, provideradapterapp.ErrRuntime
	}
	result, err := runner.Run(ctx, invocation)
	if err != nil || result.ExitCode != 0 || result.OutputTruncated ||
		len(result.StandardOutput) > maximumDockerJSON ||
		len(result.StandardError) > maximumDockerJSON {
		return argvprocess.Result{}, provideradapterapp.ErrRuntime
	}
	return result, nil
}

func (s *ProviderAdapterOperationSupervisor) validate(
	ctx context.Context,
	projectName string,
	path string,
) error {
	runner, executable, err := s.executors.composeBinding()
	if err != nil {
		return provideradapterapp.ErrRuntime
	}
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"--host", s.endpoint.String(), "--ansi", "never", "--progress", "quiet",
		"--project-name", projectName, "--file", path,
		"config", "--format", "json", "--no-env-resolution",
	})
	if err != nil {
		return provideradapterapp.ErrRuntime
	}
	result, err := runner.Run(ctx, invocation)
	if err != nil || result.ExitCode != 0 || result.OutputTruncated ||
		len(result.StandardOutput) > maximumDockerJSON ||
		len(result.StandardError) > maximumDockerJSON {
		return provideradapterapp.ErrRuntime
	}
	return nil
}

func (s *ProviderAdapterOperationSupervisor) cleanup(
	ctx context.Context,
	projectName string,
	path string,
) error {
	runner, executable, err := s.executors.composeBinding()
	if err != nil {
		return provideradapterapp.ErrRuntime
	}
	cleanupContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	invocation, err := argvprocess.NewInvocation(executable, []string{
		"--host", s.endpoint.String(), "--ansi", "never", "--progress", "quiet",
		"--project-name", projectName, "--file", path,
		"down", "--remove-orphans", "--timeout", "10",
	})
	if err != nil {
		return provideradapterapp.ErrRuntime
	}
	result, err := runner.Run(cleanupContext, invocation)
	if err != nil || result.ExitCode != 0 || result.OutputTruncated {
		return provideradapterapp.ErrRuntime
	}
	return nil
}

type boundedOperationWriter struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (w *boundedOperationWriter) Write(value []byte) (int, error) {
	if w.overflow || len(value) > w.maximum-w.buffer.Len() {
		w.overflow = true
		return len(value), nil
	}
	return w.buffer.Write(value)
}

var _ provideradapterapp.Runtime = (*ProviderAdapterRuntime)(nil)
