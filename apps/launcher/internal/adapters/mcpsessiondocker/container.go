// Package mcpsessiondocker executes one release-bound PF-005 MCP session container.
package mcpsessiondocker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const (
	maximumInspectBytes = 1024 * 1024
	containerIDLength   = 64
	containerUser       = "10001:10001"
	containerWorkdir    = "/workspace"
	temporaryMount      = "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=10001,gid=10001"
)

var (
	// ErrContainerNotFound lets the process adapter classify Docker's exact not-found exit.
	ErrContainerNotFound = errors.New("PF-005 session container was not found")
	errInvalidContainer  = errors.New("PF-005 session container authority is invalid")
)

// DockerProcessPort executes the already release-verified Docker CLI without a shell.
type DockerProcessPort interface {
	Capture(context.Context, []string) ([]byte, error)
	Stream(context.Context, []string, mcpsessionapp.Streams) error
}

// Container creates, independently inspects, and attaches one transient MCP container.
type Container struct{ process DockerProcessPort }

// NewContainer rejects partial composition before Docker can observe a side effect.
func NewContainer(process DockerProcessPort) (*Container, error) {
	if nilCapability(process) {
		return nil, errInvalidContainer
	}
	return &Container{process: process}, nil
}

// Run creates the exact sandbox, verifies Docker's materialized configuration, then attaches it.
func (c *Container) Run(
	ctx context.Context,
	plan mcpsession.ExecutionPlan,
	streams mcpsessionapp.Streams,
) error {
	if c == nil || nilCapability(c.process) || ctx == nil || !plan.Valid() ||
		!streamsAreValid(streams) || !safeMountSource(plan.WorkspaceMount().Source()) ||
		!safeMountSource(plan.CredentialMount().Source()) {
		return errInvalidContainer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	created, err := c.process.Capture(ctx, createArguments(plan))
	if err != nil {
		return err
	}
	containerID, err := parseContainerID(created)
	if err != nil {
		return err
	}
	inspection, err := c.process.Capture(ctx, []string{
		"--host", plan.RuntimeEndpoint(), "container", "inspect", "--type", "container",
		containerName(plan),
	})
	if err != nil {
		return err
	}
	if err := validateInspection(inspection, containerID, plan); err != nil {
		return err
	}
	return c.process.Stream(ctx, []string{
		"--host", plan.RuntimeEndpoint(), "container", "start", "--attach", "--interactive",
		containerName(plan),
	}, streams)
}

// Remove force-removes only the deterministic container owned by the supplied immutable plan.
func (c *Container) Remove(ctx context.Context, plan mcpsession.ExecutionPlan) error {
	if c == nil || nilCapability(c.process) || ctx == nil || !plan.Valid() {
		return errInvalidContainer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := c.process.Capture(ctx, []string{
		"--host", plan.RuntimeEndpoint(), "container", "rm", "--force", "--volumes",
		containerName(plan),
	})
	if errors.Is(err, ErrContainerNotFound) {
		return nil
	}
	return err
}

func createArguments(plan mcpsession.ExecutionPlan) []string {
	security := plan.Security()
	arguments := []string{
		"--host", plan.RuntimeEndpoint(), "container", "create", "--name", containerName(plan),
		"--rm", "--pull", "never", "--interactive", "--attach", "stdin", "--attach", "stdout",
		"--attach", "stderr", "--init", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--pids-limit",
		strconv.FormatInt(security.PIDsLimit(), 10), "--memory",
		strconv.FormatInt(security.MemoryBytes(), 10), "--memory-swap",
		strconv.FormatInt(security.MemoryBytes(), 10), "--cpus", "1.000", "--network", plan.Network(),
		"--log-driver", "none", "--user", containerUser, "--workdir", containerWorkdir,
		"--tmpfs", temporaryMount,
		"--mount", mountArgument(plan.WorkspaceMount()),
		"--mount", mountArgument(plan.CredentialMount()),
	}
	labels := expectedLabels(plan)
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		arguments = append(arguments, "--label", key+"="+labels[key])
	}
	return append(arguments, plan.Image(), "--session-id", plan.SessionID())
}

func mountArgument(mount mcpsession.Mount) string {
	value := "type=bind," + mountCSVField("source", mount.Source()) +
		"," + mountCSVField("target", mount.Target())
	if mount.ReadOnly() {
		value += ",readonly"
	}
	if mount.Propagation() != "" {
		value += ",bind-propagation=" + mount.Propagation()
	}
	if mount.RecursiveReadOnly() {
		value += ",bind-recursive=readonly"
	}
	return value
}

func mountCSVField(key, value string) string {
	field := key + "=" + value
	if strings.ContainsAny(field, ",\"") {
		return `"` + strings.ReplaceAll(field, `"`, `""`) + `"`
	}
	return field
}

func containerName(plan mcpsession.ExecutionPlan) string {
	return "agentmemory-session-" + strings.ReplaceAll(plan.SessionID(), "-", "")
}

func expectedLabels(plan mcpsession.ExecutionPlan) map[string]string {
	return map[string]string{
		"io.agentmemory.agent":          plan.AgentID(),
		"io.agentmemory.installation":   plan.InstallationID(),
		"io.agentmemory.managed":        "true",
		"io.agentmemory.manifest":       plan.ManifestDigest(),
		"io.agentmemory.release":        plan.ReleaseID(),
		"io.agentmemory.role":           "mcp-session",
		"io.agentmemory.security-epoch": strconv.FormatUint(plan.SecurityEpoch(), 10),
		"io.agentmemory.session":        plan.SessionID(),
	}
}

type inspectRecord struct {
	ID         string            `json:"Id"`
	Name       string            `json:"Name"`
	Config     inspectConfig     `json:"Config"`
	HostConfig inspectHostConfig `json:"HostConfig"`
	Mounts     []inspectMount    `json:"Mounts"`
}

type inspectConfig struct {
	Image        string            `json:"Image"`
	User         string            `json:"User"`
	WorkingDir   string            `json:"WorkingDir"`
	Tty          bool              `json:"Tty"`
	OpenStdin    bool              `json:"OpenStdin"`
	AttachStdin  bool              `json:"AttachStdin"`
	AttachStdout bool              `json:"AttachStdout"`
	AttachStderr bool              `json:"AttachStderr"`
	Labels       map[string]string `json:"Labels"`
	Cmd          []string          `json:"Cmd"`
}

type inspectHostConfig struct {
	AutoRemove     bool                       `json:"AutoRemove"`
	ReadonlyRootfs bool                       `json:"ReadonlyRootfs"`
	Privileged     bool                       `json:"Privileged"`
	CapAdd         []string                   `json:"CapAdd"`
	CapDrop        []string                   `json:"CapDrop"`
	SecurityOpt    []string                   `json:"SecurityOpt"`
	NetworkMode    string                     `json:"NetworkMode"`
	PidsLimit      int64                      `json:"PidsLimit"`
	Memory         int64                      `json:"Memory"`
	MemorySwap     int64                      `json:"MemorySwap"`
	NanoCPUs       int64                      `json:"NanoCpus"`
	PortBindings   map[string]json.RawMessage `json:"PortBindings"`
	Binds          []string                   `json:"Binds"`
	Devices        []json.RawMessage          `json:"Devices"`
	Tmpfs          map[string]string          `json:"Tmpfs"`
}

type inspectMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
	Propagation string `json:"Propagation"`
}

func parseContainerID(output []byte) (string, error) {
	if len(output) < containerIDLength || len(output) > containerIDLength+2 || !utf8.Valid(output) {
		return "", errInvalidContainer
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r")
	if len(value) != containerIDLength || !lowerHex(value) {
		return "", errInvalidContainer
	}
	return value, nil
}

func validateInspection(
	document []byte,
	containerID string,
	plan mcpsession.ExecutionPlan,
) error {
	if len(document) == 0 || len(document) > maximumInspectBytes || !utf8.Valid(document) {
		return errInvalidContainer
	}
	var records []inspectRecord
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	if err := decoder.Decode(&records); err != nil || len(records) != 1 {
		return errInvalidContainer
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidContainer
	}
	record := records[0]
	security := plan.Security()
	if record.ID != containerID || record.Name != "/"+containerName(plan) ||
		record.Config.Image != plan.Image() || record.Config.User != containerUser ||
		record.Config.WorkingDir != containerWorkdir || record.Config.Tty ||
		!record.Config.OpenStdin || !record.Config.AttachStdin || !record.Config.AttachStdout ||
		!record.Config.AttachStderr ||
		!slices.Equal(record.Config.Cmd, []string{"--session-id", plan.SessionID()}) ||
		!validLabels(record.Config.Labels, expectedLabels(plan)) ||
		!record.HostConfig.AutoRemove || !record.HostConfig.ReadonlyRootfs ||
		record.HostConfig.Privileged || len(record.HostConfig.CapAdd) != 0 ||
		!slices.Equal(record.HostConfig.CapDrop, []string{"ALL"}) ||
		!slices.Equal(record.HostConfig.SecurityOpt, []string{"no-new-privileges:true"}) ||
		record.HostConfig.NetworkMode != plan.Network() ||
		record.HostConfig.PidsLimit != security.PIDsLimit() ||
		record.HostConfig.Memory != security.MemoryBytes() ||
		record.HostConfig.MemorySwap != security.MemoryBytes() ||
		record.HostConfig.NanoCPUs != security.NanoCPUs() ||
		len(record.HostConfig.PortBindings) != 0 || len(record.HostConfig.Binds) != 0 ||
		len(record.HostConfig.Devices) != 0 ||
		!reflect.DeepEqual(record.HostConfig.Tmpfs, map[string]string{"/tmp": strings.TrimPrefix(temporaryMount, "/tmp:")}) ||
		!validMounts(record.Mounts, plan) {
		return errInvalidContainer
	}
	return nil
}

func validLabels(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	for key := range actual {
		if strings.HasPrefix(key, "io.agentmemory.") {
			if _, exists := expected[key]; !exists {
				return false
			}
		}
	}
	return true
}

func validMounts(actual []inspectMount, plan mcpsession.ExecutionPlan) bool {
	if len(actual) != 2 {
		return false
	}
	expected := map[string]mcpsession.Mount{
		plan.WorkspaceMount().Target():  plan.WorkspaceMount(),
		plan.CredentialMount().Target(): plan.CredentialMount(),
	}
	for _, observed := range actual {
		wanted, exists := expected[observed.Destination]
		if !exists || observed.Type != "bind" || observed.Source != wanted.Source() || observed.RW ||
			observed.Propagation != "rprivate" {
			return false
		}
		delete(expected, observed.Destination)
	}
	return len(expected) == 0
}

func safeMountSource(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\x00\r\n")
}

func streamsAreValid(streams mcpsessionapp.Streams) bool {
	return !nilCapability(streams.Input) && !nilCapability(streams.Output) &&
		!nilCapability(streams.Diagnostics)
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable concrete values are valid capabilities.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

func lowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
