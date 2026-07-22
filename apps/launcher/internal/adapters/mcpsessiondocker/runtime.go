package mcpsessiondocker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const maximumComposeBytes = 1024 * 1024

var errInvalidRuntimeAuthority = errors.New("PF-005 runtime authority is invalid")

// CoreReadinessPort proves the authenticated Core contract after Compose reports healthy.
type CoreReadinessPort interface {
	Ready(context.Context) (bool, error)
}

// RuntimeActivatorPort starts or reattaches only the already owned, recorded local runtime.
// Implementations are platform-specific PF-006 adapters and may not choose another endpoint.
type RuntimeActivatorPort interface {
	EnsureEndpoint(context.Context, activerelease.Pointer) error
}

// ComposeProcessPort executes the independently release-verified Compose binary.
// Keeping it separate from DockerProcessPort prevents ambient CLI-plugin lookup.
type ComposeProcessPort interface {
	Capture(context.Context, []string) ([]byte, error)
}

// RuntimeAuthority is immutable release-derived input for one active pointer.
// Its paths and image are obtained from the authenticated install plan, never Docker discovery.
type RuntimeAuthority struct {
	pointer      activerelease.Pointer
	projectName  string
	projectDir   string
	composeFile  string
	emptyEnvFile string
	image        string
	network      string
}

// NewRuntimeAuthority binds exact Compose and session resources to an active pointer.
func NewRuntimeAuthority(
	pointer activerelease.Pointer,
	projectName string,
	projectDir string,
	composeFile string,
	emptyEnvFile string,
	image string,
	network string,
) (RuntimeAuthority, error) {
	wantedProject := "agentmemory_" + strings.ReplaceAll(pointer.InstallationID(), "-", "")
	if pointer.IsZero() || projectName != wantedProject || !safeDockerName(projectName) ||
		!absoluteCleanChild(projectDir, composeFile) || !absoluteCleanChild(projectDir, emptyEnvFile) ||
		composeFile == emptyEnvFile || !validRegularPath(projectDir) ||
		!mcpsession.ValidImageReference(image) || !safeDockerName(network) ||
		network != wantedProject+"_internal" {
		return RuntimeAuthority{}, errInvalidRuntimeAuthority
	}
	return RuntimeAuthority{
		pointer: pointer, projectName: projectName, projectDir: projectDir,
		composeFile: composeFile, emptyEnvFile: emptyEnvFile, image: image, network: network,
	}, nil
}

// RuntimeController starts and independently proves the exact active local release.
type RuntimeController struct {
	docker    DockerProcessPort
	compose   ComposeProcessPort
	readiness CoreReadinessPort
	activator RuntimeActivatorPort
	authority RuntimeAuthority
}

// NewRuntimeController refuses ambient Docker/context discovery and partial composition.
func NewRuntimeController(
	docker DockerProcessPort,
	compose ComposeProcessPort,
	readiness CoreReadinessPort,
	activator RuntimeActivatorPort,
	authority RuntimeAuthority,
) (*RuntimeController, error) {
	if nilCapability(docker) || nilCapability(compose) || nilCapability(readiness) ||
		nilCapability(activator) || authority.pointer.IsZero() {
		return nil, errInvalidRuntimeAuthority
	}
	return &RuntimeController{
		docker: docker, compose: compose, readiness: readiness, activator: activator, authority: authority,
	}, nil
}

// EnsureReady verifies the signed Compose bytes, starts the exact project through the
// recorded endpoint, and requires both Compose and authenticated Core readiness.
func (r *RuntimeController) EnsureReady(
	ctx context.Context,
	pointer activerelease.Pointer,
) (mcpsessionapp.SessionRelease, error) {
	if r == nil || ctx == nil || nilCapability(r.docker) || nilCapability(r.compose) ||
		nilCapability(r.readiness) ||
		nilCapability(r.activator) ||
		pointer.IsZero() || !pointer.Digest().Equal(r.authority.pointer.Digest()) {
		return mcpsessionapp.SessionRelease{}, errInvalidRuntimeAuthority
	}
	if err := ctx.Err(); err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	if err := verifyComposeDigest(r.authority.composeFile, pointer.ComposeDigest().String()); err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	if err := verifyEmptyEnvironment(r.authority.emptyEnvFile); err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	if err := r.activator.EnsureEndpoint(ctx, pointer); err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	version, err := r.docker.Capture(ctx, []string{
		"--host", pointer.RuntimeEndpoint(), "version", "--format", "{{json .Server.Version}}",
	})
	if err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	if !validDockerVersionResponse(version) {
		return mcpsessionapp.SessionRelease{}, errInvalidRuntimeAuthority
	}
	if _, err := r.compose.Capture(ctx, []string{
		"--host", pointer.RuntimeEndpoint(), "--ansi", "never", "--progress", "quiet",
		"--project-name", r.authority.projectName,
		"--project-directory", r.authority.projectDir,
		"--file", r.authority.composeFile,
		"--env-file", r.authority.emptyEnvFile,
		"up", "--detach", "--wait", "--wait-timeout", "120",
	}); err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	if err := r.inspectNetwork(ctx, pointer); err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	if err := r.inspectImage(ctx); err != nil {
		return mcpsessionapp.SessionRelease{}, err
	}
	ready, err := r.readiness.Ready(ctx)
	if err != nil || !ready {
		return mcpsessionapp.SessionRelease{}, errors.New("PF-005 Core readiness is unavailable")
	}
	return mcpsessionapp.NewSessionRelease(pointer, r.authority.image, r.authority.network)
}

func (r *RuntimeController) inspectNetwork(ctx context.Context, pointer activerelease.Pointer) error {
	payload, err := r.docker.Capture(ctx, []string{
		"--host", pointer.RuntimeEndpoint(), "network", "inspect", r.authority.network,
	})
	if err != nil || len(payload) == 0 || len(payload) > maximumInspectBytes {
		return errInvalidRuntimeAuthority
	}
	var records []struct {
		Name     string            `json:"Name"`
		Internal bool              `json:"Internal"`
		Labels   map[string]string `json:"Labels"`
	}
	if decodeExactJSON(payload, &records) != nil || len(records) != 1 ||
		records[0].Name != r.authority.network || !records[0].Internal {
		return errInvalidRuntimeAuthority
	}
	expected := map[string]string{
		"io.agentmemory.installation": pointer.InstallationID(),
		"io.agentmemory.release":      pointer.ReleaseID(),
		"io.agentmemory.generation":   pointer.GenerationID(),
		"io.agentmemory.purpose":      "internal",
		"io.agentmemory.managed":      "true",
	}
	if !validExactAgentMemoryLabels(records[0].Labels, expected) {
		return errInvalidRuntimeAuthority
	}
	return nil
}

func (r *RuntimeController) inspectImage(ctx context.Context) error {
	payload, err := r.docker.Capture(ctx, []string{
		"--host", r.authority.pointer.RuntimeEndpoint(), "image", "inspect", r.authority.image,
	})
	if err != nil || len(payload) == 0 || len(payload) > maximumInspectBytes {
		return errInvalidRuntimeAuthority
	}
	var records []struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	if decodeExactJSON(payload, &records) != nil || len(records) != 1 ||
		!slices.Contains(records[0].RepoDigests, r.authority.image) {
		return errInvalidRuntimeAuthority
	}
	return nil
}

func verifyComposeDigest(path string, expected string) error {
	file, err := os.Open(path) // #nosec G304 -- exact signed-plan path validated at construction.
	if err != nil {
		return errInvalidRuntimeAuthority
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumComposeBytes {
		return errInvalidRuntimeAuthority
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumComposeBytes+1)); err != nil ||
		!strings.EqualFold(expected, strings.ToLower(stringHex(hash.Sum(nil)))) {
		return errInvalidRuntimeAuthority
	}
	return nil
}

func verifyEmptyEnvironment(path string) error {
	file, err := os.Open(path) // #nosec G304 -- exact signed-plan path validated at construction.
	if err != nil {
		return errInvalidRuntimeAuthority
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return errInvalidRuntimeAuthority
	}
	return nil
}

func validDockerVersionResponse(payload []byte) bool {
	if len(payload) < 3 || len(payload) > 130 {
		return false
	}
	var version string
	if decodeExactJSON(payload, &version) != nil || version == "" || len(version) > 128 {
		return false
	}
	for _, character := range version {
		if (character >= '0' && character <= '9') || character == '.' || character == '-' ||
			(character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') {
			continue
		}
		return false
	}
	return true
}

func decodeExactJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidRuntimeAuthority
	}
	return nil
}

func validExactAgentMemoryLabels(actual, expected map[string]string) bool {
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

func absoluteCleanChild(parent, child string) bool {
	if !filepath.IsAbs(parent) || !filepath.IsAbs(child) || filepath.Clean(parent) != parent ||
		filepath.Clean(child) != child {
		return false
	}
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validRegularPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func safeDockerName(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '_' || character == '-' || character == '.')) {
			continue
		}
		return false
	}
	return true
}

func stringHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&0x0f]
	}
	return string(result)
}

var _ mcpsessionapp.RuntimeController = (*RuntimeController)(nil)
