package containerengine

import (
	"context"
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	composeProjectPrefix = "agentmemory_"
	maximumComposePath   = 4096
)

var (
	// ErrInvalidComposeProject rejects ambiguous or caller-controlled Compose
	// addressing before a Docker command is built.
	ErrInvalidComposeProject = errors.New("invalid AgentMemory Compose project")
	// ErrComposeConfigurationMismatch means Docker rendered bytes that do not
	// match the release-bound normalized configuration.
	ErrComposeConfigurationMismatch = errors.New("rendered Compose configuration digest mismatch")
	// ErrComposeOperation means a bounded, explicitly addressed Compose command
	// failed. Adapters must not expose its raw stderr across the application boundary.
	ErrComposeOperation = errors.New("AgentMemory Compose operation failed")
)

// ComposeProject is the complete immutable addressing contract for one
// release-bound AgentMemory Compose project. No ambient Docker context,
// working directory, environment, or .env discovery is permitted.
type ComposeProject struct {
	endpoint        Endpoint
	name            string
	projectDir      string
	configPath      string
	emptyEnvPath    string
	expectedConfig  releaseinventory.Digest
	expectedPlan    composeplan.PolicyPlan
	waitTimeSeconds uint16
}

// ComposeReleaseSource is the immutable signed-artifact authority from which
// the Docker adapter may derive a normalized PolicyPlan and ComposeProject.
// The source digest is the release-manifest binding over the exact on-disk
// Compose document, not the later `compose config` digest.
type ComposeReleaseSource struct {
	endpoint       Endpoint
	identity       composeplan.Identity
	release        string
	projectDir     string
	configPath     string
	emptyEnvPath   string
	sourceDigest   releaseinventory.Digest
	waitTimeSecond uint16
}

// NewComposeReleaseSource validates the non-ambient signed source address.
func NewComposeReleaseSource(
	endpoint Endpoint,
	identity composeplan.Identity,
	release string,
	projectDirectory string,
	configurationPath string,
	emptyEnvironmentPath string,
	sourceDigest releaseinventory.Digest,
	waitTimeSeconds uint16,
) (ComposeReleaseSource, error) {
	if endpoint.String() == "" || !validComposeProjectName(identity.ProjectName()) ||
		!validReleaseToken(release) || !validOpaquePath(projectDirectory) ||
		!validOpaquePath(configurationPath) || !validOpaquePath(emptyEnvironmentPath) ||
		configurationPath == emptyEnvironmentPath || sourceDigest.IsZero() ||
		waitTimeSeconds == 0 || waitTimeSeconds > 300 {
		return ComposeReleaseSource{}, ErrInvalidComposeProject
	}
	return ComposeReleaseSource{
		endpoint: endpoint, identity: identity, release: release,
		projectDir: projectDirectory, configPath: configurationPath,
		emptyEnvPath: emptyEnvironmentPath, sourceDigest: sourceDigest,
		waitTimeSecond: waitTimeSeconds,
	}, nil
}

func validReleaseToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '-' || character == '_')) {
			continue
		}
		return false
	}
	return true
}

// Endpoint returns the verified local daemon endpoint.
func (s ComposeReleaseSource) Endpoint() Endpoint { return s.endpoint }

// Identity returns the validated installation/generation identity.
func (s ComposeReleaseSource) Identity() composeplan.Identity { return s.identity }

// Release returns the signed release identity.
func (s ComposeReleaseSource) Release() string { return s.release }

// ProjectDirectory returns the owner-controlled release directory.
func (s ComposeReleaseSource) ProjectDirectory() string { return s.projectDir }

// ConfigurationPath returns the exact signed Compose artifact path.
func (s ComposeReleaseSource) ConfigurationPath() string { return s.configPath }

// EmptyEnvironmentPath returns the exact empty environment-file path.
func (s ComposeReleaseSource) EmptyEnvironmentPath() string { return s.emptyEnvPath }

// SourceDigest returns the signed digest over ConfigurationPath bytes.
func (s ComposeReleaseSource) SourceDigest() releaseinventory.Digest { return s.sourceDigest }

// WaitTimeSeconds returns the bounded first-start health deadline.
func (s ComposeReleaseSource) WaitTimeSeconds() uint16 { return s.waitTimeSecond }

// NewComposeProject accepts only ADR-017's fixed project namespace and a
// release-bound rendered configuration digest. Concrete adapters additionally
// prove that all paths are absolute, regular, non-symlink files inside the
// managed project directory.
func NewComposeProject(
	endpoint Endpoint,
	name string,
	projectDirectory string,
	configurationPath string,
	emptyEnvironmentPath string,
	expectedConfiguration releaseinventory.Digest,
	expectedPlan composeplan.PolicyPlan,
	waitTimeSeconds uint16,
) (ComposeProject, error) {
	if endpoint.String() == "" || !validComposeProjectName(name) ||
		!validOpaquePath(projectDirectory) || !validOpaquePath(configurationPath) ||
		!validOpaquePath(emptyEnvironmentPath) || configurationPath == emptyEnvironmentPath ||
		expectedConfiguration.IsZero() || !expectedPlan.Valid() || waitTimeSeconds == 0 || waitTimeSeconds > 300 {
		return ComposeProject{}, ErrInvalidComposeProject
	}
	return ComposeProject{
		endpoint:        endpoint,
		name:            name,
		projectDir:      projectDirectory,
		configPath:      configurationPath,
		emptyEnvPath:    emptyEnvironmentPath,
		expectedConfig:  expectedConfiguration,
		expectedPlan:    expectedPlan,
		waitTimeSeconds: waitTimeSeconds,
	}, nil
}

// ExpectedPolicyPlan returns the immutable authenticated release-topology
// projection that every rendered configuration must match semantically.
func (p ComposeProject) ExpectedPolicyPlan() composeplan.PolicyPlan { return p.expectedPlan }

func validComposeProjectName(value string) bool {
	if len(value) != len(composeProjectPrefix)+32 || !strings.HasPrefix(value, composeProjectPrefix) {
		return false
	}
	for _, character := range strings.TrimPrefix(value, composeProjectPrefix) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validOpaquePath(value string) bool {
	return value != "" && len(value) <= maximumComposePath &&
		!strings.ContainsAny(value, "\x00\r\n") && value == strings.TrimSpace(value)
}

// Endpoint returns the exact local daemon endpoint.
func (p ComposeProject) Endpoint() Endpoint { return p.endpoint }

// Name returns the fixed installation-derived Compose project name.
func (p ComposeProject) Name() string { return p.name }

// ProjectDirectory returns the managed path used for Compose path resolution.
func (p ComposeProject) ProjectDirectory() string { return p.projectDir }

// ConfigurationPath returns the verified Compose configuration path.
func (p ComposeProject) ConfigurationPath() string { return p.configPath }

// EmptyEnvironmentPath returns the verified empty file that suppresses
// implicit host .env discovery.
func (p ComposeProject) EmptyEnvironmentPath() string { return p.emptyEnvPath }

// ExpectedConfigurationDigest returns the release-bound render digest.
func (p ComposeProject) ExpectedConfigurationDigest() releaseinventory.Digest {
	return p.expectedConfig
}

// WaitTimeSeconds returns the bounded first-start health deadline.
func (p ComposeProject) WaitTimeSeconds() uint16 { return p.waitTimeSeconds }

// RenderedConfiguration is the bounded normalized Compose JSON consumed by
// the inward topology policy before any side effect is authorized.
type RenderedConfiguration struct {
	canonical []byte
	digest    releaseinventory.Digest
}

// NewRenderedConfiguration copies a verified non-empty render.
func NewRenderedConfiguration(canonical []byte) (RenderedConfiguration, error) {
	if len(canonical) == 0 {
		return RenderedConfiguration{}, ErrComposeConfigurationMismatch
	}
	copyOfCanonical := append([]byte(nil), canonical...)
	return RenderedConfiguration{
		canonical: copyOfCanonical,
		digest:    releaseinventory.DigestBytes(copyOfCanonical),
	}, nil
}

// CanonicalBytes returns a caller-owned copy for strict topology decoding.
func (c RenderedConfiguration) CanonicalBytes() []byte {
	return append([]byte(nil), c.canonical...)
}

// Digest returns the exact normalized render binding.
func (c RenderedConfiguration) Digest() releaseinventory.Digest { return c.digest }

// ComposePort is the narrow unprivileged container-stack boundary used by
// PF-001. VerifyConfiguration performs no mutation. The other methods must
// reverify and bind the authenticated render directly to their exact side
// effect without rereading a mutable Compose source.
type ComposePort interface {
	VerifyConfiguration(context.Context, ComposeProject) (RenderedConfiguration, error)
	RunMigrations(context.Context, ComposeProject) error
	StartAndWait(context.Context, ComposeProject) error
}

// ReleaseComposePort is the production mutation boundary. It accepts only the
// signed source authority, derives the normalized semantic project internally,
// and binds that exact render directly to the requested side effect. Callers
// cannot inject a ComposeProject, PolicyPlan, or expected render digest.
type ReleaseComposePort interface {
	RunReleaseMigrations(context.Context, ComposeReleaseSource) (RenderedConfiguration, error)
	StartReleaseAndWait(context.Context, ComposeReleaseSource) (RenderedConfiguration, error)
}
