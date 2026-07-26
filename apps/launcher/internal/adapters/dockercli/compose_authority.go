package dockercli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// DeriveReleaseProject verifies an exact signed Compose source, asks the
// release-bound Compose executable for its normalized JSON, derives the closed
// semantic policy plan, and returns the sole project authority accepted by
// mutating stack operations. No caller can supply a plan or normalized digest.
func (c *Compose) DeriveReleaseProject(
	ctx context.Context,
	source containerengine.ComposeReleaseSource,
) (containerengine.ComposeProject, containerengine.RenderedConfiguration, error) {
	if c == nil || ctx == nil {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{},
			errors.Join(containerengine.ErrComposeOperation, context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{},
			errors.Join(containerengine.ErrComposeOperation, err)
	}
	before, err := snapshotReleaseSource(source)
	if err != nil {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{}, err
	}
	result, err := c.renderReleaseSource(ctx, source)
	if err != nil {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{}, err
	}
	canonical := bytes.TrimSpace(result.StandardOutput)
	if len(canonical) == 0 || len(canonical) > maximumDockerJSON {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{},
			containerengine.ErrComposeConfigurationMismatch
	}
	model, err := decodeRenderedPolicy(canonical, source.Identity().ProjectName())
	if err != nil || model.Identity.InstallationID() != source.Identity().InstallationID() ||
		model.Identity.Generation() != source.Identity().Generation() || model.Release != source.Release() ||
		!validPolicyModel(model) {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{},
			containerengine.ErrComposeConfigurationMismatch
	}
	plan, err := composeplan.NewPolicyPlan(model)
	if err != nil {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{},
			containerengine.ErrComposeConfigurationMismatch
	}
	rendered, err := containerengine.NewRenderedConfiguration(canonical)
	if err != nil {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{}, err
	}
	project, err := containerengine.NewComposeProject(
		source.Endpoint(), source.Identity().ProjectName(), source.ProjectDirectory(),
		source.ConfigurationPath(), source.EmptyEnvironmentPath(), rendered.Digest(), plan,
		source.WaitTimeSeconds(),
	)
	if err != nil || validateRenderedFiles(project, model) != nil {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{},
			containerengine.ErrInvalidComposeProject
	}
	secretSnapshots, err := snapshotPolicySecrets(ctx, project)
	zeroPrivateSnapshots(secretSnapshots)
	if err != nil || !sameReleaseSource(source, before) {
		return containerengine.ComposeProject{}, containerengine.RenderedConfiguration{},
			containerengine.ErrInvalidComposeProject
	}
	return project, rendered, nil
}

func validPolicyModel(model composeplan.Model) bool {
	plan, err := composeplan.NewPolicyPlan(model)
	return err == nil && plan.Valid()
}

// RunReleaseMigrations derives all execution authority from the signed source
// and binds the resulting normalized render directly to the one-shot migrate
// mutation. A failed derivation cannot reach the mutation boundary.
func (c *Compose) RunReleaseMigrations(
	ctx context.Context,
	source containerengine.ComposeReleaseSource,
) (containerengine.RenderedConfiguration, error) {
	project, rendered, err := c.DeriveReleaseProject(ctx, source)
	if err != nil {
		return containerengine.RenderedConfiguration{}, err
	}
	if err := c.RunMigrations(ctx, project); err != nil {
		return containerengine.RenderedConfiguration{}, err
	}
	return rendered, nil
}

// StartReleaseAndWait derives all execution authority from the signed source,
// starts only the exact production profile, and returns the normalized render
// that was reverified at the side-effect boundary.
func (c *Compose) StartReleaseAndWait(
	ctx context.Context,
	source containerengine.ComposeReleaseSource,
) (containerengine.RenderedConfiguration, error) {
	project, rendered, err := c.DeriveReleaseProject(ctx, source)
	if err != nil {
		return containerengine.RenderedConfiguration{}, err
	}
	if err := c.StartAndWait(ctx, project); err != nil {
		return containerengine.RenderedConfiguration{}, err
	}
	return rendered, nil
}

func (c *Compose) renderReleaseSource(
	ctx context.Context,
	source containerengine.ComposeReleaseSource,
) (argvprocess.Result, error) {
	runner, executable, err := c.executors.composeBinding()
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrComposeOperation
	}
	arguments := []string{
		"--host", source.Endpoint().String(),
		"--ansi", "never",
		"--progress", "quiet",
		"--project-name", source.Identity().ProjectName(),
		"--project-directory", source.ProjectDirectory(),
		"--env-file", source.EmptyEnvironmentPath(),
		"--file", source.ConfigurationPath(),
		"config", "--format", "json", "--no-env-resolution",
	}
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrComposeOperation
	}
	return c.runInvocation(ctx, runner, invocation)
}

type releaseSourceSnapshot struct {
	configuration os.FileInfo
	environment   os.FileInfo
	configToken   string
	envToken      string
	digest        releaseinventory.Digest
}

func snapshotReleaseSource(source containerengine.ComposeReleaseSource) (releaseSourceSnapshot, error) {
	directory := source.ProjectDirectory()
	configuration := source.ConfigurationPath()
	environment := source.EmptyEnvironmentPath()
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		!filepath.IsAbs(configuration) || filepath.Clean(configuration) != configuration ||
		!filepath.IsAbs(environment) || filepath.Clean(environment) != environment ||
		exactNonSymlink(directory, true) != nil || !privateComposePath(directory, true) ||
		!pathWithin(directory, configuration) || !pathWithin(directory, environment) ||
		exactNonSymlink(configuration, false) != nil || exactNonSymlink(environment, false) != nil {
		return releaseSourceSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	configurationInfo, configurationError := os.Lstat(configuration)
	environmentInfo, environmentError := os.Lstat(environment)
	contents, readError := os.ReadFile(configuration) //nolint:gosec // G304: exact absolute owner-controlled path was validated above.
	digest := releaseinventory.DigestBytes(contents)
	configToken, configTokenValid := composeNativeIdentity(configurationInfo)
	envToken, envTokenValid := composeNativeIdentity(environmentInfo)
	if configurationError != nil || environmentError != nil || readError != nil ||
		!configTokenValid || !envTokenValid ||
		configurationInfo.Size() <= 0 || configurationInfo.Size() > maximumDockerJSON ||
		environmentInfo.Size() != 0 || !privateComposePath(configuration, false) ||
		!privateComposePath(environment, false) || !digest.Equal(source.SourceDigest()) {
		return releaseSourceSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	return releaseSourceSnapshot{
		configuration: configurationInfo, environment: environmentInfo,
		configToken: configToken, envToken: envToken, digest: digest,
	}, nil
}

func sameReleaseSource(source containerengine.ComposeReleaseSource, before releaseSourceSnapshot) bool {
	after, err := snapshotReleaseSource(source)
	return err == nil && before.configuration != nil && before.environment != nil &&
		os.SameFile(before.configuration, after.configuration) &&
		os.SameFile(before.environment, after.environment) && before.configToken == after.configToken &&
		before.envToken == after.envToken && before.digest.Equal(after.digest)
}

var _ containerengine.ReleaseComposePort = (*Compose)(nil)
