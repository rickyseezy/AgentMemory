package dockercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

// Compose executes only the three exact PF-001 stack operations. It does not
// expose a generic Docker or Compose command surface.
type Compose struct {
	executors Executors
}

type verifiedComposeConfiguration struct {
	rendered containerengine.RenderedConfiguration
	secrets  map[string]privateComposeFileSnapshot
}

// NewCompose constructs an exact-argv Compose adapter.
func NewCompose(executors Executors) (*Compose, error) {
	if !executors.valid() {
		return nil, errInvalidExecutors
	}
	return &Compose{executors: executors}, nil
}

// VerifyConfiguration asks Compose to render its actual normalized model with
// the explicit empty environment file and managed project directory, then
// compares the bounded bytes with the signed release binding. It snapshots the
// authenticated installation-key file before Docker runs and proves the same
// file identity and bytes afterward. Service env-file contents are deliberately
// not expanded into diagnostic output.
func (c *Compose) VerifyConfiguration(
	ctx context.Context,
	project containerengine.ComposeProject,
) (containerengine.RenderedConfiguration, error) {
	verified, err := c.verifyConfiguration(ctx, project)
	if err != nil {
		return containerengine.RenderedConfiguration{}, err
	}
	zeroPrivateSnapshots(verified.secrets)
	return verified.rendered, nil
}

func (c *Compose) verifyConfiguration(
	ctx context.Context,
	project containerengine.ComposeProject,
) (verifiedComposeConfiguration, error) {
	if ctx == nil {
		return verifiedComposeConfiguration{}, errors.Join(containerengine.ErrComposeOperation, context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return verifiedComposeConfiguration{}, errors.Join(containerengine.ErrComposeOperation, err)
	}
	before, err := snapshotComposeFiles(project)
	if err != nil {
		return verifiedComposeConfiguration{}, err
	}
	secretBefore, err := snapshotPolicySecrets(ctx, project)
	if err != nil {
		return verifiedComposeConfiguration{}, containerengine.ErrInvalidComposeProject
	}
	preserveSecret := false
	defer func() {
		if !preserveSecret {
			zeroPrivateSnapshots(secretBefore)
		}
	}()
	result, err := c.run(ctx, project, []string{
		"config",
		"--format", "json",
		"--no-env-resolution",
	})
	if err != nil {
		return verifiedComposeConfiguration{}, err
	}
	canonical := bytes.TrimSpace(result.StandardOutput)
	if len(canonical) == 0 || len(canonical) > maximumDockerJSON {
		return verifiedComposeConfiguration{}, containerengine.ErrComposeConfigurationMismatch
	}
	rendered, err := containerengine.NewRenderedConfiguration(canonical)
	if err != nil || !rendered.Digest().Equal(project.ExpectedConfigurationDigest()) {
		return verifiedComposeConfiguration{}, containerengine.ErrComposeConfigurationMismatch
	}
	model, err := decodeRenderedPolicy(canonical, project.Name())
	if err != nil || len(composeplan.NewPolicy().Validate(model)) != 0 ||
		!project.ExpectedPolicyPlan().Matches(model) {
		return verifiedComposeConfiguration{}, containerengine.ErrComposeConfigurationMismatch
	}
	if err := validateRenderedFiles(project, model); err != nil {
		return verifiedComposeConfiguration{}, err
	}
	secretAfter, err := snapshotPolicySecrets(ctx, project)
	defer zeroPrivateSnapshots(secretAfter)
	if err != nil || !samePrivateSnapshots(secretBefore, secretAfter) {
		return verifiedComposeConfiguration{}, containerengine.ErrInvalidComposeProject
	}
	if !sameComposeFiles(project, before) {
		return verifiedComposeConfiguration{}, containerengine.ErrInvalidComposeProject
	}
	preserveSecret = true
	return verifiedComposeConfiguration{rendered: rendered, secrets: secretBefore}, nil
}

// RunMigrations revalidates the render immediately before executing only the
// signed one-shot migrate service. Pulling, building, TTY, and service stdin
// are explicitly disabled; process stdin carries only the authenticated
// Compose document. The signed dependency graph remains enabled because a
// pristine installation must start and health-gate Neo4j before graph
// migrations connect to it. Policy validation proves that migrate has exactly
// one dependency: the release-bound Neo4j service.
func (c *Compose) RunMigrations(ctx context.Context, project containerengine.ComposeProject) error {
	verified, err := c.verifyConfiguration(ctx, project)
	if err != nil {
		return err
	}
	execution, err := prepareBoundComposeExecution(
		ctx, project, verified.rendered.CanonicalBytes(), snapshotContents(verified.secrets),
	)
	zeroPrivateSnapshots(verified.secrets)
	verified.secrets = nil
	if err != nil {
		return err
	}
	err = c.runProjectedBound(ctx, project, execution, []string{
		"up",
		"--detach",
		"--wait",
		"--wait-timeout", strconv.FormatUint(uint64(project.WaitTimeSeconds()), 10),
		"--pull", "never",
		"--no-build",
		"neo4j",
	}, []string{
		"run",
		"--rm",
		"--no-deps",
		"--pull", "never",
		"--no-TTY",
		"--interactive=false",
		"migrate",
	})
	return err
}

// StartAndWait revalidates the render and starts the exact signed persistent
// profile without builds or pulls. Compose health is necessary but not PF-001
// readiness; the independent readiness adapter must still pass.
func (c *Compose) StartAndWait(ctx context.Context, project containerengine.ComposeProject) error {
	verified, err := c.verifyConfiguration(ctx, project)
	if err != nil {
		return err
	}
	execution, err := prepareBoundComposeExecution(
		ctx, project, verified.rendered.CanonicalBytes(), snapshotContents(verified.secrets),
	)
	zeroPrivateSnapshots(verified.secrets)
	verified.secrets = nil
	if err != nil {
		return err
	}
	err = c.runProjectedBound(ctx, project, execution, []string{
		"up",
		"--detach",
		"--wait",
		"--wait-timeout", strconv.FormatUint(uint64(project.WaitTimeSeconds()), 10),
		"--pull", "never",
		"--no-build",
		"core",
		"neo4j",
		"local-embedding",
		"local-reranker",
		"local-extractor",
	})
	return err
}

func (c *Compose) run(
	ctx context.Context,
	project containerengine.ComposeProject,
	operation []string,
) (argvprocess.Result, error) {
	if ctx == nil {
		return argvprocess.Result{}, errors.Join(containerengine.ErrComposeOperation, context.Canceled)
	}
	arguments := composePrefix(project)
	arguments = append(arguments, operation...)
	runner, executable, err := c.executors.composeBinding()
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrComposeOperation
	}
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrComposeOperation
	}
	return c.runInvocation(ctx, runner, invocation)
}

func (c *Compose) runBound(
	ctx context.Context,
	project containerengine.ComposeProject,
	execution boundComposeExecution,
	operation []string,
) error {
	if execution.authority != nil {
		defer execution.authority.close()
	}
	_, err := c.runBoundOperation(ctx, project, execution, operation)
	return err
}

func (c *Compose) runProjectedBound(
	ctx context.Context,
	project containerengine.ComposeProject,
	execution boundComposeExecution,
	operations ...[]string,
) error {
	if execution.authority != nil {
		defer execution.authority.close()
	}
	if len(operations) == 0 {
		return containerengine.ErrComposeOperation
	}
	projection := []string{
		"run", "--rm", "--no-deps", "--pull", "never", "--no-TTY", "--interactive=false",
		string(composeplan.ServiceSecretProjector),
	}
	result, err := c.runBoundOperation(ctx, project, execution, projection)
	if err != nil {
		return err
	}
	if !bytes.Equal(result.StandardOutput, []byte("ok\n")) {
		return containerengine.ErrComposeOperation
	}
	for _, operation := range operations {
		if len(operation) == 0 {
			return containerengine.ErrComposeOperation
		}
		if _, err = c.runBoundOperation(ctx, project, execution, operation); err != nil {
			return err
		}
	}
	return nil
}

func (c *Compose) runBoundOperation(
	ctx context.Context,
	project containerengine.ComposeProject,
	execution boundComposeExecution,
	operation []string,
) (argvprocess.Result, error) {
	if ctx == nil {
		return argvprocess.Result{}, errors.Join(containerengine.ErrComposeOperation, context.Canceled)
	}
	if execution.authority == nil || execution.authority.verify(ctx) != nil {
		return argvprocess.Result{}, containerengine.ErrInvalidComposeProject
	}
	arguments := composeBoundPrefix(project, execution)
	arguments = append(arguments, operation...)
	runner, executable, err := c.executors.composeBinding()
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrComposeOperation
	}
	invocation, err := argvprocess.NewInvocationWithStandardInput(executable, arguments, execution.configuration)
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrComposeOperation
	}
	result, operationError := c.runInvocation(ctx, runner, invocation)
	if execution.authority.verify(context.WithoutCancel(ctx)) != nil {
		return argvprocess.Result{}, containerengine.ErrInvalidComposeProject
	}
	return result, operationError
}

func (c *Compose) runInvocation(
	ctx context.Context,
	runner argvprocess.Runner,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	result, err := runner.Run(ctx, invocation)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return result, errors.Join(containerengine.ErrComposeOperation, context.Canceled)
		case errors.Is(err, context.DeadlineExceeded):
			return result, errors.Join(containerengine.ErrComposeOperation, context.DeadlineExceeded)
		default:
			return result, containerengine.ErrComposeOperation
		}
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumDockerJSON ||
		len(result.StandardError) > maximumDockerJSON {
		return result, containerengine.ErrComposeOperation
	}
	return result, nil
}

func composePrefix(project containerengine.ComposeProject) []string {
	return []string{
		"--host", project.Endpoint().String(),
		"--ansi", "never",
		"--progress", "quiet",
		"--project-name", project.Name(),
		"--project-directory", project.ProjectDirectory(),
		"--env-file", project.EmptyEnvironmentPath(),
		"--file", project.ConfigurationPath(),
	}
}

func composeBoundPrefix(
	project containerengine.ComposeProject,
	execution boundComposeExecution,
) []string {
	return []string{
		"--host", project.Endpoint().String(),
		"--ansi", "never",
		"--progress", "quiet",
		"--project-name", project.Name(),
		"--project-directory", execution.directory,
		"--env-file", execution.environment,
		"--file", "-",
	}
}

func validateComposeFiles(project containerengine.ComposeProject) error {
	directory := project.ProjectDirectory()
	configuration := project.ConfigurationPath()
	environment := project.EmptyEnvironmentPath()
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		!filepath.IsAbs(configuration) || filepath.Clean(configuration) != configuration ||
		!filepath.IsAbs(environment) || filepath.Clean(environment) != environment {
		return containerengine.ErrInvalidComposeProject
	}
	if err := exactNonSymlink(directory, true); err != nil {
		return err
	}
	if !privateComposePath(directory, true) {
		return containerengine.ErrInvalidComposeProject
	}
	for _, path := range []string{configuration, environment} {
		if !pathWithin(directory, path) {
			return containerengine.ErrInvalidComposeProject
		}
		if err := exactNonSymlink(path, false); err != nil {
			return err
		}
	}
	environmentInfo, err := os.Lstat(environment)
	if err != nil || environmentInfo.Size() != 0 || !privateComposePath(environment, false) {
		return containerengine.ErrInvalidComposeProject
	}
	configurationInfo, err := os.Lstat(configuration)
	if err != nil || configurationInfo.Size() <= 0 || configurationInfo.Size() > maximumDockerJSON ||
		!privateComposePath(configuration, false) {
		return containerengine.ErrInvalidComposeProject
	}
	return nil
}

type composeFileSnapshot struct {
	configuration os.FileInfo
	environment   os.FileInfo
	configDigest  [sha256.Size]byte
}

func snapshotComposeFiles(project containerengine.ComposeProject) (composeFileSnapshot, error) {
	if err := validateComposeFiles(project); err != nil {
		return composeFileSnapshot{}, err
	}
	configuration, err := os.Lstat(project.ConfigurationPath())
	if err != nil {
		return composeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	environment, err := os.Lstat(project.EmptyEnvironmentPath())
	if err != nil {
		return composeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	contents, err := os.ReadFile(project.ConfigurationPath())
	if err != nil || len(contents) == 0 || len(contents) > maximumDockerJSON {
		return composeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	return composeFileSnapshot{
		configuration: configuration, environment: environment, configDigest: sha256.Sum256(contents),
	}, nil
}

func sameComposeFiles(project containerengine.ComposeProject, before composeFileSnapshot) bool {
	after, err := snapshotComposeFiles(project)
	return err == nil && os.SameFile(before.configuration, after.configuration) &&
		os.SameFile(before.environment, after.environment) && before.configDigest == after.configDigest
}

func snapshotPolicySecrets(
	ctx context.Context,
	project containerengine.ComposeProject,
) (map[string]privateComposeFileSnapshot, error) {
	files, ok := project.ExpectedPolicyPlan().SecretFiles()
	if !ok || len(files) == 0 {
		return nil, containerengine.ErrInvalidComposeProject
	}
	snapshots := make(map[string]privateComposeFileSnapshot, len(files))
	seenPaths := make(map[string]struct{}, len(files))
	failed := true
	defer func() {
		if failed {
			zeroPrivateSnapshots(snapshots)
		}
	}()
	for name, path := range files {
		if _, duplicate := seenPaths[path]; duplicate || validateRenderedSecretFile(project, path) != nil {
			return nil, containerengine.ErrInvalidComposeProject
		}
		seenPaths[path] = struct{}{}
		snapshot, err := snapshotPrivateComposeFile(ctx, path, false, maximumExecutionSecretBytes)
		if err != nil || !validExecutionSecret(name, snapshot.contents) {
			zeroBytes(snapshot.contents)
			return nil, containerengine.ErrInvalidComposeProject
		}
		snapshots[name] = snapshot
	}
	failed = false
	return snapshots, nil
}

func samePrivateSnapshots(
	left map[string]privateComposeFileSnapshot,
	right map[string]privateComposeFileSnapshot,
) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	for name, before := range left {
		after, exists := right[name]
		if !exists || !samePrivateComposeFile(before, after) {
			return false
		}
	}
	return true
}

func snapshotContents(snapshots map[string]privateComposeFileSnapshot) map[string][]byte {
	contents := make(map[string][]byte, len(snapshots))
	for name, snapshot := range snapshots {
		contents[name] = snapshot.contents
	}
	return contents
}

func zeroPrivateSnapshots(snapshots map[string]privateComposeFileSnapshot) {
	for name, snapshot := range snapshots {
		zeroBytes(snapshot.contents)
		snapshot.contents = nil
		snapshots[name] = snapshot
	}
}

func validateRenderedFiles(project containerengine.ComposeProject, model composeplan.Model) error {
	for _, secret := range model.Secrets {
		if err := validateRenderedSecretFile(project, secret.File); err != nil {
			return err
		}
	}
	return nil
}

func validateRenderedSecretFile(project containerengine.ComposeProject, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!pathWithin(project.ProjectDirectory(), path) {
		return containerengine.ErrInvalidComposeProject
	}
	if err := exactNonSymlink(path, false); err != nil {
		return err
	}
	if !privateComposePath(path, false) {
		return containerengine.ErrInvalidComposeProject
	}
	return nil
}

func exactNonSymlink(path string, wantDirectory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (wantDirectory && !info.IsDir()) ||
		(!wantDirectory && !info.Mode().IsRegular()) {
		return containerengine.ErrInvalidComposeProject
	}
	evaluated, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(evaluated) != path {
		return containerengine.ErrInvalidComposeProject
	}
	return nil
}

func pathWithin(directory string, path string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

var _ containerengine.ComposePort = (*Compose)(nil)
