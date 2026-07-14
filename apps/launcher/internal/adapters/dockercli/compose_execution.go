package dockercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

const (
	executionMaterializationRoot = ".agentmemory-execution"
	executionEnvironmentName     = "empty.env"
	executionSecretName          = composeplan.SecretInstallationRootKey
	maximumExecutionSecretBytes  = 64 * 1024
)

// boundComposeExecution is the only authority accepted by a mutating Compose
// command. configuration is the already authenticated topology, rebound only
// to durable generation-owned copies of every protected-file source.
type boundComposeExecution struct {
	directory     string
	environment   string
	configuration []byte
	authority     *executionMaterializationAuthority
}

type privateComposeFileSnapshot struct {
	identity      os.FileInfo
	identityToken string
	contents      []byte
}

type executionAncestorAuthority interface {
	verify(context.Context) error
	close() error
}

func prepareBoundComposeExecution(
	ctx context.Context,
	project containerengine.ComposeProject,
	canonical []byte,
	secrets map[string][]byte,
) (boundComposeExecution, error) {
	if ctx == nil {
		return boundComposeExecution{}, errors.Join(containerengine.ErrComposeOperation, context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return boundComposeExecution{}, errors.Join(containerengine.ErrComposeOperation, err)
	}
	if len(canonical) == 0 || len(canonical) > maximumDockerJSON {
		return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
	}
	model, err := decodeRenderedPolicy(canonical, project.Name())
	if err != nil || len(composeplan.NewPolicy().Validate(model)) != 0 ||
		!project.ExpectedPolicyPlan().Matches(model) {
		return boundComposeExecution{}, containerengine.ErrComposeConfigurationMismatch
	}
	var document renderedComposeDocument
	if err := decodeStrictJSON(canonical, &document); err != nil {
		return boundComposeExecution{}, containerengine.ErrComposeConfigurationMismatch
	}
	if len(secrets) != len(model.Secrets) {
		return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
	}
	if len(document.Secrets) != len(model.Secrets) {
		return boundComposeExecution{}, containerengine.ErrComposeConfigurationMismatch
	}
	for name, source := range model.Secrets {
		renderedSource, renderedExists := document.Secrets[name]
		secret, secretExists := secrets[name]
		if !renderedExists || renderedSource.File != source.File || !secretExists || !validExecutionSecret(name, secret) {
			return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
		}
	}

	directory := filepath.Join(
		project.ProjectDirectory(), executionMaterializationRoot, model.Identity.Generation(),
	)
	if !pathWithin(project.ProjectDirectory(), directory) ||
		errEnsureExecutionDirectory(ctx, filepath.Dir(directory)) != nil ||
		errEnsureExecutionDirectory(ctx, directory) != nil {
		return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
	}
	environmentPath := filepath.Join(directory, executionEnvironmentName)
	secretPaths := make(map[string]string, len(secrets))
	for name := range secrets {
		secretPath := filepath.Join(directory, name)
		if !pathWithin(directory, secretPath) {
			return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
		}
		renderedSource := document.Secrets[name]
		renderedSource.File = secretPath
		document.Secrets[name] = renderedSource
		secretPaths[name] = secretPath
	}
	unescaped, err := json.Marshal(document)
	if err != nil || len(unescaped) > maximumDockerJSON {
		return boundComposeExecution{}, containerengine.ErrComposeConfigurationMismatch
	}

	expected := model
	expected.Secrets = make(map[string]composeplan.Secret, len(model.Secrets))
	for name, value := range model.Secrets {
		expected.Secrets[name] = value
	}
	for name, secretPath := range secretPaths {
		boundSecret := expected.Secrets[name]
		boundSecret.File = secretPath
		expected.Secrets[name] = boundSecret
	}
	boundPlan, err := composeplan.NewPolicyPlan(expected)
	boundModel, decodeError := decodeRenderedPolicy(unescaped, project.Name())
	if err != nil || decodeError != nil || len(composeplan.NewPolicy().Validate(boundModel)) != 0 ||
		!boundPlan.Matches(boundModel) {
		return boundComposeExecution{}, containerengine.ErrComposeConfigurationMismatch
	}

	configuration, err := escapeComposeInterpolation(unescaped)
	if err != nil || len(configuration) == 0 || len(configuration) > maximumDockerJSON {
		return boundComposeExecution{}, containerengine.ErrComposeConfigurationMismatch
	}
	directoryHandle, err := openPrivateExecutionDirectory(ctx, directory)
	if err != nil {
		return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
	}
	ancestorAuthority, err := openExecutionAncestorAuthority(ctx, project.ProjectDirectory())
	if err != nil {
		_ = directoryHandle.Close()
		return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
	}
	materializationComplete := false
	secretHandles := make(map[string]*os.File, len(secrets))
	var environmentHandle *os.File
	defer func() {
		if materializationComplete {
			return
		}
		for _, file := range secretHandles {
			if file != nil {
				_ = file.Close()
			}
		}
		for _, file := range []*os.File{environmentHandle, directoryHandle} {
			if file != nil {
				_ = file.Close()
			}
		}
		_ = ancestorAuthority.close()
	}()
	secretNames := make([]string, 0, len(secrets))
	for name := range secrets {
		secretNames = append(secretNames, name)
	}
	sort.Strings(secretNames)
	for _, name := range secretNames {
		secretHandle, fileError := ensureExecutionFile(
			ctx, directoryHandle, name, secretPaths[name], secrets[name], false,
		)
		if fileError != nil {
			return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
		}
		secretHandles[name] = secretHandle
	}
	environmentHandle, err = ensureExecutionFile(
		ctx, directoryHandle, executionEnvironmentName, environmentPath, nil, true,
	)
	if err != nil || sealExecutionDirectory(directoryHandle) != nil ||
		syncExecutionDirectory(directoryHandle) != nil {
		return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
	}
	authority, err := newExecutionMaterializationAuthority(
		ctx,
		directory,
		secretPaths,
		environmentPath,
		directoryHandle,
		secretHandles,
		environmentHandle,
		ancestorAuthority,
		secrets,
	)
	if err != nil {
		return boundComposeExecution{}, containerengine.ErrInvalidComposeProject
	}
	materializationComplete = true

	// The materialization is intentionally durable: Compose implements local
	// file secrets as host bind mounts, so removing it after `up` would break a
	// later daemon restart. Creation, reuse, and cleanup are serialized by the
	// machine-global installation lock. The generation resource lifecycle owns
	// deletion and may remove this directory only after every generation
	// container is gone.
	return boundComposeExecution{
		directory: directory, environment: environmentPath, configuration: configuration, authority: authority,
	}, nil
}

type executionMaterializationAuthority struct {
	directory         *os.File
	secrets           map[string]*os.File
	environment       *os.File
	directoryPath     string
	secretPaths       map[string]string
	environmentPath   string
	directoryIdentity os.FileInfo
	secretIdentities  map[string]os.FileInfo
	environmentID     os.FileInfo
	secretModes       map[string]os.FileMode
	environmentMode   os.FileMode
	directoryMode     os.FileMode
	secretDigests     map[string][sha256.Size]byte
	ancestors         executionAncestorAuthority
}

func newExecutionMaterializationAuthority(
	ctx context.Context,
	directoryPath string,
	secretPaths map[string]string,
	environmentPath string,
	directory *os.File,
	secrets map[string]*os.File,
	environment *os.File,
	ancestors executionAncestorAuthority,
	expectedSecrets map[string][]byte,
) (*executionMaterializationAuthority, error) {
	if directory == nil || len(secrets) == 0 || len(secrets) != len(secretPaths) ||
		len(secrets) != len(expectedSecrets) || environment == nil || ancestors == nil {
		return nil, containerengine.ErrInvalidComposeProject
	}
	authority := &executionMaterializationAuthority{
		directory:        directory,
		secrets:          secrets,
		environment:      environment,
		ancestors:        ancestors,
		directoryPath:    directoryPath,
		secretPaths:      secretPaths,
		environmentPath:  environmentPath,
		secretIdentities: make(map[string]os.FileInfo, len(secrets)),
		secretModes:      make(map[string]os.FileMode, len(secrets)),
		secretDigests:    make(map[string][sha256.Size]byte, len(secrets)),
	}
	failed := true
	defer func() {
		if failed {
			authority.close()
		}
	}()
	var err error
	authority.directoryIdentity, err = authority.directory.Stat()
	if err != nil {
		return nil, containerengine.ErrInvalidComposeProject
	}
	authority.environmentID, err = authority.environment.Stat()
	if err != nil {
		return nil, containerengine.ErrInvalidComposeProject
	}
	authority.directoryMode = authority.directoryIdentity.Mode()
	authority.environmentMode = authority.environmentID.Mode()
	for name, secret := range authority.secrets {
		if secret == nil || authority.secretPaths[name] == "" || !validExecutionSecret(name, expectedSecrets[name]) {
			return nil, containerengine.ErrInvalidComposeProject
		}
		identity, statError := secret.Stat()
		if statError != nil || !sealedExecutionMaterialization(
			authority.directoryIdentity, identity, authority.environmentID,
		) {
			return nil, containerengine.ErrInvalidComposeProject
		}
		authority.secretIdentities[name] = identity
		authority.secretModes[name] = identity.Mode()
		authority.secretDigests[name] = sha256.Sum256(expectedSecrets[name])
	}
	if err := authority.verify(ctx); err != nil {
		return nil, err
	}
	failed = false
	return authority, nil
}

func (a *executionMaterializationAuthority) verify(ctx context.Context) error {
	if a == nil || ctx == nil || ctx.Err() != nil || a.directory == nil || len(a.secrets) == 0 || a.environment == nil {
		return containerengine.ErrInvalidComposeProject
	}
	if a.ancestors == nil || a.ancestors.verify(ctx) != nil {
		return containerengine.ErrInvalidComposeProject
	}
	directoryInfo, err := a.directory.Stat()
	if err != nil || !os.SameFile(a.directoryIdentity, directoryInfo) || directoryInfo.Mode() != a.directoryMode ||
		!openedPathIdentity(a.directoryPath, a.directory, true) {
		return containerengine.ErrInvalidComposeProject
	}
	for name, secret := range a.secrets {
		secretSnapshot, snapshotError := snapshotOpenedComposeFile(secret, false, maximumExecutionSecretBytes)
		if snapshotError != nil {
			return containerengine.ErrInvalidComposeProject
		}
		valid := os.SameFile(a.secretIdentities[name], secretSnapshot.identity) &&
			secretSnapshot.identity.Mode() == a.secretModes[name] &&
			sha256.Sum256(secretSnapshot.contents) == a.secretDigests[name] &&
			openedPathIdentity(a.secretPaths[name], secret, false)
		zeroBytes(secretSnapshot.contents)
		if !valid {
			return containerengine.ErrInvalidComposeProject
		}
	}
	environmentSnapshot, err := snapshotOpenedComposeFile(a.environment, true, 1)
	if err != nil {
		return containerengine.ErrInvalidComposeProject
	}
	defer zeroBytes(environmentSnapshot.contents)
	if !os.SameFile(a.environmentID, environmentSnapshot.identity) ||
		environmentSnapshot.identity.Mode() != a.environmentMode || len(environmentSnapshot.contents) != 0 ||
		!openedPathIdentity(a.environmentPath, a.environment, false) {
		return containerengine.ErrInvalidComposeProject
	}
	return nil
}

func openedPathIdentity(path string, opened *os.File, wantDirectory bool) bool {
	if opened == nil || !privateExecutionMaterializationPath(path, wantDirectory) {
		return false
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.IsDir() != wantDirectory {
		return false
	}
	openedInfo, err := opened.Stat()
	return err == nil && os.SameFile(pathInfo, openedInfo)
}

func (a *executionMaterializationAuthority) close() {
	if a == nil {
		return
	}
	for _, file := range a.secrets {
		if file != nil {
			_ = file.Close()
		}
	}
	for _, file := range []*os.File{a.environment, a.directory} {
		if file != nil {
			_ = file.Close()
		}
	}
	if a.ancestors != nil {
		_ = a.ancestors.close()
	}
}

func validExecutionSecret(name string, value []byte) bool {
	if len(value) == 0 || len(value) > maximumExecutionSecretBytes {
		return false
	}
	if name == composeplan.SecretEgressAttestation {
		return len(value) <= maximumExecutionSecretBytes
	}
	if len(value) != 32 || bytes.Equal(value, make([]byte, 32)) {
		return false
	}
	switch name {
	case composeplan.SecretInstallationRootKey, composeplan.SecretAPICredential,
		composeplan.SecretAttestationHMACKey, composeplan.SecretNeo4jPassword,
		composeplan.SecretEmbeddingCapability, composeplan.SecretRerankingCapability,
		composeplan.SecretExtractionCapability:
		return true
	default:
		return false
	}
}

func errEnsureExecutionDirectory(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return containerengine.ErrInvalidComposeProject
	}
	err := createPrivateExecutionDirectory(ctx, path)
	if err != nil {
		if verifyError := exactNonSymlink(path, true); verifyError != nil || !privateComposePath(path, true) {
			return containerengine.ErrInvalidComposeProject
		}
		return nil
	}
	if verifyError := exactNonSymlink(path, true); verifyError != nil || !privateComposePath(path, true) {
		return containerengine.ErrInvalidComposeProject
	}
	return nil
}

func ensureExecutionFile(
	ctx context.Context,
	directory *os.File,
	name string,
	path string,
	contents []byte,
	allowEmpty bool,
) (*os.File, error) {
	if directory == nil || filepath.Base(name) != name || name == "." || name == ".." ||
		filepath.Join(filepath.Dir(path), name) != path {
		return nil, containerengine.ErrInvalidComposeProject
	}
	file, created, err := createPrivateExecutionChild(ctx, directory, name, path)
	if err != nil {
		return nil, containerengine.ErrInvalidComposeProject
	}
	success := false
	defer func() {
		if !success {
			_ = file.Close()
		}
	}()
	if created {
		if err := writeComplete(file, contents); err != nil || file.Sync() != nil {
			// Do not remove by pathname on failure. A partially created,
			// owner-only no-replace object quarantines this generation and
			// cannot cause cleanup to delete a hostile replacement.
			return nil, containerengine.ErrInvalidComposeProject
		}
	}
	// Existing generation-owned files are reopened read-only after their exact
	// contents and protected identity are verified. Only a newly-created file
	// needs the post-seal durability barrier; Sync rejects the reused read-only
	// Windows handle.
	if sealExecutionFile(file) != nil || created && file.Sync() != nil {
		return nil, containerengine.ErrInvalidComposeProject
	}
	snapshot, err := snapshotOpenedComposeFile(file, allowEmpty, max(len(contents), 1))
	defer zeroBytes(snapshot.contents)
	if err != nil || !bytes.Equal(snapshot.contents, contents) ||
		!openedPathIdentity(path, file, false) {
		return nil, containerengine.ErrInvalidComposeProject
	}
	success = true
	return file, nil
}

func writeComplete(file *os.File, contents []byte) error {
	if file == nil {
		return containerengine.ErrInvalidComposeProject
	}
	for len(contents) != 0 {
		written, err := file.Write(contents)
		if err != nil || written <= 0 {
			return containerengine.ErrInvalidComposeProject
		}
		contents = contents[written:]
	}
	return nil
}

func readPrivateExecutionFile(
	ctx context.Context,
	path string,
	allowEmpty bool,
	limit int,
) ([]byte, error) {
	snapshot, err := snapshotPrivateComposeFile(ctx, path, allowEmpty, limit)
	return snapshot.contents, err
}

func snapshotPrivateComposeFile(
	ctx context.Context,
	path string,
	allowEmpty bool,
	limit int,
) (privateComposeFileSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || limit <= 0 {
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	file, err := openPrivateExecutionFile(ctx, path)
	if err != nil {
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	defer func() { _ = file.Close() }()
	return snapshotOpenedComposeFile(file, allowEmpty, limit)
}

func snapshotOpenedComposeFile(
	file *os.File,
	allowEmpty bool,
	limit int,
) (privateComposeFileSnapshot, error) {
	if file == nil || limit <= 0 {
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	before, err := file.Stat()
	beforeToken, tokenValid := composeNativeIdentity(before)
	if err != nil || !tokenValid || before.Size() < 0 || before.Size() > int64(limit) {
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	contents, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(contents) > limit || (!allowEmpty && len(contents) == 0) {
		zeroBytes(contents)
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		zeroBytes(contents)
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	confirmation, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	defer zeroBytes(confirmation)
	after, statError := file.Stat()
	afterToken, afterTokenValid := composeNativeIdentity(after)
	if err != nil || statError != nil || !bytes.Equal(contents, confirmation) ||
		!afterTokenValid || beforeToken != afterToken || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		zeroBytes(contents)
		return privateComposeFileSnapshot{}, containerengine.ErrInvalidComposeProject
	}
	return privateComposeFileSnapshot{identity: before, identityToken: beforeToken, contents: contents}, nil
}

func samePrivateComposeFile(left privateComposeFileSnapshot, right privateComposeFileSnapshot) bool {
	return left.identity != nil && right.identity != nil && os.SameFile(left.identity, right.identity) &&
		left.identityToken != "" && left.identityToken == right.identityToken && bytes.Equal(left.contents, right.contents)
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func escapeComposeInterpolation(document []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errRenderedComposePolicy
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errRenderedComposePolicy
	}
	escapeComposeStrings(value)
	return json.Marshal(value)
}

func escapeComposeStrings(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				typed[key] = strings.ReplaceAll(text, "$", "$$")
				continue
			}
			escapeComposeStrings(child)
		}
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok {
				typed[index] = strings.ReplaceAll(text, "$", "$$")
				continue
			}
			escapeComposeStrings(child)
		}
	}
}
