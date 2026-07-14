package firststart

import (
	"context"
	"errors"
	"path"
	"reflect"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

const nativeCoreEndpoint = "http://127.0.0.1:9411"

// HostProjection contains only locally attested facts that cannot be carried
// by a redistributable signed release template. The source is responsible for
// resolving the invoking owner, installed executable, and certified host
// configuration location without consulting MCP input.
type HostProjection struct {
	StorageRoot        string
	RuntimeEndpoint    string
	ConfigurationPath  string
	LauncherPath       string
	LauncherDigest     agentconfigdomain.Digest
	OwnerSubjectDigest install.Digest
}

// HostProjectionSource resolves the current native machine projection.
type HostProjectionSource interface {
	Project(context.Context, agentconfigdomain.AgentHost) (HostProjection, error)
}

// PlanBinder deterministically binds durable first-start identities to one
// exact verified release template.
type PlanBinder struct{ source HostProjectionSource }

// NewPlanBinder refuses partial and typed-nil composition.
func NewPlanBinder(source HostProjectionSource) (*PlanBinder, error) {
	if nilBinderCapability(source) {
		return nil, firststartapp.ErrIntegrity
	}
	return &PlanBinder{source: source}, nil
}

// Bind preserves every release-signed field and replaces only the closed set
// of per-host fields accepted by installplan.RebindV1.
func (b *PlanBinder) Bind(
	ctx context.Context,
	template firststartapp.Template,
	preparation firststartapp.Preparation,
) (firststartapp.PreparedInstallation, error) {
	if b == nil || ctx == nil || !template.Valid() || !preparation.Valid() ||
		nilBinderCapability(b.source) {
		return firststartapp.PreparedInstallation{}, firststartapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return firststartapp.PreparedInstallation{}, err
	}
	templatePlan, err := installplan.DecodeV1(template.Canonical())
	if err != nil || !templatePlan.Digest().Equal(template.Digest()) {
		return firststartapp.PreparedInstallation{}, firststartapp.ErrIntegrity
	}
	projection, err := b.source.Project(ctx, preparation.Host())
	if err != nil {
		return firststartapp.PreparedInstallation{}, mapBinderError(err)
	}
	if !validHostProjection(projection) ||
		!projection.LauncherDigest.Equal(templatePlan.AgentConfiguration().LauncherDigest()) {
		return firststartapp.PreparedInstallation{}, firststartapp.ErrIntegrity
	}
	product, err := bindProduct(templatePlan, preparation, projection.StorageRoot)
	if err != nil {
		return firststartapp.PreparedInstallation{}, firststartapp.ErrIntegrity
	}
	product.OwnerSubjectDigest = projection.OwnerSubjectDigest
	rebound, err := installplan.RebindV1(templatePlan, installplan.RebindInput{
		OperationID: preparation.OperationID(), InstallationID: preparation.InstallationID(),
		GenerationID: preparation.GenerationID(), RuntimeEndpoint: projection.RuntimeEndpoint,
		SecurityEpoch: preparation.SecurityEpoch(), HostStorageTarget: projection.StorageRoot,
		Product: product,
		Capacity: installplan.CapacityInput{
			HostCAS:     joinHostPath(projection.StorageRoot, "cas"),
			HostRelease: product.ReleaseDirectory, DockerEngine: projection.RuntimeEndpoint,
			DockerDataVolume: templatePlan.Capacity().DockerDataVolume(),
		},
		AgentConfiguration: installplan.AgentConfigurationInput{
			AgentHost: preparation.Host(), ConfigLocation: projection.ConfigurationPath,
			EntryID: preparation.AgentEntryID(), LauncherDigest: projection.LauncherDigest,
			LauncherPath: projection.LauncherPath,
		},
	})
	if err != nil || rebound.OperationID() != preparation.OperationID() ||
		rebound.InstallationID() != preparation.InstallationID() ||
		rebound.GenerationID() != preparation.GenerationID() ||
		rebound.SecurityEpoch() != preparation.SecurityEpoch() ||
		rebound.AgentConfiguration().AgentHost() != preparation.Host() {
		return firststartapp.PreparedInstallation{}, firststartapp.ErrIntegrity
	}
	prepared, err := firststartapp.NewPreparedInstallation(
		rebound.CanonicalBytes(), preparation.OperationID(), preparation.InstallationID(), preparation.Host(),
	)
	if err != nil {
		return firststartapp.PreparedInstallation{}, firststartapp.ErrIntegrity
	}
	return prepared, nil
}

func bindProduct(
	template installplan.Plan,
	preparation firststartapp.Preparation,
	root string,
) (installplan.ProductInput, error) {
	release := joinHostPath(root, "releases", preparation.GenerationID())
	configuration := joinHostPath(root, "config")
	runtimeDirectory := joinHostPath(root, "runtime")
	secrets := joinHostPath(root, "secrets")
	backups := joinHostPath(root, "backups")
	compose := joinHostPath(release, "compose")
	secretFiles := template.Product().SecretFiles()
	boundSecrets := make([]installplan.SecretFileInput, 0, len(secretFiles))
	seen := make(map[installplan.SecretPurpose]struct{}, len(secretFiles))
	for _, secret := range secretFiles {
		if _, duplicate := seen[secret.Purpose()]; duplicate {
			return installplan.ProductInput{}, firststartapp.ErrIntegrity
		}
		seen[secret.Purpose()] = struct{}{}
		boundSecrets = append(boundSecrets, installplan.SecretFileInput{
			Purpose: secret.Purpose(), Path: joinHostPath(secrets, string(secret.Purpose())),
		})
	}
	return installplan.ProductInput{
		ReleaseDirectory: release, ConfigurationDirectory: configuration,
		RuntimeDirectory: runtimeDirectory, SecretDirectory: secrets, BackupDirectory: backups,
		ComposeProjectDirectory:  compose,
		ComposeConfigurationPath: joinHostPath(compose, "compose.yaml"),
		EmptyEnvironmentPath:     joinHostPath(compose, "empty.env"),
		EgressAttestationPath:    joinHostPath(runtimeDirectory, "egress-attestation.json"),
		CoreEndpoint:             nativeCoreEndpoint, InitialBrainID: preparation.BrainID(),
		InitialBrainName: template.Product().InitialBrainName(),
		OwnerPrincipalID: preparation.OwnerPrincipalID(), OwnerGrantID: preparation.OwnerGrantID(),
		SecretFiles: boundSecrets,
	}, nil
}

func validHostProjection(value HostProjection) bool {
	if value.StorageRoot == "" || value.RuntimeEndpoint == "" || value.ConfigurationPath == "" ||
		value.LauncherPath == "" || value.LauncherDigest.IsZero() || value.OwnerSubjectDigest.IsZero() {
		return false
	}
	windows := strings.HasPrefix(value.RuntimeEndpoint, "npipe:////./pipe/")
	if windows {
		return validWindowsAbsolute(value.StorageRoot) && validWindowsAbsolute(value.ConfigurationPath) &&
			validWindowsAbsolute(value.LauncherPath)
	}
	return strings.HasPrefix(value.RuntimeEndpoint, "unix:///") && path.IsAbs(value.StorageRoot) &&
		path.Clean(value.StorageRoot) == value.StorageRoot && path.IsAbs(value.ConfigurationPath) &&
		path.Clean(value.ConfigurationPath) == value.ConfigurationPath && path.IsAbs(value.LauncherPath) &&
		path.Clean(value.LauncherPath) == value.LauncherPath
}

func validWindowsAbsolute(value string) bool {
	return len(value) >= 4 && value[0] >= 'A' && value[0] <= 'Z' && value[1:3] == `:\` &&
		!strings.Contains(value, "/") && !strings.HasSuffix(value, `\`) && !strings.Contains(value, `\\`)
}

func joinHostPath(root string, elements ...string) string {
	separator := "/"
	if len(root) >= 3 && root[1:3] == `:\` {
		separator = `\`
	}
	result := strings.TrimSuffix(root, separator)
	for _, element := range elements {
		result += separator + strings.Trim(element, `/\`)
	}
	return result
}

func mapBinderError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, firststartapp.ErrIntegrity) {
		return firststartapp.ErrIntegrity
	}
	return firststartapp.ErrUnavailable
}

func nilBinderCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ firststartapp.PreparationBinder = (*PlanBinder)(nil)
