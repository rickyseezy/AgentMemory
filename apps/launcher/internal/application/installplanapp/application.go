package installplanapp

import (
	"context"
	"errors"
	"maps"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installphase"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// Repository is the persistence boundary for exact canonical plan bytes.
// Save is immutable and idempotent; Load must verify bytes before returning.
type Repository interface {
	Save(context.Context, installplan.Plan) error
	Load(context.Context, install.PlanDigest) (installplan.Plan, error)
}

// Application implements every current installphase plan-query interface from
// one operation-scoped canonical authority plus authenticated durable evidence.
type Application struct {
	repository        Repository
	runtimePlans      RuntimePlanRepository
	runtimeEvidence   RuntimeEvidenceResolver
	operations        OperationRepository
	readinessReceipts ReadinessReceiptRepository
	resources         ResourceInventoryRepository
	operation         install.OperationID
}

// ResolveHostVerificationPlan selects the exact release-signed compatibility
// policy carried by the parent plan. The signed policy itself is deliberately
// installation-agnostic; this projection supplies the non-circular parent
// binding that is covered by the canonical installation-plan digest.
func (a *Application) ResolveHostVerificationPlan(
	ctx context.Context,
	digest install.PlanDigest,
) (installphase.HostVerificationPlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.HostVerificationPlan{}, err
	}
	signed := plan.SignedHostPlan()
	if !signed.Valid() || !signed.Plan().Valid() {
		return installphase.HostVerificationPlan{}, ErrPlanIntegrity
	}
	return installphase.HostVerificationPlan{
		ParentPlanDigest: digest,
		SignedHostPlan:   signed,
		StorageTarget:    plan.HostStorageTarget(),
		RuntimeOwnership: install.RuntimeOwnershipUndetermined,
	}, nil
}

// New rejects incomplete and typed-nil composition. The query service is
// deliberately operation-scoped because the existing phase query methods do
// not carry operation identity themselves.
func New(dependencies Dependencies) (*Application, error) {
	if nilCapability(dependencies.Plans) || nilCapability(dependencies.RuntimePlans) ||
		nilCapability(dependencies.RuntimeEvidence) || nilCapability(dependencies.Operations) ||
		nilCapability(dependencies.ReadinessReceipts) || nilCapability(dependencies.Resources) ||
		dependencies.OperationID.IsZero() {
		return nil, ErrPlanIntegrity
	}
	return &Application{
		repository: dependencies.Plans, runtimePlans: dependencies.RuntimePlans,
		runtimeEvidence: dependencies.RuntimeEvidence, operations: dependencies.Operations,
		readinessReceipts: dependencies.ReadinessReceipts, resources: dependencies.Resources,
		operation: dependencies.OperationID,
	}, nil
}

// ResolveReleasePlan returns the exact signed release envelope bound to the parent plan.
func (a *Application) ResolveReleasePlan(
	ctx context.Context,
	digest install.PlanDigest,
) (installphase.ReleaseVerificationPlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.ReleaseVerificationPlan{}, err
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return installphase.ReleaseVerificationPlan{}, err
	}
	manifest := plan.SignedRelease().Manifest()
	manifestDigest, err := install.ParseDigest(manifest.Digest().Hex())
	if err != nil {
		return installphase.ReleaseVerificationPlan{}, ErrPlanIntegrity
	}
	return installphase.ReleaseVerificationPlan{
		PlanDigest:       digest,
		ReleaseID:        manifest.ReleaseID(),
		ManifestDigest:   manifestDigest,
		ReleaseSequence:  manifest.Sequence(),
		SignedManifest:   plan.SignedRelease(),
		RuntimeOwnership: ownership,
	}, nil
}

// ResolveArtifactAcquisitionPlan returns the complete signed-resource acquisition projection.
func (a *Application) ResolveArtifactAcquisitionPlan(
	ctx context.Context,
	digest install.PlanDigest,
) (installphase.ArtifactAcquisitionPlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.ArtifactAcquisitionPlan{}, err
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return installphase.ArtifactAcquisitionPlan{}, err
	}
	acquisition := plan.AcquisitionPlan()
	acquisitionDigest, err := install.ParseDigest(acquisition.Digest().Hex())
	if err != nil {
		return installphase.ArtifactAcquisitionPlan{}, ErrPlanIntegrity
	}
	projections, err := capacitySecretProjections(plan.InstallationID(), plan.GenerationID())
	if err != nil {
		return installphase.ArtifactAcquisitionPlan{}, err
	}
	capacity := plan.Capacity()
	return installphase.ArtifactAcquisitionPlan{
		ParentPlanDigest:      digest,
		InstallationID:        plan.InstallationID(),
		ReleaseID:             plan.SignedRelease().Manifest().ReleaseID(),
		GenerationID:          plan.GenerationID(),
		AcquisitionPlanDigest: acquisitionDigest,
		AcquisitionPlan:       acquisition,
		ComposeArtifactID:     plan.ComposeArtifactID(),
		RuntimeOwnership:      ownership,
		SecretProjections:     projections,
		HostCASCapacity:       artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS, Locator: capacity.HostCAS()},
		HostReleaseCapacity:   artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostRelease, Locator: capacity.HostRelease()},
		DockerEngineCapacity:  artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: capacity.DockerEngine()},
		DockerVolumeCapacity:  artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: capacity.DockerDataVolume()},
	}, nil
}

// ResolveNetworkVolumePlan returns exact local endpoint and ownership labels.
func (a *Application) ResolveNetworkVolumePlan(
	ctx context.Context,
	digest install.PlanDigest,
) (installphase.NetworkVolumePlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.NetworkVolumePlan{}, err
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return installphase.NetworkVolumePlan{}, err
	}
	endpoint, err := containerengine.NewEndpoint(plan.RuntimeEndpoint())
	if err != nil {
		return installphase.NetworkVolumePlan{}, ErrPlanIntegrity
	}
	projections, err := capacitySecretProjections(plan.InstallationID(), plan.GenerationID())
	if err != nil {
		return installphase.NetworkVolumePlan{}, err
	}
	manifest := plan.SignedRelease().Manifest()
	capacity := plan.Capacity()
	return installphase.NetworkVolumePlan{
		PlanDigest:        digest,
		InstallationID:    plan.InstallationID(),
		GenerationID:      plan.GenerationID(),
		Release:           manifest.ReleaseID(),
		CreationOperation: plan.OperationID().String(),
		Endpoint:          endpoint,
		RuntimeOwnership:  ownership,
		CapacityCommand: artifactapp.CapacityCommand{
			OperationID: plan.OperationID().String(), ParentPlanDigest: digest,
			InstallationID: plan.InstallationID(), ReleaseID: manifest.ReleaseID(), GenerationID: plan.GenerationID(),
			Plan: plan.AcquisitionPlan(), SecretProjections: projections,
			HostCAS:          artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS, Locator: capacity.HostCAS()},
			HostRelease:      artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostRelease, Locator: capacity.HostRelease()},
			DockerEngine:     artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: capacity.DockerEngine()},
			DockerDataVolume: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: capacity.DockerDataVolume()},
		},
	}, nil
}

// ResolveDirectoryCommand derives the complete owner-protected product layout
// from the immutable parent plan and binds it to one operation attempt.
func (a *Application) ResolveDirectoryCommand(
	ctx context.Context,
	digest install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
) (productinstall.DirectoryCommand, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return productinstall.DirectoryCommand{}, err
	}
	if operationID.IsZero() || operationID != plan.OperationID() || attempt == 0 {
		return productinstall.DirectoryCommand{}, ErrPlanIntegrity
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return productinstall.DirectoryCommand{}, err
	}
	product := plan.Product()
	inputs := []struct {
		purpose productinstall.DirectoryPurpose
		path    string
	}{
		{purpose: productinstall.DirectoryRelease, path: product.ReleaseDirectory()},
		{purpose: productinstall.DirectoryConfiguration, path: product.ConfigurationDirectory()},
		{purpose: productinstall.DirectoryRuntime, path: product.RuntimeDirectory()},
		{purpose: productinstall.DirectorySecrets, path: product.SecretDirectory()},
		{purpose: productinstall.DirectoryBackups, path: product.BackupDirectory()},
		{purpose: productinstall.DirectoryComposeProject, path: product.ComposeProjectDirectory()},
	}
	directories := make([]productinstall.DirectorySpec, 0, len(inputs))
	for _, input := range inputs {
		specification, specError := productinstall.NewDirectorySpec(input.purpose, input.path)
		if specError != nil {
			return productinstall.DirectoryCommand{}, ErrPlanIntegrity
		}
		directories = append(directories, specification)
	}
	command, err := productinstall.NewDirectoryCommand(
		operationID, digest, attempt, ownership, directories,
	)
	if err != nil {
		return productinstall.DirectoryCommand{}, ErrPlanIntegrity
	}
	return command, nil
}

// ResolveSecretCommand derives all seven purpose-separated protected file
// references from the immutable parent plan and binds them to one attempt.
func (a *Application) ResolveSecretCommand(
	ctx context.Context,
	digest install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
) (productinstall.SecretCommand, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return productinstall.SecretCommand{}, err
	}
	if operationID.IsZero() || operationID != plan.OperationID() || attempt == 0 {
		return productinstall.SecretCommand{}, ErrPlanIntegrity
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return productinstall.SecretCommand{}, err
	}
	product := plan.Product()
	planSecrets := product.SecretFiles()
	secrets := make([]productinstall.SecretSpec, 0, len(planSecrets))
	for _, protectedReference := range planSecrets {
		specification, specError := productinstall.NewSecretSpec(
			protectedReference.Purpose(), protectedReference.Path(),
		)
		if specError != nil {
			return productinstall.SecretCommand{}, ErrPlanIntegrity
		}
		secrets = append(secrets, specification)
	}
	command, err := productinstall.NewSecretCommand(
		operationID, digest, attempt, ownership, product.SecretDirectory(), secrets,
	)
	if err != nil {
		return productinstall.SecretCommand{}, ErrPlanIntegrity
	}
	return command, nil
}

// ResolveStackAuthorization derives one mutation authority from the canonical
// plan's exact runtime endpoint, release identity, signed Compose digest, and
// protected product paths. No ambient Docker context or caller-provided model
// is accepted.
func (a *Application) ResolveStackAuthorization(
	ctx context.Context,
	digest install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
	operation productstack.Operation,
) (productstack.Authorization, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return productstack.Authorization{}, err
	}
	if operationID.IsZero() || operationID != plan.OperationID() || attempt == 0 {
		return productstack.Authorization{}, ErrPlanIntegrity
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return productstack.Authorization{}, err
	}
	endpoint, err := containerengine.NewEndpoint(plan.RuntimeEndpoint())
	if err != nil {
		return productstack.Authorization{}, ErrPlanIntegrity
	}
	identity, err := composeplan.NewIdentity(plan.InstallationID(), plan.GenerationID())
	if err != nil {
		return productstack.Authorization{}, ErrPlanIntegrity
	}
	composeArtifact, exists := plan.AcquisitionPlan().Artifact(plan.ComposeArtifactID())
	if !exists || composeArtifact.Digest().IsZero() {
		return productstack.Authorization{}, ErrPlanIntegrity
	}
	product := plan.Product()
	source, err := containerengine.NewComposeReleaseSource(
		endpoint, identity, plan.SignedRelease().Manifest().ReleaseID(),
		product.ComposeProjectDirectory(), product.ComposeConfigurationPath(),
		product.EmptyEnvironmentPath(), composeArtifact.Digest(), 300,
	)
	if err != nil {
		return productstack.Authorization{}, ErrPlanIntegrity
	}
	authorization, err := productstack.NewAuthorization(
		operation, operationID, digest, attempt, ownership, source,
	)
	if err != nil {
		return productstack.Authorization{}, ErrPlanIntegrity
	}
	return authorization, nil
}

// ResolveBrainBootstrapAuthorization selects the API credential reference and
// every first-Brain/owner identity from the canonical plan. Secret bytes never
// cross this query boundary.
func (a *Application) ResolveBrainBootstrapAuthorization(
	ctx context.Context,
	digest install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
) (brainbootstrap.Authorization, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return brainbootstrap.Authorization{}, err
	}
	if operationID.IsZero() || operationID != plan.OperationID() || attempt == 0 {
		return brainbootstrap.Authorization{}, ErrPlanIntegrity
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return brainbootstrap.Authorization{}, err
	}
	product := plan.Product()
	credentialPath := ""
	for _, secret := range product.SecretFiles() {
		if secret.Purpose() == installplan.SecretAPICredential {
			credentialPath = secret.Path()
			break
		}
	}
	manifestDigest, err := install.ParseDigest(plan.SignedRelease().Manifest().Digest().Hex())
	if err != nil {
		return brainbootstrap.Authorization{}, ErrPlanIntegrity
	}
	authorization, err := brainbootstrap.NewAuthorization(brainbootstrap.AuthorizationInput{
		OperationID: operationID, ParentPlan: digest, Attempt: attempt,
		RuntimeOwnership: ownership, CoreEndpoint: product.CoreEndpoint(),
		APICredentialPath: credentialPath, InstallationID: plan.InstallationID(),
		OwnerPrincipalID: product.OwnerPrincipalID(), OwnerGrantID: product.OwnerGrantID(),
		OwnerSubjectDigest: product.OwnerSubjectDigest(), BrainID: product.InitialBrainID(),
		BrainName: product.InitialBrainName(), ReleaseDigest: manifestDigest,
		GenerationID: plan.GenerationID(),
	})
	if err != nil {
		return brainbootstrap.Authorization{}, ErrPlanIntegrity
	}
	return authorization, nil
}

// ResolveReadinessPlan returns immutable release, generation, manifest, and Compose bindings.
func (a *Application) ResolveReadinessPlan(
	ctx context.Context,
	digest install.PlanDigest,
) (installphase.ReadinessPlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.ReadinessPlan{}, err
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return installphase.ReadinessPlan{}, err
	}
	manifest := plan.SignedRelease().Manifest()
	manifestDigest, err := install.ParseDigest(manifest.Digest().Hex())
	if err != nil {
		return installphase.ReadinessPlan{}, ErrPlanIntegrity
	}
	_, coreEvidence, err := a.loadOperationEvidence(
		ctx, plan, plan.OperationID(), install.PhaseEnsureCoreAndGraph,
	)
	if err != nil || coreEvidence.VerifiedArtifactDigest().IsZero() ||
		coreEvidence.RuntimeOwnership() != ownership {
		return installphase.ReadinessPlan{}, ErrPlanIntegrity
	}
	credentialPath := ""
	for _, secret := range plan.Product().SecretFiles() {
		if secret.Purpose() == installplan.SecretAPICredential {
			credentialPath = secret.Path()
			break
		}
	}
	if credentialPath == "" {
		return installphase.ReadinessPlan{}, ErrPlanIntegrity
	}
	return installphase.ReadinessPlan{
		PlanDigest:        digest,
		ReleaseID:         manifest.ReleaseID(),
		GenerationID:      plan.GenerationID(),
		ManifestDigest:    manifestDigest,
		ComposeDigest:     coreEvidence.VerifiedArtifactDigest(),
		CoreEndpoint:      plan.Product().CoreEndpoint(),
		APICredentialPath: credentialPath,
		RuntimeOwnership:  ownership,
	}, nil
}

// ResolveAgentConfigurationPlan binds an exact operation attempt to one host merge.
func (a *Application) ResolveAgentConfigurationPlan(
	ctx context.Context,
	digest install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
) (installphase.AgentConfigurationPlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.AgentConfigurationPlan{}, err
	}
	if operationID.IsZero() || operationID != plan.OperationID() || attempt == 0 {
		return installphase.AgentConfigurationPlan{}, ErrPlanIntegrity
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return installphase.AgentConfigurationPlan{}, err
	}
	projection := plan.AgentConfiguration()
	location, err := agentconfigport.NewConfigLocation(projection.ConfigLocation())
	if err != nil {
		return installphase.AgentConfigurationPlan{}, ErrPlanIntegrity
	}
	target, err := agentconfigdomain.NewTargetForAgent(
		projection.AgentHost(), plan.InstallationID(), projection.EntryID(), projection.LauncherPath(), projection.LauncherDigest(),
	)
	if err != nil {
		return installphase.AgentConfigurationPlan{}, ErrPlanIntegrity
	}
	result, err := installphase.NewAgentConfigurationPlan(
		digest, operationID, attempt, location, target,
		projection.ExpectedManagedEntryDigest(), ownership,
	)
	if err != nil {
		return installphase.AgentConfigurationPlan{}, ErrPlanIntegrity
	}
	return result, nil
}

// ResolveRuntimePlan returns one immutable authority derived from verified
// host/discovery/catalog evidence and bound to the current operation.
func (a *Application) ResolveRuntimePlan(
	ctx context.Context,
	digest install.PlanDigest,
	operationID install.OperationID,
) (installphase.RuntimePlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.RuntimePlan{}, err
	}
	operation, hostEvidence, err := a.loadOperationEvidence(ctx, plan, operationID, install.PhaseVerifyHost)
	if err != nil || operation == nil || !operationAllowsRuntimeAuthority(operation) {
		return installphase.RuntimePlan{}, ErrRuntimeEvidenceUnavailable
	}
	authority, err := a.runtimePlans.LoadRuntimePlan(ctx, operationID, digest)
	if err == nil {
		return runtimeProjection(plan, operationID, hostEvidence.OutputDigest(), authority)
	}
	if !errors.Is(err, ErrRuntimePlanNotFound) {
		return installphase.RuntimePlan{}, err
	}
	var runtimeResource releaseinventory.Resource
	exists := false
	for _, resource := range plan.SignedRelease().Manifest().Resources() {
		if resource.ID() == plan.RuntimeCatalogResourceID() {
			runtimeResource, exists = resource, true
			break
		}
	}
	if !exists {
		return installphase.RuntimePlan{}, ErrRuntimeEvidenceUnavailable
	}
	evidence, err := a.runtimeEvidence.ResolveRuntimeEvidence(ctx, RuntimeEvidenceRequest{
		OperationID: operationID, ParentPlanDigest: digest,
		RuntimeCatalogID: plan.RuntimeCatalogResourceID(), RuntimeCatalogDigest: plan.RuntimeCatalogDigest(),
		SignedHostPlan: plan.SignedHostPlan(), HostEvidenceDigest: hostEvidence.OutputDigest(),
		HostStorageTarget: plan.HostStorageTarget(), RuntimeEndpoint: plan.RuntimeEndpoint(),
		SignedRelease: plan.SignedRelease(), RuntimeCatalogResource: runtimeResource,
	})
	if err != nil || !evidence.HostEvidenceDigest().Equal(hostEvidence.OutputDigest()) ||
		!evidence.CatalogResourceEvidenceDigest().Equal(plan.RuntimeCatalogDigest()) {
		return installphase.RuntimePlan{}, ErrRuntimeEvidenceUnavailable
	}
	nested, err := runtimeinstall.NewPlanV1(evidence.Host(), evidence.Discovery(), evidence.Catalog())
	if err != nil {
		return installphase.RuntimePlan{}, ErrRuntimePlanIntegrity
	}
	nestedCatalog, err := install.ParseDigest(nested.CatalogDigest().String())
	if err != nil || !nestedCatalog.Equal(evidence.SignedCatalogEvidenceDigest()) {
		return installphase.RuntimePlan{}, ErrRuntimePlanIntegrity
	}
	authority, err = NewRuntimePlanAuthority(
		operationID, digest, nested, evidence.HostEvidenceDigest(),
		evidence.DiscoveryEvidenceDigest(), evidence.CatalogResourceEvidenceDigest(),
		evidence.SignedCatalogEvidenceDigest(),
	)
	if err != nil {
		return installphase.RuntimePlan{}, err
	}
	if err := a.runtimePlans.SaveRuntimePlan(ctx, authority); err != nil {
		if !errors.Is(err, ErrRuntimePlanConflict) {
			return installphase.RuntimePlan{}, err
		}
		persisted, loadError := a.runtimePlans.LoadRuntimePlan(ctx, operationID, digest)
		if loadError != nil || !persisted.Equal(authority) {
			return installphase.RuntimePlan{}, ErrRuntimePlanConflict
		}
		authority = persisted
	}
	return runtimeProjection(plan, operationID, hostEvidence.OutputDigest(), authority)
}

// ResolveActivationPlan derives dynamic activation inputs only from the exact
// completed operation evidence and authenticated durable repositories.
func (a *Application) ResolveActivationPlan(
	ctx context.Context,
	digest install.PlanDigest,
	operationID install.OperationID,
) (installphase.ActivationPlan, error) {
	plan, err := a.load(ctx, digest)
	if err != nil {
		return installphase.ActivationPlan{}, err
	}
	ownership, err := a.resolvedRuntimeOwnership(ctx, plan)
	if err != nil {
		return installphase.ActivationPlan{}, err
	}
	operation, readinessEvidence, err := a.loadOperationEvidence(ctx, plan, operationID, install.PhaseVerifyReadiness)
	if err != nil || !operationAllowsActivation(operation) || !readinessEvidence.RuntimeOwnership().Resolved() ||
		readinessEvidence.RuntimeOwnership() != ownership {
		return installphase.ActivationPlan{}, ErrActivationEvidenceUnavailable
	}
	receipt, err := a.readinessReceipts.LoadReadinessReceipt(ctx, readinessEvidence.OutputDigest())
	if err != nil {
		return installphase.ActivationPlan{}, err
	}
	manifest := plan.SignedRelease().Manifest()
	manifestDigest, err := install.ParseDigest(manifest.Digest().Hex())
	if err != nil {
		return installphase.ActivationPlan{}, ErrPlanIntegrity
	}
	_, coreEvidence, err := a.loadOperationEvidence(ctx, plan, operationID, install.PhaseEnsureCoreAndGraph)
	if err != nil || coreEvidence.VerifiedArtifactDigest().IsZero() ||
		coreEvidence.RuntimeOwnership() != ownership {
		return installphase.ActivationPlan{}, ErrActivationEvidenceUnavailable
	}
	composeDigest := coreEvidence.VerifiedArtifactDigest()
	if receipt.IsZero() || !receipt.Digest().Equal(readinessEvidence.OutputDigest()) ||
		receipt.OperationID() != operationID || !receipt.PlanDigest().Equal(digest) ||
		receipt.ReleaseID() != manifest.ReleaseID() || receipt.GenerationID() != plan.GenerationID() ||
		!receipt.ManifestDigest().Equal(manifestDigest) || !receipt.ComposeDigest().Equal(composeDigest) {
		return installphase.ActivationPlan{}, ErrActivationEvidenceUnavailable
	}
	snapshot, err := a.resources.Load(ctx, plan.InstallationID())
	if err != nil {
		return installphase.ActivationPlan{}, err
	}
	inventory, err := verifiedActivationInventory(snapshot, plan, operationID)
	if err != nil {
		return installphase.ActivationPlan{}, err
	}
	inventoryDigest, err := inventory.Digest()
	if err != nil || inventory.Version() == 0 || inventoryDigest.IsZero() {
		return installphase.ActivationPlan{}, ErrActivationEvidenceUnavailable
	}
	capacity := plan.Capacity()
	projections, err := capacitySecretProjections(plan.InstallationID(), plan.GenerationID())
	if err != nil {
		return installphase.ActivationPlan{}, err
	}
	return installphase.ActivationPlan{
		PlanDigest: digest, InstallationID: plan.InstallationID(), ReleaseID: manifest.ReleaseID(),
		GenerationID: plan.GenerationID(), ManifestDigest: manifestDigest, ComposeDigest: composeDigest,
		ReadinessReceiptDigest: receipt.Digest(), RuntimeEndpoint: plan.RuntimeEndpoint(),
		ReleaseSequence: manifest.Sequence(), ResourceInventoryVersion: inventory.Version(),
		ResourceInventoryDigest: inventoryDigest, SecurityEpoch: plan.SecurityEpoch(),
		RuntimeOwnership: ownership,
		CapacityCommand: artifactapp.CapacityCommand{
			OperationID: operationID.String(), ParentPlanDigest: digest,
			InstallationID: plan.InstallationID(), ReleaseID: manifest.ReleaseID(), GenerationID: plan.GenerationID(),
			Plan: plan.AcquisitionPlan(), SecretProjections: projections,
			HostCAS:          artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostCAS, Locator: capacity.HostCAS()},
			HostRelease:      artifactapp.CapacityTarget{Kind: artifactapp.CapacityHostRelease, Locator: capacity.HostRelease()},
			DockerEngine:     artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: capacity.DockerEngine()},
			DockerDataVolume: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerDataVolume, Locator: capacity.DockerDataVolume()},
		},
	}, nil
}

func capacitySecretProjections(installationID, generationID string) ([]artifactapp.SecretProjectionCapacity, error) {
	identity, err := composeplan.NewIdentity(installationID, generationID)
	if err != nil {
		return nil, ErrPlanIntegrity
	}
	capacities, ok := identity.SecretProjectionCapacities()
	if !ok || len(capacities) != 6 {
		return nil, ErrPlanIntegrity
	}
	result := make([]artifactapp.SecretProjectionCapacity, 0, len(capacities))
	for _, capacity := range capacities {
		result = append(result, artifactapp.SecretProjectionCapacity{
			Name: capacity.Name(), Purpose: capacity.Purpose(), ReservedBytes: capacity.ReservedBytes(),
		})
	}
	return result, nil
}

func operationAllowsRuntimeAuthority(operation *install.Operation) bool {
	if operation == nil || operation.CurrentPhase() < install.PhaseEnsureContainerRuntime {
		return false
	}
	switch operation.State() {
	case install.StateRunning, install.StateRebootPending, install.StateResumeVerified,
		install.StateFailedRecoverable, install.StatePausedForAdministrator, install.StateReady:
		return true
	case install.StateUnknown, install.StateCancelled, install.StateUnsupportedHost, install.StateRuntimeConflict:
		return false
	default:
		return false
	}
}

func operationAllowsActivation(operation *install.Operation) bool {
	if operation == nil || operation.CurrentPhase() != install.PhaseCommitActiveRelease {
		return false
	}
	return operation.State() == install.StateRunning || operation.State() == install.StateReady
}

func (a *Application) loadOperationEvidence(
	ctx context.Context,
	plan installplan.Plan,
	operationID install.OperationID,
	phase install.Phase,
) (*install.Operation, install.StepEvidence, error) {
	if operationID.IsZero() || operationID != a.operation || operationID != plan.OperationID() {
		return nil, install.StepEvidence{}, ErrPlanIntegrity
	}
	operation, err := a.operations.Load(ctx, operationID)
	if err != nil || operation == nil || operation.ID() != operationID || !operation.PlanDigest().Equal(plan.Digest()) {
		return nil, install.StepEvidence{}, ErrPlanIntegrity
	}
	for _, evidence := range operation.CompletedEvidence() {
		if evidence.Phase() == phase && evidence.PlanDigest().Equal(plan.Digest()) && evidence.Attempt() > 0 &&
			!evidence.InputDigest().IsZero() && !evidence.OutputDigest().IsZero() {
			return operation, evidence, nil
		}
	}
	return nil, install.StepEvidence{}, ErrPlanIntegrity
}

// resolvedRuntimeOwnership keeps pristine plans immutable: discovery decides
// ownership once, and every later projection derives it from authenticated
// EnsureContainerRuntime evidence instead of a release-build assumption.
func (a *Application) resolvedRuntimeOwnership(
	ctx context.Context,
	plan installplan.Plan,
) (install.RuntimeOwnership, error) {
	if plan.RuntimeOwnership().Resolved() {
		return plan.RuntimeOwnership(), nil
	}
	if plan.RuntimeOwnership() != install.RuntimeOwnershipUndetermined {
		return install.RuntimeOwnershipUnknown, ErrPlanIntegrity
	}
	_, evidence, err := a.loadOperationEvidence(
		ctx, plan, plan.OperationID(), install.PhaseEnsureContainerRuntime,
	)
	if err != nil || !evidence.RuntimeOwnership().Resolved() {
		return install.RuntimeOwnershipUnknown, ErrPlanIntegrity
	}
	return evidence.RuntimeOwnership(), nil
}

func runtimeProjection(
	parent installplan.Plan,
	operationID install.OperationID,
	hostEvidence install.Digest,
	authority RuntimePlanAuthority,
) (installphase.RuntimePlan, error) {
	if authority.OperationID() != operationID || !authority.ParentPlanDigest().Equal(parent.Digest()) ||
		!authority.HostEvidenceDigest().Equal(hostEvidence) ||
		!authority.CatalogResourceEvidenceDigest().Equal(parent.RuntimeCatalogDigest()) {
		return installphase.RuntimePlan{}, ErrRuntimePlanIntegrity
	}
	nested := authority.Plan()
	decoded, err := runtimeinstall.DecodePlanV1(nested.CanonicalBytes())
	catalogDigest, digestError := install.ParseDigest(decoded.CatalogDigest().String())
	if err != nil || digestError != nil || decoded.Digest() != nested.Digest() ||
		!catalogDigest.Equal(authority.SignedCatalogEvidenceDigest()) {
		return installphase.RuntimePlan{}, ErrRuntimePlanIntegrity
	}
	projection, err := installphase.NewRuntimePlan(
		parent.Digest(), decoded.CanonicalBytes(), authority.SignedCatalogEvidenceDigest(),
	)
	if err != nil {
		return installphase.RuntimePlan{}, ErrRuntimePlanIntegrity
	}
	return projection, nil
}

func verifiedActivationInventory(
	snapshot resourceinventory.Snapshot,
	plan installplan.Plan,
	operationID install.OperationID,
) (*resourceinventory.Inventory, error) {
	inventory, err := resourceinventory.Restore(snapshot)
	if err != nil || inventory.InstallationID() != plan.InstallationID() {
		return nil, ErrActivationEvidenceUnavailable
	}
	expected, err := resourceinventory.BuildPlan(
		plan.InstallationID(), plan.GenerationID(), plan.SignedRelease().Manifest().ReleaseID(),
	)
	if err != nil || len(expected) != 7 || len(snapshot.Entries) != len(expected) {
		return nil, ErrActivationEvidenceUnavailable
	}
	for _, spec := range expected {
		entry, exists := inventory.Find(spec.Name())
		actual := entry.Spec()
		if !exists || entry.State() != resourceinventory.EntryRecorded ||
			entry.CreationOperation() != operationID.String() || entry.ObjectID() == "" ||
			actual.Kind() != spec.Kind() || actual.Purpose() != spec.Purpose() ||
			actual.Name() != spec.Name() || !maps.Equal(actual.Labels(), spec.Labels()) {
			return nil, ErrActivationEvidenceUnavailable
		}
	}
	return inventory, nil
}

func (a *Application) load(ctx context.Context, digest install.PlanDigest) (installplan.Plan, error) {
	if ctx == nil || digest.IsZero() {
		return installplan.Plan{}, ErrPlanIntegrity
	}
	if err := ctx.Err(); err != nil {
		return installplan.Plan{}, err
	}
	plan, err := a.repository.Load(ctx, digest)
	if err != nil {
		return installplan.Plan{}, err
	}
	if plan.Digest().IsZero() || !plan.Digest().Equal(digest) || plan.OperationID() != a.operation ||
		len(plan.CanonicalBytes()) == 0 {
		return installplan.Plan{}, ErrPlanIntegrity
	}
	bound, err := install.BindPlan(plan.CanonicalBytes())
	if err != nil || !bound.Equal(digest) {
		return installplan.Plan{}, ErrPlanIntegrity
	}
	return plan, nil
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Only nil-capable reflection kinds need special handling.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ installphase.HostVerificationPlanQuery    = (*Application)(nil)
	_ installphase.ReleasePlanQuery             = (*Application)(nil)
	_ installphase.ArtifactAcquisitionPlanQuery = (*Application)(nil)
	_ installphase.NetworkVolumePlanQuery       = (*Application)(nil)
	_ installphase.ReadinessPlanQuery           = (*Application)(nil)
	_ installphase.AgentConfigurationPlanQuery  = (*Application)(nil)
	_ installphase.RuntimePlanQuery             = (*Application)(nil)
	_ installphase.ActivationPlanQuery          = (*Application)(nil)
	_ installphase.DirectoryPlanQuery           = (*Application)(nil)
	_ installphase.SecretPlanQuery              = (*Application)(nil)
	_ installphase.StackPlanQuery               = (*Application)(nil)
	_ installphase.BrainBootstrapPlanQuery      = (*Application)(nil)
)
