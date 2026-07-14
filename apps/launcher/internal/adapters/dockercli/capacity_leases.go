package dockercli

import (
	"context"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/capacityhelper"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	// CapacityHelperResourceID is the signed manifest identity reserved for the
	// constrained physical-capacity helper image.
	CapacityHelperResourceID = "capacity-helper-image"
	capacityVolumePrefix     = "agentmemory_capacity_"
	capacityImageTemplate    = `{"Architecture":{{json .Architecture}},"Id":{{json .Id}},"Os":{{json .Os}},"RepoDigests":{{json .RepoDigests}}}`
	capacityVolumeTemplate   = `{"Driver":{{json .Driver}},"Labels":{{json .Labels}},"Name":{{json .Name}},"Options":{{json .Options}},"Scope":{{json .Scope}}}`
	capacityHelperMemory     = "64m"
	capacityHelperCPUs       = "0.25"
	capacityHelperPIDs       = "16"
)

var errCapacityLeaseIntegrity = errors.New("docker capacity lease integrity failure")

// CapacityLeases is the production Docker CapacityLeasePort for dedicated
// default-local named volumes. Expanded target materialization is deliberately
// a separate capability and is not inferred by this adapter.
type CapacityLeases struct {
	executors             Executors
	endpoint              containerengine.Endpoint
	helper                capacityHelperAuthority
	releaseManifestDigest releaseinventory.Digest
	pool                  artifactacquisition.StoragePool
}

// capacityHelperAuthority is projected only from VerifiedInventory by the
// exported constructor. Keeping it private prevents callers from substituting
// an individually well-formed but unverified releaseinventory.Resource.
type capacityHelperAuthority struct {
	id        string
	kind      releaseinventory.ResourceKind
	purpose   releaseinventory.ResourcePurpose
	platform  releaseinventory.Platform
	digest    releaseinventory.Digest
	sourceRef string
}

// NewCapacityLeases binds the exact local endpoint, release-bound Docker CLI,
// signed digest-pinned helper image, verified manifest, and attested pool.
func NewCapacityLeases(
	executors Executors,
	endpoint containerengine.Endpoint,
	inventory appreleaseverify.VerifiedInventory,
	pool artifactacquisition.StoragePool,
) (*CapacityLeases, error) {
	helper, found := inventory.Resource(CapacityHelperResourceID)
	if !found {
		return nil, artifactapp.ErrReservationUnsupported
	}
	return newCapacityLeases(executors, endpoint, capacityHelperAuthority{
		id: helper.ID(), kind: helper.Kind(), purpose: helper.Purpose(), platform: helper.Platform(),
		digest: helper.Digest(), sourceRef: helper.SourceRef(),
	}, inventory.ManifestDigest(), pool)
}

func newCapacityLeases(
	executors Executors,
	endpoint containerengine.Endpoint,
	helper capacityHelperAuthority,
	releaseManifestDigest releaseinventory.Digest,
	pool artifactacquisition.StoragePool,
) (*CapacityLeases, error) {
	if !executors.valid() || endpoint.String() == "" || releaseManifestDigest.IsZero() || !pool.Valid() ||
		pool.Kind() != artifactapp.CapacityDockerEngine || !validCapacityDigestID(pool.ID(), "d-") ||
		helper.id != CapacityHelperResourceID || helper.kind != releaseinventory.ResourceKindOCIImage ||
		helper.purpose != releaseinventory.ResourcePurposeOCIPlatformManifest ||
		helper.platform.OS() != "linux" || helper.platform.Architecture() != executors.dockerAuthority.Architecture() ||
		helper.digest.IsZero() || helper.sourceRef == "" ||
		!strings.HasSuffix(helper.sourceRef, "@sha256:"+helper.digest.Hex()) ||
		releaseinventory.Digest(executors.dockerAuthority.ReleaseManifestDigest()) != releaseManifestDigest {
		return nil, artifactapp.ErrReservationUnsupported
	}
	return &CapacityLeases{
		executors: executors, endpoint: endpoint, helper: helper,
		releaseManifestDigest: releaseManifestDigest, pool: pool,
	}, nil
}

// ReserveLease creates or reuses exactly one digest-derived local volume and
// accepts success only after the helper proves non-sparse physical allocation.
func (a *CapacityLeases) ReserveLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (artifactacquisition.LeaseReceipt, error) {
	request, volumeName, labels, err := a.requestForLease(capacityhelper.OperationReserve, lease, "", "", "")
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	if err := a.verifyHelperImage(ctx); err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	present, err := a.inspectVolume(ctx, volumeName, labels)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	if !present {
		if err := a.createVolume(ctx, volumeName, labels); err != nil {
			// A concurrent exact creator is safe only after a complete reinspection.
			if exact, inspectError := a.inspectVolume(ctx, volumeName, labels); inspectError != nil || !exact {
				return artifactacquisition.LeaseReceipt{}, err
			}
		}
	}
	response, err := a.runHelper(ctx, volumeName, request)
	if err != nil || !responseMatchesRequest(response, request, lease.Owner(), "reserved") {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	return artifactacquisition.NewLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), request.ReceiptToken(), true,
	)
}

// RevalidateLease proves that the exact volume, labels, canonical metadata,
// receipt, file length, and allocated blocks still match the signed lease.
func (a *CapacityLeases) RevalidateLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
) (artifactacquisition.LeaseReceipt, error) {
	request, volumeName, labels, err := a.requestForLease(capacityhelper.OperationInspect, lease, "", "", "")
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	if err := a.verifyHelperImage(ctx); err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	present, err := a.inspectVolume(ctx, volumeName, labels)
	if err != nil || !present {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	response, err := a.runHelper(ctx, volumeName, request)
	if err != nil || !responseMatchesRequest(response, request, lease.Owner(), "reserved") {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	return artifactacquisition.NewLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), request.ReceiptToken(), true,
	)
}

// TransferLease changes only reservation metadata ownership. Expanded targets
// require the still-missing materializer contract and therefore fail closed.
func (a *CapacityLeases) TransferLease(
	ctx context.Context,
	lease artifactacquisition.CapacityLease,
	newOwner string,
) (artifactacquisition.CapacityMutationProof, error) {
	if lease.Purpose() == artifactacquisition.LeaseExpanded {
		return artifactacquisition.CapacityMutationProof{}, artifactapp.ErrReservationUnsupported
	}
	operation := capacityhelper.OperationTransfer
	if lease.Purpose() == artifactacquisition.LeaseSecretProjection {
		operation = capacityhelper.OperationActivateProjection
	}
	request, volumeName, labels, err := a.requestForLease(operation, lease, newOwner, "", "")
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, err
	}
	if err := a.verifyHelperImage(ctx); err != nil {
		return artifactacquisition.CapacityMutationProof{}, err
	}
	present, err := a.inspectVolume(ctx, volumeName, labels)
	if err != nil || !present {
		return artifactacquisition.CapacityMutationProof{}, errCapacityLeaseIntegrity
	}
	response, err := a.runHelper(ctx, volumeName, request)
	validResponse := responseMatchesRequest(response, request, newOwner, "transferred")
	if lease.Purpose() == artifactacquisition.LeaseSecretProjection {
		validResponse = responseMatchesProjectionActivation(response, request, newOwner)
	}
	if err != nil || !validResponse {
		return artifactacquisition.CapacityMutationProof{}, errCapacityLeaseIntegrity
	}
	receipt, err := artifactacquisition.NewLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), request.ReceiptToken(), false,
	)
	if err != nil {
		return artifactacquisition.CapacityMutationProof{}, errCapacityLeaseIntegrity
	}
	return artifactacquisition.NewCapacityMutationProof(
		receipt, releaseinventory.Digest{}, 0, newOwner,
	)
}

// ReleaseCapacity removes only a volume selected by an aggregate-minted
// authorization after exact Docker labels and helper metadata agree.
func (a *CapacityLeases) ReleaseCapacity(
	ctx context.Context,
	authorization artifactacquisition.CapacityReleaseAuthorization,
) (artifactacquisition.LeaseReceipt, error) {
	return a.releaseCapacity(ctx, authorization, false)
}

func (a *CapacityLeases) releaseCapacity(
	ctx context.Context,
	authorization artifactacquisition.CapacityReleaseAuthorization,
	allowUntouchedConsumePending bool,
) (artifactacquisition.LeaseReceipt, error) {
	if !authorization.Valid() {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	lease := authorization.Lease()
	if lease.Purpose() == artifactacquisition.LeaseSecretProjection &&
		(authorization.FromState() == artifactacquisition.LeaseTransferPending ||
			authorization.FromState() == artifactacquisition.LeaseTransferred) {
		return a.releaseActivatedProjection(ctx, authorization)
	}
	prior, alternate, supported := releaseProjection(authorization, allowUntouchedConsumePending)
	if !supported {
		return artifactacquisition.LeaseReceipt{}, artifactapp.ErrReservationUnsupported
	}
	request, volumeName, labels, err := a.requestForLease(
		capacityhelper.OperationDeleteProof, lease, "", alternate, prior,
	)
	if err != nil || authorization.ReceiptToken() != "" && authorization.ReceiptToken() != request.ReceiptToken() {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	if err := a.verifyHelperImage(ctx); err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	present, err := a.inspectVolume(ctx, volumeName, labels)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	if !present {
		return artifactacquisition.NewLeaseReceipt(
			lease.ID(), lease.Pool(), lease.Bytes(), request.ReceiptToken(), false,
		)
	}
	response, err := a.runHelper(ctx, volumeName, request)
	if err != nil || !responseMatchesDelete(response, request) {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	removeResult, removeError := a.runDocker(ctx, []string{
		"--host", a.endpoint.String(), "volume", "rm", "--", volumeName,
	})
	if removeError == nil && string(removeResult.StandardOutput) != volumeName+"\n" {
		removeError = errCapacityLeaseIntegrity
	}
	stillPresent, inspectError := a.inspectVolume(ctx, volumeName, labels)
	if inspectError != nil || stillPresent {
		if removeError != nil {
			return artifactacquisition.LeaseReceipt{}, removeError
		}
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	return artifactacquisition.NewLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), request.ReceiptToken(), false,
	)
}

func (a *CapacityLeases) releaseActivatedProjection(
	ctx context.Context,
	authorization artifactacquisition.CapacityReleaseAuthorization,
) (artifactacquisition.LeaseReceipt, error) {
	lease := authorization.Lease()
	if !authorization.Valid() || lease.Purpose() != artifactacquisition.LeaseSecretProjection ||
		authorization.NewOwner() == "" || !authorization.TargetDigest().IsZero() || authorization.UsageBytes() != 0 {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	operation, owner := capacityhelper.OperationInspect, ""
	if authorization.FromState() == artifactacquisition.LeaseTransferPending {
		operation, owner = capacityhelper.OperationActivateProjection, authorization.NewOwner()
	}
	request, volumeName, labels, err := a.requestForLease(operation, lease, owner, "", "")
	if err != nil || authorization.ReceiptToken() != request.ReceiptToken() {
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	if err := a.verifyHelperImage(ctx); err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	present, err := a.inspectVolume(ctx, volumeName, labels)
	if err != nil {
		return artifactacquisition.LeaseReceipt{}, err
	}
	if !present {
		return artifactacquisition.NewLeaseReceipt(
			lease.ID(), lease.Pool(), lease.Bytes(), request.ReceiptToken(), false,
		)
	}
	if authorization.FromState() == artifactacquisition.LeaseTransferPending {
		response, helperError := a.runHelper(ctx, volumeName, request)
		if helperError != nil || !responseMatchesProjectionActivation(response, request, authorization.NewOwner()) {
			return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
		}
	}
	removeResult, removeError := a.runDocker(ctx, []string{
		"--host", a.endpoint.String(), "volume", "rm", "--", volumeName,
	})
	if removeError == nil && string(removeResult.StandardOutput) != volumeName+"\n" {
		removeError = errCapacityLeaseIntegrity
	}
	stillPresent, inspectError := a.inspectVolume(ctx, volumeName, labels)
	if inspectError != nil || stillPresent {
		if removeError != nil {
			return artifactacquisition.LeaseReceipt{}, removeError
		}
		return artifactacquisition.LeaseReceipt{}, errCapacityLeaseIntegrity
	}
	return artifactacquisition.NewLeaseReceipt(
		lease.ID(), lease.Pool(), lease.Bytes(), request.ReceiptToken(), false,
	)
}

func (a *CapacityLeases) requestForLease(
	operation capacityhelper.Operation,
	lease artifactacquisition.CapacityLease,
	newOwner string,
	alternateOwner string,
	prior capacityhelper.PriorState,
) (capacityhelper.Request, string, map[string]string, error) {
	if a == nil || !a.executors.valid() || a.endpoint.String() == "" ||
		!lease.Valid() || lease.Pool().ID() != a.pool.ID() || lease.Pool().Kind() != a.pool.Kind() ||
		releaseinventory.Digest(a.executors.dockerAuthority.ReleaseManifestDigest()) != a.releaseManifestDigest {
		return capacityhelper.Request{}, "", nil, artifactapp.ErrReservationUnsupported
	}
	request, err := capacityhelper.NewRequest(capacityhelper.RequestInput{
		Operation: operation, LeaseID: lease.ID(), PlanDigest: lease.PlanDigest().Hex(),
		PoolID: lease.Pool().ID(), PoolKind: lease.Pool().Kind(), Bytes: lease.Bytes(),
		Owner: lease.Owner(), NewOwner: newOwner, AlternateOwner: alternateOwner, PriorState: prior,
	})
	if err != nil {
		return capacityhelper.Request{}, "", nil, errCapacityLeaseIntegrity
	}
	identity := releaseinventory.DigestBytes([]byte(strings.Join([]string{
		"agentmemory-capacity-volume-v1", lease.ID(), lease.PlanDigest().Hex(),
		lease.Pool().Kind(), lease.Pool().ID(), request.ReceiptToken(),
	}, "\x00"))).Hex()
	name := capacityVolumePrefix + identity
	if lease.Purpose() == artifactacquisition.LeaseSecretProjection {
		name = lease.ArtifactID()
		return request, name, map[string]string{
			composeplan.LabelInstallation: lease.ProjectionInstallationID(),
			composeplan.LabelRelease:      lease.ProjectionReleaseID(),
			composeplan.LabelGeneration:   lease.ProjectionGenerationID(),
			composeplan.LabelPurpose:      lease.ResourcePurpose(),
			composeplan.LabelManaged:      "true",
		}, nil
	}
	poolBinding := releaseinventory.DigestBytes([]byte(lease.Pool().Kind() + "\x00" + lease.Pool().ID())).Hex()
	ownerBinding := releaseinventory.DigestBytes([]byte(lease.Owner())).Hex()
	labels := map[string]string{
		"io.agentmemory.capacity.lease":   strings.TrimPrefix(lease.ID(), "l-"),
		"io.agentmemory.capacity.owner":   ownerBinding,
		"io.agentmemory.capacity.plan":    lease.PlanDigest().Hex(),
		"io.agentmemory.capacity.pool":    poolBinding,
		"io.agentmemory.capacity.receipt": strings.TrimPrefix(request.ReceiptToken(), "r-"),
		"io.agentmemory.capacity.schema":  releaseinventory.DigestBytes([]byte("v1")).Hex(),
		"io.agentmemory.managed":          releaseinventory.DigestBytes([]byte("true")).Hex(),
	}
	return request, name, labels, nil
}

func (a *CapacityLeases) verifyHelperImage(ctx context.Context) error {
	result, err := a.runDocker(ctx, []string{
		"--host", a.endpoint.String(), "image", "inspect", "--format", capacityImageTemplate,
		"--", a.helper.sourceRef,
	})
	if err != nil || len(result.StandardOutput) == 0 || rejectDuplicateJSONKeys(result.StandardOutput) != nil ||
		!hasExactJSONFields(result.StandardOutput, "Architecture", "Id", "Os", "RepoDigests") {
		return artifactapp.ErrReservationOperation
	}
	var document capacityImageDocument
	if decodeStrictJSON(result.StandardOutput, &document) != nil || document.OS != "linux" ||
		document.Architecture != a.helper.platform.Architecture() || !validSHA256ObjectID(document.ID) ||
		len(document.RepoDigests) != 1 || document.RepoDigests[0] != a.helper.sourceRef {
		return artifactapp.ErrReservationUnsupported
	}
	return nil
}

func (a *CapacityLeases) createVolume(ctx context.Context, name string, labels map[string]string) error {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	arguments := make([]string, 0, 8+2*len(keys))
	arguments = append(arguments, "--host", a.endpoint.String(), "volume", "create", "--driver", "local")
	for _, key := range keys {
		arguments = append(arguments, "--label", key+"="+labels[key])
	}
	arguments = append(arguments, "--name", name)
	result, err := a.runDocker(ctx, arguments)
	if err != nil || string(result.StandardOutput) != name+"\n" {
		return artifactapp.ErrReservationOperation
	}
	present, err := a.inspectVolume(ctx, name, labels)
	if err != nil || !present {
		return errCapacityLeaseIntegrity
	}
	return nil
}

func (a *CapacityLeases) inspectVolume(
	ctx context.Context,
	name string,
	labels map[string]string,
) (bool, error) {
	if !safeManagedName(name) || len(labels) != 5 && len(labels) != 7 {
		return false, errCapacityLeaseIntegrity
	}
	listed, err := a.runDocker(ctx, []string{
		"--host", a.endpoint.String(), "volume", "ls", "--format", "{{.Name}}", "--filter", "name=^" + name + "$",
	})
	if err != nil {
		return false, err
	}
	if len(listed.StandardOutput) == 0 {
		return false, nil
	}
	if string(listed.StandardOutput) != name+"\n" {
		return false, errCapacityLeaseIntegrity
	}
	inspected, err := a.runDocker(ctx, []string{
		"--host", a.endpoint.String(), "volume", "inspect", "--format", capacityVolumeTemplate, "--", name,
	})
	if err != nil || rejectDuplicateJSONKeys(inspected.StandardOutput) != nil ||
		!hasExactJSONFields(inspected.StandardOutput, "Driver", "Labels", "Name", "Options", "Scope") {
		return false, errCapacityLeaseIntegrity
	}
	var document capacityVolumeDocument
	if decodeStrictJSON(inspected.StandardOutput, &document) != nil || document.Name != name ||
		document.Driver != "local" || document.Scope != "local" || len(document.Options) != 0 ||
		!sameLabels(document.Labels, labels) {
		return false, errCapacityLeaseIntegrity
	}
	return true, nil
}

func (a *CapacityLeases) runHelper(
	ctx context.Context,
	volumeName string,
	request capacityhelper.Request,
) (capacityhelper.Response, error) {
	mount := "type=volume,source=" + volumeName + ",target=" + capacityhelper.MountTarget + ",volume-nocopy"
	helperArguments := request.Arguments()
	arguments := make([]string, 0, 25+len(helperArguments))
	arguments = append(arguments,
		"--host", a.endpoint.String(), "run", "--rm", "--pull", "never",
		"--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", capacityHelperPIDs,
		"--memory", capacityHelperMemory, "--cpus", capacityHelperCPUs,
		"--mount", mount, "--entrypoint", capacityhelper.Entrypoint,
		a.helper.sourceRef,
	)
	arguments = append(arguments, helperArguments...)
	result, err := a.runDocker(ctx, arguments)
	if err != nil || len(result.StandardOutput) == 0 || len(result.StandardOutput) > capacityhelper.MaximumResponseBytes {
		return capacityhelper.Response{}, artifactapp.ErrReservationOperation
	}
	response, err := capacityhelper.ParseResponseLine(result.StandardOutput)
	if err != nil {
		return capacityhelper.Response{}, errCapacityLeaseIntegrity
	}
	return response, nil
}

func (a *CapacityLeases) runDocker(
	ctx context.Context,
	arguments []string,
) (argvprocess.Result, error) {
	if ctx == nil {
		return argvprocess.Result{}, artifactapp.ErrReservationOperation
	}
	if err := ctx.Err(); err != nil {
		return argvprocess.Result{}, errors.Join(artifactapp.ErrReservationOperation, err)
	}
	runner, executable, err := a.executors.dockerBinding()
	if err != nil {
		return argvprocess.Result{}, artifactapp.ErrReservationUnsupported
	}
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		return argvprocess.Result{}, artifactapp.ErrReservationUnsupported
	}
	result, err := runner.Run(ctx, invocation)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return argvprocess.Result{}, errors.Join(artifactapp.ErrReservationOperation, err)
		}
		return argvprocess.Result{}, artifactapp.ErrReservationOperation
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumDockerJSON ||
		len(result.StandardError) != 0 {
		return argvprocess.Result{}, artifactapp.ErrReservationOperation
	}
	return result, nil
}

func releaseProjection(
	authorization artifactacquisition.CapacityReleaseAuthorization,
	allowUntouchedConsumePending bool,
) (capacityhelper.PriorState, string, bool) {
	lease := authorization.Lease()
	if !authorization.TargetDigest().IsZero() || authorization.UsageBytes() != 0 {
		return "", "", false
	}
	switch authorization.FromState() {
	case artifactacquisition.LeaseReservePending:
		return capacityhelper.PriorReservePending, "", true
	case artifactacquisition.LeaseReserved:
		return capacityhelper.PriorReserved, "", true
	case artifactacquisition.LeaseConsumePending:
		if lease.Purpose() != artifactacquisition.LeaseExpanded || !allowUntouchedConsumePending {
			return "", "", false
		}
		return capacityhelper.PriorReserved, "", true
	case artifactacquisition.LeaseTransferPending:
		if lease.Purpose() == artifactacquisition.LeaseExpanded || authorization.NewOwner() == "" {
			return "", "", false
		}
		return capacityhelper.PriorTransferPending, authorization.NewOwner(), true
	case artifactacquisition.LeaseTransferred:
		if lease.Purpose() == artifactacquisition.LeaseExpanded || authorization.NewOwner() == "" {
			return "", "", false
		}
		return capacityhelper.PriorTransferred, authorization.NewOwner(), true
	case artifactacquisition.LeaseConsumed,
		artifactacquisition.LeaseReleasePending, artifactacquisition.LeaseReleased:
		return "", "", false
	default:
		return "", "", false
	}
}

func responseMatchesRequest(
	response capacityhelper.Response,
	request capacityhelper.Request,
	owner string,
	state string,
) bool {
	return response.SchemaVersion == capacityhelper.ProtocolVersion &&
		response.Operation == string(request.Operation()) && response.LeaseID == request.LeaseID() &&
		response.PlanDigest == request.PlanDigest() && response.PoolID == request.PoolID() &&
		response.PoolKind == request.PoolKind() && response.Bytes == request.Bytes() &&
		response.ReceiptToken == request.ReceiptToken() && response.Owner == owner &&
		response.State == state && response.Present && response.FileSizeBytes == request.Bytes() &&
		response.AllocatedBlockBytes >= request.Bytes()
}

func responseMatchesDelete(response capacityhelper.Response, request capacityhelper.Request) bool {
	ownerAllowed := response.Owner == request.Owner() ||
		request.AlternateOwner() != "" && response.Owner == request.AlternateOwner()
	return response.SchemaVersion == capacityhelper.ProtocolVersion &&
		response.Operation == string(capacityhelper.OperationDeleteProof) &&
		response.LeaseID == request.LeaseID() && response.PlanDigest == request.PlanDigest() &&
		response.PoolID == request.PoolID() && response.PoolKind == request.PoolKind() &&
		response.Bytes == request.Bytes() && response.ReceiptToken == request.ReceiptToken() &&
		response.State == "delete-approved" && response.Present && ownerAllowed
}

func responseMatchesProjectionActivation(
	response capacityhelper.Response,
	request capacityhelper.Request,
	owner string,
) bool {
	return response.SchemaVersion == capacityhelper.ProtocolVersion &&
		response.Operation == string(capacityhelper.OperationActivateProjection) &&
		response.LeaseID == request.LeaseID() && response.PlanDigest == request.PlanDigest() &&
		response.PoolID == request.PoolID() && response.PoolKind == request.PoolKind() &&
		response.Bytes == request.Bytes() && response.ReceiptToken == request.ReceiptToken() &&
		response.Owner == owner && response.State == "projection-ready" && !response.Present &&
		response.FileSizeBytes == 0 && response.AllocatedBlockBytes == 0
}

func validSHA256ObjectID(value string) bool {
	return validCapacityDigestID(value, "sha256:")
}

func validCapacityDigestID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digest := strings.TrimPrefix(value, prefix)
	if len(digest) != sha256.Size*2 || digest == strings.Repeat("0", sha256.Size*2) {
		return false
	}
	for _, character := range digest {
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type capacityImageDocument struct {
	Architecture string   `json:"Architecture"`
	ID           string   `json:"Id"`
	OS           string   `json:"Os"`
	RepoDigests  []string `json:"RepoDigests"`
}

type capacityVolumeDocument struct {
	Driver  string            `json:"Driver"`
	Labels  map[string]string `json:"Labels"`
	Name    string            `json:"Name"`
	Options map[string]string `json:"Options"`
	Scope   string            `json:"Scope"`
}

var _ artifactapp.CapacityLeasePort = (*CapacityLeases)(nil)
