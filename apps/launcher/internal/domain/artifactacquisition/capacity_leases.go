package artifactacquisition

import (
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// LeasePurpose is a closed capacity ownership class. Keeping these classes
// separate prevents download staging from silently spending rollback or
// post-install safety capacity.
type LeasePurpose string

// Closed capacity purposes understood by the installer.
const (
	LeaseExpanded         LeasePurpose = "expanded"
	LeaseSecretProjection LeasePurpose = "secret-projection"
	LeaseRollback         LeasePurpose = "rollback"
	LeaseSafety           LeasePurpose = "safety"
)

func validLeasePurpose(value LeasePurpose) bool {
	return value == LeaseExpanded || value == LeaseSecretProjection || value == LeaseRollback || value == LeaseSafety
}

// LeaseState is the durable state of one exact pool allocation. Every adapter
// mutation has a pending state so replay never guesses whether missing bytes
// are loss or the committed side of an interrupted operation.
type LeaseState string

// Durable capacity-lease states, including every pre-effect pending boundary.
const (
	LeaseReservePending  LeaseState = "reserve-pending"
	LeaseReserved        LeaseState = "reserved"
	LeaseConsumePending  LeaseState = "consume-pending"
	LeaseConsumed        LeaseState = "consumed"
	LeaseTransferPending LeaseState = "transfer-pending"
	LeaseTransferred     LeaseState = "transferred"
	LeaseReleasePending  LeaseState = "release-pending"
	LeaseReleased        LeaseState = "released"
)

// CapacityReleaseKind binds cleanup to the lifecycle decision that authorized
// it. A replay may continue only the same kind, preventing a normal
// post-activation remainder release from being widened into uninstall or
// cancellation cleanup.
type CapacityReleaseKind string

// Closed lifecycle reasons that may authorize physical capacity release.
const (
	CapacityReleaseRemainder    CapacityReleaseKind = "remainder"
	CapacityReleaseCompensation CapacityReleaseKind = "compensation"
	CapacityReleaseUninstall    CapacityReleaseKind = "uninstall"
)

func validCapacityReleaseKind(value CapacityReleaseKind) bool {
	return value == CapacityReleaseRemainder || value == CapacityReleaseCompensation || value == CapacityReleaseUninstall
}

// StoragePool identifies a concrete backing allocation pool, not a path. ID
// must be stable across restart. Kind distinguishes the host CAS from Docker
// engine and volume pools even when an adapter proves that two share media.
type StoragePool struct {
	id   string
	kind string
}

// NewStoragePool constructs a stable physical allocation-pool identity.
func NewStoragePool(id, kind string) (StoragePool, error) {
	if !validIdentifier(id) || !validIdentifier(kind) {
		return StoragePool{}, ErrInvalidTransition
	}
	return StoragePool{id: id, kind: kind}, nil
}

// ID returns the stable adapter-proven pool identity.
func (p StoragePool) ID() string { return p.id }

// Kind returns the closed allocation-pool class.
func (p StoragePool) Kind() string { return p.kind }

// Valid reports whether the pool contains a complete safe identity.
func (p StoragePool) Valid() bool { return validIdentifier(p.id) && validIdentifier(p.kind) }

// CapacityLease is the immutable signed-plan projection for one purpose and
// one attested backing pool.
type CapacityLease struct {
	id                     string
	purpose                LeasePurpose
	owner                  string
	artifactID             string
	resourcePurpose        string
	projectionInstallation string
	projectionRelease      string
	projectionGeneration   string
	pool                   StoragePool
	bytes                  uint64
	planDigest             releaseinventory.Digest
	sourceDigest           releaseinventory.Digest
	sourceBytes            uint64
	expectedTargetDigest   releaseinventory.Digest
	targetKind             releaseinventory.ExpandedTargetKind
	targetStorageID        string
	targetAuthorityDigest  releaseinventory.Digest
	targetRoot             string
	targetDigest           releaseinventory.Digest
}

// ExpandedLeaseTarget binds installation-agnostic publisher authority to the
// exact parent-plan release root selected for this operation.
type ExpandedLeaseTarget struct {
	Kind            releaseinventory.ExpandedTargetKind
	StorageID       string
	AuthorityDigest releaseinventory.Digest
	Root            string
}

// SecretProjectionLeaseAuthority is the closed final Docker-label identity
// for one generation-pinned protected projection volume. Docker volume labels
// are immutable, so this authority must be present before capacity creates the
// volume and is bound into the lease identity.
type SecretProjectionLeaseAuthority struct {
	InstallationID string
	ReleaseID      string
	GenerationID   string
}

// NewCapacityLease projects one signed plan allocation into immutable domain authority.
func NewCapacityLease(
	operationID string,
	purpose LeasePurpose,
	owner string,
	artifactID string,
	pool StoragePool,
	bytes uint64,
	planDigest releaseinventory.Digest,
	sourceDigest releaseinventory.Digest,
	sourceBytes uint64,
	expectedTarget releaseinventory.Digest,
) (CapacityLease, error) {
	return newCapacityLease(operationID, purpose, owner, artifactID, pool, bytes, planDigest,
		sourceDigest, sourceBytes, expectedTarget, "", SecretProjectionLeaseAuthority{}, ExpandedLeaseTarget{})
}

// NewExpandedCapacityLease constructs one fully signed and parent-bound host
// release target lease. Expanded leases cannot be created through the generic
// constructor because that would omit representation and target-root authority.
func NewExpandedCapacityLease(
	operationID string,
	owner string,
	artifactID string,
	pool StoragePool,
	bytes uint64,
	planDigest releaseinventory.Digest,
	sourceDigest releaseinventory.Digest,
	sourceBytes uint64,
	expectedTarget releaseinventory.Digest,
	target ExpandedLeaseTarget,
) (CapacityLease, error) {
	return newCapacityLease(operationID, LeaseExpanded, owner, artifactID, pool, bytes, planDigest,
		sourceDigest, sourceBytes, expectedTarget, "", SecretProjectionLeaseAuthority{}, target)
}

// NewSecretProjectionCapacityLease constructs one exact engine-managed
// protected-file projection volume reservation.
func NewSecretProjectionCapacityLease(
	operationID string,
	owner string,
	volumeName string,
	resourcePurpose string,
	pool StoragePool,
	bytes uint64,
	planDigest releaseinventory.Digest,
	authority SecretProjectionLeaseAuthority,
) (CapacityLease, error) {
	return newCapacityLease(operationID, LeaseSecretProjection, owner, volumeName, pool, bytes, planDigest,
		releaseinventory.Digest{}, 0, releaseinventory.Digest{}, resourcePurpose, authority, ExpandedLeaseTarget{})
}

func newCapacityLease(
	operationID string,
	purpose LeasePurpose,
	owner string,
	artifactID string,
	pool StoragePool,
	bytes uint64,
	planDigest releaseinventory.Digest,
	sourceDigest releaseinventory.Digest,
	sourceBytes uint64,
	expectedTarget releaseinventory.Digest,
	resourcePurpose string,
	projectionAuthority SecretProjectionLeaseAuthority,
	target ExpandedLeaseTarget,
) (CapacityLease, error) {
	if !validIdentifier(operationID) || !validLeasePurpose(purpose) || !validIdentifier(owner) ||
		!pool.Valid() || bytes == 0 || bytes > maximumSafeBytes || planDigest.IsZero() ||
		((purpose == LeaseExpanded || purpose == LeaseSecretProjection) != validIdentifier(artifactID)) ||
		((purpose == LeaseExpanded) != !expectedTarget.IsZero()) ||
		!validCapacitySource(purpose, sourceDigest, sourceBytes) ||
		((purpose == LeaseSecretProjection) != validIdentifier(resourcePurpose)) ||
		!validSecretProjectionAuthority(purpose, projectionAuthority) ||
		!validExpandedLeaseTarget(purpose, sourceDigest, sourceBytes, expectedTarget, bytes, target) {
		return CapacityLease{}, ErrInvalidTransition
	}
	material := "capacity-lease\x00" + operationID + "\x00" + string(purpose) + "\x00" + owner +
		"\x00" + artifactID + "\x00" + resourcePurpose + "\x00" + projectionAuthority.InstallationID +
		"\x00" + projectionAuthority.ReleaseID + "\x00" + projectionAuthority.GenerationID +
		"\x00" + pool.kind + "\x00" + pool.id + "\x00" +
		strconv.FormatUint(bytes, 10) + "\x00" + planDigest.Hex() + "\x00" + digestText(sourceDigest) +
		"\x00" + strconv.FormatUint(sourceBytes, 10) + "\x00" + digestText(expectedTarget) +
		"\x00" + string(target.Kind) + "\x00" + target.StorageID + "\x00" + target.AuthorityDigest.Hex() + "\x00" + target.Root
	digest := sha256.Sum256([]byte(material))
	return CapacityLease{
		id: "l-" + releaseinventory.Digest(digest).Hex(), purpose: purpose, owner: owner,
		artifactID: artifactID, resourcePurpose: resourcePurpose,
		projectionInstallation: projectionAuthority.InstallationID, projectionRelease: projectionAuthority.ReleaseID,
		projectionGeneration: projectionAuthority.GenerationID, pool: pool, bytes: bytes, planDigest: planDigest,
		sourceDigest: sourceDigest, sourceBytes: sourceBytes, expectedTargetDigest: expectedTarget,
		targetKind: target.Kind, targetStorageID: target.StorageID,
		targetAuthorityDigest: target.AuthorityDigest, targetRoot: target.Root,
	}, nil
}

// ID returns the deterministic lease identity.
func (l CapacityLease) ID() string { return l.id }

// Purpose returns the lease ownership class.
func (l CapacityLease) Purpose() LeasePurpose { return l.purpose }

// Owner returns the current signed-plan owner.
func (l CapacityLease) Owner() string { return l.owner }

// ArtifactID returns the expanded artifact or projection-volume identity.
func (l CapacityLease) ArtifactID() string { return l.artifactID }

// ResourcePurpose returns the protected projection purpose, when applicable.
func (l CapacityLease) ResourcePurpose() string { return l.resourcePurpose }

// ProjectionInstallationID returns the canonical installation label authority.
func (l CapacityLease) ProjectionInstallationID() string { return l.projectionInstallation }

// ProjectionReleaseID returns the signed release label authority.
func (l CapacityLease) ProjectionReleaseID() string { return l.projectionRelease }

// ProjectionGenerationID returns the canonical generation label authority.
func (l CapacityLease) ProjectionGenerationID() string { return l.projectionGeneration }

// Pool returns the exact allocation pool.
func (l CapacityLease) Pool() StoragePool { return l.pool }

// Bytes returns the reserved byte count.
func (l CapacityLease) Bytes() uint64 { return l.bytes }

// PlanDigest returns the authorizing signed plan digest.
func (l CapacityLease) PlanDigest() releaseinventory.Digest { return l.planDigest }

// SourceDigest returns the immutable CAS object consumed by an expanded lease.
func (l CapacityLease) SourceDigest() releaseinventory.Digest { return l.sourceDigest }

// SourceBytes returns the exact signed CAS object size consumed by an expanded lease.
func (l CapacityLease) SourceBytes() uint64 { return l.sourceBytes }

// ExpectedTargetDigest returns the immutable expanded target expected after consumption.
func (l CapacityLease) ExpectedTargetDigest() releaseinventory.Digest { return l.expectedTargetDigest }

// TargetKind returns the publisher-signed target representation.
func (l CapacityLease) TargetKind() releaseinventory.ExpandedTargetKind { return l.targetKind }

// TargetStorageID returns the publisher-signed release-relative target path.
func (l CapacityLease) TargetStorageID() string { return l.targetStorageID }

// TargetAuthorityDigest returns the publisher-signed target selection digest.
func (l CapacityLease) TargetAuthorityDigest() releaseinventory.Digest {
	return l.targetAuthorityDigest
}

// TargetRoot returns the parent installation plan's exact release directory.
func (l CapacityLease) TargetRoot() string { return l.targetRoot }

// TargetDigest returns the observed expanded target digest after consumption.
func (l CapacityLease) TargetDigest() releaseinventory.Digest { return l.targetDigest }

// Valid reports whether the lease contains complete immutable authority.
func (l CapacityLease) Valid() bool {
	return validIdentifier(l.id) && validLeasePurpose(l.purpose) && validIdentifier(l.owner) &&
		l.pool.Valid() && l.bytes > 0 && l.bytes <= maximumSafeBytes && !l.planDigest.IsZero() &&
		((l.purpose == LeaseExpanded || l.purpose == LeaseSecretProjection) == validIdentifier(l.artifactID)) &&
		((l.purpose == LeaseExpanded) == !l.expectedTargetDigest.IsZero()) &&
		((l.purpose == LeaseSecretProjection) == validIdentifier(l.resourcePurpose)) &&
		validSecretProjectionAuthority(l.purpose, SecretProjectionLeaseAuthority{
			InstallationID: l.projectionInstallation, ReleaseID: l.projectionRelease, GenerationID: l.projectionGeneration,
		}) &&
		validCapacitySource(l.purpose, l.sourceDigest, l.sourceBytes) &&
		validExpandedLeaseTarget(l.purpose, l.sourceDigest, l.sourceBytes, l.expectedTargetDigest, l.bytes, ExpandedLeaseTarget{
			Kind: l.targetKind, StorageID: l.targetStorageID, AuthorityDigest: l.targetAuthorityDigest, Root: l.targetRoot,
		})
}

func validSecretProjectionAuthority(purpose LeasePurpose, authority SecretProjectionLeaseAuthority) bool {
	valid := validCanonicalUUID(authority.InstallationID) && validCanonicalUUIDv7(authority.GenerationID) &&
		validIdentifier(authority.ReleaseID)
	if purpose == LeaseSecretProjection {
		return valid
	}
	return authority == (SecretProjectionLeaseAuthority{})
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validCanonicalUUIDv7(value string) bool {
	return validCanonicalUUID(value) && value[14] == '7' &&
		(value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b')
}

func validCapacitySource(purpose LeasePurpose, digest releaseinventory.Digest, bytes uint64) bool {
	if purpose == LeaseExpanded {
		return !digest.IsZero() && bytes > 0 && bytes <= maximumSafeBytes
	}
	return digest.IsZero() && bytes == 0
}

func validExpandedLeaseTarget(
	purpose LeasePurpose,
	sourceDigest releaseinventory.Digest,
	sourceBytes uint64,
	targetDigest releaseinventory.Digest,
	targetBytes uint64,
	target ExpandedLeaseTarget,
) bool {
	if purpose != LeaseExpanded {
		return target == (ExpandedLeaseTarget{})
	}
	if target.Root == "" || len(target.Root) > 4096 || strings.ContainsAny(target.Root, "\x00\r\n") ||
		target.AuthorityDigest.IsZero() {
		return false
	}
	reconstructed, err := releaseinventory.NewReleaseExpandedTarget(sourceDigest, sourceBytes, releaseinventory.ReleaseExpandedTargetInput{
		Kind: target.Kind, StorageID: target.StorageID, Digest: targetDigest, Bytes: targetBytes,
	})
	return err == nil && reconstructed.AuthorityDigest().Equal(target.AuthorityDigest)
}

// CapacityConsumeAuthorization binds materialization to the exact reserved
// lease and replay-stable reservation receipt that ConsumePending replaced.
type CapacityConsumeAuthorization struct {
	lease                 CapacityLease
	receiptToken          string
	receiptAllocatedBytes uint64
}

// RestoreCapacityConsumeAuthorization reconstructs an authorization only from
// an authenticated target journal's exact lease and receipt projection.
func RestoreCapacityConsumeAuthorization(
	lease CapacityLease,
	receiptToken string,
	receiptAllocatedBytes ...uint64,
) (CapacityConsumeAuthorization, error) {
	allocated := lease.bytes
	if len(receiptAllocatedBytes) == 1 {
		allocated = receiptAllocatedBytes[0]
	} else if len(receiptAllocatedBytes) > 1 {
		return CapacityConsumeAuthorization{}, ErrInvalidTransition
	}
	value := CapacityConsumeAuthorization{lease: lease, receiptToken: receiptToken, receiptAllocatedBytes: allocated}
	if !value.Valid() {
		return CapacityConsumeAuthorization{}, ErrInvalidTransition
	}
	return value, nil
}

// Lease returns the immutable expanded allocation authority.
func (a CapacityConsumeAuthorization) Lease() CapacityLease { return a.lease }

// ReceiptToken returns the exact reservation receipt that materialization consumes.
func (a CapacityConsumeAuthorization) ReceiptToken() string { return a.receiptToken }

// ReceiptAllocatedBytes returns the reservation's measured allocated blocks.
func (a CapacityConsumeAuthorization) ReceiptAllocatedBytes() uint64 { return a.receiptAllocatedBytes }

// Valid reports whether the authorization can be used at a materialization boundary.
func (a CapacityConsumeAuthorization) Valid() bool {
	return a.lease.Valid() && a.lease.purpose == LeaseExpanded && validIdentifier(a.receiptToken) &&
		a.receiptAllocatedBytes >= a.lease.bytes && a.receiptAllocatedBytes <= maximumSafeBytes
}

// LeaseReceipt is an adapter observation for one physical or engine-backed
// allocation. Pool and bytes are repeated to detect substitution on replay.
type LeaseReceipt struct {
	leaseID        string
	pool           StoragePool
	bytes          uint64
	allocatedBytes uint64
	token          string
	present        bool
}

// NewLeaseReceipt constructs a physical allocation observation.
func NewLeaseReceipt(leaseID string, pool StoragePool, bytes uint64, token string, present bool) (LeaseReceipt, error) {
	return NewMeasuredLeaseReceipt(leaseID, pool, bytes, bytes, token, present)
}

// NewMeasuredLeaseReceipt preserves the distinct logical reservation length
// and physical allocated-block charge returned by a production adapter.
func NewMeasuredLeaseReceipt(leaseID string, pool StoragePool, bytes, allocatedBytes uint64, token string, present bool) (LeaseReceipt, error) {
	if !validIdentifier(leaseID) || !pool.Valid() || bytes == 0 || bytes > maximumSafeBytes ||
		allocatedBytes < bytes || allocatedBytes > maximumSafeBytes || !validIdentifier(token) {
		return LeaseReceipt{}, ErrInvalidTransition
	}
	return LeaseReceipt{leaseID: leaseID, pool: pool, bytes: bytes, allocatedBytes: allocatedBytes, token: token, present: present}, nil
}

// LeaseID returns the exact observed lease.
func (r LeaseReceipt) LeaseID() string { return r.leaseID }

// Pool returns the observed allocation pool.
func (r LeaseReceipt) Pool() StoragePool { return r.pool }

// Bytes returns the observed allocation size.
func (r LeaseReceipt) Bytes() uint64 { return r.bytes }

// AllocatedBytes returns measured backing allocation, distinct from length.
func (r LeaseReceipt) AllocatedBytes() uint64 { return r.allocatedBytes }

// Token returns the replay-stable adapter receipt identity.
func (r LeaseReceipt) Token() string { return r.token }

// Present reports whether the physical allocation remains present.
func (r LeaseReceipt) Present() bool { return r.present }

// CapacityMutationProof proves a consume/transfer result. Consume additionally
// requires an immutable target digest and measured target usage.
type CapacityMutationProof struct {
	receipt        LeaseReceipt
	targetDigest   releaseinventory.Digest
	usageBytes     uint64
	allocatedBytes uint64
	owner          string
}

// NewCapacityMutationProof constructs exact consume or transfer evidence.
func NewCapacityMutationProof(receipt LeaseReceipt, target releaseinventory.Digest, usage uint64, owner string) (CapacityMutationProof, error) {
	allocated := uint64(0)
	if !target.IsZero() {
		allocated = usage
	}
	return NewMeasuredCapacityMutationProof(receipt, target, usage, allocated, owner)
}

// NewMeasuredCapacityMutationProof records logical target bytes separately
// from allocated blocks, bounded by the exact reservation receipt.
func NewMeasuredCapacityMutationProof(receipt LeaseReceipt, target releaseinventory.Digest, usage, allocated uint64, owner string) (CapacityMutationProof, error) {
	if receipt.leaseID == "" || !validIdentifier(owner) || (target.IsZero() != (usage == 0)) ||
		(target.IsZero() != (allocated == 0)) || usage > receipt.bytes || allocated > receipt.allocatedBytes {
		return CapacityMutationProof{}, ErrInvalidTransition
	}
	return CapacityMutationProof{receipt: receipt, targetDigest: target, usageBytes: usage, allocatedBytes: allocated, owner: owner}, nil
}

// Receipt returns the underlying allocation observation.
func (p CapacityMutationProof) Receipt() LeaseReceipt { return p.receipt }

// TargetDigest returns the materialized target digest.
func (p CapacityMutationProof) TargetDigest() releaseinventory.Digest { return p.targetDigest }

// UsageBytes returns the measured materialized usage.
func (p CapacityMutationProof) UsageBytes() uint64 { return p.usageBytes }

// AllocatedBytes returns measured target blocks, distinct from logical bytes.
func (p CapacityMutationProof) AllocatedBytes() uint64 { return p.allocatedBytes }

// Owner returns the exact post-mutation owner.
func (p CapacityMutationProof) Owner() string { return p.owner }

// CapacityReleaseAuthorization is the only token with which an adapter may
// delete capacity. It captures the exact state that preceded cleanup, the
// immutable lease, the measured expanded target (when known), and both owners
// that an interrupted transfer may have left behind. Adapters must treat every
// field as a conjunction and fail closed on any foreign object.
type CapacityReleaseAuthorization struct {
	lease                 CapacityLease
	from                  LeaseState
	kind                  CapacityReleaseKind
	receiptToken          string
	receiptAllocatedBytes uint64
	targetDigest          releaseinventory.Digest
	usageBytes            uint64
	allocatedBytes        uint64
	newOwner              string
}

// Lease returns the immutable allocation authority.
func (a CapacityReleaseAuthorization) Lease() CapacityLease { return a.lease }

// FromState returns the exact durable state that authorized cleanup.
func (a CapacityReleaseAuthorization) FromState() LeaseState { return a.from }

// Kind returns the lifecycle reason for cleanup.
func (a CapacityReleaseAuthorization) Kind() CapacityReleaseKind { return a.kind }

// ReceiptToken returns the last physical allocation receipt.
func (a CapacityReleaseAuthorization) ReceiptToken() string { return a.receiptToken }

// ReceiptAllocatedBytes returns the reservation allocation being retired.
func (a CapacityReleaseAuthorization) ReceiptAllocatedBytes() uint64 { return a.receiptAllocatedBytes }

// TargetDigest returns the consumed expanded target, when present.
func (a CapacityReleaseAuthorization) TargetDigest() releaseinventory.Digest { return a.targetDigest }

// UsageBytes returns the measured target usage.
func (a CapacityReleaseAuthorization) UsageBytes() uint64 { return a.usageBytes }

// AllocatedBytes returns the exact target allocation being retired.
func (a CapacityReleaseAuthorization) AllocatedBytes() uint64 { return a.allocatedBytes }

// NewOwner returns the activation owner involved in a transfer.
func (a CapacityReleaseAuthorization) NewOwner() string { return a.newOwner }

// Valid reports whether the token was minted from a complete legal aggregate
// state. External adapters must reject invalid authorizations before probing
// or mutating storage.
func (a CapacityReleaseAuthorization) Valid() bool { return a.valid() }

// ExpectedTargetDigest returns the signed target digest from the immutable lease.
func (a CapacityReleaseAuthorization) ExpectedTargetDigest() releaseinventory.Digest {
	return a.lease.expectedTargetDigest
}

func (a CapacityReleaseAuthorization) valid() bool {
	if !a.lease.Valid() || !validCapacityReleaseKind(a.kind) || !releasablePriorState(a.from) {
		return false
	}
	return validReleaseHistory(a.lease, a.from, a.receiptToken, a.receiptAllocatedBytes,
		a.targetDigest, a.usageBytes, a.allocatedBytes, a.newOwner)
}

// CapacityLeaseSnapshot is persistence-neutral authenticated state.
type CapacityLeaseSnapshot struct {
	LeaseID                  string
	Purpose                  string
	Owner                    string
	ArtifactID               string
	ResourcePurpose          string
	ProjectionInstallationID string
	ProjectionReleaseID      string
	ProjectionGenerationID   string
	PoolID                   string
	PoolKind                 string
	Bytes                    uint64
	PlanDigest               string
	SourceDigest             string
	SourceBytes              uint64
	ExpectedTargetDigest     string
	TargetKind               string
	TargetStorageID          string
	TargetAuthorityDigest    string
	TargetRoot               string
	State                    string
	ReceiptToken             string
	ReceiptAllocatedBytes    uint64
	TargetDigest             string
	UsageBytes               uint64
	AllocatedBytes           uint64
	NewOwner                 string
	ReleaseFrom              string
	ReleaseKind              string
	ReleaseReceiptToken      string
}

// CapacityAggregateSnapshot is the complete authenticated journal payload.
type CapacityAggregateSnapshot struct {
	SchemaVersion  uint16
	OperationID    string
	PlanDigest     string
	Version        uint64
	ReleaseBatches uint64
	Leases         []CapacityLeaseSnapshot
}

type capacityLeaseState struct {
	lease                 CapacityLease
	state                 LeaseState
	receiptToken          string
	receiptAllocatedBytes uint64
	usageBytes            uint64
	allocatedBytes        uint64
	newOwner              string
	releaseFrom           LeaseState
	releaseKind           CapacityReleaseKind
	releaseReceiptToken   string
}

// CapacityAggregate journals independent leases for one operation.
type CapacityAggregate struct {
	operationID    string
	planDigest     releaseinventory.Digest
	version        uint64
	releaseBatches uint64
	leases         map[string]capacityLeaseState
}

// NewCapacityAggregate creates one operation-bound aggregate with every lease pending reservation.
func NewCapacityAggregate(operationID string, planDigest releaseinventory.Digest, leases []CapacityLease) (*CapacityAggregate, error) {
	if !validIdentifier(operationID) || planDigest.IsZero() || len(leases) == 0 || len(leases) > 8194 {
		return nil, ErrInvalidPlan
	}
	a := &CapacityAggregate{operationID: operationID, planDigest: planDigest, leases: make(map[string]capacityLeaseState, len(leases))}
	for _, lease := range leases {
		if !lease.Valid() || !lease.planDigest.Equal(planDigest) {
			return nil, ErrInvalidPlan
		}
		if _, duplicate := a.leases[lease.id]; duplicate {
			return nil, ErrInvalidPlan
		}
		a.leases[lease.id] = capacityLeaseState{lease: lease, state: LeaseReservePending}
	}
	return a, nil
}

// RestoreCapacityAggregate strictly validates every immutable lease field and
// every legal durable state. Callers must authenticate and rollback-protect
// the payload before invoking this domain restoration boundary.
func RestoreCapacityAggregate(expected []CapacityLease, snapshot CapacityAggregateSnapshot) (*CapacityAggregate, error) {
	planDigest, err := releaseinventory.ParseDigest(snapshot.PlanDigest)
	if err != nil || snapshot.SchemaVersion != 6 || len(snapshot.Leases) != len(expected) ||
		snapshot.ReleaseBatches > uint64(len(expected)) {
		return nil, ErrIntegrity
	}
	a, err := NewCapacityAggregate(snapshot.OperationID, planDigest, expected)
	if err != nil {
		return nil, ErrIntegrity
	}
	seen := make(map[string]struct{}, len(expected))
	var minimumVersion uint64
	releaseStatePresent := false
	for _, persisted := range snapshot.Leases {
		current, ok := a.leases[persisted.LeaseID]
		if !ok {
			return nil, ErrIntegrity
		}
		if _, duplicate := seen[persisted.LeaseID]; duplicate {
			return nil, ErrIntegrity
		}
		seen[persisted.LeaseID] = struct{}{}
		lease := current.lease
		if persisted.Purpose != string(lease.purpose) || persisted.Owner != lease.owner ||
			persisted.ArtifactID != lease.artifactID || persisted.ResourcePurpose != lease.resourcePurpose ||
			persisted.ProjectionInstallationID != lease.projectionInstallation ||
			persisted.ProjectionReleaseID != lease.projectionRelease ||
			persisted.ProjectionGenerationID != lease.projectionGeneration || persisted.PoolID != lease.pool.id ||
			persisted.PoolKind != lease.pool.kind || persisted.Bytes != lease.bytes ||
			persisted.PlanDigest != lease.planDigest.Hex() || persisted.SourceDigest != digestText(lease.sourceDigest) ||
			persisted.SourceBytes != lease.sourceBytes || persisted.ExpectedTargetDigest != digestText(lease.expectedTargetDigest) ||
			persisted.TargetKind != string(lease.targetKind) || persisted.TargetStorageID != lease.targetStorageID ||
			persisted.TargetAuthorityDigest != digestText(lease.targetAuthorityDigest) || persisted.TargetRoot != lease.targetRoot {
			return nil, ErrIntegrity
		}
		current.state = LeaseState(persisted.State)
		current.receiptToken, current.receiptAllocatedBytes = persisted.ReceiptToken, persisted.ReceiptAllocatedBytes
		current.usageBytes, current.allocatedBytes, current.newOwner = persisted.UsageBytes, persisted.AllocatedBytes, persisted.NewOwner
		current.releaseFrom, current.releaseKind, current.releaseReceiptToken = LeaseState(persisted.ReleaseFrom), CapacityReleaseKind(persisted.ReleaseKind), persisted.ReleaseReceiptToken
		target := releaseinventory.Digest{}
		if persisted.TargetDigest != "" {
			var parseError error
			target, parseError = releaseinventory.ParseDigest(persisted.TargetDigest)
			if parseError != nil || target.IsZero() {
				return nil, ErrIntegrity
			}
		}
		current.lease.targetDigest = target
		switch current.state {
		case LeaseReservePending:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.state, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
		case LeaseReserved:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.state, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
			minimumVersion += capacityHistorySteps(lease.purpose, current.state)
		case LeaseConsumePending:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.state, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
			minimumVersion += capacityHistorySteps(lease.purpose, current.state)
		case LeaseConsumed:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.state, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
			minimumVersion += capacityHistorySteps(lease.purpose, current.state)
		case LeaseTransferPending:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.state, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
			minimumVersion += capacityHistorySteps(lease.purpose, current.state)
		case LeaseTransferred:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.state, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
			minimumVersion += capacityHistorySteps(lease.purpose, current.state)
		case LeaseReleasePending:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.releaseFrom, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
			minimumVersion += capacityHistorySteps(lease.purpose, current.releaseFrom)
			releaseStatePresent = true
		case LeaseReleased:
			if !validReleaseMetadata(current, current.state) || !validReleaseHistory(lease, current.releaseFrom, current.receiptToken, current.receiptAllocatedBytes, target, current.usageBytes, current.allocatedBytes, current.newOwner) {
				return nil, ErrIntegrity
			}
			minimumVersion += capacityHistorySteps(lease.purpose, current.releaseFrom) + 1
			releaseStatePresent = true
		default:
			return nil, ErrIntegrity
		}
		a.leases[persisted.LeaseID] = current
	}
	if releaseStatePresent != (snapshot.ReleaseBatches > 0) {
		return nil, ErrIntegrity
	}
	minimumVersion += snapshot.ReleaseBatches
	if snapshot.Version != minimumVersion {
		return nil, ErrIntegrity
	}
	a.version, a.releaseBatches = snapshot.Version, snapshot.ReleaseBatches
	return a, nil
}

// Version returns the optimistic aggregate revision.
func (a *CapacityAggregate) Version() uint64 { return a.version }

// Leases returns deterministic copies of all immutable leases.
func (a *CapacityAggregate) Leases() []CapacityLease {
	result := make([]CapacityLease, 0, len(a.leases))
	for _, state := range a.leases {
		result = append(result, state.lease)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].id < result[j].id })
	return result
}

// State returns the durable state of one lease.
func (a *CapacityAggregate) State(leaseID string) (LeaseState, bool) {
	state, ok := a.leases[leaseID]
	return state.state, ok
}

// RecordReserved records a proven physical reservation idempotently.
func (a *CapacityAggregate) RecordReserved(lease CapacityLease, receipt LeaseReceipt) (bool, error) {
	current, ok := a.leases[lease.id]
	if !ok || current.lease != lease || !matchingReceipt(lease, receipt) {
		return false, ErrInvalidTransition
	}
	if current.state == LeaseReserved {
		if current.receiptToken != receipt.token || current.receiptAllocatedBytes != receipt.allocatedBytes || !receipt.present {
			return false, ErrInvalidTransition
		}
		return false, nil
	}
	if current.state != LeaseReservePending || !receipt.present {
		return false, ErrInvalidTransition
	}
	current.state, current.receiptToken, current.receiptAllocatedBytes = LeaseReserved, receipt.token, receipt.allocatedBytes
	a.leases[lease.id] = current
	a.version++
	return true, nil
}

// BeginConsume durably authorizes replacement of an expanded reservation with its target.
func (a *CapacityAggregate) BeginConsume(leaseID string) (CapacityConsumeAuthorization, bool, error) {
	current, ok := a.leases[leaseID]
	if !ok || current.lease.purpose != LeaseExpanded {
		return CapacityConsumeAuthorization{}, false, ErrInvalidTransition
	}
	authorization := CapacityConsumeAuthorization{
		lease: current.lease, receiptToken: current.receiptToken, receiptAllocatedBytes: current.receiptAllocatedBytes,
	}
	if current.state == LeaseConsumePending {
		if !authorization.Valid() {
			return CapacityConsumeAuthorization{}, false, ErrInvalidTransition
		}
		return authorization, false, nil
	}
	if current.state != LeaseReserved {
		return CapacityConsumeAuthorization{}, false, ErrInvalidTransition
	}
	current.state = LeaseConsumePending
	a.leases[leaseID] = current
	a.version++
	if !authorization.Valid() {
		return CapacityConsumeAuthorization{}, false, ErrInvalidTransition
	}
	return authorization, true, nil
}

// RecordConsumed records the exact materialized target and measured usage.
func (a *CapacityAggregate) RecordConsumed(leaseID string, proof CapacityMutationProof) (bool, error) {
	current, ok := a.leases[leaseID]
	if !ok || current.state != LeaseConsumePending || current.lease.purpose != LeaseExpanded ||
		!matchingReceipt(current.lease, proof.receipt) || proof.receipt.token != current.receiptToken ||
		proof.receipt.allocatedBytes != current.receiptAllocatedBytes ||
		proof.receipt.present || proof.targetDigest.IsZero() || proof.usageBytes == 0 ||
		proof.usageBytes != current.lease.bytes || proof.allocatedBytes == 0 ||
		proof.allocatedBytes > current.receiptAllocatedBytes || proof.owner != current.lease.owner ||
		!proof.targetDigest.Equal(current.lease.expectedTargetDigest) {
		return false, ErrInvalidTransition
	}
	// A missing lease is valid only here: ConsumePending proves intent was
	// durable before the adapter replaced the reservation with target bytes.
	current.state, current.lease.targetDigest, current.usageBytes, current.allocatedBytes =
		LeaseConsumed, proof.targetDigest, proof.usageBytes, proof.allocatedBytes
	a.leases[leaseID] = current
	a.version++
	return true, nil
}

// BeginTransfer durably authorizes ownership transfer to an activation owner.
func (a *CapacityAggregate) BeginTransfer(leaseID, newOwner string) (CapacityLease, bool, error) {
	current, ok := a.leases[leaseID]
	if !ok || !validIdentifier(newOwner) {
		return CapacityLease{}, false, ErrInvalidTransition
	}
	if current.state == LeaseTransferPending {
		if current.newOwner != newOwner {
			return CapacityLease{}, false, ErrInvalidTransition
		}
		return current.lease, false, nil
	}
	expectedState := LeaseReserved
	if current.lease.purpose == LeaseExpanded {
		expectedState = LeaseConsumed
	}
	if current.state != expectedState {
		return CapacityLease{}, false, ErrInvalidTransition
	}
	current.state, current.newOwner = LeaseTransferPending, newOwner
	a.leases[leaseID] = current
	a.version++
	return current.lease, true, nil
}

// RecordTransferred records exact post-transfer ownership evidence.
func (a *CapacityAggregate) RecordTransferred(leaseID string, proof CapacityMutationProof) (bool, error) {
	current, ok := a.leases[leaseID]
	if !ok || current.state != LeaseTransferPending || !matchingReceipt(current.lease, proof.receipt) ||
		proof.receipt.token != current.receiptToken || proof.receipt.allocatedBytes != current.receiptAllocatedBytes || proof.receipt.present ||
		proof.owner != current.newOwner || !validTransferTarget(current, proof) {
		return false, ErrInvalidTransition
	}
	current.state = LeaseTransferred
	a.leases[leaseID] = current
	a.version++
	return true, nil
}

// BeginReleaseRemainder settles only capacity still owned by the completed
// install operation. Consumed or in-flight transfers are rejected because a
// successful activation must have transferred every lifecycle target first.
func (a *CapacityAggregate) BeginReleaseRemainder() ([]CapacityReleaseAuthorization, error) {
	for _, current := range a.leases {
		if current.state == LeaseConsumePending || current.state == LeaseConsumed || current.state == LeaseTransferPending {
			return nil, ErrInvalidTransition
		}
	}
	return a.beginRelease(CapacityReleaseRemainder, func(current capacityLeaseState) bool {
		return current.state == LeaseReservePending || current.state == LeaseReserved
	})
}

// BeginCompensation authorizes exact removal of every allocation that an
// unfinished operation may own. Pending reserve, consume, and transfer states
// are deliberately included so cancellation after an adapter side effect can
// settle without completing the abandoned forward action.
func (a *CapacityAggregate) BeginCompensation() ([]CapacityReleaseAuthorization, error) {
	return a.beginRelease(CapacityReleaseCompensation, func(current capacityLeaseState) bool {
		return current.state != LeaseReleased
	})
}

// BeginUninstall releases only the exact owners established by activation.
// Any operation-owned or pending allocation makes the uninstall projection
// inconsistent and is rejected before release intent is recorded.
func (a *CapacityAggregate) BeginUninstall(generationID, installationID string) ([]CapacityReleaseAuthorization, error) {
	if !validIdentifier(generationID) || !validIdentifier(installationID) {
		return nil, ErrInvalidTransition
	}
	for _, current := range a.leases {
		if current.state == LeaseReleased {
			continue
		}
		expectedOwner := generationID
		if current.lease.purpose == LeaseSafety {
			expectedOwner = installationID
		}
		validTransferred := current.state == LeaseTransferred
		validReplay := current.state == LeaseReleasePending &&
			current.releaseKind == CapacityReleaseUninstall && current.releaseFrom == LeaseTransferred
		if (!validTransferred && !validReplay) || current.newOwner != expectedOwner {
			return nil, ErrInvalidTransition
		}
	}
	return a.beginRelease(CapacityReleaseUninstall, func(current capacityLeaseState) bool {
		return current.state == LeaseTransferred
	})
}

func (a *CapacityAggregate) beginRelease(
	kind CapacityReleaseKind,
	selected func(capacityLeaseState) bool,
) ([]CapacityReleaseAuthorization, error) {
	if !validCapacityReleaseKind(kind) || selected == nil {
		return nil, ErrInvalidTransition
	}
	result := make([]CapacityReleaseAuthorization, 0, len(a.leases))
	changed := false
	for id, current := range a.leases {
		//nolint:exhaustive // All non-release states are intentionally selected by the guarded default.
		switch current.state {
		case LeaseReleasePending:
			if current.releaseKind != kind {
				return nil, ErrInvalidTransition
			}
			result = append(result, releaseAuthorization(current))
		case LeaseReleased:
			continue
		default:
			if !selected(current) || !releasablePriorState(current.state) {
				continue
			}
			current.releaseFrom, current.releaseKind, current.state = current.state, kind, LeaseReleasePending
			a.leases[id] = current
			result = append(result, releaseAuthorization(current))
			changed = true
		}
	}
	if changed {
		a.version++
		a.releaseBatches++
	}
	sort.Slice(result, func(i, j int) bool { return result[i].lease.id < result[j].lease.id })
	for _, authorization := range result {
		if !authorization.valid() {
			return nil, ErrInvalidTransition
		}
	}
	return result, nil
}

// RecordReleased records that an exactly authorized allocation is absent.
func (a *CapacityAggregate) RecordReleased(authorization CapacityReleaseAuthorization, receipt LeaseReceipt) (bool, error) {
	current, ok := a.leases[authorization.lease.id]
	if !ok || current.state != LeaseReleasePending || !authorization.valid() ||
		releaseAuthorization(current) != authorization || !matchingReceipt(current.lease, receipt) ||
		current.receiptAllocatedBytes != 0 && receipt.allocatedBytes != current.receiptAllocatedBytes || receipt.present {
		return false, ErrInvalidTransition
	}
	current.state, current.releaseReceiptToken = LeaseReleased, receipt.token
	a.leases[authorization.lease.id] = current
	a.version++
	return true, nil
}

// Snapshot returns the persistence-neutral authenticated aggregate projection.
func (a *CapacityAggregate) Snapshot() CapacityAggregateSnapshot {
	result := make([]CapacityLeaseSnapshot, 0, len(a.leases))
	for _, lease := range a.Leases() {
		current := a.leases[lease.id]
		result = append(result, CapacityLeaseSnapshot{LeaseID: lease.id, Purpose: string(lease.purpose), Owner: lease.owner,
			ArtifactID: lease.artifactID, ResourcePurpose: lease.resourcePurpose,
			ProjectionInstallationID: lease.projectionInstallation, ProjectionReleaseID: lease.projectionRelease,
			ProjectionGenerationID: lease.projectionGeneration, PoolID: lease.pool.id, PoolKind: lease.pool.kind, Bytes: lease.bytes,
			PlanDigest: lease.planDigest.Hex(), SourceDigest: digestText(lease.sourceDigest), SourceBytes: lease.sourceBytes,
			ExpectedTargetDigest: digestText(lease.expectedTargetDigest), TargetKind: string(lease.targetKind),
			TargetStorageID: lease.targetStorageID, TargetAuthorityDigest: digestText(lease.targetAuthorityDigest), TargetRoot: lease.targetRoot,
			State: string(current.state), ReceiptToken: current.receiptToken, ReceiptAllocatedBytes: current.receiptAllocatedBytes,
			TargetDigest: digestText(lease.targetDigest), UsageBytes: current.usageBytes, AllocatedBytes: current.allocatedBytes, NewOwner: current.newOwner,
			ReleaseFrom: string(current.releaseFrom), ReleaseKind: string(current.releaseKind), ReleaseReceiptToken: current.releaseReceiptToken})
	}
	return CapacityAggregateSnapshot{SchemaVersion: 6, OperationID: a.operationID, PlanDigest: a.planDigest.Hex(), Version: a.version, ReleaseBatches: a.releaseBatches, Leases: result}
}

func digestText(digest releaseinventory.Digest) string {
	if digest.IsZero() {
		return ""
	}
	return digest.Hex()
}

func validTransferTarget(current capacityLeaseState, proof CapacityMutationProof) bool {
	if current.lease.purpose == LeaseExpanded {
		return !current.lease.targetDigest.IsZero() &&
			proof.targetDigest.Equal(current.lease.targetDigest) && proof.usageBytes == current.usageBytes &&
			proof.allocatedBytes == current.allocatedBytes
	}
	return proof.targetDigest.IsZero() && proof.usageBytes == 0 && proof.allocatedBytes == 0
}

func releasablePriorState(state LeaseState) bool {
	switch state {
	case LeaseReservePending, LeaseReserved, LeaseConsumePending, LeaseConsumed, LeaseTransferPending, LeaseTransferred:
		return true
	case LeaseReleasePending, LeaseReleased:
		return false
	}
	return false
}

func releaseAuthorization(current capacityLeaseState) CapacityReleaseAuthorization {
	return CapacityReleaseAuthorization{
		lease: current.lease, from: current.releaseFrom, kind: current.releaseKind,
		receiptToken: current.receiptToken, receiptAllocatedBytes: current.receiptAllocatedBytes,
		targetDigest: current.lease.targetDigest, usageBytes: current.usageBytes,
		allocatedBytes: current.allocatedBytes, newOwner: current.newOwner,
	}
}

func validReleaseMetadata(current capacityLeaseState, state LeaseState) bool {
	//nolint:exhaustive // Non-release states must have empty release metadata and share the default rule.
	switch state {
	case LeaseReleasePending:
		return releasablePriorState(current.releaseFrom) && validCapacityReleaseKind(current.releaseKind) && current.releaseReceiptToken == ""
	case LeaseReleased:
		return releasablePriorState(current.releaseFrom) && validCapacityReleaseKind(current.releaseKind) && validIdentifier(current.releaseReceiptToken)
	default:
		return current.releaseFrom == "" && current.releaseKind == "" && current.releaseReceiptToken == ""
	}
}

func validReleaseHistory(
	lease CapacityLease,
	state LeaseState,
	receiptToken string,
	receiptAllocatedBytes uint64,
	targetDigest releaseinventory.Digest,
	usageBytes uint64,
	allocatedBytes uint64,
	newOwner string,
) bool {
	//nolint:exhaustive // Release states are not valid predecessor history and intentionally fall through to false.
	switch state {
	case LeaseReservePending:
		return receiptToken == "" && receiptAllocatedBytes == 0 && targetDigest.IsZero() && usageBytes == 0 && allocatedBytes == 0 && newOwner == ""
	case LeaseReserved:
		return validIdentifier(receiptToken) && validReceiptAllocation(lease, receiptAllocatedBytes) && targetDigest.IsZero() && usageBytes == 0 && allocatedBytes == 0 && newOwner == ""
	case LeaseConsumePending:
		return lease.purpose == LeaseExpanded && validIdentifier(receiptToken) && validReceiptAllocation(lease, receiptAllocatedBytes) && targetDigest.IsZero() && usageBytes == 0 && allocatedBytes == 0 && newOwner == ""
	case LeaseConsumed:
		return lease.purpose == LeaseExpanded && validIdentifier(receiptToken) && validReceiptAllocation(lease, receiptAllocatedBytes) &&
			targetDigest.Equal(lease.expectedTargetDigest) && usageBytes == lease.bytes && allocatedBytes > 0 &&
			allocatedBytes <= receiptAllocatedBytes && newOwner == ""
	case LeaseTransferPending, LeaseTransferred:
		if !validIdentifier(receiptToken) || !validReceiptAllocation(lease, receiptAllocatedBytes) || !validIdentifier(newOwner) {
			return false
		}
		if lease.purpose == LeaseExpanded {
			return targetDigest.Equal(lease.expectedTargetDigest) && usageBytes == lease.bytes &&
				allocatedBytes > 0 && allocatedBytes <= receiptAllocatedBytes
		}
		return (lease.purpose == LeaseSecretProjection || lease.purpose == LeaseRollback || lease.purpose == LeaseSafety) &&
			targetDigest.IsZero() && usageBytes == 0 && allocatedBytes == 0
	}
	return false
}

func validReceiptAllocation(lease CapacityLease, allocated uint64) bool {
	return allocated >= lease.bytes && allocated <= maximumSafeBytes
}

func capacityHistorySteps(purpose LeasePurpose, state LeaseState) uint64 {
	//nolint:exhaustive // Release states are accounted separately and intentionally return the invalid sentinel.
	switch state {
	case LeaseReservePending:
		return 0
	case LeaseReserved:
		return 1
	case LeaseConsumePending:
		return 2
	case LeaseConsumed:
		return 3
	case LeaseTransferPending:
		if purpose == LeaseExpanded {
			return 4
		}
		return 2
	case LeaseTransferred:
		if purpose == LeaseExpanded {
			return 5
		}
		return 3
	}
	return ^uint64(0)
}

func matchingReceipt(lease CapacityLease, receipt LeaseReceipt) bool {
	return receipt.leaseID == lease.id && receipt.pool == lease.pool && receipt.bytes == lease.bytes &&
		validReceiptAllocation(lease, receipt.allocatedBytes) && validIdentifier(receipt.token)
}

// SecretProjectionCapacityInput is the parent-plan-derived, content-free
// capacity authority for one engine-managed protected projection volume.
type SecretProjectionCapacityInput struct {
	Name          string
	Purpose       string
	ReservedBytes uint64
}

// CapacityLeases projects non-download signed capacity into independent
// per-purpose, per-pool leases. Download capacity remains represented by the
// acquisition aggregate's per-artifact ReservationAllocation slots; it is
// deliberately not duplicated here.
func (p Plan) CapacityLeases(
	operationID string,
	hostCAS StoragePool,
	hostRelease StoragePool,
	dockerTarget StoragePool,
	hostReleaseRoot string,
) ([]CapacityLease, error) {
	return p.capacityLeases(operationID, p.digest, hostCAS, hostRelease, dockerTarget, hostReleaseRoot,
		SecretProjectionLeaseAuthority{}, nil)
}

// CapacityLeasesForAuthority binds every lease, including the exact six
// protected projection volumes, to the canonical parent installation plan.
func (p Plan) CapacityLeasesForAuthority(
	operationID string,
	parentPlanDigest releaseinventory.Digest,
	hostCAS StoragePool,
	hostRelease StoragePool,
	dockerTarget StoragePool,
	hostReleaseRoot string,
	projectionAuthority SecretProjectionLeaseAuthority,
	projections []SecretProjectionCapacityInput,
) ([]CapacityLease, error) {
	return p.capacityLeases(operationID, parentPlanDigest, hostCAS, hostRelease, dockerTarget, hostReleaseRoot,
		projectionAuthority, projections)
}

func (p Plan) capacityLeases(
	operationID string,
	capacityPlanDigest releaseinventory.Digest,
	hostCAS StoragePool,
	hostRelease StoragePool,
	dockerTarget StoragePool,
	hostReleaseRoot string,
	projectionAuthority SecretProjectionLeaseAuthority,
	projections []SecretProjectionCapacityInput,
) ([]CapacityLease, error) {
	if !validIdentifier(operationID) || !hostCAS.Valid() || !hostRelease.Valid() || !dockerTarget.Valid() ||
		capacityPlanDigest.IsZero() || hostReleaseRoot == "" || len(hostReleaseRoot) > 4096 ||
		strings.ContainsAny(hostReleaseRoot, "\x00\r\n") || len(projections) != 0 && len(projections) != 6 ||
		(len(projections) == 0) != (projectionAuthority == (SecretProjectionLeaseAuthority{})) ||
		len(projections) != 0 && !validSecretProjectionAuthority(LeaseSecretProjection, projectionAuthority) {
		return nil, ErrInvalidPlan
	}
	canonicalProjections := append([]SecretProjectionCapacityInput(nil), projections...)
	sort.Slice(canonicalProjections, func(i, j int) bool { return canonicalProjections[i].Name < canonicalProjections[j].Name })
	seenNames := make(map[string]struct{}, len(canonicalProjections))
	seenPurposes := make(map[string]struct{}, len(canonicalProjections))
	for _, projection := range canonicalProjections {
		if !validIdentifier(projection.Name) || !validIdentifier(projection.Purpose) ||
			projection.ReservedBytes == 0 || projection.ReservedBytes > maximumSafeBytes {
			return nil, ErrInvalidPlan
		}
		if _, duplicate := seenNames[projection.Name]; duplicate {
			return nil, ErrInvalidPlan
		}
		if _, duplicate := seenPurposes[projection.Purpose]; duplicate {
			return nil, ErrInvalidPlan
		}
		seenNames[projection.Name], seenPurposes[projection.Purpose] = struct{}{}, struct{}{}
	}
	leases := make([]CapacityLease, 0, len(p.artifacts)+len(canonicalProjections)+2)
	for _, artifact := range p.artifacts {
		if artifact.expandedBytes != 0 {
			expanded, leaseError := NewExpandedCapacityLease(
				operationID, operationID, artifact.id, hostRelease, artifact.expandedBytes, capacityPlanDigest,
				artifact.digest, artifact.size, artifact.expandedDigest, ExpandedLeaseTarget{
					Kind: artifact.targetKind, StorageID: artifact.targetStorageID,
					AuthorityDigest: artifact.targetAuthorityDigest, Root: hostReleaseRoot,
				},
			)
			if leaseError != nil {
				return nil, leaseError
			}
			leases = append(leases, expanded)
		}
	}
	for _, projection := range canonicalProjections {
		lease, leaseError := NewSecretProjectionCapacityLease(
			operationID, operationID, projection.Name, projection.Purpose, dockerTarget,
			projection.ReservedBytes, capacityPlanDigest, projectionAuthority,
		)
		if leaseError != nil {
			return nil, leaseError
		}
		leases = append(leases, lease)
	}
	rollback, err := NewCapacityLease(operationID, LeaseRollback, operationID, "", dockerTarget, p.totals.rollback,
		capacityPlanDigest, releaseinventory.Digest{}, 0, releaseinventory.Digest{})
	if err != nil {
		return nil, err
	}
	safety, err := NewCapacityLease(operationID, LeaseSafety, operationID, "", dockerTarget, p.totals.safety,
		capacityPlanDigest, releaseinventory.Digest{}, 0, releaseinventory.Digest{})
	if err != nil {
		return nil, err
	}
	leases = append(leases, rollback, safety)
	return leases, nil
}
