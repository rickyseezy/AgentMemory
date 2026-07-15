package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const maximumPrivilegeLifetime = 5 * time.Minute

var (
	// ErrPrivilegeUnavailable means the certified native prompt/helper cannot
	// authenticate and execute the closed request on this machine.
	ErrPrivilegeUnavailable = errors.New("authenticated Linux privilege helper is unavailable")
	// ErrPrivilegeDenied means the user explicitly refused the native prompt.
	ErrPrivilegeDenied = errors.New("linux privilege request was denied")
	// ErrPrivilegePolicy means device policy denied an otherwise valid request.
	ErrPrivilegePolicy = errors.New("linux privilege request is blocked by device policy")
	// ErrPrivilegeIntegrity rejects a forged, stale, replayed, or mismatched receipt.
	ErrPrivilegeIntegrity = errors.New("linux privilege receipt integrity validation failed")
)

// PrivilegeOperation is a closed helper capability. It is intentionally not a
// command name and has no arbitrary argument or environment escape hatch.
type PrivilegeOperation string

const (
	// PrivilegeConfigureRepository writes/verifies only the signed official repository.
	PrivilegeConfigureRepository PrivilegeOperation = "configure_official_repository"
	// PrivilegeInstallPackages installs/verifies the exact signed package set.
	PrivilegeInstallPackages PrivilegeOperation = "install_exact_packages"
	// PrivilegeRemoveManagedPackages stops the exact managed user service and
	// removes only vendor-runtime packages while preserving local runtime data.
	PrivilegeRemoveManagedPackages PrivilegeOperation = "remove_managed_packages_preserve_data"
	// PrivilegeConfigureSubordinateIDs atomically allocates collision-free UID/GID ranges.
	PrivilegeConfigureSubordinateIDs PrivilegeOperation = "configure_subordinate_ids"
	// PrivilegeEnableUserService validates, enables, and starts the exact rootless user unit.
	PrivilegeEnableUserService PrivilegeOperation = "enable_start_user_service"
	// PrivilegeVerifyManagedState re-proves repository, package, ID, and service receipts.
	PrivilegeVerifyManagedState PrivilegeOperation = "verify_managed_state"
)

func (o PrivilegeOperation) valid() bool {
	switch o {
	case PrivilegeConfigureRepository, PrivilegeInstallPackages, PrivilegeRemoveManagedPackages,
		PrivilegeConfigureSubordinateIDs, PrivilegeEnableUserService,
		PrivilegeVerifyManagedState:
		return true
	default:
		return false
	}
}

// Nonce is a cryptographically random, one-use helper challenge.
type Nonce [32]byte

// IsZero reports whether no challenge was supplied.
func (n Nonce) IsZero() bool { return n == Nonce{} }

// PrivilegeRequestInput is populated exclusively by the PF-006 adapter from
// LinuxAuthority and durable operation identity.
type PrivilegeRequestInput struct {
	OperationID         string
	Attempt             uint32
	Operation           PrivilegeOperation
	Authority           LinuxAuthority
	AuthorizationDigest runtimeinstall.Hash
	Nonce               Nonce
	IssuedAt            time.Time
	ExpiresAt           time.Time
	ExpectedState       runtimeinstall.Hash
}

// PrivilegeRequest is immutable typed authority sent to the native helper.
type PrivilegeRequest struct {
	operationID         string
	attempt             uint32
	operation           PrivilegeOperation
	authority           LinuxAuthority
	authorizationDigest runtimeinstall.Hash
	nonce               Nonce
	issuedAt            time.Time
	expiresAt           time.Time
	expectedState       runtimeinstall.Hash
	operationKey        runtimeinstall.Hash
	digest              runtimeinstall.Hash
}

// NewPrivilegeRequest binds one bounded helper call to the plan, principal,
// machine, attempt, nonce, expiry, and exact desired state.
func NewPrivilegeRequest(input PrivilegeRequestInput) (PrivilegeRequest, error) {
	if !validOperationID(input.OperationID) || input.Attempt == 0 || !input.Operation.valid() ||
		!input.Authority.Valid() || input.Nonce.IsZero() || input.IssuedAt.IsZero() || input.ExpiresAt.IsZero() ||
		input.IssuedAt.Location() != time.UTC || input.ExpiresAt.Location() != time.UTC ||
		!input.ExpiresAt.After(input.IssuedAt) || input.ExpiresAt.Sub(input.IssuedAt) > maximumPrivilegeLifetime ||
		input.ExpectedState.IsZero() ||
		(input.Operation == PrivilegeRemoveManagedPackages) != !input.AuthorizationDigest.IsZero() {
		return PrivilegeRequest{}, ErrPrivilegeIntegrity
	}
	request := PrivilegeRequest{
		operationID: input.OperationID, attempt: input.Attempt, operation: input.Operation,
		authority: input.Authority, authorizationDigest: input.AuthorizationDigest,
		nonce: input.Nonce, issuedAt: input.IssuedAt,
		expiresAt: input.ExpiresAt, expectedState: input.ExpectedState,
	}
	request.operationKey = request.computeOperationKey()
	request.digest = request.computeDigest()
	if request.operationKey.IsZero() || request.digest.IsZero() {
		return PrivilegeRequest{}, ErrPrivilegeIntegrity
	}
	return request, nil
}

func validOperationID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func (r PrivilegeRequest) computeOperationKey() runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Authority     string `json:"authority_digest"`
		Authorization string `json:"authorization_digest"`
		ID            string `json:"operation_id"`
		Operation     string `json:"operation"`
		Plan          string `json:"plan_digest"`
	}{
		Authority: r.authority.Digest().String(), Authorization: r.authorizationDigest.String(), ID: r.operationID,
		Operation: string(r.operation), Plan: r.authority.PlanDigest().String(),
	})
	return runtimeinstall.Sum(encoded)
}

func (r PrivilegeRequest) computeDigest() runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Attempt       uint32 `json:"attempt"`
		Authority     string `json:"authority_digest"`
		Authorization string `json:"authorization_digest"`
		ExpectedState string `json:"expected_state_digest"`
		ExpiresAt     int64  `json:"expires_at_unix_micro"`
		IssuedAt      int64  `json:"issued_at_unix_micro"`
		Machine       string `json:"machine_digest"`
		Nonce         Nonce  `json:"nonce"`
		Operation     string `json:"operation"`
		OperationID   string `json:"operation_id"`
		OperationKey  string `json:"operation_key"`
		Plan          string `json:"plan_digest"`
		Principal     string `json:"principal"`
	}{
		Attempt: r.attempt, Authority: r.authority.Digest().String(), Authorization: r.authorizationDigest.String(),
		ExpectedState: r.expectedState.String(), ExpiresAt: r.expiresAt.UnixMicro(),
		IssuedAt: r.issuedAt.UnixMicro(), Machine: r.authority.MachineDigest().String(),
		Nonce: r.nonce, Operation: string(r.operation), OperationID: r.operationID,
		OperationKey: r.operationKey.String(), Plan: r.authority.PlanDigest().String(),
		Principal: r.authority.PrincipalID(),
	})
	return runtimeinstall.Sum(encoded)
}

// OperationID returns the durable parent operation identifier.
func (r PrivilegeRequest) OperationID() string { return r.operationID }

// Attempt returns the one-based PF-006 phase attempt.
func (r PrivilegeRequest) Attempt() uint32 { return r.attempt }

// Operation returns the only requested helper capability.
func (r PrivilegeRequest) Operation() PrivilegeOperation { return r.operation }

// Authority returns immutable signed execution authority.
func (r PrivilegeRequest) Authority() LinuxAuthority { return r.authority }

// AuthorizationDigest binds separately consented destructive authority. It is
// non-zero only for managed-runtime removal and covers the exact removal plan,
// ownership record, execution-time dependency scan, and consent receipt.
func (r PrivilegeRequest) AuthorizationDigest() runtimeinstall.Hash { return r.authorizationDigest }

// Nonce returns the exact one-use helper challenge.
func (r PrivilegeRequest) Nonce() Nonce { return r.nonce }

// IssuedAt returns the trusted UTC request time.
func (r PrivilegeRequest) IssuedAt() time.Time { return r.issuedAt }

// ExpiresAt returns the bounded helper deadline.
func (r PrivilegeRequest) ExpiresAt() time.Time { return r.expiresAt }

// ExpectedState returns the precomputed exact postcondition digest.
func (r PrivilegeRequest) ExpectedState() runtimeinstall.Hash { return r.expectedState }

// OperationKey is stable across crash retry attempts and enables helper-side
// idempotency without accepting a reused nonce.
func (r PrivilegeRequest) OperationKey() runtimeinstall.Hash { return r.operationKey }

// Digest binds every request field.
func (r PrivilegeRequest) Digest() runtimeinstall.Hash { return r.digest }

// TransportInput returns a defensive constructor DTO for the canonical
// helper wire. It is data, not proof of signed authority.
func (r PrivilegeRequest) TransportInput() PrivilegeRequestInput {
	return PrivilegeRequestInput{
		OperationID: r.operationID, Attempt: r.attempt, Operation: r.operation,
		Authority: r.authority, AuthorizationDigest: r.authorizationDigest,
		Nonce: r.nonce, IssuedAt: r.issuedAt,
		ExpiresAt: r.expiresAt, ExpectedState: r.expectedState,
	}
}

// ExpectedPrivilegeState derives the only valid postcondition for one helper
// capability directly from signed authority.
func ExpectedPrivilegeState(authority LinuxAuthority, operation PrivilegeOperation) (runtimeinstall.Hash, error) {
	if !authority.Valid() || !operation.valid() {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	packages := authority.Packages()
	packageBindings := make([]string, 0, len(packages))
	for _, pkg := range packages {
		packageBindings = append(packageBindings, pkg.RepositoryID()+":"+pkg.Name()+"="+pkg.Version()+"@"+pkg.NativeReceiptDigest().String())
	}
	repository := authority.Repository()
	document := struct {
		Authority    string   `json:"authority_digest"`
		Key          string   `json:"key_digest,omitempty"`
		Metadata     string   `json:"metadata_digest,omitempty"`
		Operation    string   `json:"operation"`
		Packages     []string `json:"packages,omitempty"`
		Repository   string   `json:"repository_digest,omitempty"`
		Service      string   `json:"service_unit_digest,omitempty"`
		Subordinates uint32   `json:"subordinate_ids,omitempty"`
	}{Authority: authority.Digest().String(), Operation: string(operation)}
	switch operation {
	case PrivilegeConfigureRepository:
		document.Key = repository.SigningKeyDigest().String()
		document.Metadata = repository.MetadataDigest().String()
		document.Repository = repository.ConfigurationDigest().String()
	case PrivilegeInstallPackages:
		document.Key = repository.SigningKeyDigest().String()
		document.Metadata = repository.MetadataDigest().String()
		document.Packages = packageBindings
		document.Repository = repository.ConfigurationDigest().String()
	case PrivilegeRemoveManagedPackages:
		removed, err := ExpectedRemovedPackageStateDigest(authority)
		if err != nil {
			return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
		}
		document.Packages = []string{removed.String()}
		document.Service = authority.ServiceUnitDigest().String()
	case PrivilegeConfigureSubordinateIDs:
		document.Subordinates = authority.SubordinateIDCount()
	case PrivilegeEnableUserService:
		document.Service = authority.ServiceUnitDigest().String()
	case PrivilegeVerifyManagedState:
		document.Key = repository.SigningKeyDigest().String()
		document.Metadata = repository.MetadataDigest().String()
		document.Packages = packageBindings
		document.Repository = repository.ConfigurationDigest().String()
		document.Service = authority.ServiceUnitDigest().String()
		document.Subordinates = authority.SubordinateIDCount()
	default:
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	return runtimeinstall.Sum(encoded), nil
}

// ExpectedPackageStateDigest binds every exact name, native version, semantic
// purpose, and publisher/package-manager receipt in deterministic order.
func ExpectedPackageStateDigest(authority LinuxAuthority) (runtimeinstall.Hash, error) {
	if !authority.Valid() {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	type packageBinding struct {
		Name       string `json:"name"`
		Purpose    string `json:"purpose"`
		Receipt    string `json:"receipt_digest"`
		Repository string `json:"repository_id"`
		Version    string `json:"version"`
	}
	packages := authority.Packages()
	document := make([]packageBinding, 0, len(packages))
	for _, pkg := range packages {
		document = append(document, packageBinding{
			Name: pkg.Name(), Purpose: string(pkg.Purpose()), Receipt: pkg.NativeReceiptDigest().String(),
			Repository: pkg.RepositoryID(), Version: pkg.Version(),
		})
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	return runtimeinstall.Sum(encoded), nil
}

// ManagedRuntimePackages returns only packages authenticated by the signed
// runtime repository. Distribution prerequisites are deliberately excluded
// from removal because they may be shared by unrelated software.
func ManagedRuntimePackages(authority LinuxAuthority) ([]Package, error) {
	if !authority.Valid() {
		return nil, ErrPrivilegeIntegrity
	}
	repositoryID := authority.Repository().ID()
	packages := make([]Package, 0, len(authority.Packages()))
	for _, pkg := range authority.Packages() {
		if pkg.RepositoryID() == repositoryID {
			if pkg.Purpose() != PackagePurposeRuntime {
				return nil, ErrPrivilegeIntegrity
			}
			packages = append(packages, pkg)
		}
	}
	if len(packages) == 0 {
		return nil, ErrPrivilegeIntegrity
	}
	return packages, nil
}

// ExpectedRemovedPackageStateDigest binds exact vendor package identities to
// an absent-software/preserved-data postcondition.
func ExpectedRemovedPackageStateDigest(authority LinuxAuthority) (runtimeinstall.Hash, error) {
	packages, err := ManagedRuntimePackages(authority)
	if err != nil {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	type packageBinding struct {
		Name       string `json:"name"`
		Receipt    string `json:"receipt_digest"`
		Repository string `json:"repository_id"`
		Version    string `json:"version"`
	}
	document := struct {
		Packages      []packageBinding `json:"packages"`
		Present       bool             `json:"present"`
		PreserveData  bool             `json:"preserve_local_runtime_data"`
		ServiceActive bool             `json:"service_active"`
	}{Packages: make([]packageBinding, 0, len(packages)), PreserveData: true}
	for _, pkg := range packages {
		document.Packages = append(document.Packages, packageBinding{
			Name: pkg.Name(), Receipt: pkg.NativeReceiptDigest().String(),
			Repository: pkg.RepositoryID(), Version: pkg.Version(),
		})
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	return runtimeinstall.Sum(encoded), nil
}

// ExpectedRepositoryStateDigest binds the exact configuration, signing key,
// fingerprint, and signed metadata snapshot.
func ExpectedRepositoryStateDigest(authority LinuxAuthority) (runtimeinstall.Hash, error) {
	if !authority.Valid() {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	repository := authority.Repository()
	encoded, err := json.Marshal(struct {
		Configuration string `json:"configuration_digest"`
		Fingerprint   string `json:"key_fingerprint"`
		Key           string `json:"key_digest"`
		Metadata      string `json:"metadata_digest"`
		Repository    string `json:"repository_id"`
	}{
		Configuration: repository.ConfigurationDigest().String(), Fingerprint: repository.SigningKeyFingerprint(),
		Key: repository.SigningKeyDigest().String(), Metadata: repository.MetadataDigest().String(),
		Repository: repository.ID(),
	})
	if err != nil {
		return runtimeinstall.Hash{}, ErrPrivilegeIntegrity
	}
	return runtimeinstall.Sum(encoded), nil
}

// PrivilegeResult is the only semantic helper result.
type PrivilegeResult string

const (
	// PrivilegeResultCompleted means the exact desired state was produced.
	PrivilegeResultCompleted PrivilegeResult = "completed"
	// PrivilegeResultAlreadyApplied means idempotent re-probe proved that state.
	PrivilegeResultAlreadyApplied PrivilegeResult = "already_applied"
)

func (r PrivilegeResult) valid() bool {
	return r == PrivilegeResultCompleted || r == PrivilegeResultAlreadyApplied
}

// PrivilegeReceiptInput is emitted by the immutable helper transport. The
// signature is verified independently before any field is trusted.
type PrivilegeReceiptInput struct {
	RequestDigest          runtimeinstall.Hash
	OperationKey           runtimeinstall.Hash
	PlanDigest             runtimeinstall.Hash
	AuthorityDigest        runtimeinstall.Hash
	Operation              PrivilegeOperation
	PrincipalID            string
	MachineDigest          runtimeinstall.Hash
	Nonce                  Nonce
	ExpiresAt              time.Time
	Result                 PrivilegeResult
	ObservedState          runtimeinstall.Hash
	PackageStateDigest     runtimeinstall.Hash
	RepositoryDigest       runtimeinstall.Hash
	ServiceUnitDigest      runtimeinstall.Hash
	ServiceEnabled         bool
	ServiceActive          bool
	UserLingerEnabled      bool
	SubordinateIDs         uint32
	SubordinateUIDStart    uint32
	SubordinateGIDStart    uint32
	SubordinateStateDigest runtimeinstall.Hash
	HelperDigest           runtimeinstall.Hash
	Signature              []byte
}

// PrivilegeReceipt contains no helper stdout, paths, password, or secret.
type PrivilegeReceipt struct {
	input  PrivilegeReceiptInput
	digest runtimeinstall.Hash
}

// NewPrivilegeReceipt strictly validates and copies a signed helper receipt.
func NewPrivilegeReceipt(input PrivilegeReceiptInput) (PrivilegeReceipt, error) {
	if input.RequestDigest.IsZero() || input.OperationKey.IsZero() || input.PlanDigest.IsZero() ||
		input.AuthorityDigest.IsZero() || !input.Operation.valid() || !validIdentity(input.PrincipalID) ||
		input.MachineDigest.IsZero() || input.Nonce.IsZero() || input.ExpiresAt.IsZero() ||
		input.ExpiresAt.Location() != time.UTC || !input.Result.valid() || input.ObservedState.IsZero() ||
		input.HelperDigest.IsZero() || !validReceiptSubordinateShape(input) ||
		len(input.Signature) < 32 || len(input.Signature) > 4096 {
		return PrivilegeReceipt{}, ErrPrivilegeIntegrity
	}
	input.Signature = append([]byte(nil), input.Signature...)
	receipt := PrivilegeReceipt{input: input}
	receipt.digest = receipt.computeDigest()
	return receipt, nil
}

func validReceiptSubordinateShape(input PrivilegeReceiptInput) bool {
	present := input.SubordinateIDs != 0 || input.SubordinateUIDStart != 0 || input.SubordinateGIDStart != 0 ||
		!input.SubordinateStateDigest.IsZero()
	if input.Operation != PrivilegeConfigureSubordinateIDs && input.Operation != PrivilegeVerifyManagedState {
		return !present
	}
	if input.SubordinateIDs < minimumSubordinateIDs || input.SubordinateUIDStart < minimumSubordinateIDs ||
		input.SubordinateGIDStart < minimumSubordinateIDs || input.SubordinateStateDigest.IsZero() {
		return false
	}
	uidEnd := uint64(input.SubordinateUIDStart) + uint64(input.SubordinateIDs)
	gidEnd := uint64(input.SubordinateGIDStart) + uint64(input.SubordinateIDs)
	return uidEnd <= uint64(1)<<32 && gidEnd <= uint64(1)<<32
}

func (r PrivilegeReceipt) computeDigest() runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Authority      string          `json:"authority_digest"`
		ExpiresAt      int64           `json:"expires_at_unix_micro"`
		Helper         string          `json:"helper_digest"`
		Machine        string          `json:"machine_digest"`
		Nonce          Nonce           `json:"nonce"`
		Observed       string          `json:"observed_state_digest"`
		Operation      string          `json:"operation"`
		OperationKey   string          `json:"operation_key"`
		Packages       string          `json:"package_state_digest"`
		Plan           string          `json:"plan_digest"`
		Principal      string          `json:"principal"`
		Repository     string          `json:"repository_digest"`
		Request        string          `json:"request_digest"`
		Result         PrivilegeResult `json:"result"`
		Service        string          `json:"service_unit_digest"`
		ServiceActive  bool            `json:"service_active"`
		ServiceEnabled bool            `json:"service_enabled"`
		SubIDs         uint32          `json:"subordinate_ids"`
		SubGIDStart    uint32          `json:"subordinate_gid_start"`
		SubState       string          `json:"subordinate_state_digest"`
		SubUIDStart    uint32          `json:"subordinate_uid_start"`
		UserLinger     bool            `json:"user_linger_enabled"`
	}{
		Authority: r.input.AuthorityDigest.String(), ExpiresAt: r.input.ExpiresAt.UnixMicro(),
		Helper: r.input.HelperDigest.String(), Machine: r.input.MachineDigest.String(), Nonce: r.input.Nonce,
		Observed: r.input.ObservedState.String(), Operation: string(r.input.Operation),
		OperationKey: r.input.OperationKey.String(), Packages: r.input.PackageStateDigest.String(),
		Plan: r.input.PlanDigest.String(), Principal: r.input.PrincipalID,
		Repository: r.input.RepositoryDigest.String(), Request: r.input.RequestDigest.String(),
		Result: r.input.Result, Service: r.input.ServiceUnitDigest.String(),
		ServiceActive: r.input.ServiceActive, ServiceEnabled: r.input.ServiceEnabled,
		SubIDs:      r.input.SubordinateIDs,
		SubGIDStart: r.input.SubordinateGIDStart, SubState: r.input.SubordinateStateDigest.String(),
		SubUIDStart: r.input.SubordinateUIDStart, UserLinger: r.input.UserLingerEnabled,
	})
	return runtimeinstall.Sum(encoded)
}

// Matches rejects cross-operation, TOCTOU, expiry, and substitution receipts.
func (r PrivilegeReceipt) Matches(request PrivilegeRequest, now time.Time) bool {
	return !r.digest.IsZero() && now.Location() == time.UTC && !now.Before(request.IssuedAt()) &&
		now.Before(r.input.ExpiresAt) &&
		r.input.RequestDigest == request.Digest() && r.input.OperationKey == request.OperationKey() &&
		r.input.PlanDigest == request.Authority().PlanDigest() &&
		r.input.AuthorityDigest == request.Authority().Digest() && r.input.Operation == request.Operation() &&
		r.input.PrincipalID == request.Authority().PrincipalID() &&
		r.input.MachineDigest == request.Authority().MachineDigest() && r.input.Nonce == request.Nonce() &&
		r.input.ExpiresAt.Equal(request.ExpiresAt()) && r.input.ObservedState == request.ExpectedState() &&
		r.input.Result.valid() && r.matchesOperationEvidence(request.Authority())
}

func (r PrivilegeReceipt) matchesOperationEvidence(authority LinuxAuthority) bool {
	repository, repositoryError := ExpectedRepositoryStateDigest(authority)
	packages, packageError := ExpectedPackageStateDigest(authority)
	if repositoryError != nil || packageError != nil {
		return false
	}
	switch r.input.Operation {
	case PrivilegeConfigureRepository:
		return r.input.RepositoryDigest == repository &&
			r.input.PackageStateDigest.IsZero() && r.noServiceEvidence() && r.noSubordinateEvidence()
	case PrivilegeInstallPackages:
		return r.input.RepositoryDigest == repository &&
			r.input.PackageStateDigest == packages && r.noServiceEvidence() && r.noSubordinateEvidence()
	case PrivilegeRemoveManagedPackages:
		removed, err := ExpectedRemovedPackageStateDigest(authority)
		return err == nil && r.input.RepositoryDigest.IsZero() && r.input.PackageStateDigest == removed &&
			r.validRemovedServiceEvidence(authority) && r.noSubordinateEvidence()
	case PrivilegeConfigureSubordinateIDs:
		return r.input.RepositoryDigest.IsZero() && r.input.PackageStateDigest.IsZero() &&
			r.noServiceEvidence() && r.validSubordinateEvidence(authority)
	case PrivilegeEnableUserService:
		return r.input.RepositoryDigest.IsZero() && r.input.PackageStateDigest.IsZero() &&
			r.validServiceEvidence(authority) && r.noSubordinateEvidence()
	case PrivilegeVerifyManagedState:
		return r.input.RepositoryDigest == repository &&
			r.input.PackageStateDigest == packages && r.validServiceEvidence(authority) &&
			r.validSubordinateEvidence(authority)
	default:
		return false
	}
}

func (r PrivilegeReceipt) validRemovedServiceEvidence(authority LinuxAuthority) bool {
	return r.input.ServiceUnitDigest == authority.ServiceUnitDigest() &&
		!r.input.ServiceEnabled && !r.input.ServiceActive
}

func (r PrivilegeReceipt) noServiceEvidence() bool {
	return r.input.ServiceUnitDigest.IsZero() && !r.input.ServiceEnabled &&
		!r.input.ServiceActive && !r.input.UserLingerEnabled
}

func (r PrivilegeReceipt) validServiceEvidence(authority LinuxAuthority) bool {
	return r.input.ServiceUnitDigest == authority.ServiceUnitDigest() && r.input.ServiceEnabled &&
		r.input.ServiceActive && r.input.UserLingerEnabled
}

func (r PrivilegeReceipt) noSubordinateEvidence() bool {
	return r.input.SubordinateIDs == 0 && r.input.SubordinateUIDStart == 0 &&
		r.input.SubordinateGIDStart == 0 && r.input.SubordinateStateDigest.IsZero()
}

func (r PrivilegeReceipt) validSubordinateEvidence(authority LinuxAuthority) bool {
	return r.input.SubordinateIDs == authority.SubordinateIDCount() && validReceiptSubordinateShape(r.input)
}

// Digest returns a signature-independent receipt binding used by the replay ledger.
func (r PrivilegeReceipt) Digest() runtimeinstall.Hash { return r.digest }

// AuthenticationPayload returns the domain-separated, signature-independent
// bytes signed by the immutable privilege helper. Signing the receipt digest
// keeps the helper protocol bounded while binding every semantic field.
func (r PrivilegeReceipt) AuthenticationPayload() []byte {
	if r.digest.IsZero() {
		return nil
	}
	return []byte("agentmemory.runtime-helper.privilege-receipt.v1\n" + r.digest.String())
}

// Signature returns a caller-owned copy for the authenticated verifier.
func (r PrivilegeReceipt) Signature() []byte { return append([]byte(nil), r.input.Signature...) }

// TransportInput returns a defensive constructor DTO for canonical receipt
// encoding. Consumers must still verify the helper signature and request match.
func (r PrivilegeReceipt) TransportInput() PrivilegeReceiptInput {
	input := r.input
	input.Signature = append([]byte(nil), r.input.Signature...)
	return input
}

// HelperDigest returns the exact signed immutable helper binary binding.
func (r PrivilegeReceipt) HelperDigest() runtimeinstall.Hash { return r.input.HelperDigest }

// PackageStateDigest returns the exact installed package/receipt inventory.
func (r PrivilegeReceipt) PackageStateDigest() runtimeinstall.Hash {
	return r.input.PackageStateDigest
}

// RepositoryDigest returns the exact installed repository/key state.
func (r PrivilegeReceipt) RepositoryDigest() runtimeinstall.Hash { return r.input.RepositoryDigest }

// ServiceUnitDigest returns the exact installed rootless user unit state.
func (r PrivilegeReceipt) ServiceUnitDigest() runtimeinstall.Hash {
	return r.input.ServiceUnitDigest
}

// ServiceEnabled reports the authenticated user-unit enablement state.
func (r PrivilegeReceipt) ServiceEnabled() bool { return r.input.ServiceEnabled }

// ServiceActive reports the authenticated user-unit active state.
func (r PrivilegeReceipt) ServiceActive() bool { return r.input.ServiceActive }

// UserLingerEnabled reports whether the invoking user's service survives
// logout and starts after reboot without a rootful daemon or docker group.
func (r PrivilegeReceipt) UserLingerEnabled() bool { return r.input.UserLingerEnabled }

// SubordinateIDs returns the collision-checked allocated range size.
func (r PrivilegeReceipt) SubordinateIDs() uint32 { return r.input.SubordinateIDs }

// SubordinateUIDStart returns the collision-checked UID allocation start.
func (r PrivilegeReceipt) SubordinateUIDStart() uint32 { return r.input.SubordinateUIDStart }

// SubordinateGIDStart returns the collision-checked GID allocation start.
func (r PrivilegeReceipt) SubordinateGIDStart() uint32 { return r.input.SubordinateGIDStart }

// SubordinateStateDigest binds the exact root-owned subuid/subgid state that
// the authenticated helper collision-checked immediately after mutation.
func (r PrivilegeReceipt) SubordinateStateDigest() runtimeinstall.Hash {
	return r.input.SubordinateStateDigest
}

// PrivilegeBroker transports only typed requests to the immutable signed helper.
type PrivilegeBroker interface {
	Execute(context.Context, PrivilegeRequest) (PrivilegeReceipt, error)
}

// ReceiptAuthenticator verifies the helper signature, executable identity,
// IPC peer/ACL, and current helper trust policy against the same request.
type ReceiptAuthenticator interface {
	VerifyPrivilegeReceipt(context.Context, PrivilegeRequest, PrivilegeReceipt) error
}

// ReplayLedger atomically consumes one authenticated nonce/receipt binding.
type ReplayLedger interface {
	ConsumePrivilegeReceipt(context.Context, Nonce, runtimeinstall.Hash) error
}

// NonceSource produces cryptographically random challenges.
type NonceSource interface {
	NewPrivilegeNonce(context.Context) (Nonce, error)
}

// Clock supplies trusted UTC time for expiry checks.
type Clock interface {
	Now() time.Time
}
