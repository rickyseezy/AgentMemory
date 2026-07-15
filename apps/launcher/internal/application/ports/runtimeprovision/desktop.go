package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	desktopRequestMaximumLifetime = 10 * time.Minute
	desktopConsentMaximumLifetime = 30 * 24 * time.Hour
)

var (
	// ErrDesktopEvidenceIntegrity rejects malformed or contradictory native evidence.
	ErrDesktopEvidenceIntegrity = errors.New("desktop runtime evidence integrity validation failed")
	// ErrDesktopConsentUnavailable reports that no trusted consent surface exists.
	ErrDesktopConsentUnavailable = errors.New("desktop runtime consent surface is unavailable")
	// ErrDesktopConsentDeclined reports an explicit negative user decision.
	ErrDesktopConsentDeclined = errors.New("desktop runtime consent was declined")
	// ErrDesktopConsentIntegrity rejects malformed or unauthenticated consent.
	ErrDesktopConsentIntegrity = errors.New("desktop runtime consent receipt integrity validation failed")
	// ErrDesktopMutationUnavailable reports that no trusted native helper exists.
	ErrDesktopMutationUnavailable = errors.New("native desktop mutation helper is unavailable")
	// ErrDesktopMutationDenied reports a native authorization denial.
	ErrDesktopMutationDenied = errors.New("native desktop mutation was denied")
	// ErrDesktopMutationPolicy reports an operating-system policy denial.
	ErrDesktopMutationPolicy = errors.New("native desktop mutation is blocked by device policy")
	// ErrDesktopMutationIntegrity rejects malformed or unauthenticated helper evidence.
	ErrDesktopMutationIntegrity = errors.New("native desktop mutation receipt integrity validation failed")
	// ErrDesktopTermsPending reports that the visible vendor agreement remains undecided.
	ErrDesktopTermsPending = errors.New("vendor terms surface still requires an explicit decision")
)

// DesktopAuthorityResolver verifies the signed platform execution projection.
type DesktopAuthorityResolver interface {
	ResolveDesktopAuthority(context.Context, []byte) (DesktopAuthority, error)
}

// DesktopHostEvidenceInput contains independently observed host facts.
type DesktopHostEvidenceInput struct {
	Platform                        runtimeinstall.Platform
	Architecture                    runtimeinstall.Architecture
	OSProduct                       string
	OSVersion                       string
	Build                           uint32
	PrincipalID                     string
	MachineDigest                   runtimeinstall.Hash
	CPUs                            uint16
	TotalMemory                     uint64
	AvailableMemory                 uint64
	FreeDisk                        uint64
	Virtualization                  bool
	LocalFilesystem                 bool
	AtRestEncryption                bool
	EnabledWindowsFeatures          []string
	WSLVersion                      string
	InstalledWSLDistribution        string
	InstalledWSLDistributionVersion uint8
}

// DesktopHostEvidence is a privacy-safe exact host observation.
type DesktopHostEvidence struct {
	input  DesktopHostEvidenceInput
	digest runtimeinstall.Hash
}

// NewDesktopHostEvidence validates a native host observation.
func NewDesktopHostEvidence(input DesktopHostEvidenceInput) (DesktopHostEvidence, error) {
	if !validDesktopPlatformArchitecture(input.Platform, input.Architecture) ||
		!safeAuthorityIdentifier(input.OSProduct, 64) || !safeVersion(input.OSVersion) || input.Build == 0 ||
		!safePrincipal(input.PrincipalID, input.Platform) || input.MachineDigest.IsZero() || input.CPUs == 0 ||
		input.TotalMemory == 0 || input.AvailableMemory > input.TotalMemory || input.FreeDisk == 0 ||
		input.Platform == runtimeinstall.PlatformDarwin &&
			(len(input.EnabledWindowsFeatures) != 0 || input.WSLVersion != "" || input.InstalledWSLDistribution != "" ||
				input.InstalledWSLDistributionVersion != 0) ||
		input.Platform == runtimeinstall.PlatformWindows && !validObservedWindowsFeatures(input.EnabledWindowsFeatures) ||
		input.WSLVersion != "" && !safeVersion(input.WSLVersion) ||
		input.InstalledWSLDistribution != "" && !safeAuthorityIdentifier(input.InstalledWSLDistribution, 128) {
		return DesktopHostEvidence{}, ErrDesktopEvidenceIntegrity
	}
	if input.Platform == runtimeinstall.PlatformWindows &&
		(input.InstalledWSLDistribution == "") != (input.InstalledWSLDistributionVersion == 0) ||
		input.InstalledWSLDistributionVersion != 0 && input.InstalledWSLDistributionVersion != 2 {
		return DesktopHostEvidence{}, ErrDesktopEvidenceIntegrity
	}
	copyInput := input
	copyInput.EnabledWindowsFeatures = slices.Clone(input.EnabledWindowsFeatures)
	encoded, err := json.Marshal(copyInput)
	if err != nil {
		return DesktopHostEvidence{}, ErrDesktopEvidenceIntegrity
	}
	evidence := DesktopHostEvidence{input: copyInput, digest: runtimeinstall.Sum(encoded)}
	return evidence, nil
}

func validObservedWindowsFeatures(features []string) bool {
	wanted := []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"}
	if len(features) > len(wanted) {
		return false
	}
	previous := -1
	for _, feature := range features {
		index := slices.Index(wanted, feature)
		if index < 0 || index <= previous {
			return false
		}
		previous = index
	}
	return true
}

// Supports revalidates every execution-relevant host fact.
func (e DesktopHostEvidence) Supports(authority DesktopAuthority) error {
	if !authority.Valid() || e.digest.IsZero() || e.input.Platform != authority.Platform() ||
		e.input.Architecture != authority.Architecture() || e.input.OSProduct != authority.OSProduct() ||
		compareNumericVersion(e.input.OSVersion, authority.MinimumOSVersion()) < 0 ||
		compareNumericVersion(e.input.OSVersion, authority.MaximumOSVersion()) > 0 ||
		e.input.Build < authority.MinimumBuild() || e.input.Build > authority.MaximumBuild() ||
		e.input.PrincipalID != authority.PrincipalID() || e.input.MachineDigest != authority.MachineDigest() ||
		e.input.CPUs < authority.MinimumCPUs() || e.input.TotalMemory < authority.MinimumTotalMemory() ||
		e.input.AvailableMemory < authority.MinimumAvailableMemory() || e.input.FreeDisk < authority.MinimumFreeDisk() ||
		!e.input.Virtualization || !e.input.LocalFilesystem || !e.input.AtRestEncryption ||
		e.input.WSLVersion != "" && compareNumericVersion(e.input.WSLVersion, authority.MinimumWSLVersion()) < 0 ||
		e.input.InstalledWSLDistribution != "" && e.input.InstalledWSLDistribution != authority.WSLDistributionName() {
		return ErrDesktopEvidenceIntegrity
	}
	return nil
}

// PrerequisitesReady reports exact WSL feature/version readiness.
func (e DesktopHostEvidence) PrerequisitesReady(authority DesktopAuthority) bool {
	if e.Supports(authority) != nil {
		return false
	}
	if authority.Platform() == runtimeinstall.PlatformDarwin {
		return true
	}
	return slices.Equal(e.input.EnabledWindowsFeatures, authority.WindowsFeatures()) &&
		e.input.WSLVersion != "" && compareNumericVersion(e.input.WSLVersion, authority.MinimumWSLVersion()) >= 0 &&
		e.input.InstalledWSLDistribution == authority.WSLDistributionName() &&
		e.input.InstalledWSLDistributionVersion == 2
}

// Digest returns the complete immutable host observation digest.
func (e DesktopHostEvidence) Digest() runtimeinstall.Hash { return e.digest }

// DesktopHostProbe performs native read-only discovery.
type DesktopHostProbe interface {
	ProbeDesktopHost(context.Context, DesktopAuthority) (DesktopHostEvidence, error)
}

// DesktopWindowsEncryptionAttestor proves BitLocker conversion and protection
// through the native volume identity, never through a localized status string.
type DesktopWindowsEncryptionAttestor interface {
	AttestWindowsVolumeEncryption(context.Context, string) error
}

// DesktopRuntimeEvidenceInput is an explicitly addressed Docker Desktop observation.
type DesktopRuntimeEvidenceInput struct {
	Condition          runtimeinstall.RuntimeCondition
	Ownership          runtimeinstall.OwnershipDisposition
	Product            string
	RuntimeVersion     string
	EngineVersion      string
	ComposeVersion     string
	Endpoint           string
	ApplicationPresent bool
	ApplicationRunning bool
	PublisherVerified  bool
	LocalEndpoint      bool
	LinuxContainers    bool
	CloudOffload       bool
	TCPListener        bool
	UnrelatedWorkloads uint32
}

// DesktopRuntimeEvidence is a bounded Docker Desktop state observation.
type DesktopRuntimeEvidence struct {
	input  DesktopRuntimeEvidenceInput
	digest runtimeinstall.Hash
}

// NewDesktopRuntimeEvidence validates one absent or concrete observation.
func NewDesktopRuntimeEvidence(input DesktopRuntimeEvidenceInput) (DesktopRuntimeEvidence, error) {
	if input.Condition == runtimeinstall.RuntimeConditionUnknown ||
		input.Condition == runtimeinstall.RuntimeConditionAbsent &&
			(input.Ownership != runtimeinstall.OwnershipUnknown || input.Product != "" || input.RuntimeVersion != "" ||
				input.EngineVersion != "" || input.ComposeVersion != "" || input.Endpoint != "" || input.ApplicationPresent ||
				input.ApplicationRunning || input.PublisherVerified || input.LocalEndpoint || input.LinuxContainers ||
				input.CloudOffload || input.TCPListener || input.UnrelatedWorkloads != 0) ||
		input.Condition != runtimeinstall.RuntimeConditionAbsent &&
			(input.Ownership == runtimeinstall.OwnershipUnknown || !safeAuthorityIdentifier(input.Product, 128) ||
				!safeVersion(input.RuntimeVersion) || input.Endpoint == "" || !input.ApplicationPresent ||
				!input.PublisherVerified || !input.LocalEndpoint) ||
		input.Condition == runtimeinstall.RuntimeConditionRunning &&
			(!safeVersion(input.EngineVersion) || !safeVersion(input.ComposeVersion) || !input.ApplicationRunning) ||
		(input.Condition == runtimeinstall.RuntimeConditionStopped || input.Condition == runtimeinstall.RuntimeConditionDamaged) &&
			(input.EngineVersion != "" || input.ComposeVersion != "" || input.ApplicationRunning || input.LinuxContainers ||
				input.CloudOffload || input.TCPListener) {
		return DesktopRuntimeEvidence{}, ErrDesktopEvidenceIntegrity
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return DesktopRuntimeEvidence{}, ErrDesktopEvidenceIntegrity
	}
	return DesktopRuntimeEvidence{input: input, digest: runtimeinstall.Sum(encoded)}, nil
}

// Compatible proves exact local Linux-container Docker Desktop state.
func (e DesktopRuntimeEvidence) Compatible(authority DesktopAuthority) bool {
	return authority.Valid() && !e.digest.IsZero() && e.input.Condition == runtimeinstall.RuntimeConditionRunning &&
		e.input.Product == "docker_desktop" && e.input.RuntimeVersion == authority.RuntimeVersion() &&
		e.input.EngineVersion == authority.EngineVersion() && e.input.ComposeVersion == authority.ComposeVersion() &&
		e.input.Endpoint == authority.Endpoint() && e.input.ApplicationPresent && e.input.ApplicationRunning &&
		e.input.PublisherVerified && e.input.LocalEndpoint && e.input.LinuxContainers &&
		!e.input.CloudOffload && !e.input.TCPListener && e.input.UnrelatedWorkloads == authority.UnrelatedWorkloads()
}

// Digest returns the complete immutable runtime observation digest.
func (e DesktopRuntimeEvidence) Digest() runtimeinstall.Hash { return e.digest }

// Condition returns the observed runtime condition.
func (e DesktopRuntimeEvidence) Condition() runtimeinstall.RuntimeCondition { return e.input.Condition }

// Ownership returns the observed runtime ownership disposition.
func (e DesktopRuntimeEvidence) Ownership() runtimeinstall.OwnershipDisposition {
	return e.input.Ownership
}

// Workloads returns the observed unrelated workload count.
func (e DesktopRuntimeEvidence) Workloads() uint32 { return e.input.UnrelatedWorkloads }

// DesktopRuntimeInspector verifies application identity and the exact local engine endpoint.
type DesktopRuntimeInspector interface {
	InspectDesktopRuntime(context.Context, runtimeinstall.Plan, DesktopAuthority) (DesktopRuntimeEvidence, error)
}

// DesktopArtifactEvidenceInput binds acquisition/native verification to one exact file.
type DesktopArtifactEvidenceInput struct {
	AuthorityDigest   runtimeinstall.Hash
	Path              string
	SHA256            runtimeinstall.Hash
	Bytes             uint64
	SourceURL         string
	TLSVerified       bool
	PublisherKind     DesktopPublisherKind
	PublisherIdentity string
	CertificateSHA256 runtimeinstall.Hash
	NativeVerified    bool
}

// DesktopArtifactEvidence is immutable retained-artifact evidence.
type DesktopArtifactEvidence struct {
	input  DesktopArtifactEvidenceInput
	digest runtimeinstall.Hash
}

// NewDesktopArtifactEvidence validates bounded artifact evidence.
func NewDesktopArtifactEvidence(input DesktopArtifactEvidenceInput) (DesktopArtifactEvidence, error) {
	if input.AuthorityDigest.IsZero() || input.Path == "" || input.SHA256.IsZero() || input.Bytes == 0 ||
		input.SourceURL == "" || !input.TLSVerified || input.NativeVerified &&
		(input.PublisherKind == "" || input.PublisherIdentity == "" || input.CertificateSHA256.IsZero()) {
		return DesktopArtifactEvidence{}, ErrDesktopEvidenceIntegrity
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return DesktopArtifactEvidence{}, ErrDesktopEvidenceIntegrity
	}
	return DesktopArtifactEvidence{input: input, digest: runtimeinstall.Sum(encoded)}, nil
}

// AcquiredFor verifies digest, size, source, path, and authority binding.
func (e DesktopArtifactEvidence) AcquiredFor(authority DesktopAuthority) bool {
	return authority.Valid() && !e.digest.IsZero() && e.input.AuthorityDigest == authority.Digest() &&
		e.input.Path == authority.ArtifactPath() && e.input.SHA256 == authority.ArtifactSHA256() &&
		e.input.Bytes == authority.ArtifactBytes() && e.input.SourceURL == authority.ArtifactSourceURL() && e.input.TLSVerified
}

// VerifiedFor additionally requires exact native publisher evidence.
func (e DesktopArtifactEvidence) VerifiedFor(authority DesktopAuthority) bool {
	publisher := authority.Publisher()
	return e.AcquiredFor(authority) && e.input.NativeVerified && e.input.PublisherKind == publisher.Kind() &&
		e.input.PublisherIdentity == publisher.Identity() && e.input.CertificateSHA256 == publisher.CertificateSHA256()
}

// Digest returns the complete immutable artifact evidence digest.
func (e DesktopArtifactEvidence) Digest() runtimeinstall.Hash { return e.digest }

// DesktopArtifactAcquirer performs allowlisted resumable acquisition.
type DesktopArtifactAcquirer interface {
	AcquireDesktopArtifact(context.Context, DesktopAuthority) (DesktopArtifactEvidence, error)
}

// DesktopArtifactVerifier performs digest plus native publisher verification.
type DesktopArtifactVerifier interface {
	VerifyDesktopArtifact(context.Context, DesktopAuthority) (DesktopArtifactEvidence, error)
}

// DesktopWindowsSignerIdentityVerifier extracts and authenticates the exact
// Authenticode leaf certificate while the artifact is retained against replacement.
type DesktopWindowsSignerIdentityVerifier interface {
	VerifyWindowsDesktopSigner(context.Context, DesktopAuthority) (runtimeinstall.Hash, error)
}

// DesktopInstalledApplicationEvidenceInput binds native application identity
// and the signed product version to one exact desktop authority.
type DesktopInstalledApplicationEvidenceInput struct {
	AuthorityDigest   runtimeinstall.Hash
	Present           bool
	RuntimeVersion    string
	PublisherKind     DesktopPublisherKind
	PublisherIdentity string
	CertificateSHA256 runtimeinstall.Hash
	NativeVerified    bool
}

// DesktopInstalledApplicationEvidence is immutable installed-application evidence.
type DesktopInstalledApplicationEvidence struct {
	input  DesktopInstalledApplicationEvidenceInput
	digest runtimeinstall.Hash
}

// NewDesktopInstalledApplicationEvidence accepts either an exact absence
// observation or complete native publisher and signed-version evidence.
func NewDesktopInstalledApplicationEvidence(
	input DesktopInstalledApplicationEvidenceInput,
) (DesktopInstalledApplicationEvidence, error) {
	if input.AuthorityDigest.IsZero() || !input.Present &&
		(input.RuntimeVersion != "" || input.PublisherKind != "" || input.PublisherIdentity != "" ||
			!input.CertificateSHA256.IsZero() || input.NativeVerified) || input.Present &&
		(!safeVersion(input.RuntimeVersion) || input.PublisherKind == "" || input.PublisherIdentity == "" ||
			input.CertificateSHA256.IsZero() || !input.NativeVerified) {
		return DesktopInstalledApplicationEvidence{}, ErrDesktopEvidenceIntegrity
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return DesktopInstalledApplicationEvidence{}, ErrDesktopEvidenceIntegrity
	}
	return DesktopInstalledApplicationEvidence{input: input, digest: runtimeinstall.Sum(encoded)}, nil
}

// Present reports whether the exact application path exists.
func (e DesktopInstalledApplicationEvidence) Present() bool { return e.input.Present }

// RuntimeVersion returns the signed native product version when present.
func (e DesktopInstalledApplicationEvidence) RuntimeVersion() string { return e.input.RuntimeVersion }

// VerifiedFor proves exact authority, product version, and native publisher identity.
func (e DesktopInstalledApplicationEvidence) VerifiedFor(authority DesktopAuthority) bool {
	if !authority.Valid() || e.digest.IsZero() || e.input.AuthorityDigest != authority.Digest() {
		return false
	}
	if !e.input.Present {
		return true
	}
	publisher := authority.Publisher()
	return e.input.RuntimeVersion == authority.RuntimeVersion() && e.input.NativeVerified &&
		e.input.PublisherKind == publisher.Kind() && e.input.PublisherIdentity == publisher.Identity() &&
		e.input.CertificateSHA256 == publisher.CertificateSHA256()
}

// Digest returns the complete installed-application observation binding.
func (e DesktopInstalledApplicationEvidence) Digest() runtimeinstall.Hash { return e.digest }

// DesktopInstalledApplicationProbe performs native path, signed version, and
// publisher verification without launching the application.
type DesktopInstalledApplicationProbe interface {
	ProbeDesktopInstalledApplication(context.Context, DesktopAuthority) (DesktopInstalledApplicationEvidence, error)
}

// DesktopWindowsApplicationSignerIdentityVerifier authenticates the installed
// Docker Desktop executable's exact Authenticode leaf certificate.
type DesktopWindowsApplicationSignerIdentityVerifier interface {
	VerifyWindowsDesktopApplicationSigner(context.Context, DesktopAuthority) (runtimeinstall.Hash, error)
}

// DesktopConsentRequest binds one explicit decision to the full install plan and terms.
type DesktopConsentRequest struct {
	operationID string
	attempt     uint32
	authority   DesktopAuthority
	nonce       Nonce
	issuedAt    time.Time
	expiresAt   time.Time
	digest      runtimeinstall.Hash
}

// NewDesktopConsentRequest creates bounded consent authority.
func NewDesktopConsentRequest(
	operationID string,
	attempt uint32,
	authority DesktopAuthority,
	nonce Nonce,
	issuedAt time.Time,
	expiresAt time.Time,
) (DesktopConsentRequest, error) {
	if !validOperationID(operationID) || attempt == 0 || !authority.Valid() || nonce.IsZero() ||
		issuedAt.IsZero() || expiresAt.IsZero() || issuedAt.Location() != time.UTC || expiresAt.Location() != time.UTC ||
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > desktopRequestMaximumLifetime {
		return DesktopConsentRequest{}, ErrDesktopConsentIntegrity
	}
	request := DesktopConsentRequest{operationID: operationID, attempt: attempt, authority: authority,
		nonce: nonce, issuedAt: issuedAt, expiresAt: expiresAt}
	request.digest = desktopConsentRequestDigest(request)
	return request, nil
}

func desktopConsentRequestDigest(request DesktopConsentRequest) runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Operation, Authority, Plan, Terms, Principal, Machine string
		Attempt                                               uint32
		Nonce                                                 Nonce
		IssuedAt, ExpiresAt                                   int64
	}{
		Operation: request.operationID, Authority: request.authority.Digest().String(),
		Plan: request.authority.PlanDigest().String(), Terms: request.authority.Terms().Digest().String(),
		Principal: request.authority.PrincipalID(), Machine: request.authority.MachineDigest().String(),
		Attempt: request.attempt, Nonce: request.nonce, IssuedAt: request.issuedAt.UnixMicro(),
		ExpiresAt: request.expiresAt.UnixMicro(),
	})
	return runtimeinstall.Sum(encoded)
}

// OperationID returns the bound installation operation identifier.
func (r DesktopConsentRequest) OperationID() string { return r.operationID }

// Attempt returns the bound installation attempt number.
func (r DesktopConsentRequest) Attempt() uint32 { return r.attempt }

// Authority returns the complete desktop execution authority.
func (r DesktopConsentRequest) Authority() DesktopAuthority { return r.authority }

// Nonce returns the single-use consent request nonce.
func (r DesktopConsentRequest) Nonce() Nonce { return r.nonce }

// IssuedAt returns the request issue time.
func (r DesktopConsentRequest) IssuedAt() time.Time { return r.issuedAt }

// ExpiresAt returns the request expiration time.
func (r DesktopConsentRequest) ExpiresAt() time.Time { return r.expiresAt }

// Digest returns the complete immutable consent request digest.
func (r DesktopConsentRequest) Digest() runtimeinstall.Hash { return r.digest }

// DesktopConsentReceiptInput is populated only by the visible consent surface.
type DesktopConsentReceiptInput struct {
	RequestDigest              runtimeinstall.Hash
	AuthorityDigest            runtimeinstall.Hash
	PlanDigest                 runtimeinstall.Hash
	TermsDigest                runtimeinstall.Hash
	PrincipalID                string
	MachineDigest              runtimeinstall.Hash
	Nonce                      Nonce
	ExplicitlyAccepted         bool
	AuthorityAndEntitlement    bool
	NonPreselectedConfirmation bool
	AcceptedAt                 time.Time
	ExpiresAt                  time.Time
	Signature                  []byte
	SignatureDigest            runtimeinstall.Hash
}

// DesktopConsentReceipt is an authenticated exact-plan user decision.
type DesktopConsentReceipt struct {
	input  DesktopConsentReceiptInput
	digest runtimeinstall.Hash
}

// NewDesktopConsentReceipt validates the receipt shape; the authenticator must
// separately verify its external signature.
func NewDesktopConsentReceipt(input DesktopConsentReceiptInput) (DesktopConsentReceipt, error) {
	if input.RequestDigest.IsZero() || input.AuthorityDigest.IsZero() || input.PlanDigest.IsZero() ||
		input.TermsDigest.IsZero() || input.MachineDigest.IsZero() || input.Nonce.IsZero() ||
		!input.ExplicitlyAccepted || !input.AuthorityAndEntitlement || !input.NonPreselectedConfirmation ||
		input.AcceptedAt.IsZero() || input.ExpiresAt.IsZero() || input.AcceptedAt.Location() != time.UTC ||
		input.ExpiresAt.Location() != time.UTC || !input.ExpiresAt.After(input.AcceptedAt) ||
		input.ExpiresAt.Sub(input.AcceptedAt) > desktopConsentMaximumLifetime ||
		!validDesktopSignature(input.Signature, input.SignatureDigest) {
		return DesktopConsentReceipt{}, ErrDesktopConsentIntegrity
	}
	copyInput := input
	copyInput.Signature = slices.Clone(input.Signature)
	encoded, err := json.Marshal(copyInput)
	if err != nil {
		return DesktopConsentReceipt{}, ErrDesktopConsentIntegrity
	}
	return DesktopConsentReceipt{input: copyInput, digest: runtimeinstall.Sum(encoded)}, nil
}

// Matches proves the decision was explicit, current, and exact-request bound.
func (r DesktopConsentReceipt) Matches(request DesktopConsentRequest, now time.Time) bool {
	return !r.digest.IsZero() && !request.digest.IsZero() && r.input.RequestDigest == request.digest &&
		r.input.AuthorityDigest == request.authority.Digest() && r.input.PlanDigest == request.authority.PlanDigest() &&
		r.input.TermsDigest == request.authority.Terms().Digest() && r.input.PrincipalID == request.authority.PrincipalID() &&
		r.input.MachineDigest == request.authority.MachineDigest() && r.input.Nonce == request.nonce &&
		!now.Before(r.input.AcceptedAt) && now.Before(r.input.ExpiresAt)
}

// Authorizes revalidates a stored consent against the exact authority after
// the short-lived interactive request has been consumed.
func (r DesktopConsentReceipt) Authorizes(authority DesktopAuthority, now time.Time) bool {
	return authority.Valid() && !r.digest.IsZero() && r.input.AuthorityDigest == authority.Digest() &&
		r.input.PlanDigest == authority.PlanDigest() && r.input.TermsDigest == authority.Terms().Digest() &&
		r.input.PrincipalID == authority.PrincipalID() && r.input.MachineDigest == authority.MachineDigest() &&
		!now.Before(r.input.AcceptedAt) && now.Before(r.input.ExpiresAt)
}

// Digest returns the complete immutable consent receipt digest.
func (r DesktopConsentReceipt) Digest() runtimeinstall.Hash { return r.digest }

// Signature returns a defensive copy of the external consent signature.
func (r DesktopConsentReceipt) Signature() []byte { return slices.Clone(r.input.Signature) }

// DesktopConsentBroker obtains one visible, explicit vendor-terms decision.
type DesktopConsentBroker interface {
	AwaitDesktopConsent(context.Context, DesktopConsentRequest) (DesktopConsentReceipt, error)
}

// DesktopConsentAuthenticator verifies fresh and stored consent signatures.
type DesktopConsentAuthenticator interface {
	VerifyDesktopConsent(context.Context, DesktopConsentRequest, DesktopConsentReceipt) error
	VerifyStoredDesktopConsent(context.Context, DesktopAuthority, DesktopConsentReceipt) error
}

// DesktopConsentRepository persists consent by operation and authority digest.
type DesktopConsentRepository interface {
	StoreDesktopConsent(context.Context, string, DesktopConsentReceipt) error
	LoadDesktopConsent(context.Context, string, runtimeinstall.Hash) (DesktopConsentReceipt, error)
}

// DesktopMutationOperation is a closed elevated capability.
type DesktopMutationOperation string

const (
	// DesktopMutationInstallPrerequisites enables the exact Windows WSL prerequisites.
	DesktopMutationInstallPrerequisites DesktopMutationOperation = "install_wsl_prerequisites"
	// DesktopMutationInstallRuntime installs the exact verified Docker Desktop artifact.
	DesktopMutationInstallRuntime DesktopMutationOperation = "install_docker_desktop"
)

func (o DesktopMutationOperation) validFor(platform runtimeinstall.Platform) bool {
	return o == DesktopMutationInstallRuntime ||
		platform == runtimeinstall.PlatformWindows && o == DesktopMutationInstallPrerequisites
}

// DesktopMutationRequest is exact typed authority for a native helper.
type DesktopMutationRequest struct {
	operationID    string
	attempt        uint32
	operation      DesktopMutationOperation
	authority      DesktopAuthority
	consentDigest  runtimeinstall.Hash
	artifactDigest runtimeinstall.Hash
	nonce          Nonce
	issuedAt       time.Time
	expiresAt      time.Time
	expectedState  runtimeinstall.Hash
	digest         runtimeinstall.Hash
}

// NewDesktopMutationRequest binds helper authority to consent, artifact, principal, and state.
func NewDesktopMutationRequest(
	operationID string,
	attempt uint32,
	operation DesktopMutationOperation,
	authority DesktopAuthority,
	consentDigest runtimeinstall.Hash,
	artifactDigest runtimeinstall.Hash,
	nonce Nonce,
	issuedAt time.Time,
	expiresAt time.Time,
) (DesktopMutationRequest, error) {
	if !validOperationID(operationID) || attempt == 0 || !authority.Valid() || !operation.validFor(authority.Platform()) ||
		consentDigest.IsZero() || operation == DesktopMutationInstallRuntime && artifactDigest.IsZero() || nonce.IsZero() ||
		issuedAt.IsZero() || expiresAt.IsZero() || issuedAt.Location() != time.UTC || expiresAt.Location() != time.UTC ||
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > desktopRequestMaximumLifetime {
		return DesktopMutationRequest{}, ErrDesktopMutationIntegrity
	}
	request := DesktopMutationRequest{operationID: operationID, attempt: attempt, operation: operation,
		authority: authority, consentDigest: consentDigest, artifactDigest: artifactDigest, nonce: nonce,
		issuedAt: issuedAt, expiresAt: expiresAt}
	request.expectedState = desktopExpectedMutationState(authority, operation)
	request.digest = runtimeinstall.Sum(request.CanonicalBytes())
	return request, nil
}

func desktopExpectedMutationState(authority DesktopAuthority, operation DesktopMutationOperation) runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Authority, Operation, Application, Runtime, Artifact string
		Features                                             []string
	}{
		Authority: authority.Digest().String(), Operation: string(operation), Application: authority.ApplicationPath(),
		Runtime: authority.RuntimeVersion(), Artifact: authority.ArtifactSHA256().String(), Features: authority.WindowsFeatures(),
	})
	return runtimeinstall.Sum(encoded)
}

// OperationID returns the bound installation operation identifier.
func (r DesktopMutationRequest) OperationID() string { return r.operationID }

// Attempt returns the bound installation attempt number.
func (r DesktopMutationRequest) Attempt() uint32 { return r.attempt }

// Operation returns the closed elevated capability.
func (r DesktopMutationRequest) Operation() DesktopMutationOperation { return r.operation }

// Authority returns the complete desktop execution authority.
func (r DesktopMutationRequest) Authority() DesktopAuthority { return r.authority }

// ConsentDigest returns the authenticated consent binding.
func (r DesktopMutationRequest) ConsentDigest() runtimeinstall.Hash { return r.consentDigest }

// ArtifactDigest returns the exact verified installer artifact digest.
func (r DesktopMutationRequest) ArtifactDigest() runtimeinstall.Hash { return r.artifactDigest }

// Nonce returns the single-use elevated mutation nonce.
func (r DesktopMutationRequest) Nonce() Nonce { return r.nonce }

// IssuedAt returns the request issue time.
func (r DesktopMutationRequest) IssuedAt() time.Time { return r.issuedAt }

// ExpiresAt returns the request expiration time.
func (r DesktopMutationRequest) ExpiresAt() time.Time { return r.expiresAt }

// ExpectedState returns the exact successful postcondition digest.
func (r DesktopMutationRequest) ExpectedState() runtimeinstall.Hash { return r.expectedState }

// Digest returns the complete immutable mutation request digest.
func (r DesktopMutationRequest) Digest() runtimeinstall.Hash { return r.digest }

type desktopMutationRequestDocument struct {
	Artifact      string `json:"artifact_digest"`
	Attempt       uint32 `json:"attempt"`
	Authority     string `json:"authority_digest"`
	Catalog       string `json:"catalog_digest"`
	Consent       string `json:"consent_digest"`
	Expected      string `json:"expected_state_digest"`
	ExpiresAt     int64  `json:"expires_at_unix_micro"`
	IssuedAt      int64  `json:"issued_at_unix_micro"`
	Machine       string `json:"machine_digest"`
	Nonce         Nonce  `json:"nonce"`
	Operation     string `json:"operation"`
	OperationID   string `json:"operation_id"`
	Plan          string `json:"plan_digest"`
	Principal     string `json:"principal"`
	RequestDigest string `json:"request_digest,omitempty"`
}

// CanonicalBytes returns the exact non-secret helper request document.
func (r DesktopMutationRequest) CanonicalBytes() []byte {
	if !r.authority.Valid() || r.operationID == "" || r.nonce.IsZero() {
		return nil
	}
	document := desktopMutationRequestDocument{
		Artifact: r.artifactDigest.String(), Attempt: r.attempt, Authority: r.authority.Digest().String(),
		Catalog: r.authority.CatalogDigest().String(), Consent: r.consentDigest.String(),
		Expected: r.expectedState.String(), ExpiresAt: r.expiresAt.UnixMicro(), IssuedAt: r.issuedAt.UnixMicro(),
		Machine: r.authority.MachineDigest().String(), Nonce: r.nonce, Operation: string(r.operation),
		OperationID: r.operationID, Plan: r.authority.PlanDigest().String(), Principal: r.authority.PrincipalID(),
	}
	encoded, _ := json.Marshal(document)
	return encoded
}

// DesktopMutationReceiptInput is returned only by the signed native helper.
type DesktopMutationReceiptInput struct {
	RequestDigest   runtimeinstall.Hash
	AuthorityDigest runtimeinstall.Hash
	Nonce           Nonce
	ExitCode        uint32
	PostState       runtimeinstall.Hash
	RebootReceipt   runtimeinstall.Hash
	CompletedAt     time.Time
	ExpiresAt       time.Time
	Signature       []byte
	SignatureDigest runtimeinstall.Hash
}

// DesktopMutationReceipt is authenticated native-helper evidence.
type DesktopMutationReceipt struct {
	input  DesktopMutationReceiptInput
	digest runtimeinstall.Hash
}

// NewDesktopMutationReceipt validates one bounded helper result.
func NewDesktopMutationReceipt(input DesktopMutationReceiptInput) (DesktopMutationReceipt, error) {
	if input.RequestDigest.IsZero() || input.AuthorityDigest.IsZero() || input.Nonce.IsZero() ||
		input.PostState.IsZero() || input.CompletedAt.IsZero() || input.ExpiresAt.IsZero() ||
		input.CompletedAt.Location() != time.UTC || input.ExpiresAt.Location() != time.UTC ||
		!input.ExpiresAt.After(input.CompletedAt) || input.ExpiresAt.Sub(input.CompletedAt) > desktopRequestMaximumLifetime ||
		!validDesktopSignature(input.Signature, input.SignatureDigest) {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	copyInput := input
	copyInput.Signature = slices.Clone(input.Signature)
	encoded, err := desktopMutationReceiptBytes(copyInput)
	if err != nil {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	return DesktopMutationReceipt{input: copyInput, digest: runtimeinstall.Sum(encoded)}, nil
}

// Matches verifies exact request, exit-code, expiry, and reboot semantics.
func (r DesktopMutationReceipt) Matches(request DesktopMutationRequest, now time.Time) bool {
	if !r.BoundTo(request) || now.Before(r.input.CompletedAt) || !now.Before(r.input.ExpiresAt) {
		return false
	}
	return true
}

// BoundTo verifies the exact request and semantic exit/reboot shape without
// consulting a clock. It exists so the cryptographic authenticator can reject
// a correctly signed receipt substituted from another helper request.
func (r DesktopMutationReceipt) BoundTo(request DesktopMutationRequest) bool {
	if r.digest.IsZero() || request.digest.IsZero() || r.input.RequestDigest != request.digest ||
		r.input.AuthorityDigest != request.authority.Digest() || r.input.Nonce != request.nonce ||
		r.input.PostState != request.expectedState {
		return false
	}
	reboot := slices.Contains(request.authority.RebootExitCodes(), r.input.ExitCode)
	return r.input.ExitCode == 0 && r.input.RebootReceipt.IsZero() || reboot && !r.input.RebootReceipt.IsZero()
}

// Digest returns the complete immutable mutation receipt digest.
func (r DesktopMutationReceipt) Digest() runtimeinstall.Hash { return r.digest }

// RebootReceipt returns the authenticated reboot-required binding, when any.
func (r DesktopMutationReceipt) RebootReceipt() runtimeinstall.Hash { return r.input.RebootReceipt }

// Signature returns a defensive copy of the native helper signature.
func (r DesktopMutationReceipt) Signature() []byte { return slices.Clone(r.input.Signature) }

// AuthenticationPayload returns the domain-separated canonical statement
// signed by the native mutation helper. Signature bytes and their checksum
// are intentionally excluded to avoid a circular signature definition.
func (r DesktopMutationReceipt) AuthenticationPayload() []byte {
	if r.digest.IsZero() {
		return nil
	}
	payload, err := desktopMutationReceiptAuthenticationBytes(r.input)
	if err != nil {
		return nil
	}
	return append([]byte("agentmemory.runtime-helper.desktop-mutation-receipt.v1\n"), payload...)
}

func desktopMutationReceiptAuthenticationBytes(input DesktopMutationReceiptInput) ([]byte, error) {
	return json.Marshal(struct {
		Authority     string `json:"authority_digest"`
		CompletedAt   int64  `json:"completed_at_unix_micro"`
		ExitCode      uint32 `json:"exit_code"`
		ExpiresAt     int64  `json:"expires_at_unix_micro"`
		Nonce         Nonce  `json:"nonce"`
		PostState     string `json:"post_state_digest"`
		RebootReceipt string `json:"reboot_receipt"`
		Request       string `json:"request_digest"`
	}{
		Authority: input.AuthorityDigest.String(), CompletedAt: input.CompletedAt.UnixMicro(),
		ExitCode: input.ExitCode, ExpiresAt: input.ExpiresAt.UnixMicro(), Nonce: input.Nonce,
		PostState: input.PostState.String(), RebootReceipt: input.RebootReceipt.String(),
		Request: input.RequestDigest.String(),
	})
}

type desktopMutationReceiptDocument struct {
	Authority       string `json:"authority_digest"`
	CompletedAt     int64  `json:"completed_at_unix_micro"`
	ExitCode        uint32 `json:"exit_code"`
	ExpiresAt       int64  `json:"expires_at_unix_micro"`
	Nonce           Nonce  `json:"nonce"`
	PostState       string `json:"post_state_digest"`
	RebootReceipt   string `json:"reboot_receipt"`
	Request         string `json:"request_digest"`
	Signature       []byte `json:"signature"`
	SignatureDigest string `json:"signature_digest"`
}

func desktopMutationReceiptBytes(input DesktopMutationReceiptInput) ([]byte, error) {
	return json.Marshal(desktopMutationReceiptDocument{
		Authority: input.AuthorityDigest.String(), CompletedAt: input.CompletedAt.UnixMicro(),
		ExitCode: input.ExitCode, ExpiresAt: input.ExpiresAt.UnixMicro(), Nonce: input.Nonce,
		PostState: input.PostState.String(), RebootReceipt: input.RebootReceipt.String(),
		Request: input.RequestDigest.String(), Signature: slices.Clone(input.Signature),
		SignatureDigest: input.SignatureDigest.String(),
	})
}

// CanonicalBytes returns the exact helper receipt, including its signature.
func (r DesktopMutationReceipt) CanonicalBytes() []byte {
	encoded, err := desktopMutationReceiptBytes(r.input)
	if err != nil || r.digest.IsZero() {
		return nil
	}
	return encoded
}

// DecodeDesktopMutationReceiptV1 strictly decodes one canonical helper receipt.
func DecodeDesktopMutationReceiptV1(raw []byte) (DesktopMutationReceipt, error) {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document desktopMutationReceiptDocument
	if err := decoder.Decode(&document); err != nil {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	parse := runtimeinstall.ParseHash
	requestDigest, err := parse(document.Request)
	if err != nil {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	authorityDigest, err := parse(document.Authority)
	if err != nil {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	postState, err := parse(document.PostState)
	if err != nil {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	reboot := runtimeinstall.Hash{}
	if document.RebootReceipt != (runtimeinstall.Hash{}).String() {
		reboot, err = parse(document.RebootReceipt)
		if err != nil {
			return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
		}
	}
	signatureDigest, err := parse(document.SignatureDigest)
	if err != nil {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	receipt, err := NewDesktopMutationReceipt(DesktopMutationReceiptInput{
		RequestDigest: requestDigest, AuthorityDigest: authorityDigest, Nonce: document.Nonce,
		ExitCode: document.ExitCode, PostState: postState, RebootReceipt: reboot,
		CompletedAt: time.UnixMicro(document.CompletedAt).UTC(), ExpiresAt: time.UnixMicro(document.ExpiresAt).UTC(),
		Signature: slices.Clone(document.Signature), SignatureDigest: signatureDigest,
	})
	if err != nil || !bytes.Equal(raw, receipt.CanonicalBytes()) {
		return DesktopMutationReceipt{}, ErrDesktopMutationIntegrity
	}
	return receipt, nil
}

func validDesktopSignature(signature []byte, digest runtimeinstall.Hash) bool {
	return len(signature) >= 64 && len(signature) <= 4096 && runtimeinstall.Sum(signature) == digest
}

// DesktopMutationBroker executes one exact request through the native helper.
type DesktopMutationBroker interface {
	ExecuteDesktopMutation(context.Context, DesktopMutationRequest) (DesktopMutationReceipt, error)
}

// DesktopMutationAuthenticator verifies the native helper receipt signature.
type DesktopMutationAuthenticator interface {
	VerifyDesktopMutation(context.Context, DesktopMutationRequest, DesktopMutationReceipt) error
}

// DesktopMutationReplayLedger atomically rejects reused helper receipts.
type DesktopMutationReplayLedger interface {
	ConsumeDesktopMutation(context.Context, Nonce, runtimeinstall.Hash) error
}

// DesktopRuntimeLauncher launches only the signed application path as the invoking user.
type DesktopRuntimeLauncher interface {
	LaunchDesktopRuntime(context.Context, DesktopAuthority) (runtimeinstall.Hash, error)
}

// DesktopCapabilityProbe performs active Engine, Compose, bind, network, volume,
// loopback publication, workload-preservation, and local-execution probes.
type DesktopCapabilityProbe interface {
	VerifyDesktopCapabilities(context.Context, DesktopAuthority) (runtimeinstall.Hash, error)
}
