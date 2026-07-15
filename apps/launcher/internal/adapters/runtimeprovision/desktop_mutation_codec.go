package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const desktopMutationWireSchemaVersion = uint16(1)

// DesktopMutationEnvelopeInput is retained, signed authority transported to a
// native desktop helper. The codec does not trust these bytes. The elevated
// helper must independently verify both signed envelopes, the canonical plan,
// the current host binding, and its own executable before binding a request.
type DesktopMutationEnvelopeInput struct {
	SignedRelease            []byte
	SignedRuntimeCatalog     []byte
	CanonicalPlan            []byte
	RuntimeCatalogResourceID string
	HelperResourceID         string
}

// CanonicalDesktopMutationTransportCodec owns the only accepted macOS and
// Windows helper request envelope. It carries data, never ambient command or
// path authority.
type CanonicalDesktopMutationTransportCodec struct {
	signedRelease        []byte
	signedRuntimeCatalog []byte
	canonicalPlan        []byte
	catalogResourceID    string
	helperResourceID     string
	plan                 runtimeinstall.Plan
}

// NewCanonicalDesktopMutationTransportCodec copies one complete release,
// catalog, plan, and helper selection for subsequent request encoding.
func NewCanonicalDesktopMutationTransportCodec(
	input DesktopMutationEnvelopeInput,
) (*CanonicalDesktopMutationTransportCodec, error) {
	plan, err := runtimeinstall.DecodePlanV1(input.CanonicalPlan)
	if err != nil || !validCanonicalPrivilegeObject(input.SignedRelease) ||
		!validCanonicalPrivilegeObject(input.SignedRuntimeCatalog) ||
		!validPrivilegeWireID(input.RuntimeCatalogResourceID) || !validPrivilegeWireID(input.HelperResourceID) ||
		input.RuntimeCatalogResourceID == input.HelperResourceID ||
		len(input.SignedRelease)+len(input.SignedRuntimeCatalog)+len(input.CanonicalPlan) > maximumPrivilegeWireBytes {
		return nil, ErrProvisionIntegrity
	}
	return &CanonicalDesktopMutationTransportCodec{
		signedRelease:        append([]byte(nil), input.SignedRelease...),
		signedRuntimeCatalog: append([]byte(nil), input.SignedRuntimeCatalog...),
		canonicalPlan:        append([]byte(nil), input.CanonicalPlan...),
		catalogResourceID:    input.RuntimeCatalogResourceID,
		helperResourceID:     input.HelperResourceID,
		plan:                 plan,
	}, nil
}

// EncodeDesktopMutationRequest binds one transient consented request to the
// exact signed inputs. Only the installer path already present in the verified
// desktop authority is transported, and only for the runtime-install cell.
func (c *CanonicalDesktopMutationTransportCodec) EncodeDesktopMutationRequest(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
) ([]byte, error) {
	if c == nil || ctx == nil || !request.Authority().ValidFor(c.plan) || request.Digest().IsZero() ||
		request.Authority().PlanDigest() != c.plan.Digest() {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	document := canonicalDesktopMutationEnvelope{
		CanonicalPlan:            json.RawMessage(c.canonicalPlan),
		HelperResourceID:         c.helperResourceID,
		Request:                  desktopMutationRequestDocumentFrom(request),
		RuntimeCatalogResourceID: c.catalogResourceID,
		SchemaVersion:            desktopMutationWireSchemaVersion,
		SignedRelease:            json.RawMessage(c.signedRelease),
		SignedRuntimeCatalog:     json.RawMessage(c.signedRuntimeCatalog),
	}
	if request.Operation() == runtimeport.DesktopMutationInstallRuntime {
		binding, err := NewDesktopMutationArtifactBinding(
			request.Authority().ArtifactPath(), request.Authority().ArtifactSHA256(),
			request.Authority().ArtifactBytes(),
		)
		if err != nil || binding.sha256 != request.ArtifactDigest() {
			return nil, ErrProvisionIntegrity
		}
		document.Artifact = &canonicalDesktopMutationArtifact{
			Path: binding.path, SHA256: binding.sha256.String(), Size: binding.size,
		}
	} else if request.Operation() != runtimeport.DesktopMutationInstallPrerequisites ||
		!request.ArtifactDigest().IsZero() {
		return nil, ErrProvisionIntegrity
	}
	return encodeCanonicalDesktopMutationEnvelope(document)
}

type canonicalDesktopMutationEnvelope struct {
	Artifact                 *canonicalDesktopMutationArtifact `json:"artifact"`
	CanonicalPlan            json.RawMessage                   `json:"canonical_plan"`
	HelperResourceID         string                            `json:"helper_resource_id"`
	Request                  canonicalDesktopMutationRequest   `json:"request"`
	RuntimeCatalogResourceID string                            `json:"runtime_catalog_resource_id"`
	SchemaVersion            uint16                            `json:"schema_version"`
	SignedRelease            json.RawMessage                   `json:"signed_release"`
	SignedRuntimeCatalog     json.RawMessage                   `json:"signed_runtime_catalog"`
}

type canonicalDesktopMutationArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}

type canonicalDesktopMutationRequest struct {
	ArtifactDigest     string `json:"artifact_digest"`
	Attempt            uint32 `json:"attempt"`
	AuthorityDigest    string `json:"authority_digest"`
	CatalogDigest      string `json:"catalog_digest"`
	ConsentDigest      string `json:"consent_digest"`
	ExpectedState      string `json:"expected_state_digest"`
	ExpiresAtUnixMicro int64  `json:"expires_at_unix_micro"`
	IssuedAtUnixMicro  int64  `json:"issued_at_unix_micro"`
	MachineDigest      string `json:"machine_digest"`
	Nonce              string `json:"nonce"`
	Operation          string `json:"operation"`
	OperationID        string `json:"operation_id"`
	PlanDigest         string `json:"plan_digest"`
	PrincipalID        string `json:"principal_id"`
	RequestDigest      string `json:"request_digest"`
}

func desktopMutationRequestDocumentFrom(
	request runtimeport.DesktopMutationRequest,
) canonicalDesktopMutationRequest {
	nonce := request.Nonce()
	authority := request.Authority()
	return canonicalDesktopMutationRequest{
		ArtifactDigest: request.ArtifactDigest().String(), Attempt: request.Attempt(),
		AuthorityDigest: authority.Digest().String(), CatalogDigest: authority.CatalogDigest().String(),
		ConsentDigest: request.ConsentDigest().String(), ExpectedState: request.ExpectedState().String(),
		ExpiresAtUnixMicro: request.ExpiresAt().UnixMicro(), IssuedAtUnixMicro: request.IssuedAt().UnixMicro(),
		MachineDigest: authority.MachineDigest().String(), Nonce: hex.EncodeToString(nonce[:]),
		Operation: string(request.Operation()), OperationID: request.OperationID(),
		PlanDigest: authority.PlanDigest().String(), PrincipalID: authority.PrincipalID(),
		RequestDigest: request.Digest().String(),
	}
}

// DesktopMutationArtifactBinding is an untrusted handoff path paired with the
// exact catalog-derived digest and byte length. The elevated helper must reopen
// it without following links and verify both values before execution.
type DesktopMutationArtifactBinding struct {
	path   string
	sha256 runtimeinstall.Hash
	size   uint64
}

// NewDesktopMutationArtifactBinding rejects relative, ambiguous, empty, and
// unbounded handoff paths. It grants no trust by itself.
func NewDesktopMutationArtifactBinding(
	path string,
	sha256 runtimeinstall.Hash,
	size uint64,
) (DesktopMutationArtifactBinding, error) {
	if !validDesktopMutationArtifactPath(path) || sha256.IsZero() || size == 0 || size > 1<<53-1 {
		return DesktopMutationArtifactBinding{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return DesktopMutationArtifactBinding{path: path, sha256: sha256, size: size}, nil
}

// Path returns transport data, not execution authority.
func (b DesktopMutationArtifactBinding) Path() string { return b.path }

// SHA256 returns the exact signed catalog content binding.
func (b DesktopMutationArtifactBinding) SHA256() runtimeinstall.Hash { return b.sha256 }

// Size returns the exact signed catalog byte count.
func (b DesktopMutationArtifactBinding) Size() uint64 { return b.size }

// DecodedDesktopMutationRequest is untrusted transport until helper-side
// release/catalog/host/self verification has reconstructed DesktopAuthority.
type DecodedDesktopMutationRequest struct {
	document canonicalDesktopMutationEnvelope
	plan     runtimeinstall.Plan
	artifact *DesktopMutationArtifactBinding
}

// DecodeCanonicalDesktopMutationRequest accepts only exact schema-v1 JSON.
func DecodeCanonicalDesktopMutationRequest(raw []byte) (DecodedDesktopMutationRequest, error) {
	if len(raw) == 0 || len(raw) > maximumPrivilegeWireBytes || rejectPrivilegeDuplicateJSONKeys(raw) != nil {
		return DecodedDesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	var document canonicalDesktopMutationEnvelope
	if decodePrivilegeJSON(raw, &document) != nil || document.SchemaVersion != desktopMutationWireSchemaVersion ||
		!validPrivilegeWireID(document.RuntimeCatalogResourceID) || !validPrivilegeWireID(document.HelperResourceID) ||
		document.RuntimeCatalogResourceID == document.HelperResourceID ||
		!validCanonicalPrivilegeObject(document.SignedRelease) ||
		!validCanonicalPrivilegeObject(document.SignedRuntimeCatalog) {
		return DecodedDesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	plan, err := runtimeinstall.DecodePlanV1(document.CanonicalPlan)
	if err != nil {
		return DecodedDesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	var artifact *DesktopMutationArtifactBinding
	if document.Artifact != nil {
		digest, parseError := runtimeinstall.ParseHash(document.Artifact.SHA256)
		binding, bindingError := NewDesktopMutationArtifactBinding(document.Artifact.Path, digest, document.Artifact.Size)
		if parseError != nil || bindingError != nil {
			return DecodedDesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
		}
		artifact = &binding
	}
	canonical, err := encodeCanonicalDesktopMutationEnvelope(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return DecodedDesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return DecodedDesktopMutationRequest{
		document: copyDesktopMutationEnvelope(document), plan: plan, artifact: artifact,
	}, nil
}

// BindAuthority reconstructs the immutable request only after independent
// helper-side verification projects the exact desktop authority.
func (d DecodedDesktopMutationRequest) BindAuthority(
	authority runtimeport.DesktopAuthority,
) (runtimeport.DesktopMutationRequest, error) {
	claims := d.document.Request
	authorityDigest, authorityError := runtimeinstall.ParseHash(claims.AuthorityDigest)
	catalogDigest, catalogError := runtimeinstall.ParseHash(claims.CatalogDigest)
	consentDigest, consentError := runtimeinstall.ParseHash(claims.ConsentDigest)
	artifactDigest, artifactError := parseOptionalDesktopMutationHash(claims.ArtifactDigest)
	expectedState, expectedError := runtimeinstall.ParseHash(claims.ExpectedState)
	machineDigest, machineError := runtimeinstall.ParseHash(claims.MachineDigest)
	planDigest, planError := runtimeinstall.ParseHash(claims.PlanDigest)
	requestDigest, requestError := runtimeinstall.ParseHash(claims.RequestDigest)
	nonce, nonceError := parsePrivilegeNonce(claims.Nonce)
	if !authority.ValidFor(d.plan) || authority.PlanDigest() != d.plan.Digest() ||
		authorityError != nil || authorityDigest != authority.Digest() ||
		catalogError != nil || catalogDigest != authority.CatalogDigest() ||
		consentError != nil || artifactError != nil || expectedError != nil ||
		machineError != nil || machineDigest != authority.MachineDigest() ||
		planError != nil || planDigest != authority.PlanDigest() ||
		requestError != nil || nonceError != nil || claims.PrincipalID != authority.PrincipalID() {
		return runtimeport.DesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	operation := runtimeport.DesktopMutationOperation(claims.Operation)
	if !desktopMutationArtifactMatches(d.artifact, authority, operation, artifactDigest) {
		return runtimeport.DesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	request, err := runtimeport.NewDesktopMutationRequest(
		claims.OperationID, claims.Attempt, operation, authority, consentDigest, artifactDigest, nonce,
		time.UnixMicro(claims.IssuedAtUnixMicro).UTC(), time.UnixMicro(claims.ExpiresAtUnixMicro).UTC(),
	)
	if err != nil || request.ExpectedState() != expectedState || request.Digest() != requestDigest {
		return runtimeport.DesktopMutationRequest{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return request, nil
}

func parseOptionalDesktopMutationHash(value string) (runtimeinstall.Hash, error) {
	if value == (runtimeinstall.Hash{}).String() {
		return runtimeinstall.Hash{}, nil
	}
	return runtimeinstall.ParseHash(value)
}

func desktopMutationArtifactMatches(
	binding *DesktopMutationArtifactBinding,
	authority runtimeport.DesktopAuthority,
	operation runtimeport.DesktopMutationOperation,
	digest runtimeinstall.Hash,
) bool {
	switch operation {
	case runtimeport.DesktopMutationInstallRuntime:
		return binding != nil && binding.path == authority.ArtifactPath() &&
			binding.sha256 == authority.ArtifactSHA256() && binding.sha256 == digest &&
			binding.size == authority.ArtifactBytes()
	case runtimeport.DesktopMutationInstallPrerequisites:
		return authority.Platform() == runtimeinstall.PlatformWindows && binding == nil && digest.IsZero()
	default:
		return false
	}
}

// CanonicalBytes returns a defensive exact re-encoding.
func (d DecodedDesktopMutationRequest) CanonicalBytes() ([]byte, error) {
	return encodeCanonicalDesktopMutationEnvelope(d.document)
}

// SignedRelease returns the exact untrusted signed-release envelope.
func (d DecodedDesktopMutationRequest) SignedRelease() []byte {
	return append([]byte(nil), d.document.SignedRelease...)
}

// SignedRuntimeCatalog returns the exact untrusted signed-catalog envelope.
func (d DecodedDesktopMutationRequest) SignedRuntimeCatalog() []byte {
	return append([]byte(nil), d.document.SignedRuntimeCatalog...)
}

// CanonicalPlan returns the exact nested PF-006 plan bytes.
func (d DecodedDesktopMutationRequest) CanonicalPlan() []byte {
	return append([]byte(nil), d.document.CanonicalPlan...)
}

// RuntimeCatalogResourceID identifies the signed release resource to rejoin.
func (d DecodedDesktopMutationRequest) RuntimeCatalogResourceID() string {
	return d.document.RuntimeCatalogResourceID
}

// HelperResourceID identifies the exact release-owned helper resource.
func (d DecodedDesktopMutationRequest) HelperResourceID() string {
	return d.document.HelperResourceID
}

// Artifact returns a defensive copy of the untrusted installer handoff.
func (d DecodedDesktopMutationRequest) Artifact() (DesktopMutationArtifactBinding, bool) {
	if d.artifact == nil {
		return DesktopMutationArtifactBinding{}, false
	}
	return *d.artifact, true
}

func encodeCanonicalDesktopMutationEnvelope(document canonicalDesktopMutationEnvelope) ([]byte, error) {
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPrivilegeWireBytes {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return encoded, nil
}

func copyDesktopMutationEnvelope(document canonicalDesktopMutationEnvelope) canonicalDesktopMutationEnvelope {
	document.CanonicalPlan = append(json.RawMessage(nil), document.CanonicalPlan...)
	document.SignedRelease = append(json.RawMessage(nil), document.SignedRelease...)
	document.SignedRuntimeCatalog = append(json.RawMessage(nil), document.SignedRuntimeCatalog...)
	if document.Artifact != nil {
		artifact := *document.Artifact
		document.Artifact = &artifact
	}
	return document
}

func validDesktopMutationArtifactPath(value string) bool {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if strings.HasPrefix(value, "/") {
		if strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
			return false
		}
		for _, component := range strings.Split(value, "/") {
			if component == "." || component == ".." {
				return false
			}
		}
		return true
	}
	if len(value) < 4 || value[0] < 'A' || value[0] > 'Z' || value[1:3] != `:\` ||
		strings.HasSuffix(value, `\`) || strings.Contains(value[3:], `\\`) ||
		strings.ContainsAny(value, "/\"") || strings.Contains(value[3:], ":") {
		return false
	}
	for _, component := range strings.Split(value[3:], `\`) {
		if component == "" || component == "." || component == ".." ||
			strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return false
		}
	}
	return true
}
