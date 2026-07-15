package runtimeprovision

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const (
	privilegeWireSchemaVersion  = uint16(1)
	maximumPrivilegeWireBytes   = 64 << 20
	maximumPrivilegeJSONDepth   = uint32(64)
	maximumPrivilegeSignedBytes = 32 << 20
)

// PrivilegeEnvelopeInput is the already-retained signed authority transported
// to the immutable helper. The wire codec preserves these bytes but does not
// claim they are trusted; helper-side verification must decode and re-verify
// both signed envelopes independently before BindAuthority is called.
type PrivilegeEnvelopeInput struct {
	SignedRelease            []byte
	SignedRuntimeCatalog     []byte
	CanonicalPlan            []byte
	RuntimeCatalogResourceID string
	HelperResourceID         string
	ArtifactStager           PrivilegeArtifactStager
}

// CanonicalPrivilegeTransportCodec owns the fixed, stdin-only PF-006 helper
// envelope for one reverified release/catalog/plan selection.
type CanonicalPrivilegeTransportCodec struct {
	signedRelease        []byte
	signedRuntimeCatalog []byte
	canonicalPlan        []byte
	catalogResourceID    string
	helperResourceID     string
	plan                 runtimeinstall.Plan
	artifactStager       PrivilegeArtifactStager
}

// NewCanonicalPrivilegeTransportCodec copies immutable transport authority and
// rejects normalization, ambiguous identifiers, and a noncanonical PF-006 plan.
func NewCanonicalPrivilegeTransportCodec(
	input PrivilegeEnvelopeInput,
) (*CanonicalPrivilegeTransportCodec, error) {
	plan, err := runtimeinstall.DecodePlanV1(input.CanonicalPlan)
	if err != nil || !validCanonicalPrivilegeObject(input.SignedRelease) ||
		!validCanonicalPrivilegeObject(input.SignedRuntimeCatalog) ||
		!validPrivilegeWireID(input.RuntimeCatalogResourceID) || !validPrivilegeWireID(input.HelperResourceID) ||
		nilArtifactDependency(input.ArtifactStager) ||
		len(input.SignedRelease)+len(input.SignedRuntimeCatalog)+len(input.CanonicalPlan) > maximumPrivilegeWireBytes {
		return nil, ErrProvisionIntegrity
	}
	return &CanonicalPrivilegeTransportCodec{
		signedRelease:        append([]byte(nil), input.SignedRelease...),
		signedRuntimeCatalog: append([]byte(nil), input.SignedRuntimeCatalog...),
		canonicalPlan:        append([]byte(nil), input.CanonicalPlan...),
		catalogResourceID:    input.RuntimeCatalogResourceID, helperResourceID: input.HelperResourceID,
		plan: plan, artifactStager: input.ArtifactStager,
	}, nil
}

// EncodePrivilegeRequest binds the transient nonce/operation request to the
// exact canonical plan. It never serializes a caller-selected command or path.
func (c *CanonicalPrivilegeTransportCodec) EncodePrivilegeRequest(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) ([]byte, error) {
	if c == nil || ctx == nil || nilArtifactDependency(c.artifactStager) ||
		!request.Authority().ValidFor(c.plan) || request.Digest().IsZero() ||
		request.Authority().PlanDigest() != c.plan.Digest() {
		return nil, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expected, err := runtimeport.ExpectedPrivilegeState(request.Authority(), request.Operation())
	if err != nil || expected != request.ExpectedState() {
		return nil, ErrProvisionIntegrity
	}
	bindings, err := c.artifactStager.StagePrivilegeArtifacts(ctx, request.Authority())
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return nil, contextError
		}
		return nil, ErrProvisionIntegrity
	}
	artifacts, err := canonicalPrivilegeArtifacts(bindings, request.Authority())
	if err != nil {
		return nil, ErrProvisionIntegrity
	}
	document := canonicalPrivilegeEnvelope{
		Artifacts: artifacts, CanonicalPlan: json.RawMessage(c.canonicalPlan), HelperResourceID: c.helperResourceID,
		Request: privilegeRequestDocument(request), RuntimeCatalogResourceID: c.catalogResourceID,
		SchemaVersion: privilegeWireSchemaVersion, SignedRelease: json.RawMessage(c.signedRelease),
		SignedRuntimeCatalog: json.RawMessage(c.signedRuntimeCatalog),
	}
	return encodeCanonicalPrivilegeEnvelope(document)
}

type canonicalPrivilegeEnvelope struct {
	Artifacts                []canonicalPrivilegeArtifact `json:"artifacts"`
	CanonicalPlan            json.RawMessage              `json:"canonical_plan"`
	HelperResourceID         string                       `json:"helper_resource_id"`
	Request                  canonicalPrivilegeRequest    `json:"request"`
	RuntimeCatalogResourceID string                       `json:"runtime_catalog_resource_id"`
	SchemaVersion            uint16                       `json:"schema_version"`
	SignedRelease            json.RawMessage              `json:"signed_release"`
	SignedRuntimeCatalog     json.RawMessage              `json:"signed_runtime_catalog"`
}

type canonicalPrivilegeArtifact struct {
	ArtifactID string `json:"artifact_id"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       uint64 `json:"size"`
}

type canonicalPrivilegeRequest struct {
	Attempt             uint32 `json:"attempt"`
	AuthorityDigest     string `json:"authority_digest"`
	AuthorizationDigest string `json:"authorization_digest"`
	ExpectedStateDigest string `json:"expected_state_digest"`
	ExpiresAtUnixMicro  int64  `json:"expires_at_unix_micro"`
	IssuedAtUnixMicro   int64  `json:"issued_at_unix_micro"`
	Nonce               string `json:"nonce"`
	Operation           string `json:"operation"`
	OperationID         string `json:"operation_id"`
	OperationKey        string `json:"operation_key"`
	RequestDigest       string `json:"request_digest"`
}

func privilegeRequestDocument(request runtimeport.PrivilegeRequest) canonicalPrivilegeRequest {
	nonce := request.Nonce()
	return canonicalPrivilegeRequest{
		Attempt: request.Attempt(), AuthorityDigest: request.Authority().Digest().String(),
		AuthorizationDigest: optionalPrivilegeHashString(request.AuthorizationDigest()),
		ExpectedStateDigest: request.ExpectedState().String(), ExpiresAtUnixMicro: request.ExpiresAt().UnixMicro(),
		IssuedAtUnixMicro: request.IssuedAt().UnixMicro(), Nonce: hex.EncodeToString(nonce[:]),
		Operation: string(request.Operation()), OperationID: request.OperationID(),
		OperationKey: request.OperationKey().String(), RequestDigest: request.Digest().String(),
	}
}

// DecodedPrivilegeRequest is untrusted transport data until the helper has
// independently verified its signed release/catalog and projected authority.
type DecodedPrivilegeRequest struct {
	document  canonicalPrivilegeEnvelope
	plan      runtimeinstall.Plan
	artifacts []PrivilegeArtifactBinding
}

// DecodeCanonicalPrivilegeRequest accepts only the exact schema-v1 canonical
// JSON representation and does not normalize signed nested bytes.
func DecodeCanonicalPrivilegeRequest(raw []byte) (DecodedPrivilegeRequest, error) {
	if len(raw) == 0 || len(raw) > maximumPrivilegeWireBytes || rejectPrivilegeDuplicateJSONKeys(raw) != nil {
		return DecodedPrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	var document canonicalPrivilegeEnvelope
	if decodePrivilegeJSON(raw, &document) != nil || document.SchemaVersion != privilegeWireSchemaVersion ||
		!validPrivilegeWireID(document.RuntimeCatalogResourceID) || !validPrivilegeWireID(document.HelperResourceID) ||
		!validCanonicalPrivilegeObject(document.SignedRelease) ||
		!validCanonicalPrivilegeObject(document.SignedRuntimeCatalog) {
		return DecodedPrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	plan, err := runtimeinstall.DecodePlanV1(document.CanonicalPlan)
	if err != nil {
		return DecodedPrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	artifacts, err := privilegeArtifactsFromCanonical(document.Artifacts)
	if err != nil {
		return DecodedPrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	canonical, err := encodeCanonicalPrivilegeEnvelope(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return DecodedPrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	return DecodedPrivilegeRequest{
		document: copyPrivilegeEnvelope(document), plan: plan,
		artifacts: append([]PrivilegeArtifactBinding(nil), artifacts...),
	}, nil
}

// BindAuthority reconstructs the immutable request only after the caller has
// independently projected the signed Linux authority. It rejects a stale,
// forged, cross-plan, or semantically incorrect expected state.
func (d DecodedPrivilegeRequest) BindAuthority(
	authority runtimeport.LinuxAuthority,
) (runtimeport.PrivilegeRequest, error) {
	claims := d.document.Request
	authorityDigest, authorityError := runtimeinstall.ParseHash(claims.AuthorityDigest)
	authorizationDigest, authorizationError := parseOptionalPrivilegeHash(claims.AuthorizationDigest)
	expectedState, expectedError := runtimeinstall.ParseHash(claims.ExpectedStateDigest)
	operationKey, operationKeyError := runtimeinstall.ParseHash(claims.OperationKey)
	requestDigest, requestDigestError := runtimeinstall.ParseHash(claims.RequestDigest)
	nonce, nonceError := parsePrivilegeNonce(claims.Nonce)
	if !authority.ValidFor(d.plan) || authority.PlanDigest() != d.plan.Digest() ||
		!validPrivilegeArtifactBindings(d.artifacts, authority) ||
		authorityError != nil || authorityDigest != authority.Digest() || authorizationError != nil || expectedError != nil ||
		operationKeyError != nil || requestDigestError != nil || nonceError != nil {
		return runtimeport.PrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	operation := runtimeport.PrivilegeOperation(claims.Operation)
	canonicalState, err := runtimeport.ExpectedPrivilegeState(authority, operation)
	if err != nil || canonicalState != expectedState {
		return runtimeport.PrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: claims.OperationID, Attempt: claims.Attempt, Operation: operation,
		Authority: authority, AuthorizationDigest: authorizationDigest,
		Nonce: nonce, IssuedAt: time.UnixMicro(claims.IssuedAtUnixMicro).UTC(),
		ExpiresAt: time.UnixMicro(claims.ExpiresAtUnixMicro).UTC(), ExpectedState: expectedState,
	})
	if err != nil || request.OperationKey() != operationKey || request.Digest() != requestDigest {
		return runtimeport.PrivilegeRequest{}, runtimeport.ErrPrivilegeIntegrity
	}
	return request, nil
}

func optionalPrivilegeHashString(value runtimeinstall.Hash) string {
	if value.IsZero() {
		return ""
	}
	return value.String()
}

// CanonicalBytes returns a defensive exact re-encoding for authenticated
// persistence or helper-side evidence binding.
func (d DecodedPrivilegeRequest) CanonicalBytes() ([]byte, error) {
	return encodeCanonicalPrivilegeEnvelope(d.document)
}

// SignedRelease returns the untrusted exact signed-release envelope bytes.
func (d DecodedPrivilegeRequest) SignedRelease() []byte {
	return append([]byte(nil), d.document.SignedRelease...)
}

// SignedRuntimeCatalog returns the untrusted exact signed-catalog envelope bytes.
func (d DecodedPrivilegeRequest) SignedRuntimeCatalog() []byte {
	return append([]byte(nil), d.document.SignedRuntimeCatalog...)
}

// CanonicalPlan returns the exact nested PF-006 plan bytes.
func (d DecodedPrivilegeRequest) CanonicalPlan() []byte {
	return append([]byte(nil), d.document.CanonicalPlan...)
}

// Artifacts returns a defensive copy of the untrusted helper handoff paths and
// their signed identities. BindAuthority and helper-side file verification are
// both required before these paths may be consumed.
func (d DecodedPrivilegeRequest) Artifacts() []PrivilegeArtifactBinding {
	return append([]PrivilegeArtifactBinding(nil), d.artifacts...)
}

// RuntimeCatalogResourceID identifies the signed release resource to rejoin.
func (d DecodedPrivilegeRequest) RuntimeCatalogResourceID() string {
	return d.document.RuntimeCatalogResourceID
}

// HelperResourceID identifies the exact release-owned helper resource.
func (d DecodedPrivilegeRequest) HelperResourceID() string { return d.document.HelperResourceID }

func encodeCanonicalPrivilegeEnvelope(document canonicalPrivilegeEnvelope) ([]byte, error) {
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPrivilegeWireBytes {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return encoded, nil
}

func copyPrivilegeEnvelope(document canonicalPrivilegeEnvelope) canonicalPrivilegeEnvelope {
	document.Artifacts = append([]canonicalPrivilegeArtifact(nil), document.Artifacts...)
	document.CanonicalPlan = append(json.RawMessage(nil), document.CanonicalPlan...)
	document.SignedRelease = append(json.RawMessage(nil), document.SignedRelease...)
	document.SignedRuntimeCatalog = append(json.RawMessage(nil), document.SignedRuntimeCatalog...)
	return document
}

func canonicalPrivilegeArtifacts(
	bindings []PrivilegeArtifactBinding,
	authority runtimeport.LinuxAuthority,
) ([]canonicalPrivilegeArtifact, error) {
	if !validPrivilegeArtifactBindings(bindings, authority) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	result := make([]canonicalPrivilegeArtifact, 0, len(bindings))
	for _, binding := range bindings {
		result = append(result, canonicalPrivilegeArtifact{
			ArtifactID: binding.artifactID, Path: binding.path,
			SHA256: binding.sha256.String(), Size: binding.size,
		})
	}
	return result, nil
}

func privilegeArtifactsFromCanonical(
	documents []canonicalPrivilegeArtifact,
) ([]PrivilegeArtifactBinding, error) {
	if len(documents) == 0 || len(documents) > 4096 || !sort.SliceIsSorted(documents, func(left, right int) bool {
		return documents[left].ArtifactID < documents[right].ArtifactID
	}) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	result := make([]PrivilegeArtifactBinding, 0, len(documents))
	for index, document := range documents {
		digest, err := runtimeinstall.ParseHash(document.SHA256)
		if err != nil || digest.IsZero() || document.Size == 0 || document.Size > 1<<53-1 ||
			!validPrivilegeWireID(document.ArtifactID) || !validPrivilegeArtifactPath(document.Path) ||
			index > 0 && documents[index-1].ArtifactID == document.ArtifactID {
			return nil, runtimeport.ErrPrivilegeIntegrity
		}
		result = append(result, PrivilegeArtifactBinding{
			artifactID: document.ArtifactID, path: document.Path, sha256: digest, size: document.Size,
		})
	}
	return result, nil
}

func validPrivilegeArtifactBindings(
	bindings []PrivilegeArtifactBinding,
	authority runtimeport.LinuxAuthority,
) bool {
	if !authority.Valid() || len(bindings) == 0 || len(bindings) > 4096 ||
		!sort.SliceIsSorted(bindings, func(left, right int) bool { return bindings[left].artifactID < bindings[right].artifactID }) {
		return false
	}
	packages := make(map[string]struct{}, len(authority.Packages()))
	for _, pkg := range authority.Packages() {
		packages[pkg.Name()] = struct{}{}
	}
	seenPackages := make(map[string]struct{}, len(packages))
	for index, binding := range bindings {
		if binding.sha256.IsZero() || binding.size == 0 || !validPrivilegeWireID(binding.artifactID) ||
			!validPrivilegeArtifactPath(binding.path) ||
			index > 0 && bindings[index-1].artifactID == binding.artifactID ||
			path.Dir(binding.path) != path.Join(
				authority.HomeDirectory(), ".agentmemory", authority.Digest().String(),
			) {
			return false
		}
		extension := path.Ext(binding.path)
		if _, packageArtifact := packages[binding.artifactID]; packageArtifact {
			wanted := ".deb"
			if authority.PackageManager() == runtimeport.PackageManagerDNF {
				wanted = ".rpm"
			}
			if extension != wanted {
				return false
			}
			seenPackages[binding.artifactID] = struct{}{}
		} else if !strings.HasPrefix(binding.artifactID, "repo-") || extension != ".metadata" {
			return false
		}
		if strings.TrimSuffix(path.Base(binding.path), extension) !=
			binding.artifactID+"-"+binding.sha256.String() {
			return false
		}
	}
	return len(seenPackages) == len(packages)
}

func validPrivilegeArtifactPath(value string) bool {
	return value != "" && len(value) <= 4096 && path.IsAbs(value) && path.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

type canonicalPrivilegeReceipt struct {
	AuthorityDigest        string                      `json:"authority_digest"`
	ExpiresAtUnixMicro     int64                       `json:"expires_at_unix_micro"`
	HelperDigest           string                      `json:"helper_digest"`
	MachineDigest          string                      `json:"machine_digest"`
	Nonce                  string                      `json:"nonce"`
	ObservedStateDigest    string                      `json:"observed_state_digest"`
	Operation              string                      `json:"operation"`
	OperationKey           string                      `json:"operation_key"`
	PackageStateDigest     string                      `json:"package_state_digest"`
	PlanDigest             string                      `json:"plan_digest"`
	PrincipalID            string                      `json:"principal_id"`
	ReceiptDigest          string                      `json:"receipt_digest"`
	RepositoryDigest       string                      `json:"repository_digest"`
	RequestDigest          string                      `json:"request_digest"`
	Result                 runtimeport.PrivilegeResult `json:"result"`
	SchemaVersion          uint16                      `json:"schema_version"`
	ServiceActive          bool                        `json:"service_active"`
	ServiceEnabled         bool                        `json:"service_enabled"`
	ServiceUnitDigest      string                      `json:"service_unit_digest"`
	Signature              string                      `json:"signature"`
	SubordinateGIDStart    uint32                      `json:"subordinate_gid_start"`
	SubordinateIDs         uint32                      `json:"subordinate_ids"`
	SubordinateStateDigest string                      `json:"subordinate_state_digest"`
	SubordinateUIDStart    uint32                      `json:"subordinate_uid_start"`
	UserLingerEnabled      bool                        `json:"user_linger_enabled"`
}

// EncodeCanonicalPrivilegeReceipt serializes only the closed semantic helper
// receipt. It includes no diagnostic output, path, environment, or password.
func EncodeCanonicalPrivilegeReceipt(receipt runtimeport.PrivilegeReceipt) ([]byte, error) {
	if receipt.Digest().IsZero() {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	document := privilegeReceiptDocument(receipt)
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPrivilegeWireBytes {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return encoded, nil
}

func privilegeReceiptDocument(receipt runtimeport.PrivilegeReceipt) canonicalPrivilegeReceipt {
	input := receipt.TransportInput()
	return canonicalPrivilegeReceipt{
		AuthorityDigest: input.AuthorityDigest.String(), ExpiresAtUnixMicro: input.ExpiresAt.UnixMicro(),
		HelperDigest: input.HelperDigest.String(), MachineDigest: input.MachineDigest.String(),
		Nonce: hex.EncodeToString(input.Nonce[:]), ObservedStateDigest: input.ObservedState.String(),
		Operation: string(input.Operation), OperationKey: input.OperationKey.String(),
		PackageStateDigest: input.PackageStateDigest.String(), PlanDigest: input.PlanDigest.String(),
		PrincipalID: input.PrincipalID, ReceiptDigest: receipt.Digest().String(),
		RepositoryDigest: input.RepositoryDigest.String(), RequestDigest: input.RequestDigest.String(),
		Result: input.Result, SchemaVersion: privilegeWireSchemaVersion,
		ServiceActive: input.ServiceActive, ServiceEnabled: input.ServiceEnabled,
		ServiceUnitDigest: input.ServiceUnitDigest.String(), Signature: base64.StdEncoding.EncodeToString(input.Signature),
		SubordinateGIDStart: input.SubordinateGIDStart, SubordinateIDs: input.SubordinateIDs,
		SubordinateStateDigest: input.SubordinateStateDigest.String(), SubordinateUIDStart: input.SubordinateUIDStart,
		UserLingerEnabled: input.UserLingerEnabled,
	}
}

// DecodeCanonicalPrivilegeReceipt validates transport shape and receipt digest.
// Signature trust remains the independent ReceiptAuthenticator decision.
func DecodeCanonicalPrivilegeReceipt(raw []byte) (runtimeport.PrivilegeReceipt, error) {
	if len(raw) == 0 || len(raw) > maximumPrivilegeWireBytes || rejectPrivilegeDuplicateJSONKeys(raw) != nil {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	var document canonicalPrivilegeReceipt
	if decodePrivilegeJSON(raw, &document) != nil || document.SchemaVersion != privilegeWireSchemaVersion {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	input, digest, err := privilegeReceiptInput(document)
	if err != nil {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	receipt, err := runtimeport.NewPrivilegeReceipt(input)
	if err != nil || receipt.Digest() != digest {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	canonical, err := EncodeCanonicalPrivilegeReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, raw) {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	return receipt, nil
}

// DecodePrivilegeReceipt implements the broker's narrow outbound codec port.
func (*CanonicalPrivilegeTransportCodec) DecodePrivilegeReceipt(
	raw []byte,
) (runtimeport.PrivilegeReceipt, error) {
	return DecodeCanonicalPrivilegeReceipt(raw)
}

func privilegeReceiptInput(
	document canonicalPrivilegeReceipt,
) (runtimeport.PrivilegeReceiptInput, runtimeinstall.Hash, error) {
	request, e1 := runtimeinstall.ParseHash(document.RequestDigest)
	operationKey, e2 := runtimeinstall.ParseHash(document.OperationKey)
	plan, e3 := runtimeinstall.ParseHash(document.PlanDigest)
	authority, e4 := runtimeinstall.ParseHash(document.AuthorityDigest)
	machine, e5 := runtimeinstall.ParseHash(document.MachineDigest)
	observed, e6 := runtimeinstall.ParseHash(document.ObservedStateDigest)
	packages, e7 := parseOptionalPrivilegeHash(document.PackageStateDigest)
	repository, e8 := parseOptionalPrivilegeHash(document.RepositoryDigest)
	service, e9 := parseOptionalPrivilegeHash(document.ServiceUnitDigest)
	subordinate, e10 := parseOptionalPrivilegeHash(document.SubordinateStateDigest)
	helper, e11 := runtimeinstall.ParseHash(document.HelperDigest)
	digest, e12 := runtimeinstall.ParseHash(document.ReceiptDigest)
	nonce, e13 := parsePrivilegeNonce(document.Nonce)
	signature, e14 := base64.StdEncoding.Strict().DecodeString(document.Signature)
	if errors.Join(e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14) != nil ||
		base64.StdEncoding.EncodeToString(signature) != document.Signature {
		return runtimeport.PrivilegeReceiptInput{}, runtimeinstall.Hash{}, runtimeport.ErrPrivilegeIntegrity
	}
	return runtimeport.PrivilegeReceiptInput{
		RequestDigest: request, OperationKey: operationKey, PlanDigest: plan, AuthorityDigest: authority,
		Operation: runtimeport.PrivilegeOperation(document.Operation), PrincipalID: document.PrincipalID,
		MachineDigest: machine, Nonce: nonce, ExpiresAt: time.UnixMicro(document.ExpiresAtUnixMicro).UTC(),
		Result: document.Result, ObservedState: observed, PackageStateDigest: packages,
		RepositoryDigest: repository, ServiceUnitDigest: service, ServiceEnabled: document.ServiceEnabled,
		ServiceActive: document.ServiceActive, UserLingerEnabled: document.UserLingerEnabled,
		SubordinateIDs: document.SubordinateIDs, SubordinateUIDStart: document.SubordinateUIDStart,
		SubordinateGIDStart: document.SubordinateGIDStart, SubordinateStateDigest: subordinate,
		HelperDigest: helper, Signature: signature,
	}, digest, nil
}

func parseOptionalPrivilegeHash(value string) (runtimeinstall.Hash, error) {
	zero := runtimeinstall.Hash{}
	if value == "" || value == zero.String() {
		return zero, nil
	}
	return runtimeinstall.ParseHash(value)
}

func parsePrivilegeNonce(value string) (runtimeport.Nonce, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(runtimeport.Nonce{}) || hex.EncodeToString(decoded) != value {
		return runtimeport.Nonce{}, runtimeport.ErrPrivilegeIntegrity
	}
	var nonce runtimeport.Nonce
	copy(nonce[:], decoded)
	return nonce, nil
}

func validCanonicalPrivilegeObject(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maximumPrivilegeSignedBytes || raw[0] != '{' || raw[len(raw)-1] != '}' ||
		rejectPrivilegeDuplicateJSONKeys(raw) != nil {
		return false
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil || !bytes.Equal(compact.Bytes(), raw) {
		return false
	}
	return true
}

func validPrivilegeWireID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-_.", character) {
			continue
		}
		return false
	}
	return true
}

func decodePrivilegeJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	return nil
}

func rejectPrivilegeDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanPrivilegeJSONValue(decoder, 0); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return runtimeport.ErrPrivilegeIntegrity
	}
	return nil
}

func scanPrivilegeJSONValue(decoder *json.Decoder, depth uint32) error {
	if depth > maximumPrivilegeJSONDepth {
		return runtimeport.ErrPrivilegeIntegrity
	}
	token, err := decoder.Token()
	if err != nil {
		return runtimeport.ErrPrivilegeIntegrity
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			key, ok := keyToken.(string)
			if keyError != nil || !ok {
				return runtimeport.ErrPrivilegeIntegrity
			}
			if _, duplicate := seen[key]; duplicate {
				return runtimeport.ErrPrivilegeIntegrity
			}
			seen[key] = struct{}{}
			if err := scanPrivilegeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closingError := decoder.Token()
		if closingError != nil || closing != json.Delim('}') {
			return runtimeport.ErrPrivilegeIntegrity
		}
	case '[':
		for decoder.More() {
			if err := scanPrivilegeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closingError := decoder.Token()
		if closingError != nil || closing != json.Delim(']') {
			return runtimeport.ErrPrivilegeIntegrity
		}
	default:
		return runtimeport.ErrPrivilegeIntegrity
	}
	return nil
}

var _ PrivilegeTransportCodec = (*CanonicalPrivilegeTransportCodec)(nil)
