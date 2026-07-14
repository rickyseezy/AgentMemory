package installplanfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const maximumRuntimeAuthorityBytes = 256 * 1024

// SaveRuntimePlan durably publishes one immutable authenticated operation-scoped authority.
func (r *Repository) SaveRuntimePlan(ctx context.Context, authority installplanapp.RuntimePlanAuthority) error {
	if r == nil || ctx == nil || authority.OperationID().IsZero() || authority.ParentPlanDigest().IsZero() {
		return installplanapp.ErrRuntimePlanIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.store == nil {
		return installplanapp.ErrRuntimePlanIntegrity
	}
	restored, err := installplanapp.RestoreRuntimePlanAuthority(authority.Record())
	if err != nil || !restored.Equal(authority) {
		return installplanapp.ErrRuntimePlanIntegrity
	}
	raw, err := encodeRuntimeAuthority(authority)
	if err != nil || len(raw) == 0 || len(raw) > maximumRuntimeAuthorityBytes {
		return installplanapp.ErrRuntimePlanIntegrity
	}
	if err := r.store.save(ctx, runtimeAuthorityFilename(authority.OperationID(), authority.ParentPlanDigest()), raw); err != nil {
		if errors.Is(err, errImmutableConflict) {
			return installplanapp.ErrRuntimePlanConflict
		}
		return fmt.Errorf("persist runtime plan authority: %w", installplanapp.ErrRuntimePlanIntegrity)
	}
	return nil
}

// LoadRuntimePlan authenticates exact durable bytes and every operation/parent binding.
func (r *Repository) LoadRuntimePlan(
	ctx context.Context,
	operationID install.OperationID,
	parent install.PlanDigest,
) (installplanapp.RuntimePlanAuthority, error) {
	if r == nil || ctx == nil || operationID.IsZero() || parent.IsZero() {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	if err := ctx.Err(); err != nil {
		return installplanapp.RuntimePlanAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.store == nil {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	raw, err := r.store.load(ctx, runtimeAuthorityFilename(operationID, parent))
	if err != nil {
		if errors.Is(err, errPlanNotFound) {
			return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanNotFound
		}
		return installplanapp.RuntimePlanAuthority{}, fmt.Errorf("load runtime plan authority: %w", installplanapp.ErrRuntimePlanIntegrity)
	}
	if len(raw) == 0 || len(raw) > maximumRuntimeAuthorityBytes {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	authority, err := decodeRuntimeAuthority(raw)
	if err != nil || authority.OperationID() != operationID || !authority.ParentPlanDigest().Equal(parent) {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	return authority, nil
}

func encodeRuntimeAuthority(authority installplanapp.RuntimePlanAuthority) ([]byte, error) {
	record := authority.Record()
	document := canonicalRuntimeAuthority{
		BindingDigest:               record.BindingDigest,
		CanonicalPlan:               base64.StdEncoding.EncodeToString(record.CanonicalPlan),
		DiscoveryEvidenceDigest:     record.DiscoveryEvidenceDigest,
		HostEvidenceDigest:          record.HostEvidenceDigest,
		OperationID:                 record.OperationID,
		ParentPlanDigest:            record.ParentPlanDigest,
		SchemaVersion:               record.SchemaVersion,
		SignedCatalogEvidenceDigest: record.SignedCatalogEvidenceDigest,
	}
	return json.Marshal(document)
}

func decodeRuntimeAuthority(raw []byte) (installplanapp.RuntimePlanAuthority, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document canonicalRuntimeAuthority
	if err := decoder.Decode(&document); err != nil {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	canonicalPlan, err := base64.StdEncoding.Strict().DecodeString(document.CanonicalPlan)
	if err != nil || base64.StdEncoding.EncodeToString(canonicalPlan) != document.CanonicalPlan {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	authority, err := installplanapp.RestoreRuntimePlanAuthority(installplanapp.RuntimePlanAuthorityRecord{
		SchemaVersion: document.SchemaVersion, OperationID: document.OperationID,
		ParentPlanDigest: document.ParentPlanDigest, CanonicalPlan: canonicalPlan,
		HostEvidenceDigest:          document.HostEvidenceDigest,
		DiscoveryEvidenceDigest:     document.DiscoveryEvidenceDigest,
		SignedCatalogEvidenceDigest: document.SignedCatalogEvidenceDigest,
		BindingDigest:               document.BindingDigest,
	})
	if err != nil {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	canonical, err := encodeRuntimeAuthority(authority)
	if err != nil || !bytes.Equal(raw, canonical) {
		return installplanapp.RuntimePlanAuthority{}, installplanapp.ErrRuntimePlanIntegrity
	}
	return authority, nil
}

func runtimeAuthorityFilename(operationID install.OperationID, parent install.PlanDigest) string {
	binding := sha256.Sum256([]byte(operationID.String() + "\x00" + parent.String()))
	return "runtime-sha256-" + hex.EncodeToString(binding[:]) + ".json"
}

type canonicalRuntimeAuthority struct {
	BindingDigest               string `json:"binding_digest"`
	CanonicalPlan               string `json:"canonical_plan"`
	DiscoveryEvidenceDigest     string `json:"discovery_evidence_digest"`
	HostEvidenceDigest          string `json:"host_evidence_digest"`
	OperationID                 string `json:"operation_id"`
	ParentPlanDigest            string `json:"parent_plan_digest"`
	SchemaVersion               uint16 `json:"schema_version"`
	SignedCatalogEvidenceDigest string `json:"signed_catalog_evidence_digest"`
}

var _ installplanapp.RuntimePlanRepository = (*Repository)(nil)
