package runtimeconsent

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

const consentSigningOperationID = "019f6000-0000-7000-8000-000000000001"

// ProtectedSigner authenticates consent statements with a purpose-separated,
// owner-and-machine-bound key. Key bytes exist only inside UseHMACKey.
type ProtectedSigner struct {
	owners bootstrapport.OwnerBindingSource
	keys   bootstrapport.OperationKeySource
	keyID  install.OperationID
}

// SignManagedRuntimeRemovalConsent authenticates the complete separately
// planned removal authority and its explicit, non-preselected approval using
// the same protected owner/machine-bound consent key as runtime installation.
func (s *ProtectedSigner) SignManagedRuntimeRemovalConsent(
	ctx context.Context,
	plan runtimeremoval.Plan,
	acceptedAt time.Time,
) (runtimeinstall.Hash, error) {
	if !plan.Valid() || acceptedAt.IsZero() || acceptedAt.Location() != time.UTC {
		return runtimeinstall.Hash{}, ErrIntegrity
	}
	payload, err := json.Marshal(struct {
		Schema          string `json:"schema"`
		Operation       string `json:"operation"`
		SourceOperation string `json:"source_operation"`
		Plan            string `json:"plan"`
		Ownership       string `json:"ownership"`
		InitialScan     string `json:"initial_scan"`
		Impact          string `json:"impact"`
		AcceptedAt      int64  `json:"accepted_at_unix_micro"`
		Explicit        bool   `json:"explicit"`
		NonPreselected  bool   `json:"non_preselected"`
	}{
		Schema:    "agentmemory.managed-runtime-removal-consent.v1",
		Operation: plan.OperationID().String(), SourceOperation: plan.SourceOperationID(),
		Plan: plan.Digest().String(), Ownership: plan.OwnershipRecordDigest().String(),
		InitialScan: plan.ScanDigest().String(), Impact: plan.ImpactConfirmation(),
		AcceptedAt: acceptedAt.UnixMicro(), Explicit: true, NonPreselected: true,
	})
	if err != nil {
		return runtimeinstall.Hash{}, ErrIntegrity
	}
	signature, err := s.sign(ctx, payload)
	if err != nil || len(signature) != sha512.Size {
		return runtimeinstall.Hash{}, ErrIntegrity
	}
	receipt := make([]byte, 0, len(payload)+len(signature)+1)
	receipt = append(receipt, payload...)
	receipt = append(receipt, '\n')
	receipt = append(receipt, signature...)
	return runtimeinstall.Sum(receipt), nil
}

// NewProtectedSigner constructs a signer from native protected-key capabilities.
func NewProtectedSigner(
	owners bootstrapport.OwnerBindingSource,
	keys bootstrapport.OperationKeySource,
) (*ProtectedSigner, error) {
	keyID, err := install.NewOperationID(consentSigningOperationID)
	if err != nil || nilInterface(owners) || nilInterface(keys) {
		return nil, ErrIntegrity
	}
	return &ProtectedSigner{owners: owners, keys: keys, keyID: keyID}, nil
}

// SignLinux signs one validated canonical Linux statement.
func (s *ProtectedSigner) SignLinux(
	ctx context.Context,
	statement runtimeport.LinuxConsentStatement,
) (runtimeport.LinuxConsentReceipt, error) {
	payload, err := statement.CanonicalBytes()
	if err != nil {
		return runtimeport.LinuxConsentReceipt{}, runtimeport.ErrLinuxConsentIntegrity
	}
	signature, err := s.sign(ctx, payload)
	if err != nil {
		return runtimeport.LinuxConsentReceipt{}, err
	}
	return runtimeport.NewSignedLinuxConsentReceipt(statement, signature)
}

// VerifyLinux verifies fresh or stored Linux receipt authentication.
func (s *ProtectedSigner) VerifyLinux(
	ctx context.Context,
	receipt runtimeport.LinuxConsentReceipt,
) error {
	payload, err := receipt.Statement().CanonicalBytes()
	if err != nil || s.verify(ctx, payload, receipt.Signature()) != nil {
		return runtimeport.ErrLinuxConsentIntegrity
	}
	return nil
}

// SignDesktop signs one validated canonical desktop statement.
func (s *ProtectedSigner) SignDesktop(
	ctx context.Context,
	statement runtimeport.DesktopConsentStatement,
) (runtimeport.DesktopConsentReceipt, error) {
	payload, err := statement.CanonicalBytes()
	if err != nil {
		return runtimeport.DesktopConsentReceipt{}, runtimeport.ErrDesktopConsentIntegrity
	}
	signature, err := s.sign(ctx, payload)
	if err != nil {
		return runtimeport.DesktopConsentReceipt{}, err
	}
	return runtimeport.NewSignedDesktopConsentReceipt(statement, signature)
}

// VerifyDesktop verifies fresh or stored desktop receipt authentication.
func (s *ProtectedSigner) VerifyDesktop(
	ctx context.Context,
	receipt runtimeport.DesktopConsentReceipt,
) error {
	payload, err := receipt.Statement().CanonicalBytes()
	if err != nil || s.verify(ctx, payload, receipt.Signature()) != nil {
		return runtimeport.ErrDesktopConsentIntegrity
	}
	return nil
}

func (s *ProtectedSigner) sign(ctx context.Context, payload []byte) ([]byte, error) {
	if s == nil || ctx == nil || len(payload) == 0 || nilInterface(s.owners) || nilInterface(s.keys) || s.keyID.IsZero() {
		return nil, ErrIntegrity
	}
	owner, err := s.owners.Current(ctx)
	if err != nil || owner.IsZero() {
		return nil, errors.New("runtime consent owner authority is unavailable")
	}
	keyRef, err := s.keys.Ensure(ctx, s.keyID, owner)
	if err != nil || keyRef.IsZero() {
		return nil, errors.New("runtime consent signing key is unavailable")
	}
	var signature []byte
	err = s.keys.UseHMACKey(ctx, keyRef, s.keyID, owner, func(key []byte) error {
		if len(key) < 32 {
			return ErrIntegrity
		}
		mac := hmac.New(sha512.New, key)
		_, _ = mac.Write(payload)
		signature = mac.Sum(nil)
		return nil
	})
	if err != nil || len(signature) != sha512.Size {
		return nil, errors.New("runtime consent signing authority is unavailable")
	}
	return signature, nil
}

func (s *ProtectedSigner) verify(ctx context.Context, payload, signature []byte) error {
	expected, err := s.sign(ctx, payload)
	if err != nil || !hmac.Equal(expected, signature) {
		return ErrIntegrity
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable reflection kind is accepted by default.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
