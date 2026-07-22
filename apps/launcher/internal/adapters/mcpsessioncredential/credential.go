// Package mcpsessioncredential mints locally generated, Core-registered PF-005 credentials.
package mcpsessioncredential

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpsessionapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const credentialBytes = 32

var errCredentialAuthority = errors.New("PF-005 credential authority is invalid")

// Registrar registers and revokes only credential digests; secret bytes never cross it.
type Registrar interface {
	Register(context.Context, mcpsessionapp.CredentialRegistration) error
	Revoke(context.Context, string) error
}

// ProtectedStore persists secret bytes behind native owner/link/ACL checks.
type ProtectedStore interface {
	Write(context.Context, string, []byte) (string, error)
	Delete(context.Context, string, string) error
}

// Clock supplies the exact issue time shared with the session application.
type Clock interface{ Now() time.Time }

// Adapter composes CSPRNG generation, protected storage, and hash-only Core registration.
type Adapter struct {
	registrar Registrar
	store     ProtectedStore
	clock     Clock
	entropy   io.Reader
}

// New constructs the production credential adapter with crypto/rand entropy.
func New(registrar Registrar, store ProtectedStore, clock Clock) (*Adapter, error) {
	return NewWithEntropy(registrar, store, clock, rand.Reader)
}

// NewWithEntropy permits deterministic TDD without weakening production entropy.
func NewWithEntropy(
	registrar Registrar,
	store ProtectedStore,
	clock Clock,
	entropy io.Reader,
) (*Adapter, error) {
	if nilCapability(registrar) || nilCapability(store) || nilCapability(clock) ||
		nilCapability(entropy) {
		return nil, errCredentialAuthority
	}
	return &Adapter{registrar: registrar, store: store, clock: clock, entropy: entropy}, nil
}

// Mint creates one 256-bit credential, writes it once, and registers only its digest.
func (a *Adapter) Mint(
	ctx context.Context,
	scope mcpsessionapp.CredentialScope,
) (mcpsession.CredentialLease, error) {
	if a == nil || ctx == nil || !a.valid() || !validScope(scope) {
		return mcpsession.CredentialLease{}, errCredentialAuthority
	}
	if err := ctx.Err(); err != nil {
		return mcpsession.CredentialLease{}, err
	}
	secret := make([]byte, credentialBytes)
	defer clear(secret)
	if _, err := io.ReadFull(a.entropy, secret); err != nil {
		return mcpsession.CredentialLease{}, errors.New("PF-005 credential entropy is unavailable")
	}
	digestBytes := sha256.Sum256(secret)
	digest := hex.EncodeToString(digestBytes[:])
	issuedAt := a.clock.Now().UTC().Truncate(time.Microsecond)
	expiresAt := issuedAt.Add(scope.TTL)
	if issuedAt.IsZero() {
		return mcpsession.CredentialLease{}, errCredentialAuthority
	}
	path, err := a.store.Write(ctx, scope.SessionID, secret)
	if err != nil {
		return mcpsession.CredentialLease{}, errors.New("PF-005 credential storage is unavailable")
	}
	lease, err := mcpsession.NewCredentialLease(digest, path, issuedAt, expiresAt)
	if err != nil {
		_ = a.store.Delete(context.WithoutCancel(ctx), path, digest)
		return mcpsession.CredentialLease{}, errCredentialAuthority
	}
	registration := mcpsessionapp.CredentialRegistration{
		Scope: scope, Digest: digest, IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	if err := a.registrar.Register(ctx, registration); err != nil {
		deleteError := a.store.Delete(context.WithoutCancel(ctx), path, digest)
		return mcpsession.CredentialLease{}, errors.Join(
			errors.New("PF-005 credential registration is unavailable"), deleteError,
		)
	}
	return lease, nil
}

// Revoke invalidates Core authority before deleting the exact protected file.
func (a *Adapter) Revoke(ctx context.Context, lease mcpsession.CredentialLease) error {
	if a == nil || ctx == nil || !a.valid() || !lease.Valid() {
		return errCredentialAuthority
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	revokeError := a.registrar.Revoke(ctx, lease.Digest())
	deleteError := a.store.Delete(context.WithoutCancel(ctx), lease.ProtectedFile(), lease.Digest())
	return errors.Join(revokeError, deleteError)
}

func (a *Adapter) valid() bool {
	return !nilCapability(a.registrar) && !nilCapability(a.store) && !nilCapability(a.clock) &&
		!nilCapability(a.entropy)
}

func validScope(scope mcpsessionapp.CredentialScope) bool {
	return mcpsession.ValidUUIDv7(scope.SessionID) && mcpsession.ValidUUIDv7(scope.InstallationID) &&
		mcpsession.ValidUUIDv7(scope.BrainID) && mcpsession.ValidUUIDv7(scope.ActorID) &&
		mcpsession.ValidUUIDv7(scope.GrantID) &&
		mcpsession.ValidAgentID(scope.AgentID) &&
		mcpsession.ValidSHA256Digest(scope.WorkspaceFingerprint) &&
		scope.DeviceIdentity != "" && len(scope.DeviceIdentity) <= 512 &&
		!strings.ContainsAny(scope.DeviceIdentity, "\x00\r\n") && validGitScope(scope) &&
		scope.SecurityEpoch > 0 &&
		scope.TTL > 0 && scope.TTL <= 12*time.Hour
}

func validGitScope(scope mcpsessionapp.CredentialScope) bool {
	switch scope.GitCoverage {
	case mcpsession.GitCoverageNone:
		return scope.GitRepositoryID == "" && scope.GitWorktreeID == ""
	case mcpsession.GitCoveragePartial, mcpsession.GitCoverageComplete:
		return mcpsession.ValidSHA256Digest(scope.GitRepositoryID) &&
			mcpsession.ValidSHA256Digest(scope.GitWorktreeID)
	default:
		return false
	}
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable concrete capabilities are valid.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

var _ mcpsessionapp.SessionCredentialPort = (*Adapter)(nil)
