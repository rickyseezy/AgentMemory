// Package rebootfs persists the minimal owner-only PF-001 reboot continuation.
package rebootfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
)

const (
	activeSuffix  = ".json"
	claimedSuffix = ".claimed"
	maximumBytes  = 8 * 1024
)

// Repository uses immutable publication and a separate durable claim file.
// The claim is idempotent only for the same exact seven-field record.
type Repository struct {
	root string
	mu   sync.Mutex
}

// Entropy is the production non-secret continuation nonce source.
type Entropy struct{}

// Bytes returns exactly size cryptographically random bytes.
func (Entropy) Bytes(ctx context.Context, size int) ([]byte, error) {
	if ctx == nil || size <= 0 || size > 1024 {
		return nil, rebootapp.ErrRecordIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, rebootapp.ErrUnavailable
	}
	return value, nil
}

// NewRepository creates or opens one explicit private continuation root.
func NewRepository(root string) (*Repository, error) {
	if root == "" || strings.IndexByte(root, 0) >= 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, rebootapp.ErrRecordIntegrity
	}
	if err := platformEnsurePrivateRoot(root); err != nil {
		return nil, rebootapp.ErrRecordIntegrity
	}
	return &Repository{root: root}, nil
}

// Load prefers a durable claim over the active file, allowing process-crash
// recovery after atomic consumption but before the aggregate leaves RebootPending.
func (r *Repository) Load(ctx context.Context, operationID install.OperationID) (rebootcontinuation.Record, error) {
	if r == nil || ctx == nil || operationID.IsZero() {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	if err := ctx.Err(); err != nil {
		return rebootcontinuation.Record{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	claimed, claimedError := r.loadPath(ctx, r.claimedPath(operationID), operationID)
	active, activeError := r.loadPath(ctx, r.activePath(operationID), operationID)
	if claimedError == nil {
		if activeError == nil {
			if !sameRecord(claimed, active) {
				return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
			}
			if err := removeAndSync(r.root, r.activePath(operationID)); err != nil {
				return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
			}
		}
		if activeError != nil && !errors.Is(activeError, rebootapp.ErrRecordNotFound) {
			return rebootcontinuation.Record{}, activeError
		}
		return claimed, nil
	}
	if !errors.Is(claimedError, rebootapp.ErrRecordNotFound) {
		return rebootcontinuation.Record{}, claimedError
	}
	if activeError != nil {
		return rebootcontinuation.Record{}, activeError
	}
	return active, nil
}

// LoadByToken is the narrow native-login inbound lookup. The token is a fixed
// lowercase SHA-256 identifier; the decoded record must reproduce it exactly.
func (r *Repository) LoadByToken(ctx context.Context, token string) (rebootcontinuation.Record, error) {
	if r == nil || ctx == nil || !validToken(token) {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	if err := ctx.Err(); err != nil {
		return rebootcontinuation.Record{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	claimedPath := filepath.Join(r.root, "sha256-"+token+claimedSuffix)
	activePath := filepath.Join(r.root, "sha256-"+token+activeSuffix)
	claimed, claimedError := r.loadUnboundPath(ctx, claimedPath)
	active, activeError := r.loadUnboundPath(ctx, activePath)
	if claimedError == nil {
		if activeError == nil && !sameRecord(claimed, active) {
			return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
		}
		if activeError == nil {
			if err := removeAndSync(r.root, activePath); err != nil {
				return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
			}
		} else if !errors.Is(activeError, rebootapp.ErrRecordNotFound) {
			return rebootcontinuation.Record{}, activeError
		}
		if !recordMatchesToken(claimed, token) {
			return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
		}
		return claimed, nil
	}
	if !errors.Is(claimedError, rebootapp.ErrRecordNotFound) {
		return rebootcontinuation.Record{}, claimedError
	}
	if activeError != nil {
		return rebootcontinuation.Record{}, activeError
	}
	if !recordMatchesToken(active, token) {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	return active, nil
}

// Publish atomically exposes complete bytes and never replaces existing state.
func (r *Repository) Publish(ctx context.Context, record rebootcontinuation.Record) error {
	if err := r.validateCall(ctx, record.OperationID()); err != nil || record.Nonce().IsZero() {
		if err != nil {
			return err
		}
		return rebootapp.ErrRecordIntegrity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if pathExists(r.activePath(record.OperationID())) || pathExists(r.claimedPath(record.OperationID())) {
		return rebootapp.ErrRecordConflict
	}
	encoded, err := encodeRecord(record)
	if err != nil {
		return rebootapp.ErrRecordIntegrity
	}
	if err := publishCompleteFile(ctx, r.root, r.activePath(record.OperationID()), encoded); err != nil {
		if errors.Is(err, os.ErrExist) {
			return rebootapp.ErrRecordConflict
		}
		return rebootapp.ErrRecordIntegrity
	}
	return nil
}

// Claim durably publishes the claimed record before removing the active name.
// An exact existing claim is idempotent; every substitution conflicts.
func (r *Repository) Claim(ctx context.Context, record rebootcontinuation.Record) error {
	if err := r.validateCall(ctx, record.OperationID()); err != nil || record.Nonce().IsZero() {
		if err != nil {
			return err
		}
		return rebootapp.ErrRecordIntegrity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	claimed, claimedError := r.loadPath(ctx, r.claimedPath(record.OperationID()), record.OperationID())
	if claimedError == nil {
		if !sameRecord(claimed, record) {
			return rebootapp.ErrRecordConflict
		}
		if err := removeAndSync(r.root, r.activePath(record.OperationID())); err != nil {
			return rebootapp.ErrRecordIntegrity
		}
		return nil
	}
	if !errors.Is(claimedError, rebootapp.ErrRecordNotFound) {
		return claimedError
	}
	active, activeError := r.loadPath(ctx, r.activePath(record.OperationID()), record.OperationID())
	if activeError != nil {
		if errors.Is(activeError, rebootapp.ErrRecordNotFound) {
			return rebootapp.ErrRecordConflict
		}
		return activeError
	}
	if !sameRecord(active, record) {
		return rebootapp.ErrRecordConflict
	}
	encoded, err := encodeRecord(record)
	if err != nil {
		return rebootapp.ErrRecordIntegrity
	}
	if err := publishCompleteFile(ctx, r.root, r.claimedPath(record.OperationID()), encoded); err != nil {
		if errors.Is(err, os.ErrExist) {
			return rebootapp.ErrRecordConflict
		}
		return rebootapp.ErrRecordIntegrity
	}
	if err := removeAndSync(r.root, r.activePath(record.OperationID())); err != nil {
		return rebootapp.ErrRecordIntegrity
	}
	return nil
}

// Delete removes both names. Absence is a successful idempotent replay.
func (r *Repository) Delete(ctx context.Context, operationID install.OperationID) error {
	if err := r.validateCall(ctx, operationID); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, path := range []string{r.activePath(operationID), r.claimedPath(operationID)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return rebootapp.ErrRecordIntegrity
		}
	}
	if err := platformSyncDirectory(r.root); err != nil {
		return rebootapp.ErrRecordIntegrity
	}
	return nil
}

func (r *Repository) validateCall(ctx context.Context, operationID install.OperationID) error {
	if r == nil || ctx == nil || operationID.IsZero() || r.root == "" {
		return rebootapp.ErrRecordIntegrity
	}
	return ctx.Err()
}

func (r *Repository) loadPath(
	ctx context.Context,
	path string,
	operationID install.OperationID,
) (rebootcontinuation.Record, error) {
	record, err := r.loadUnboundPath(ctx, path)
	if err != nil {
		return rebootcontinuation.Record{}, err
	}
	if record.OperationID() != operationID {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	return record, nil
}

func (r *Repository) loadUnboundPath(
	ctx context.Context,
	path string,
) (rebootcontinuation.Record, error) {
	file, err := platformOpenProtectedFile(ctx, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rebootcontinuation.Record{}, rebootapp.ErrRecordNotFound
		}
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumBytes {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	record, err := decodeRecord(raw)
	if err != nil {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	return record, nil
}

func (r *Repository) activePath(operationID install.OperationID) string {
	return filepath.Join(r.root, recordBasename(operationID)+activeSuffix)
}

func (r *Repository) claimedPath(operationID install.OperationID) string {
	return filepath.Join(r.root, recordBasename(operationID)+claimedSuffix)
}

func recordBasename(operationID install.OperationID) string {
	token, _ := rebootcontinuation.TokenFor(operationID)
	return "sha256-" + token
}

type recordDTO struct {
	LauncherPath   string `json:"launcher_path"`
	LauncherSHA256 string `json:"launcher_sha256"`
	OperationID    string `json:"operation_id"`
	JournalPath    string `json:"journal_path"`
	JournalSHA256  string `json:"journal_sha256"`
	ExpiresAt      string `json:"expires_at"`
	Nonce          string `json:"nonce"`
}

func encodeRecord(record rebootcontinuation.Record) ([]byte, error) {
	if record.OperationID().IsZero() || record.Nonce().IsZero() {
		return nil, rebootapp.ErrRecordIntegrity
	}
	return json.Marshal(recordDTO{
		LauncherPath: record.LauncherPath(), LauncherSHA256: record.LauncherDigest().String(),
		OperationID: record.OperationID().String(), JournalPath: record.JournalPath(),
		JournalSHA256: record.JournalDigest().String(), ExpiresAt: record.ExpiresAt().Format(time.RFC3339Nano),
		Nonce: base64.RawURLEncoding.EncodeToString(record.Nonce().Bytes()),
	})
}

func decodeRecord(raw []byte) (rebootcontinuation.Record, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var dto recordDTO
	if err := decoder.Decode(&dto); err != nil {
		return rebootcontinuation.Record{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	launcherDigest, launcherError := install.ParseDigest(dto.LauncherSHA256)
	journalDigest, journalError := install.ParseDigest(dto.JournalSHA256)
	operationID, operationError := install.NewOperationID(dto.OperationID)
	expiresAt, expiryError := time.Parse(time.RFC3339Nano, dto.ExpiresAt)
	nonceBytes, nonceDecodeError := base64.RawURLEncoding.DecodeString(dto.Nonce)
	nonce, nonceError := rebootcontinuation.NewNonce(nonceBytes)
	if launcherError != nil || journalError != nil || operationError != nil || expiryError != nil ||
		nonceDecodeError != nil || nonceError != nil {
		return rebootcontinuation.Record{}, rebootapp.ErrRecordIntegrity
	}
	// Production records always use the exact 24-hour lifetime. Reconstructing
	// from that fixed lower bound validates shape even after the record expires.
	return rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath: dto.LauncherPath, LauncherDigest: launcherDigest, OperationID: operationID,
		JournalPath: dto.JournalPath, JournalDigest: journalDigest, ExpiresAt: expiresAt, Nonce: nonce,
	}, expiresAt.Add(-rebootcontinuation.MaximumLifetime))
}

func publishCompleteFile(ctx context.Context, root, target string, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := filepath.Join(root, ".continuation-"+hex.EncodeToString(random[:])+".tmp")
	file, err := platformCreateProtectedFile(ctx, temporary)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(payload); err == nil {
		err = file.Sync()
	}
	if closeError := file.Close(); err == nil {
		err = closeError
	}
	if err != nil {
		return err
	}
	if err = os.Link(temporary, target); err != nil {
		return err
	}
	if err = platformSyncDirectory(root); err != nil {
		return err
	}
	if err = os.Remove(temporary); err != nil {
		return err
	}
	removeTemporary = false
	return platformSyncDirectory(root)
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func removeAndSync(root, path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return platformSyncDirectory(root)
}

func sameRecord(left, right rebootcontinuation.Record) bool {
	return left.OperationID() == right.OperationID() && left.LauncherPath() == right.LauncherPath() &&
		left.LauncherDigest().Equal(right.LauncherDigest()) && left.JournalPath() == right.JournalPath() &&
		left.JournalDigest().Equal(right.JournalDigest()) && left.ExpiresAt().Equal(right.ExpiresAt()) &&
		left.Nonce() == right.Nonce()
}

func validToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for _, character := range token {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func recordMatchesToken(record rebootcontinuation.Record, token string) bool {
	actual, err := rebootcontinuation.TokenFor(record.OperationID())
	return err == nil && actual == token
}

var _ rebootapp.RecordRepository = (*Repository)(nil)
