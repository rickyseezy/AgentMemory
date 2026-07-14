// Package installplanfs persists immutable canonical PF-001 plans in one
// explicitly configured owner-controlled local directory.
package installplanfs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

const maximumPersistedPlanBytes = 32 * 1024 * 1024

var errImmutableConflict = errors.New("immutable plan bytes conflict")

type platformStore interface {
	load(context.Context, string) ([]byte, error)
	save(context.Context, string, []byte) error
	close() error
}

// Repository is a repository-pattern adapter over an owner-only descriptor/
// handle rooted store. Plan filenames are derived only from SHA-256.
type Repository struct {
	mu    sync.RWMutex
	store platformStore
}

// NewRepository opens or creates one explicit private repository root. It
// never selects a home directory, environment variable, or ambient path.
func NewRepository(ctx context.Context, root string) (*Repository, error) {
	if ctx == nil || strings.TrimSpace(root) == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		strings.IndexByte(root, 0) >= 0 {
		return nil, installplanapp.ErrPlanIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := openPlatformStore(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("open canonical plan repository: %w", installplanapp.ErrPlanIntegrity)
	}
	return &Repository{store: store}, nil
}

// Save durably publishes exact canonical bytes once. Same-content replay is
// idempotent; replacement or contradictory content is impossible.
func (r *Repository) Save(ctx context.Context, plan installplan.Plan) error {
	if r == nil || ctx == nil || plan.Digest().IsZero() {
		return installplanapp.ErrPlanIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.store == nil {
		return installplanapp.ErrPlanIntegrity
	}
	canonical := plan.CanonicalBytes()
	if len(canonical) == 0 || len(canonical) > maximumPersistedPlanBytes {
		return installplanapp.ErrPlanIntegrity
	}
	verified, err := installplan.DecodeV1(canonical)
	if err != nil || !verified.Digest().Equal(plan.Digest()) {
		return installplanapp.ErrPlanIntegrity
	}
	if err := r.store.save(ctx, planFilename(plan.Digest()), canonical); err != nil {
		if errors.Is(err, errImmutableConflict) {
			return installplanapp.ErrPlanConflict
		}
		return fmt.Errorf("persist canonical plan: %w", installplanapp.ErrPlanIntegrity)
	}
	return nil
}

// Load authenticates file shape/ownership and exact bytes before returning an
// immutable domain plan.
func (r *Repository) Load(ctx context.Context, digest install.PlanDigest) (installplan.Plan, error) {
	if r == nil || ctx == nil || digest.IsZero() {
		return installplan.Plan{}, installplanapp.ErrPlanIntegrity
	}
	if err := ctx.Err(); err != nil {
		return installplan.Plan{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.store == nil {
		return installplan.Plan{}, installplanapp.ErrPlanIntegrity
	}
	raw, err := r.store.load(ctx, planFilename(digest))
	if err != nil {
		if errors.Is(err, errPlanNotFound) {
			return installplan.Plan{}, installplanapp.ErrPlanNotFound
		}
		return installplan.Plan{}, fmt.Errorf("load canonical plan: %w", installplanapp.ErrPlanIntegrity)
	}
	if len(raw) == 0 || len(raw) > maximumPersistedPlanBytes {
		return installplan.Plan{}, installplanapp.ErrPlanIntegrity
	}
	plan, err := installplan.DecodeV1(raw)
	if err != nil || !plan.Digest().Equal(digest) {
		return installplan.Plan{}, installplanapp.ErrPlanIntegrity
	}
	return plan, nil
}

// Close releases retained directory descriptors/handles. It is idempotent.
func (r *Repository) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		return nil
	}
	err := r.store.close()
	r.store = nil
	return err
}

func planFilename(digest install.PlanDigest) string {
	return "sha256-" + digest.String() + ".json"
}

var _ installplanapp.Repository = (*Repository)(nil)
