// Package productfs implements PF-001 product-directory and protected-secret
// ports with native descriptor/handle security and durable atomic publication.
package productfs

import (
	"context"
	"crypto/rand"
	"io"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
)

// Ensurer is the stateless production product-filesystem adapter. The mutex
// only serializes reads from the configured cryptographic entropy source.
type Ensurer struct {
	randomMu sync.Mutex
	random   io.Reader
}

// NewEnsurer uses the operating system cryptographic random source.
func NewEnsurer() *Ensurer { return &Ensurer{random: rand.Reader} }

func newEnsurerWithRandom(random io.Reader) *Ensurer { return &Ensurer{random: random} }

// EnsureDirectories creates or re-verifies the exact plan-authorized layout.
func (e *Ensurer) EnsureDirectories(
	ctx context.Context,
	command productinstall.DirectoryCommand,
) (productinstall.DirectoryReceipt, error) {
	if e == nil {
		return productinstall.DirectoryReceipt{}, productinstall.ErrUnavailable
	}
	return ensureNativeDirectories(ctx, command)
}

// EnsureSecrets atomically creates or re-verifies all seven exact 256-bit values.
func (e *Ensurer) EnsureSecrets(
	ctx context.Context,
	command productinstall.SecretCommand,
) (productinstall.SecretReceipt, error) {
	if e == nil || e.random == nil {
		return productinstall.SecretReceipt{}, productinstall.ErrUnavailable
	}
	return ensureNativeSecrets(ctx, command, e.fillRandom)
}

func (e *Ensurer) fillRandom(target []byte) error {
	e.randomMu.Lock()
	defer e.randomMu.Unlock()
	_, err := io.ReadFull(e.random, target)
	return err
}

var (
	_ productinstall.DirectoryEnsurer = (*Ensurer)(nil)
	_ productinstall.SecretEnsurer    = (*Ensurer)(nil)
)
