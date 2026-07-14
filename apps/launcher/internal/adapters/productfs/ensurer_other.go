//go:build !darwin && !linux && !windows

package productfs

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
)

func ensureNativeDirectories(
	context.Context,
	productinstall.DirectoryCommand,
) (productinstall.DirectoryReceipt, error) {
	return productinstall.DirectoryReceipt{}, productinstall.ErrUnsupported
}

func ensureNativeSecrets(
	context.Context,
	productinstall.SecretCommand,
	func([]byte) error,
) (productinstall.SecretReceipt, error) {
	return productinstall.SecretReceipt{}, productinstall.ErrUnsupported
}
