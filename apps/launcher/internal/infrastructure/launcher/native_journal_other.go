//go:build !darwin && !linux && !windows

package launcher

import (
	"errors"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeconsent"
)

func newPlatformJournalProvider(
	*bootstrapadapter.OperationLocator,
) (filesystem.OperationJournalProvider, error) {
	return nil, errors.New("native journal platform is unsupported")
}

func newPlatformConsentSigner(
	*bootstrapadapter.OperationLocator,
) (*runtimeconsent.ProtectedSigner, error) {
	return nil, errors.New("native consent signing is unsupported on this platform")
}
