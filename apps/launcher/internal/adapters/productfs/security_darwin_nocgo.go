//go:build darwin && !cgo

package productfs

import (
	"os"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
)

func verifyNativeACL(*os.File) error { return productinstall.ErrUnsupported }

func syncNativeFile(*os.File) error { return productinstall.ErrUnsupported }
