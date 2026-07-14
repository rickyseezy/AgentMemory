//go:build darwin && !cgo

package agentconfigadapter

import (
	"errors"
	"os"
)

func darwinACLFree(*os.File) error {
	return errors.New("darwin ACL proof requires the native cgo capability")
}
