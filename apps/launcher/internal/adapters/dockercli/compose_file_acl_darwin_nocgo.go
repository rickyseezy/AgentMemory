//go:build darwin && !cgo

package dockercli

import "os"

func composeACLFree(string) bool { return false }

func composeACLFreeOpened(*os.File) bool { return false }
