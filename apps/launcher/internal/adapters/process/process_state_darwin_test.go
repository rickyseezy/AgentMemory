//go:build darwin

package process

import (
	"errors"
	"syscall"
)

func processGoneOrZombie(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
