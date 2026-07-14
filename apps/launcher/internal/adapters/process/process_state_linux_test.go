//go:build linux

package process

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func processGoneOrZombie(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat") // #nosec G304 -- pid is a positive native child identifier from the test process.
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	closingName := strings.LastIndexByte(string(raw), ')')
	return closingName >= 0 && len(raw) > closingName+2 && raw[closingName+2] == 'Z'
}
