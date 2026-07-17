//go:build darwin

package dockercli

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestPF001ComposeNativeIdentityBindsEveryDarwinInodeField(t *testing.T) {
	t.Parallel()
	status := &syscall.Stat_t{
		Dev: 41,
		Ino: 73,
		Birthtimespec: syscall.Timespec{
			Sec:  101,
			Nsec: 131,
		},
	}
	token, valid := composeNativeIdentity(darwinIdentityFileInfo{status: status})
	expected := fmt.Sprintf("%d:%d:%d:%d", status.Dev, status.Ino, status.Birthtimespec.Sec, status.Birthtimespec.Nsec)
	if !valid || token != expected {
		t.Fatalf("native identity=%q valid=%t", token, valid)
	}
	zeroToken, zeroValid := composeNativeIdentity(darwinIdentityFileInfo{status: &syscall.Stat_t{}})
	if !zeroValid || zeroToken != "0:0:0:0" {
		t.Fatalf("zero-boundary native identity=%q valid=%t", zeroToken, zeroValid)
	}

	for name, info := range map[string]os.FileInfo{
		"nil":          nil,
		"foreign stat": darwinIdentityFileInfo{status: struct{}{}},
		"negative dev": darwinIdentityFileInfo{status: &syscall.Stat_t{Dev: -1}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := composeNativeIdentity(info); ok || got != "" {
				t.Fatalf("native identity=%q valid=%t", got, ok)
			}
		})
	}
}

type darwinIdentityFileInfo struct{ status any }

func (darwinIdentityFileInfo) Name() string       { return "identity" }
func (darwinIdentityFileInfo) Size() int64        { return 0 }
func (darwinIdentityFileInfo) Mode() os.FileMode  { return 0 }
func (darwinIdentityFileInfo) ModTime() time.Time { return time.Time{} }
func (darwinIdentityFileInfo) IsDir() bool        { return false }
func (i darwinIdentityFileInfo) Sys() any         { return i.status }
