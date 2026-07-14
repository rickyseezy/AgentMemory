//go:build !darwin && !linux && !windows

package dockercli

func privateComposePath(string, bool) bool { return false }
