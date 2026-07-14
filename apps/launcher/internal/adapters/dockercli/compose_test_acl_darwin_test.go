//go:build darwin

package dockercli

import "testing"

func removeInheritedTestACL(*testing.T, string, bool) {}
