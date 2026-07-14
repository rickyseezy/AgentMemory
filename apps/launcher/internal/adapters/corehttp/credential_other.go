//go:build !darwin && !linux && !windows

package corehttp

import "context"

func readNativeCredential(context.Context, string) ([]byte, error) {
	return nil, errCredentialUnavailable
}
