//go:build darwin && !cgo

package corehttp

func verifyCredentialACL(int, bool) error { return errCredentialUnavailable }
