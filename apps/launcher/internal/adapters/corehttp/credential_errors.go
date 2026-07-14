package corehttp

import "errors"

var (
	errCredentialIntegrity   = errors.New("core API credential integrity violation")
	errCredentialUnavailable = errors.New("core API credential unavailable")
)
