// Package hostverification defines the signed, immutable policy and native
// evidence required by PF-001's pre-runtime VerifyHost phase.
package hostverification

import "errors"

var (
	// ErrMalformed means a persisted host plan is not one bounded JSON object.
	ErrMalformed = errors.New("host verification plan is malformed")
	// ErrUnknownField means the closed v1 schema does not understand a member.
	ErrUnknownField = errors.New("host verification plan contains an unknown field")
	// ErrUnsupportedSchema means the host plan schema is not exactly v1.
	ErrUnsupportedSchema = errors.New("host verification plan schema is unsupported")
	// ErrNonCanonical means otherwise valid values were not encoded canonically.
	ErrNonCanonical = errors.New("host verification plan is not canonical")
	// ErrIntegrity means a policy, signature envelope, or observation is incomplete.
	ErrIntegrity = errors.New("host verification integrity validation failed")
)
