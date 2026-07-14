// Package installplan defines the one closed canonical PF-001 installation
// plan understood by this launcher generation.
package installplan

import "errors"

var (
	// ErrMalformed means the input is not one bounded JSON object.
	ErrMalformed = errors.New("installation plan JSON is malformed")
	// ErrDuplicateKey means an object repeats a JSON member at any depth.
	ErrDuplicateKey = errors.New("installation plan contains a duplicate JSON key")
	// ErrUnknownField means schema v1 does not understand an input member.
	ErrUnknownField = errors.New("installation plan contains an unknown field")
	// ErrUnsupportedSchema means the declared installation-plan major is not v1.
	ErrUnsupportedSchema = errors.New("installation plan schema major is unsupported")
	// ErrNonCanonical means valid values were not encoded as the exact canonical bytes.
	ErrNonCanonical = errors.New("installation plan JSON is not canonical")
	// ErrIntegrity means a required binding is absent, contradictory, or unsafe.
	ErrIntegrity = errors.New("installation plan integrity validation failed")
)
