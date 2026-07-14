// Package artifactsource routes exact signed sources to scheme-specific,
// independently hardened acquisition adapters.
package artifactsource

import (
	"context"
	"reflect"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

// Fetcher composes strict HTTPS and owner-controlled offline-bundle sources.
type Fetcher struct {
	https  artifactapp.Fetcher
	bundle artifactapp.Fetcher
}

// New rejects absent and typed-nil source capabilities.
func New(https artifactapp.Fetcher, bundle artifactapp.Fetcher) (*Fetcher, error) {
	if nilFetcher(https) || nilFetcher(bundle) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	return &Fetcher{https: https, bundle: bundle}, nil
}

// Fetch authorizes the exact signed source before selecting one closed route.
func (f *Fetcher) Fetch(
	ctx context.Context,
	artifact artifactacquisition.Artifact,
	source string,
	chunk artifactacquisition.Chunk,
) ([]byte, error) {
	if ctx == nil || !artifact.SourceAuthorized(source) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	switch {
	case strings.HasPrefix(source, "https://"):
		return f.https.Fetch(ctx, artifact, source, chunk)
	case strings.HasPrefix(source, "bundle://"):
		return f.bundle.Fetch(ctx, artifact, source, chunk)
	default:
		return nil, artifactapp.ErrFetchIntegrity
	}
}

func nilFetcher(value artifactapp.Fetcher) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ artifactapp.Fetcher = (*Fetcher)(nil)
