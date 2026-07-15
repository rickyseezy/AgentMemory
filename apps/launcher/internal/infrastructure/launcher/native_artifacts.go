package launcher

import (
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifacthttp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactsource"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/systemproxy"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
)

const nativeArtifactFetchTimeout = 2 * time.Minute

// newNativeArtifactApplication composes the only production acquisition
// routes: strict TLS 1.3 HTTPS through the invoking user's native per-URL
// proxy/PAC authority (never process environment) and the exact retained
// bundle already owned by the verified release authority.
func newNativeArtifactApplication(
	repository artifactapp.Repository,
	store *artifactfs.Store,
	release *nativeReleaseAuthority,
) (*artifactapp.Application, error) {
	if nilAny(repository) || store == nil || release == nil || release.source == nil {
		return nil, errNativeInstallerIntegrity
	}
	proxy, err := systemproxy.New()
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	https, err := artifacthttp.New(artifacthttp.ProxyPolicy{
		Mode: artifacthttp.ProxySystem, Resolver: proxy, CredentialProvider: proxy,
	}, nativeArtifactFetchTimeout)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	fetcher, err := artifactsource.New(https, release.source)
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	application, err := artifactapp.New(artifactapp.Dependencies{
		Repository: repository, Reservation: store, Fetcher: fetcher, Store: store,
	})
	if err != nil {
		return nil, errNativeInstallerIntegrity
	}
	return application, nil
}
