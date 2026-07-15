package launcher

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/setuphost"
)

func TestPF001NativeArtifactApplicationUsesVerifiedBundleAndNativeSystemProxyHTTPS(t *testing.T) {
	t.Parallel()
	repository, err := artifactjournal.New(nativeMissingJournalProvider{}, setuphost.Clock{})
	if err != nil {
		t.Fatal(err)
	}
	storeRoot := filepath.Join(nativeReleaseAuthorityBundleRoot(t), "cas")
	if err := ensureNativePrivateDirectory(t.Context(), storeRoot); err != nil {
		t.Fatal(err)
	}
	store, err := artifactfs.NewStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	releaseFixture := nativeReleaseStackFixture(t)
	release, err := newNativeReleaseAuthority(t.Context(), nativeReleaseAuthorityDependencies{
		BundleRoot: func() (string, error) { return nativeReleaseAuthorityBundleRoot(t), nil },
		Trust:      func() (nativeReleaseTrustMaterial, error) { return releaseFixture.Trust, nil },
		Clock:      releaseFixture.Clock, AntiRollback: releaseFixture.AntiRollback,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release.Close(t.Context()) })
	application, err := newNativeArtifactApplication(repository, store, release)
	if err != nil || application == nil {
		t.Fatalf("application=%#v error=%v", application, err)
	}
}

func TestPF001NativeArtifactApplicationRejectsPartialAcquisitionAuthority(t *testing.T) {
	t.Parallel()
	var repository *artifactjournal.Repository
	var store *artifactfs.Store
	var release *nativeReleaseAuthority
	for _, test := range []struct {
		name       string
		repository *artifactjournal.Repository
		store      *artifactfs.Store
		release    *nativeReleaseAuthority
	}{
		{name: "repository", store: store, release: release},
		{name: "store", repository: repository, release: release},
		{name: "release", repository: repository, store: store},
		{
			name:       "release without verified bundle source",
			repository: &artifactjournal.Repository{},
			store:      &artifactfs.Store{},
			release:    &nativeReleaseAuthority{},
		},
	} {
		if application, err := newNativeArtifactApplication(test.repository, test.store, test.release); application != nil ||
			!errors.Is(err, errNativeInstallerIntegrity) {
			t.Fatalf("%s application=%#v error=%v", test.name, application, err)
		}
	}
}
