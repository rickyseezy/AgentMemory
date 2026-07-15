//go:build darwin || linux

package launcher

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006NativePrivilegeHelperSelfVerifierHashesProtectedExactExecutable(t *testing.T) {
	t.Parallel()
	if verifier, err := NewNativePrivilegeHelperSelfVerifier(); err != nil || verifier == nil {
		t.Fatalf("production self verifier=%+v error=%v", verifier, err)
	}
	raw := []byte("signed immutable Linux helper")
	path := filepath.Join(t.TempDir(), "agentmemory-runtime-helper")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o500); err != nil { // #nosec G302 -- executable-only fixture is intentional.
		t.Fatal(err)
	}
	resource := nativePrivilegeHelperResource(t, raw)
	uid, gid := nativePrivilegeTestOwner(t)
	verifier, err := newNativePrivilegeHelperFileVerifier(path, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := verifier.VerifyPrivilegeHelperSelf(
		t.Context(), resource, launcherLinuxAuthority(t, runtimeport.PackageManagerAPT),
	)
	if err != nil || digest != runtimeinstall.Sum(raw) {
		t.Fatalf("digest=%s error=%v", digest, err)
	}
}

func TestPF006NativePrivilegeHelperSelfVerifierRejectsPathMetadataAndContentSubstitution(t *testing.T) {
	t.Parallel()
	raw := []byte("signed immutable Linux helper")
	root := t.TempDir()
	valid := filepath.Join(root, "agentmemory-runtime-helper")
	if err := os.WriteFile(valid, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(valid, 0o500); err != nil { // #nosec G302 -- executable-only fixture is intentional.
		t.Fatal(err)
	}
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerAPT)
	resource := nativePrivilegeHelperResource(t, raw)
	uid, gid := nativePrivilegeTestOwner(t)
	for name, prepare := range map[string]func(*testing.T) (string, releaseinventory.Resource, uint32, uint32){
		"symlink": func(t *testing.T) (string, releaseinventory.Resource, uint32, uint32) {
			path := filepath.Join(root, "helper-link")
			if err := os.Symlink(valid, path); err != nil {
				t.Fatal(err)
			}
			return path, resource, uid, gid
		},
		"group writable": func(t *testing.T) (string, releaseinventory.Resource, uint32, uint32) {
			path := filepath.Join(root, "helper-writable")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o520); err != nil { // #nosec G302 -- unsafe mode is the negative fixture.
				t.Fatal(err)
			}
			return path, resource, uid, gid
		},
		"wrong owner": func(*testing.T) (string, releaseinventory.Resource, uint32, uint32) {
			return valid, resource, uid + 1, gid
		},
		"digest": func(t *testing.T) (string, releaseinventory.Resource, uint32, uint32) {
			foreign := append([]byte(nil), raw...)
			foreign[0] ^= 0xff
			return valid, nativePrivilegeHelperResource(t, foreign), uid, gid
		},
		"architecture": func(t *testing.T) (string, releaseinventory.Resource, uint32, uint32) {
			return valid, nativePrivilegeHelperResourceForArchitecture(t, raw, "arm64"), uid, gid
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, candidate, uid, gid := prepare(t)
			verifier, constructError := newNativePrivilegeHelperFileVerifier(path, uid, gid)
			if constructError != nil {
				t.Fatal(constructError)
			}
			if digest, verifyError := verifier.VerifyPrivilegeHelperSelf(
				t.Context(), candidate, authority,
			); !errors.Is(verifyError, runtimeport.ErrPrivilegeIntegrity) || !digest.IsZero() {
				t.Fatalf("digest=%s error=%v", digest, verifyError)
			}
		})
	}
	if verifier, err := newNativePrivilegeHelperFileVerifier("relative", 0, 0); verifier != nil || err == nil {
		t.Fatal("relative helper path accepted")
	}
	verifier, err := newNativePrivilegeHelperFileVerifier(valid, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if digest, verifyError := verifier.VerifyPrivilegeHelperSelf(cancelled, resource, authority); !errors.Is(verifyError, context.Canceled) || !digest.IsZero() {
		t.Fatalf("cancelled digest=%s error=%v", digest, verifyError)
	}
}

func nativePrivilegeTestOwner(t testing.TB) (uint32, uint32) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid < 0 || gid < 0 || uint64(uid) > math.MaxUint32 || uint64(gid) > math.MaxUint32 {
		t.Fatal("test owner is outside the supported Linux identity range")
	}
	return uint32(uid), uint32(gid) // #nosec G115 -- ranges are proven above.
}

func nativePrivilegeHelperResource(t testing.TB, raw []byte) releaseinventory.Resource {
	t.Helper()
	return nativePrivilegeHelperResourceForArchitecture(t, raw, "amd64")
}

func nativePrivilegeHelperResourceForArchitecture(
	t testing.TB,
	raw []byte,
	architecture string,
) releaseinventory.Resource {
	t.Helper()
	platform, err := releaseinventory.NewPlatform("linux", architecture)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID:   "runtime-helper-linux-" + architecture,
		Kind: releaseinventory.ResourceKindHelper, Purpose: releaseinventory.ResourcePurposeNativeHelper,
		MediaType: releaseinventory.MediaTypeNativeExecutable, Platform: platform,
		Digest: releaseinventory.DigestBytes(raw), Size: uint64(len(raw)),
		SourceRef:               "bundle://runtime-helper-linux-" + architecture,
		SourceAllowlist:         []string{"bundle://runtime-helper-linux-" + architecture},
		CycloneDXSBOMResourceID: "helper-cyclonedx", SPDXSBOMResourceID: "helper-spdx",
		ProvenanceResourceID: "helper-provenance", LicenseResourceID: "helper-license",
		VulnerabilityResourceID: "helper-vulnerability", NativePublisherIdentity: "agentmemory.publisher",
		NativePublisherPolicyID: "agentmemory-native-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}
