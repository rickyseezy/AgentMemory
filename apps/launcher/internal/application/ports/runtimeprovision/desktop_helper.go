package runtimeprovision

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// DesktopHelperAuthorityInput is populated only from the signed launcher
// release manifest and the exact desktop plan.
type DesktopHelperAuthorityInput struct {
	Platform              runtimeinstall.Platform
	Architecture          runtimeinstall.Architecture
	PlanDigest            runtimeinstall.Hash
	PrincipalID           string
	MachineDigest         runtimeinstall.Hash
	CanonicalPath         string
	SHA256                runtimeinstall.Hash
	PublisherIdentity     string
	PublisherCertificate  runtimeinstall.Hash
	ReleaseManifestDigest runtimeinstall.Hash
	ExchangeDirectory     string
}

// DesktopHelperAuthority is immutable native-elevation helper authority.
type DesktopHelperAuthority struct {
	input  DesktopHelperAuthorityInput
	digest runtimeinstall.Hash
}

// NewDesktopHelperAuthority validates one exact signed helper projection.
func NewDesktopHelperAuthority(input DesktopHelperAuthorityInput) (DesktopHelperAuthority, error) {
	if !validDesktopPlatformArchitecture(input.Platform, input.Architecture) || input.PlanDigest.IsZero() ||
		!safePrincipal(input.PrincipalID, input.Platform) || input.MachineDigest.IsZero() || input.SHA256.IsZero() ||
		!safeAuthorityIdentifier(input.PublisherIdentity, 128) || input.PublisherCertificate.IsZero() ||
		input.ReleaseManifestDigest.IsZero() || !validDesktopHelperPaths(input) {
		return DesktopHelperAuthority{}, ErrDesktopMutationIntegrity
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return DesktopHelperAuthority{}, ErrDesktopMutationIntegrity
	}
	return DesktopHelperAuthority{input: input, digest: runtimeinstall.Sum(encoded)}, nil
}

func validDesktopHelperPaths(input DesktopHelperAuthorityInput) bool {
	switch input.Platform {
	case runtimeinstall.PlatformDarwin:
		return input.CanonicalPath == "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper" &&
			safeUnixAbsolute(input.ExchangeDirectory) && strings.Contains(input.ExchangeDirectory, "/Library/Application Support/AgentMemory/bootstrap/") &&
			strings.HasSuffix(input.ExchangeDirectory, "/native") && !strings.HasPrefix(input.ExchangeDirectory, "/tmp/")
	case runtimeinstall.PlatformWindows:
		return input.CanonicalPath == `C:\Program Files\AgentMemory\bin\agentmemory-runtime-helper.exe` &&
			safeWindowsAbsolute(input.ExchangeDirectory) &&
			strings.Contains(strings.ToLower(input.ExchangeDirectory), `\appdata\local\agentmemory\bootstrap\`) &&
			strings.HasSuffix(strings.ToLower(input.ExchangeDirectory), `\native`)
	case runtimeinstall.PlatformUnknown, runtimeinstall.PlatformLinux:
		return false
	}
	return false
}

// Valid revalidates every helper authority field.
func (a DesktopHelperAuthority) Valid() bool {
	restored, err := NewDesktopHelperAuthority(a.input)
	return err == nil && restored.digest == a.digest && !a.digest.IsZero()
}

// ValidFor binds the helper to one host, principal, and desktop plan.
func (a DesktopHelperAuthority) ValidFor(desktop DesktopAuthority) bool {
	return a.Valid() && desktop.Valid() && a.input.Platform == desktop.Platform() &&
		a.input.Architecture == desktop.Architecture() && a.input.PlanDigest == desktop.PlanDigest() &&
		a.input.PrincipalID == desktop.PrincipalID() && a.input.MachineDigest == desktop.MachineDigest()
}

// Platform returns the authorized helper host platform.
func (a DesktopHelperAuthority) Platform() runtimeinstall.Platform { return a.input.Platform }

// Architecture returns the authorized helper host architecture.
func (a DesktopHelperAuthority) Architecture() runtimeinstall.Architecture {
	return a.input.Architecture
}

// PlanDigest returns the bound desktop plan digest.
func (a DesktopHelperAuthority) PlanDigest() runtimeinstall.Hash { return a.input.PlanDigest }

// PrincipalID returns the authorized native principal identity.
func (a DesktopHelperAuthority) PrincipalID() string { return a.input.PrincipalID }

// MachineDigest returns the bound machine identity digest.
func (a DesktopHelperAuthority) MachineDigest() runtimeinstall.Hash { return a.input.MachineDigest }

// CanonicalPath returns the exact installed helper path.
func (a DesktopHelperAuthority) CanonicalPath() string { return a.input.CanonicalPath }

// SHA256 returns the exact signed helper artifact digest.
func (a DesktopHelperAuthority) SHA256() runtimeinstall.Hash { return a.input.SHA256 }

// PublisherIdentity returns the pinned native helper publisher identity.
func (a DesktopHelperAuthority) PublisherIdentity() string { return a.input.PublisherIdentity }

// PublisherCertificate returns the pinned helper signer certificate digest.
func (a DesktopHelperAuthority) PublisherCertificate() runtimeinstall.Hash {
	return a.input.PublisherCertificate
}

// ReleaseManifestDigest returns the signed release manifest digest.
func (a DesktopHelperAuthority) ReleaseManifestDigest() runtimeinstall.Hash {
	return a.input.ReleaseManifestDigest
}

// ExchangeDirectory returns the private native-helper exchange directory.
func (a DesktopHelperAuthority) ExchangeDirectory() string { return a.input.ExchangeDirectory }

// Digest returns the complete immutable helper authority digest.
func (a DesktopHelperAuthority) Digest() runtimeinstall.Hash { return a.digest }

// DesktopHelperAuthorityResolver verifies the release manifest projection.
type DesktopHelperAuthorityResolver interface {
	ResolveDesktopHelperAuthority(context.Context, DesktopAuthority) (DesktopHelperAuthority, error)
}

// DesktopHelperPublisherVerifier proves the retained helper's exact native signer.
type DesktopHelperPublisherVerifier interface {
	VerifyDesktopHelperPublisher(context.Context, DesktopHelperAuthority) error
}
