package runtimecatalog

import (
	"sort"
	"strings"
)

// PublisherPolicyInput declares the exact platform-native artifact identity.
type PublisherPolicyInput struct {
	Verification       NativeVerification
	Identity           string
	SigningKeyIdentity string
	PackageIdentity    string
}

// PublisherPolicy is immutable native publisher verification authority.
type PublisherPolicy struct {
	verification       NativeVerification
	identity           string
	signingKeyIdentity string
	packageIdentity    string
}

func newPublisherPolicy(input PublisherPolicyInput, platform OSKind) (PublisherPolicy, error) {
	if !input.Verification.valid() || !validIdentifier(input.Identity) ||
		!validIdentifier(input.SigningKeyIdentity) || !validIdentifier(input.PackageIdentity) ||
		platform == OSKindMacOS && input.Verification != NativeVerificationAppleNotarized ||
		platform == OSKindWindows && input.Verification != NativeVerificationAuthenticode ||
		platform == OSKindLinux && input.Verification != NativeVerificationPackageSignature {
		return PublisherPolicy{}, ErrManifestIntegrity
	}
	return PublisherPolicy{
		verification: input.Verification, identity: input.Identity,
		signingKeyIdentity: input.SigningKeyIdentity, packageIdentity: input.PackageIdentity,
	}, nil
}

// Verification returns the required native trust mechanism.
func (p PublisherPolicy) Verification() NativeVerification { return p.verification }

// Identity returns the exact native publisher identity.
func (p PublisherPolicy) Identity() string { return p.identity }

// SigningKeyIdentity returns the exact native signing key or certificate identity.
func (p PublisherPolicy) SigningKeyIdentity() string { return p.signingKeyIdentity }

// PackageIdentity returns the exact native package/application identity.
func (p PublisherPolicy) PackageIdentity() string { return p.packageIdentity }

func (p PublisherPolicy) valid(platform OSKind) bool {
	_, err := newPublisherPolicy(PublisherPolicyInput{
		Verification: p.verification, Identity: p.identity,
		SigningKeyIdentity: p.signingKeyIdentity, PackageIdentity: p.packageIdentity,
	}, platform)
	return err == nil
}

// ArtifactPolicyInput declares immutable artifact acquisition and trust policy.
type ArtifactPolicyInput struct {
	DownloadBytes           uint64
	ExpandedBytes           uint64
	ReserveBytes            uint64
	SHA256                  Digest
	Sources                 []OfficialSourceInput
	ProxyMode               ProxyMode
	OfflinePolicy           OfflinePolicy
	RedistributionPermitted bool
	Publisher               PublisherPolicyInput
}

// ArtifactPolicy is a complete immutable artifact descriptor.
type ArtifactPolicy struct {
	downloadBytes           uint64
	expandedBytes           uint64
	reserveBytes            uint64
	sha256                  Digest
	sources                 []SourceLocation
	proxyMode               ProxyMode
	offlinePolicy           OfflinePolicy
	redistributionPermitted bool
	publisher               PublisherPolicy
}

func newArtifactPolicy(input ArtifactPolicyInput, platform OSKind) (ArtifactPolicy, error) {
	if input.DownloadBytes == 0 || input.DownloadBytes > maximumSafeJSONInteger ||
		input.ExpandedBytes < input.DownloadBytes || input.ExpandedBytes > maximumSafeJSONInteger ||
		input.ReserveBytes < input.ExpandedBytes || input.ReserveBytes > maximumSafeJSONInteger ||
		input.SHA256.IsZero() || len(input.Sources) == 0 || len(input.Sources) > 16 ||
		!input.ProxyMode.valid() || !input.OfflinePolicy.valid() ||
		input.OfflinePolicy == OfflinePolicyBundled && !input.RedistributionPermitted ||
		input.OfflinePolicy == OfflinePolicyUserSelectedOfficial && input.RedistributionPermitted {
		return ArtifactPolicy{}, ErrManifestIntegrity
	}
	publisher, err := newPublisherPolicy(input.Publisher, platform)
	if err != nil {
		return ArtifactPolicy{}, ErrManifestIntegrity
	}
	sources := make([]SourceLocation, 0, len(input.Sources))
	for _, sourceInput := range input.Sources {
		if !strings.HasSuffix(sourceInput.PathPrefix, "/") {
			return ArtifactPolicy{}, ErrManifestIntegrity
		}
		source, sourceError := NewSourceLocation(sourceInput)
		if sourceError != nil {
			return ArtifactPolicy{}, ErrManifestIntegrity
		}
		sources = append(sources, source)
	}
	sort.Slice(sources, func(left int, right int) bool {
		if sources[left].host != sources[right].host {
			return sources[left].host < sources[right].host
		}
		return sources[left].pathPrefix < sources[right].pathPrefix
	})
	for index := 1; index < len(sources); index++ {
		if sources[index] == sources[index-1] {
			return ArtifactPolicy{}, ErrManifestIntegrity
		}
	}
	return ArtifactPolicy{
		downloadBytes: input.DownloadBytes, expandedBytes: input.ExpandedBytes,
		reserveBytes: input.ReserveBytes, sha256: input.SHA256, sources: sources,
		proxyMode: input.ProxyMode, offlinePolicy: input.OfflinePolicy,
		redistributionPermitted: input.RedistributionPermitted, publisher: publisher,
	}, nil
}

// DownloadBytes returns the exact network artifact byte length.
func (a ArtifactPolicy) DownloadBytes() uint64 { return a.downloadBytes }

// ExpandedBytes returns the certified expanded size bound.
func (a ArtifactPolicy) ExpandedBytes() uint64 { return a.expandedBytes }

// ReserveBytes returns the required free-space reservation.
func (a ArtifactPolicy) ReserveBytes() uint64 { return a.reserveBytes }

// SHA256 returns the exact artifact digest.
func (a ArtifactPolicy) SHA256() Digest { return a.sha256 }

// Sources returns a defensive copy of the official source allowlist.
func (a ArtifactPolicy) Sources() []SourceLocation {
	return append([]SourceLocation(nil), a.sources...)
}

// ProxyMode returns the closed acquisition proxy policy.
func (a ArtifactPolicy) ProxyMode() ProxyMode { return a.proxyMode }

// OfflinePolicy returns the signed offline artifact policy.
func (a ArtifactPolicy) OfflinePolicy() OfflinePolicy { return a.offlinePolicy }

// RedistributionPermitted reports whether the vendor artifact may be bundled.
func (a ArtifactPolicy) RedistributionPermitted() bool { return a.redistributionPermitted }

// Publisher returns the exact native publisher policy.
func (a ArtifactPolicy) Publisher() PublisherPolicy { return a.publisher }

func (a ArtifactPolicy) valid(platform OSKind) bool {
	inputSources := make([]OfficialSourceInput, 0, len(a.sources))
	for _, source := range a.sources {
		inputSources = append(inputSources, OfficialSourceInput{
			Scheme: source.scheme, Host: source.host, PathPrefix: source.pathPrefix,
		})
	}
	validated, err := newArtifactPolicy(ArtifactPolicyInput{
		DownloadBytes: a.downloadBytes, ExpandedBytes: a.expandedBytes, ReserveBytes: a.reserveBytes,
		SHA256: a.sha256, Sources: inputSources, ProxyMode: a.proxyMode,
		OfflinePolicy: a.offlinePolicy, RedistributionPermitted: a.redistributionPermitted,
		Publisher: PublisherPolicyInput{
			Verification: a.publisher.verification, Identity: a.publisher.identity,
			SigningKeyIdentity: a.publisher.signingKeyIdentity,
			PackageIdentity:    a.publisher.packageIdentity,
		},
	}, platform)
	return err == nil && len(validated.sources) == len(a.sources)
}
