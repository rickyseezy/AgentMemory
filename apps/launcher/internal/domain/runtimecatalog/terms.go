package runtimecatalog

// TermsPolicyInput binds the exact third-party terms shown before mutation.
type TermsPolicyInput struct {
	ID           string
	Version      string
	URL          OfficialSourceInput
	Digest       Digest
	Presentation TermsPresentation
}

// TermsPolicy is immutable third-party terms authority.
type TermsPolicy struct {
	id           string
	version      string
	url          SourceLocation
	digest       Digest
	presentation TermsPresentation
}

func newTermsPolicy(input TermsPolicyInput) (TermsPolicy, error) {
	url, err := NewSourceLocation(input.URL)
	if !validIdentifier(input.ID) || !validExactVersion(input.Version) || input.Digest.IsZero() ||
		!input.Presentation.valid() || err != nil {
		return TermsPolicy{}, ErrManifestIntegrity
	}
	return TermsPolicy{
		id: input.ID, version: input.Version, url: url,
		digest: input.Digest, presentation: input.Presentation,
	}, nil
}

// ID returns the terms document identity.
func (p TermsPolicy) ID() string { return p.id }

// Version returns the exact terms version.
func (p TermsPolicy) Version() string { return p.version }

// URL returns the structured official terms location.
func (p TermsPolicy) URL() SourceLocation { return p.url }

// Digest returns the exact terms content digest.
func (p TermsPolicy) Digest() Digest { return p.digest }

// Presentation returns the required presentation behavior.
func (p TermsPolicy) Presentation() TermsPresentation { return p.presentation }

func (p TermsPolicy) valid() bool {
	_, err := newTermsPolicy(TermsPolicyInput{
		ID: p.id, Version: p.version,
		URL:    OfficialSourceInput{Scheme: p.url.scheme, Host: p.url.host, PathPrefix: p.url.pathPrefix},
		Digest: p.digest, Presentation: p.presentation,
	})
	return err == nil
}
