package runtimeinstall

import "testing"

func runtimeTermsFixture(platform Platform, digest Hash) RuntimeTermsInput {
	if platform == PlatformLinux {
		return RuntimeTermsInput{
			ID: DockerEngineTermsID, Version: "apache-2.0",
			URL: "https://docs.docker.com/engine/", Digest: digest,
			Presentation: TermsPresentationAgentMemory,
		}
	}
	return RuntimeTermsInput{
		ID: DockerDesktopTermsID, Version: "2025.07.02",
		URL: "https://www.docker.com/legal/docker-subscription-service-agreement/", Digest: digest,
		Presentation: TermsPresentationAgentMemoryThenNative,
	}
}

func TestRuntimeTermsAuthorityIsPlatformSpecificAndClosed(t *testing.T) {
	t.Parallel()
	digest := Sum([]byte("terms"))
	tests := []struct {
		name     string
		platform Platform
		input    RuntimeTermsInput
	}{
		{name: "desktop terms on Linux", platform: PlatformLinux, input: runtimeTermsFixture(PlatformDarwin, digest)},
		{name: "engine terms on macOS", platform: PlatformDarwin, input: runtimeTermsFixture(PlatformLinux, digest)},
		{name: "engine terms on Windows", platform: PlatformWindows, input: runtimeTermsFixture(PlatformLinux, digest)},
		{name: "unknown platform", platform: PlatformUnknown, input: runtimeTermsFixture(PlatformDarwin, digest)},
		{name: "out of vocabulary platform", platform: Platform(255), input: runtimeTermsFixture(PlatformDarwin, digest)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := newRuntimeTerms(test.platform, test.input); err == nil {
				t.Fatal("cross-platform or unknown terms authority was accepted")
			}
		})
	}
}

func TestRuntimeTermsAuthorityRejectsMalformedMetadata(t *testing.T) {
	t.Parallel()
	valid := runtimeTermsFixture(PlatformDarwin, Sum([]byte("terms")))
	tests := []struct {
		name   string
		mutate func(*RuntimeTermsInput)
	}{
		{name: "blank version", mutate: func(input *RuntimeTermsInput) { input.Version = "" }},
		{name: "spaced version", mutate: func(input *RuntimeTermsInput) { input.Version = " 2025.07.02" }},
		{name: "unsafe version", mutate: func(input *RuntimeTermsInput) { input.Version = "2025.07.02\nnext" }},
		{name: "long version", mutate: func(input *RuntimeTermsInput) { input.Version = string(make([]byte, 129)) }},
		{name: "zero digest", mutate: func(input *RuntimeTermsInput) { input.Digest = Hash{} }},
		{name: "HTTP URL", mutate: func(input *RuntimeTermsInput) {
			input.URL = "http://www.docker.com/legal/docker-subscription-service-agreement/"
		}},
		{name: "URL userinfo", mutate: func(input *RuntimeTermsInput) {
			input.URL = "https://user@www.docker.com/legal/docker-subscription-service-agreement/"
		}},
		{name: "URL query", mutate: func(input *RuntimeTermsInput) { input.URL += "?source=ambient" }},
		{name: "URL fragment", mutate: func(input *RuntimeTermsInput) { input.URL += "#ambient" }},
		{name: "foreign terms ID", mutate: func(input *RuntimeTermsInput) { input.ID = "foreign" }},
		{name: "foreign presentation", mutate: func(input *RuntimeTermsInput) { input.Presentation = "foreign" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := valid
			test.mutate(&input)
			if _, err := newRuntimeTerms(PlatformDarwin, input); err == nil {
				t.Fatal("malformed terms authority was accepted")
			}
		})
	}
}
