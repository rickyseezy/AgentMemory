package agentconfigadapter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

func TestPF001AgentLocationResolverUsesDocumentedUserScopeFiles(t *testing.T) {
	t.Parallel()
	home := filepath.Clean(filepath.Join(t.TempDir(), "owner"))
	resolver, err := newLocationResolver(homeProviderStub{home: home})
	if err != nil {
		t.Fatal(err)
	}
	expected := map[domain.AgentHost]string{
		domain.AgentHostCodex:  filepath.Join(home, ".codex", "config.toml"),
		domain.AgentHostClaude: filepath.Join(home, ".claude.json"),
		domain.AgentHostGemini: filepath.Join(home, ".gemini", "settings.json"),
	}
	for host, path := range expected {
		host, path := host, path
		t.Run(string(host), func(t *testing.T) {
			t.Parallel()
			location, resolveErr := resolver.Resolve(t.Context(), host)
			if resolveErr != nil || location.String() != path {
				t.Fatalf("Resolve(%s)=%q,%v", host, location.String(), resolveErr)
			}
		})
	}
	for _, host := range []domain.AgentHost{domain.AgentHostGeneric, domain.AgentHostGLM} {
		if _, err := resolver.Resolve(t.Context(), host); !errors.Is(err, ErrLocationUnsupported) {
			t.Fatalf("Resolve(%s) error=%v", host, err)
		}
	}
}

func TestPF001AgentLocationResolverRejectsUntrustedHomeAndBoundaryState(t *testing.T) {
	t.Parallel()
	var typedNil *homeProviderStub
	if resolver, err := newLocationResolver(typedNil); resolver != nil || !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("typed nil resolver=%+v error=%v", resolver, err)
	}
	valid, _ := newLocationResolver(homeProviderStub{home: filepath.Clean(t.TempDir())})
	var absent *LocationResolver
	if _, err := absent.Resolve(t.Context(), domain.AgentHostCodex); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("nil resolver error=%v", err)
	}
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := valid.Resolve(nil, domain.AgentHostCodex); !errors.Is(err, port.ErrInvalidArgument) { //nolint:staticcheck // Security fixture.
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := valid.Resolve(t.Context(), domain.AgentHost("foreign")); !errors.Is(err, port.ErrInvalidArgument) {
		t.Fatalf("foreign host error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := valid.Resolve(cancelled, domain.AgentHostCodex); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	for name, provider := range map[string]homeProviderStub{
		"error":    {err: errors.New("private")},
		"empty":    {},
		"relative": {home: "relative"},
		"unclean":  {home: t.TempDir() + string(filepath.Separator) + "child" + string(filepath.Separator) + ".."},
	} {
		resolver, _ := newLocationResolver(provider)
		if _, err := resolver.Resolve(t.Context(), domain.AgentHostCodex); !errors.Is(err, port.ErrIO) {
			t.Fatalf("%s home error=%v", name, err)
		}
	}
	if resolver := NewLocationResolver(); resolver == nil {
		t.Fatal("production location resolver is nil")
	}
	if nilLocationDependency(struct{}{}) || !nilLocationDependency(nil) {
		t.Fatal("location dependency classification changed")
	}
}

type homeProviderStub struct {
	home string
	err  error
}

func (p homeProviderStub) UserHomeDir() (string, error) { return p.home, p.err }
