package agentconfigadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

// ErrLocationUnsupported means the selected agent has no certified native
// user-scope MCP configuration contract. The installer must not guess one.
var ErrLocationUnsupported = errors.New("agent configuration location is unsupported")

// HomeDirectoryProvider returns the invoking user's native home directory.
// Implementations must not honor an MCP-supplied or plan-supplied home path.
type HomeDirectoryProvider interface {
	UserHomeDir() (string, error)
}

type osHomeDirectory struct{}

func (osHomeDirectory) UserHomeDir() (string, error) { return os.UserHomeDir() }

// LocationResolver projects documented user-scope configuration locations for
// host formats that have been independently certified. The custom-host value
// is an AgentMemory-owned binding namespace, not a guessed host configuration
// path. Generic and GLM model selection are not filesystem formats.
type LocationResolver struct{ home HomeDirectoryProvider }

// NewLocationResolver constructs the production invoking-user resolver.
func NewLocationResolver() *LocationResolver {
	resolver, _ := newLocationResolver(osHomeDirectory{})
	return resolver
}

func newLocationResolver(home HomeDirectoryProvider) (*LocationResolver, error) {
	if nilLocationDependency(home) {
		return nil, port.ErrInvalidArgument
	}
	return &LocationResolver{home: home}, nil
}

// Resolve returns the exact documented user-scope file for one agent host.
func (r *LocationResolver) Resolve(
	ctx context.Context,
	host domain.AgentHost,
) (port.ConfigLocation, error) {
	if r == nil || ctx == nil || !host.Valid() || nilLocationDependency(r.home) {
		return port.ConfigLocation{}, port.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return port.ConfigLocation{}, err
	}
	home, err := r.home.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return port.ConfigLocation{}, port.ErrIO
	}
	var path string
	switch host {
	case domain.AgentHostCodex:
		path = filepath.Join(home, ".codex", "config.toml")
	case domain.AgentHostClaude:
		path = filepath.Join(home, ".claude.json")
	case domain.AgentHostGemini:
		path = filepath.Join(home, ".gemini", "settings.json")
	case domain.AgentHostCursor:
		path = filepath.Join(home, ".cursor", "mcp.json")
	case domain.AgentHostCustom:
		path = filepath.Join(home, ".agentmemory", "registrations", "custom-v1")
	case domain.AgentHostGeneric, domain.AgentHostGLM:
		return port.ConfigLocation{}, ErrLocationUnsupported
	default:
		return port.ConfigLocation{}, port.ErrInvalidArgument
	}
	location, err := port.NewConfigLocation(path)
	if err != nil {
		return port.ConfigLocation{}, port.ErrIO
	}
	return location, nil
}

func nilLocationDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid provider.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
