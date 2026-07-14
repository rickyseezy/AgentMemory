// Package containerengine defines an explicitly addressed local Docker Engine
// boundary. It contains no global-context or remote-daemon operation.
package containerengine

import (
	"context"
	"errors"
	"strings"
)

// ErrInvalidEndpoint rejects remote or syntactically unsafe daemon endpoints.
var ErrInvalidEndpoint = errors.New("invalid local container-engine endpoint")

// Endpoint is a validated local Unix socket or Windows named pipe.
type Endpoint struct{ value string }

// NewEndpoint accepts only explicitly local transports. TCP, SSH, HTTP, Docker
// contexts, and bare names are deliberately unsupported.
func NewEndpoint(value string) (Endpoint, error) {
	if value == "" || len(value) > 4096 || strings.IndexByte(value, 0) >= 0 ||
		strings.ContainsAny(value, "\r\n") {
		return Endpoint{}, ErrInvalidEndpoint
	}
	switch {
	case strings.HasPrefix(value, "unix:///"):
		path := strings.TrimPrefix(value, "unix://")
		if !safeAbsoluteSocketPath(path) {
			return Endpoint{}, ErrInvalidEndpoint
		}
	case strings.HasPrefix(value, "npipe:////./pipe/"):
		name := strings.TrimPrefix(value, "npipe:////./pipe/")
		if name == "" || strings.ContainsAny(name, `/\\`) || name == "." || name == ".." {
			return Endpoint{}, ErrInvalidEndpoint
		}
	default:
		return Endpoint{}, ErrInvalidEndpoint
	}
	return Endpoint{value: value}, nil
}

func safeAbsoluteSocketPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// String returns the exact endpoint passed to the Docker CLI --host argument.
func (e Endpoint) String() string { return e.value }

// ProbeResult contains bounded non-secret daemon capability facts.
type ProbeResult struct {
	ClientVersion   string
	ServerVersion   string
	APIVersion      string
	ComposeVersion  string
	OperatingSystem string
	Architecture    string
	OSType          string
	SecurityOptions []string
	CPUs            int
	MemoryBytes     int64
}

// ProbePort verifies Engine and modern Compose through the exact endpoint.
type ProbePort interface {
	Probe(context.Context, Endpoint) (ProbeResult, error)
}
