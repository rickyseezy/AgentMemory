package firststart

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	agentconfigport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

type configurationLocationResolver interface {
	Resolve(context.Context, agentconfigdomain.AgentHost) (agentconfigport.ConfigLocation, error)
}

type nativeProjectionDependencies struct {
	home       func() (string, error)
	executable func() (string, error)
	open       func(string) (*os.File, error)
	lstat      func(string) (os.FileInfo, error)
	locations  configurationLocationResolver
	owners     bootstrapport.OwnerBindingSource
	goos       string
}

// NativeHostProjectionSource derives all dynamic plan inputs from the invoking
// native process and protected owner identity. It never accepts path or
// endpoint input from MCP.
type NativeHostProjectionSource struct{ dependencies nativeProjectionDependencies }

// NewNativeHostProjectionSource constructs the production projection source.
func NewNativeHostProjectionSource(
	locations configurationLocationResolver,
	owners bootstrapport.OwnerBindingSource,
) (*NativeHostProjectionSource, error) {
	return newNativeHostProjectionSource(nativeProjectionDependencies{
		home: os.UserHomeDir, executable: os.Executable, open: os.Open, lstat: os.Lstat,
		locations: locations, owners: owners, goos: runtime.GOOS,
	})
}

func newNativeHostProjectionSource(
	dependencies nativeProjectionDependencies,
) (*NativeHostProjectionSource, error) {
	if dependencies.home == nil || dependencies.executable == nil || dependencies.open == nil ||
		dependencies.lstat == nil || nilBinderCapability(dependencies.locations) ||
		nilBinderCapability(dependencies.owners) ||
		(dependencies.goos != "linux" && dependencies.goos != "darwin" && dependencies.goos != "windows") {
		return nil, firstStartIntegrityError()
	}
	return &NativeHostProjectionSource{dependencies: dependencies}, nil
}

// Project resolves and cross-validates the invoking-user projection.
func (s *NativeHostProjectionSource) Project(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (HostProjection, error) {
	if s == nil || ctx == nil || !host.Valid() {
		return HostProjection{}, firstStartIntegrityError()
	}
	if err := ctx.Err(); err != nil {
		return HostProjection{}, err
	}
	home, err := s.dependencies.home()
	if err != nil || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return HostProjection{}, firstStartUnavailableError()
	}
	location, err := s.dependencies.locations.Resolve(ctx, host)
	if err != nil {
		return HostProjection{}, firstStartUnavailableError()
	}
	owner, err := s.dependencies.owners.Current(ctx)
	if err != nil || owner.IsZero() {
		return HostProjection{}, firstStartUnavailableError()
	}
	executablePath, digest, err := s.executableDigest(ctx)
	if err != nil {
		return HostProjection{}, err
	}
	root := filepath.Join(home, ".agentmemory")
	endpoint := "unix:///var/run/docker.sock"
	switch s.dependencies.goos {
	case "darwin":
		endpoint = "unix://" + filepath.Join(home, ".docker", "run", "docker.sock")
	case "windows":
		endpoint = "npipe:////./pipe/docker_engine"
	case "linux":
	}
	projection := HostProjection{
		StorageRoot: root, RuntimeEndpoint: endpoint, ConfigurationPath: location.String(),
		LauncherPath: executablePath, LauncherDigest: digest,
		OwnerSubjectDigest: owner.PrincipalDigest(),
	}
	if !validHostProjection(projection) {
		return HostProjection{}, firstStartIntegrityError()
	}
	return projection, nil
}

func (s *NativeHostProjectionSource) executableDigest(
	ctx context.Context,
) (string, agentconfigdomain.Digest, error) {
	name, err := s.dependencies.executable()
	if err != nil || !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return "", agentconfigdomain.Digest{}, firstStartUnavailableError()
	}
	before, err := s.dependencies.lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", agentconfigdomain.Digest{}, firstStartIntegrityError()
	}
	file, err := s.dependencies.open(name)
	if err != nil {
		return "", agentconfigdomain.Digest{}, firstStartUnavailableError()
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return "", agentconfigdomain.Digest{}, firstStartIntegrityError()
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, &contextReader{ctx: ctx, reader: file}); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", agentconfigdomain.Digest{}, err
		}
		return "", agentconfigdomain.Digest{}, firstStartUnavailableError()
	}
	var digest agentconfigdomain.Digest
	copy(digest[:], hash.Sum(nil))
	if digest.IsZero() {
		return "", agentconfigdomain.Digest{}, firstStartIntegrityError()
	}
	return name, digest, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func firstStartIntegrityError() error   { return firststartapp.ErrIntegrity }
func firstStartUnavailableError() error { return firststartapp.ErrUnavailable }

var _ HostProjectionSource = (*NativeHostProjectionSource)(nil)
