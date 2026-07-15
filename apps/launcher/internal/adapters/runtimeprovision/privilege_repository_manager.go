package runtimeprovision

import (
	"context"
	"errors"
	pathpkg "path"
	"strings"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const privilegeRepositoryFileMode = uint32(0o644)

// PrivilegeProtectedFileWriter publishes root-owned exact files without
// symlink traversal and reports whether bytes changed.
type PrivilegeProtectedFileWriter interface {
	EnsurePrivilegeFile(context.Context, string, []byte, uint32) (bool, error)
	EnsurePrivilegeArtifactFile(
		context.Context,
		string,
		PrivilegeTransactionArtifact,
		uint32,
	) (bool, error)
}

// CanonicalPrivilegeRepositoryManager renders no caller-provided text. Every
// byte and destination is derived from signed LinuxAuthority.
type CanonicalPrivilegeRepositoryManager struct {
	writer PrivilegeProtectedFileWriter
}

// NewCanonicalPrivilegeRepositoryManager requires descriptor-safe root file
// publication.
func NewCanonicalPrivilegeRepositoryManager(
	writer PrivilegeProtectedFileWriter,
) (*CanonicalPrivilegeRepositoryManager, error) {
	if nilArtifactDependency(writer) {
		return nil, errors.New("protected privilege repository writer is required")
	}
	return &CanonicalPrivilegeRepositoryManager{writer: writer}, nil
}

// EnsurePrivilegeRepository publishes the exact key then exact configuration.
func (m *CanonicalPrivilegeRepositoryManager) EnsurePrivilegeRepository(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	artifacts PrivilegeArtifactSet,
) (bool, error) {
	if m == nil || ctx == nil || nilArtifactDependency(m.writer) ||
		request.Operation() != runtimeport.PrivilegeConfigureRepository || request.Digest().IsZero() ||
		nilArtifactDependency(artifacts) || artifacts.Root() == "" {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	authority := request.Authority()
	repository := authority.Repository()
	keyID := "repo-" + repository.ID() + "-signing_key"
	key, found := artifacts.Artifact(keyID)
	if !found || key.IsPackage() || key.SHA256() != repository.SigningKeyDigest() ||
		key.Size() == 0 || pathpkg.Dir(key.TargetPath()) != artifacts.Root() {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	configurationPath, keyPath, configuration, err := renderPrivilegeRepository(authority)
	if err != nil || runtimeinstall.Sum(configuration) != repository.ConfigurationDigest() {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	keyChanged, err := m.writer.EnsurePrivilegeArtifactFile(
		ctx, keyPath, key, privilegeRepositoryFileMode,
	)
	if err != nil {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	configurationChanged, err := m.writer.EnsurePrivilegeFile(
		ctx, configurationPath, configuration, privilegeRepositoryFileMode,
	)
	if err != nil {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	return keyChanged || configurationChanged, nil
}

func renderPrivilegeRepository(
	authority runtimeport.LinuxAuthority,
) (string, string, []byte, error) {
	if !authority.Valid() {
		return "", "", nil, runtimeport.ErrPrivilegeIntegrity
	}
	repositoryID := authority.Repository().ID()
	switch authority.PackageManager() {
	case runtimeport.PackageManagerAPT:
		keyPath := "/etc/apt/keyrings/agentmemory-" + repositoryID + ".gpg"
		configuration, err := renderAPTPrivilegeRepository(authority, keyPath)
		return "/etc/apt/sources.list.d/agentmemory-" + repositoryID + ".sources", keyPath, configuration, err
	case runtimeport.PackageManagerDNF:
		keyPath := "/etc/pki/rpm-gpg/RPM-GPG-KEY-agentmemory-" + repositoryID
		configuration, err := renderDNFPrivilegeRepository(authority, keyPath)
		return "/etc/yum.repos.d/agentmemory-" + repositoryID + ".repo", keyPath, configuration, err
	default:
		return "", "", nil, runtimeport.ErrPrivilegeIntegrity
	}
}

func renderAPTPrivilegeRepository(
	authority runtimeport.LinuxAuthority,
	keyPath string,
) ([]byte, error) {
	if !authority.Valid() || authority.PackageManager() != runtimeport.PackageManagerAPT ||
		!canonicalPrivilegeSystemPath(keyPath) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	architecture, err := privilegeAPTArchitecture(authority.Architecture())
	if err != nil {
		return nil, err
	}
	repository := authority.Repository()
	configuration := "Architectures: " + architecture + "\n" +
		"Components: " + repository.Component() + "\n" +
		"Signed-By: " + keyPath + "\n" +
		"Suites: " + repository.Suite() + "\n" +
		"Types: deb\n" +
		"URIs: " + strings.TrimSuffix(repository.URL(), "/") + "\n"
	return []byte(configuration), nil
}

func renderDNFPrivilegeRepository(
	authority runtimeport.LinuxAuthority,
	keyPath string,
) ([]byte, error) {
	if !authority.Valid() || authority.PackageManager() != runtimeport.PackageManagerDNF ||
		!canonicalPrivilegeSystemPath(keyPath) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	repository := authority.Repository()
	configuration := "[" + repository.ID() + "]\n" +
		"baseurl=" + strings.TrimSuffix(repository.URL(), "/") + "/" + repository.Suite() +
		"/$basearch/" + repository.Component() + "\n" +
		"enabled=1\n" +
		"gpgcheck=1\n" +
		"gpgkey=file://" + keyPath + "\n" +
		"metadata_expire=never\n" +
		"name=AgentMemory managed " + repository.ID() + "\n" +
		"repo_gpgcheck=1\n" +
		"skip_if_unavailable=0\n"
	return []byte(configuration), nil
}

func privilegeAPTArchitecture(architecture runtimeinstall.Architecture) (string, error) {
	switch architecture {
	case runtimeinstall.ArchitectureAMD64:
		return "amd64", nil
	case runtimeinstall.ArchitectureARM64:
		return "arm64", nil
	case runtimeinstall.ArchitectureUnknown:
		return "", runtimeport.ErrPrivilegeIntegrity
	}
	return "", runtimeport.ErrPrivilegeIntegrity
}

func canonicalPrivilegeSystemPath(path string) bool {
	return path != "" && pathpkg.IsAbs(path) && pathpkg.Clean(path) == path &&
		!strings.ContainsAny(path, "\x00\r\n")
}

var _ PrivilegeRepositoryManager = (*CanonicalPrivilegeRepositoryManager)(nil)
