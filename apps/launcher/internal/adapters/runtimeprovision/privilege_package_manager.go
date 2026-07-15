package runtimeprovision

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const maximumPrivilegePackageQueryBytes = 1 << 20

// PrivilegePackageStateProbe proves exact installed package name/version state
// through one signed native package database executable.
type PrivilegePackageStateProbe interface {
	PrivilegePackageStateMatches(context.Context, runtimeport.LinuxAuthority) (bool, error)
}

// ExactPrivilegePackageManager installs only the descriptor-verified local
// closure, and reports success only after an independent native re-query.
type ExactPrivilegePackageManager struct {
	transaction argvprocess.Runner
	state       PrivilegePackageStateProbe
}

// NewExactPrivilegePackageManager requires a closed APT or DNF runner and an
// independent installed-state probe.
func NewExactPrivilegePackageManager(
	transaction argvprocess.Runner,
	state PrivilegePackageStateProbe,
) (*ExactPrivilegePackageManager, error) {
	if nilArtifactDependency(transaction) || nilArtifactDependency(state) ||
		!validPrivilegeTransactionRunner(transaction.ExecutableAuthority()) {
		return nil, errors.New("closed privilege package transaction dependencies are required")
	}
	return &ExactPrivilegePackageManager{transaction: transaction, state: state}, nil
}

// EnsurePrivilegePackages is idempotent and never resolves package names or
// downloads bytes. Every argv path is the root-owned request transaction.
func (m *ExactPrivilegePackageManager) EnsurePrivilegePackages(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	artifacts PrivilegeArtifactSet,
) (bool, error) {
	if m == nil || ctx == nil || nilArtifactDependency(m.transaction) || nilArtifactDependency(m.state) ||
		request.Operation() != runtimeport.PrivilegeInstallPackages || request.Digest().IsZero() ||
		nilArtifactDependency(artifacts) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	authority := request.Authority()
	paths, err := exactPrivilegePackagePaths(request, artifacts)
	if err != nil || !privilegePackageRunnerMatchesAuthority(m.transaction.ExecutableAuthority(), authority) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	matches, err := m.state.PrivilegePackageStateMatches(ctx, authority)
	if err != nil {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	if matches {
		return false, nil
	}
	invocation, err := privilegePackageInstallInvocation(authority.PackageManager(), paths)
	if err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	result, err := m.transaction.Run(ctx, invocation)
	if err != nil || result.ExitCode != 0 || result.OutputTruncated {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	matches, err = m.state.PrivilegePackageStateMatches(ctx, authority)
	if err != nil || !matches {
		return false, privilegeOperationContextOrIntegrity(ctx)
	}
	return true, nil
}

func exactPrivilegePackagePaths(
	request runtimeport.PrivilegeRequest,
	artifacts PrivilegeArtifactSet,
) ([]string, error) {
	authority := request.Authority()
	wantedRoot := filepath.Join(linuxPrivilegeTransactionRoot, request.Digest().String())
	if !authority.Valid() || artifacts.Root() != wantedRoot {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	extension := ".deb"
	if authority.PackageManager() == runtimeport.PackageManagerDNF {
		extension = ".rpm"
	}
	packages := authority.Packages()
	paths := make([]string, 0, len(packages))
	for _, pkg := range packages {
		artifact, present := artifacts.Artifact(pkg.Name())
		if !present || !artifact.IsPackage() || artifact.ArtifactID() != pkg.Name() ||
			artifact.SHA256().IsZero() || artifact.Size() == 0 || filepath.Dir(artifact.TargetPath()) != wantedRoot ||
			filepath.Base(artifact.TargetPath()) != pkg.Name()+"-"+artifact.SHA256().String()+extension {
			return nil, runtimeport.ErrPrivilegeIntegrity
		}
		paths = append(paths, artifact.TargetPath())
	}
	slices.Sort(paths)
	if !slices.Equal(paths, artifacts.PackagePaths()) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return paths, nil
}

func privilegePackageInstallInvocation(
	manager runtimeport.PackageManager,
	paths []string,
) (argvprocess.Invocation, error) {
	switch manager {
	case runtimeport.PackageManagerAPT:
		return argvprocess.NewAPTInstallInvocation("/usr/bin/apt-get", paths)
	case runtimeport.PackageManagerDNF:
		return argvprocess.NewDNFInstallInvocation("/usr/bin/dnf5", paths)
	}
	return argvprocess.Invocation{}, argvprocess.ErrInvalidInvocation
}

func validPrivilegeTransactionRunner(authority argvprocess.ExecutableAuthority) bool {
	return authority.Valid() && authority.Platform() == runtimeinstall.PlatformLinux.String() &&
		(authority.Role() == argvprocess.ExecutableRoleAPTTransaction && authority.CanonicalPath() == "/usr/bin/apt-get" ||
			authority.Role() == argvprocess.ExecutableRoleDNFTransaction && authority.CanonicalPath() == "/usr/bin/dnf5")
}

func privilegePackageRunnerMatchesAuthority(
	executable argvprocess.ExecutableAuthority,
	authority runtimeport.LinuxAuthority,
) bool {
	if !validPrivilegeTransactionRunner(executable) || !authority.Valid() ||
		executable.RuntimePlanDigest() != authority.PlanDigest() ||
		executable.Architecture() != authority.Architecture().String() {
		return false
	}
	return authority.PackageManager() == runtimeport.PackageManagerAPT &&
		executable.Role() == argvprocess.ExecutableRoleAPTTransaction ||
		authority.PackageManager() == runtimeport.PackageManagerDNF &&
			executable.Role() == argvprocess.ExecutableRoleDNFTransaction
}

// NativePrivilegePackageStateProbe uses only a signed dpkg-query or rpm
// runner. Query exit 1 is a normal absent-package observation; every other
// failure or malformed record is an integrity failure.
type NativePrivilegePackageStateProbe struct{ query argvprocess.Runner }

// NewNativePrivilegePackageStateProbe closes the query executable role.
func NewNativePrivilegePackageStateProbe(
	query argvprocess.Runner,
) (*NativePrivilegePackageStateProbe, error) {
	if nilArtifactDependency(query) || !validPrivilegePackageQueryRunner(query.ExecutableAuthority()) {
		return nil, errors.New("closed privilege package query runner is required")
	}
	return &NativePrivilegePackageStateProbe{query: query}, nil
}

// PrivilegePackageStateMatches parses only the fixed machine-readable query
// schema and requires one exact installed record for every signed package.
func (p *NativePrivilegePackageStateProbe) PrivilegePackageStateMatches(
	ctx context.Context,
	authority runtimeport.LinuxAuthority,
) (bool, error) {
	if p == nil || ctx == nil || nilArtifactDependency(p.query) || !authority.Valid() ||
		!privilegePackageQueryRunnerMatchesAuthority(p.query.ExecutableAuthority(), authority) {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	packages := authority.Packages()
	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		names = append(names, pkg.Name())
	}
	slices.Sort(names)
	invocation, err := privilegePackageQueryInvocation(authority.PackageManager(), names)
	if err != nil {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	result, runError := p.query.Run(ctx, invocation)
	if runError != nil {
		if contextError := ctx.Err(); contextError != nil {
			return false, contextError
		}
		if result.ExitCode == 1 && !result.OutputTruncated {
			return false, nil
		}
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumPrivilegePackageQueryBytes {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	return parsePrivilegePackageQuery(authority.PackageManager(), result.StandardOutput, packages)
}

func privilegePackageQueryInvocation(
	manager runtimeport.PackageManager,
	names []string,
) (argvprocess.Invocation, error) {
	switch manager {
	case runtimeport.PackageManagerAPT:
		return argvprocess.NewDPKGQueryInvocation("/usr/bin/dpkg-query", names)
	case runtimeport.PackageManagerDNF:
		return argvprocess.NewRPMQueryInvocation("/usr/bin/rpm", names)
	}
	return argvprocess.Invocation{}, argvprocess.ErrInvalidInvocation
}

func validPrivilegePackageQueryRunner(authority argvprocess.ExecutableAuthority) bool {
	return authority.Valid() && authority.Platform() == runtimeinstall.PlatformLinux.String() &&
		(authority.Role() == argvprocess.ExecutableRoleDPKGQuery && authority.CanonicalPath() == "/usr/bin/dpkg-query" ||
			authority.Role() == argvprocess.ExecutableRoleRPMQuery && authority.CanonicalPath() == "/usr/bin/rpm")
}

func privilegePackageQueryRunnerMatchesAuthority(
	executable argvprocess.ExecutableAuthority,
	authority runtimeport.LinuxAuthority,
) bool {
	if !validPrivilegePackageQueryRunner(executable) || !authority.Valid() ||
		executable.RuntimePlanDigest() != authority.PlanDigest() ||
		executable.Architecture() != authority.Architecture().String() {
		return false
	}
	return authority.PackageManager() == runtimeport.PackageManagerAPT &&
		executable.Role() == argvprocess.ExecutableRoleDPKGQuery ||
		authority.PackageManager() == runtimeport.PackageManagerDNF &&
			executable.Role() == argvprocess.ExecutableRoleRPMQuery
}

func parsePrivilegePackageQuery(
	manager runtimeport.PackageManager,
	raw []byte,
	packages []runtimeport.Package,
) (bool, error) {
	if len(raw) == 0 || len(raw) > maximumPrivilegePackageQueryBytes || raw[len(raw)-1] != '\n' || len(packages) == 0 {
		return false, runtimeport.ErrPrivilegeIntegrity
	}
	expected := make(map[string]string, len(packages))
	for _, pkg := range packages {
		expected[pkg.Name()] = pkg.Version()
	}
	seen := make(map[string]struct{}, len(packages))
	matches := true
	for _, line := range strings.Split(string(raw[:len(raw)-1]), "\n") {
		fields := strings.Split(line, "\t")
		name, version, err := parsePrivilegePackageQueryRecord(manager, fields)
		wanted, present := expected[name]
		if err != nil || !present {
			return false, runtimeport.ErrPrivilegeIntegrity
		}
		if _, duplicate := seen[name]; duplicate {
			return false, runtimeport.ErrPrivilegeIntegrity
		}
		seen[name] = struct{}{}
		if version != wanted {
			matches = false
		}
	}
	return matches && len(seen) == len(expected), nil
}

func parsePrivilegePackageQueryRecord(
	manager runtimeport.PackageManager,
	fields []string,
) (string, string, error) {
	switch manager {
	case runtimeport.PackageManagerAPT:
		if len(fields) != 3 || fields[0] == "" || fields[1] == "" || fields[2] != "installed" ||
			strings.ContainsAny(fields[0]+fields[1], "\x00\r\n") {
			return "", "", runtimeport.ErrPrivilegeIntegrity
		}
		return fields[0], fields[1], nil
	case runtimeport.PackageManagerDNF:
		if len(fields) != 4 || fields[0] == "" || fields[2] == "" || fields[3] == "" ||
			strings.ContainsAny(strings.Join(fields, ""), "\x00\r\n") {
			return "", "", runtimeport.ErrPrivilegeIntegrity
		}
		epoch, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil || strconv.FormatUint(epoch, 10) != fields[1] {
			return "", "", runtimeport.ErrPrivilegeIntegrity
		}
		version := fields[2] + "-" + fields[3]
		if epoch != 0 {
			version = fields[1] + ":" + version
		}
		return fields[0], version, nil
	}
	return "", "", runtimeport.ErrPrivilegeIntegrity
}

var _ PrivilegePackageManager = (*ExactPrivilegePackageManager)(nil)
var _ PrivilegePackageStateProbe = (*NativePrivilegePackageStateProbe)(nil)
