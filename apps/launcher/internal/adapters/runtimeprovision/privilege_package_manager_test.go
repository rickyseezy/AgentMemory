package runtimeprovision

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006ExactPrivilegePackageManagerInstallsRootOwnedClosureThenReprovesState(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeInstallPackages)
	runner := &privilegePackageRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleAPTTransaction),
	}
	state := &privilegePackageStateProbeStub{matches: []bool{false, true}}
	manager, err := NewExactPrivilegePackageManager(runner, state)
	if err != nil {
		t.Fatal(err)
	}
	transaction := privilegePackageTransaction(t, request)
	changed, err := manager.EnsurePrivilegePackages(t.Context(), request, transaction)
	if err != nil || !changed || runner.calls != 1 || state.calls != 2 {
		t.Fatalf("changed=%t runner=%d probes=%d error=%v", changed, runner.calls, state.calls, err)
	}
	want := transaction.PackagePaths()
	if runner.invocation.EnvironmentProfile() != argvprocess.EnvironmentProfileAPTTransaction ||
		!slices.Equal(runner.invocation.Arguments()[11:], want) {
		t.Fatalf("invocation=%+v want packages=%v", runner.invocation, want)
	}

	idempotentRunner := &privilegePackageRunnerStub{authority: runner.authority}
	idempotent, err := NewExactPrivilegePackageManager(
		idempotentRunner, &privilegePackageStateProbeStub{matches: []bool{true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	changed, err = idempotent.EnsurePrivilegePackages(t.Context(), request, transaction)
	if err != nil || changed || idempotentRunner.calls != 0 {
		t.Fatalf("idempotent changed=%t calls=%d error=%v", changed, idempotentRunner.calls, err)
	}
}

func TestPF006ExactPrivilegePackageManagerRejectsTransactionOrPostStateSubstitution(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeInstallPackages)
	validRunner := privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleAPTTransaction)
	transaction := privilegePackageTransaction(t, request)
	for name, test := range map[string]struct {
		runner    *privilegePackageRunnerStub
		state     *privilegePackageStateProbeStub
		artifacts PrivilegeArtifactSet
	}{
		"transaction failure": {
			runner: &privilegePackageRunnerStub{authority: validRunner, err: errors.New("apt failed")},
			state:  &privilegePackageStateProbeStub{matches: []bool{false}}, artifacts: transaction,
		},
		"post state mismatch": {
			runner: &privilegePackageRunnerStub{authority: validRunner},
			state:  &privilegePackageStateProbeStub{matches: []bool{false, false}}, artifacts: transaction,
		},
		"foreign transaction root": {
			runner: &privilegePackageRunnerStub{authority: validRunner},
			state:  &privilegePackageStateProbeStub{matches: []bool{false}},
			artifacts: PrivilegeArtifactTransaction{
				root: "/var/lib/agentmemory/runtime-helper/transactions/" + strings.Repeat("f", 64),
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			manager, err := NewExactPrivilegePackageManager(test.runner, test.state)
			if err != nil {
				t.Fatal(err)
			}
			changed, callError := manager.EnsurePrivilegePackages(t.Context(), request, test.artifacts)
			if !errors.Is(callError, runtimeport.ErrPrivilegeIntegrity) || changed {
				t.Fatalf("changed=%t error=%v", changed, callError)
			}
		})
	}
	wrongRole := &privilegePackageRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleDPKGQuery),
	}
	if manager, err := NewExactPrivilegePackageManager(wrongRole, &privilegePackageStateProbeStub{}); manager != nil || err == nil {
		t.Fatal("query runner accepted as package transaction")
	}
}

func TestPF001ExactPrivilegePackageManagerRemovesOnlyVendorPackagesAndPreservesData(t *testing.T) {
	t.Parallel()
	_, authority, baseRequest, _ := privilegeCodecFixture(t)
	request := privilegeOperationRequest(t, baseRequest, runtimeport.PrivilegeRemoveManagedPackages)
	runner := &privilegePackageRunnerStub{
		authority: privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleAPTTransaction),
	}
	state := &privilegePackageStateProbeStub{
		managedMatches: []bool{true}, managedAbsent: []bool{false, true},
	}
	manager, err := NewExactPrivilegePackageManager(runner, state)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := manager.RemovePrivilegePackages(t.Context(), request, privilegePackageTransaction(t, request))
	managed, _ := runtimeport.ManagedRuntimePackages(authority)
	want := make([]string, 0, len(managed))
	for _, pkg := range managed {
		want = append(want, pkg.Name())
	}
	slices.Sort(want)
	arguments := runner.invocation.Arguments()
	separator := slices.Index(arguments, "--")
	if err != nil || !changed || runner.calls != 1 || separator < 0 ||
		!slices.Equal(arguments[separator+1:], want) || slices.Contains(arguments, "uidmap") ||
		state.absentCalls != 2 || state.managedCalls != 1 {
		t.Fatalf("changed=%t args=%v absent=%d managed=%d error=%v", changed, arguments, state.absentCalls, state.managedCalls, err)
	}

	idempotentRunner := &privilegePackageRunnerStub{authority: runner.authority}
	idempotent, _ := NewExactPrivilegePackageManager(
		idempotentRunner, &privilegePackageStateProbeStub{managedAbsent: []bool{true}},
	)
	changed, err = idempotent.RemovePrivilegePackages(
		t.Context(), request, privilegePackageTransaction(t, request),
	)
	if err != nil || changed || idempotentRunner.calls != 0 {
		t.Fatalf("idempotent changed=%t calls=%d error=%v", changed, idempotentRunner.calls, err)
	}

	substitutedRunner := &privilegePackageRunnerStub{authority: runner.authority}
	substituted, _ := NewExactPrivilegePackageManager(
		substitutedRunner,
		&privilegePackageStateProbeStub{managedAbsent: []bool{false}, managedMatches: []bool{false}},
	)
	if changed, err := substituted.RemovePrivilegePackages(
		t.Context(), request, privilegePackageTransaction(t, request),
	); changed || !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) || substitutedRunner.calls != 0 {
		t.Fatalf("substituted changed=%t calls=%d error=%v", changed, substitutedRunner.calls, err)
	}
}

func TestPF001PrivilegePackageManagerBuildsClosedDNFInstallAndRemovalInvocations(t *testing.T) {
	t.Parallel()
	packagePath := linuxPrivilegeTransactionRoot + "/" + strings.Repeat("a", 64) +
		"/docker-ce-" + strings.Repeat("b", 64) + ".rpm"
	install, err := privilegePackageInstallInvocation(
		runtimeport.PackageManagerDNF, []string{packagePath},
	)
	if err != nil || install.EnvironmentProfile() != argvprocess.EnvironmentProfileDNFTransaction {
		t.Fatalf("install=%+v error=%v", install, err)
	}
	remove, err := privilegePackageRemoveInvocation(
		runtimeport.PackageManagerDNF, []string{"docker-ce", "docker-ce-cli"},
	)
	if err != nil || remove.EnvironmentProfile() != argvprocess.EnvironmentProfileDNFTransaction ||
		!slices.Equal(remove.Arguments()[len(remove.Arguments())-2:], []string{"docker-ce", "docker-ce-cli"}) {
		t.Fatalf("remove=%+v error=%v", remove, err)
	}
	if _, err := privilegePackageInstallInvocation("unknown", []string{"/tmp/package"}); err == nil {
		t.Fatal("unknown package-manager install invocation accepted")
	}
	if _, err := privilegePackageRemoveInvocation("unknown", []string{"docker-ce"}); err == nil {
		t.Fatal("unknown package-manager removal invocation accepted")
	}
}

func TestPF006NativePrivilegePackageProbeParsesExactAPTAndRPMState(t *testing.T) {
	t.Parallel()
	_, aptAuthority, _, _ := privilegeCodecFixture(t)
	aptOutput := privilegeAPTQueryOutput(aptAuthority)
	aptRunner := &privilegePackageRunnerStub{
		authority: privilegePackageExecutableAuthority(t, aptAuthority, argvprocess.ExecutableRoleDPKGQuery),
		result:    argvprocess.Result{StandardOutput: []byte(aptOutput)},
	}
	probe, err := NewNativePrivilegePackageStateProbe(aptRunner)
	if err != nil {
		t.Fatal(err)
	}
	if matches, matchError := probe.PrivilegePackageStateMatches(t.Context(), aptAuthority); matchError != nil || !matches {
		t.Fatalf("APT matches=%t error=%v", matches, matchError)
	}

	dnfAuthority := privilegeDNFAuthority(t, aptAuthority)
	rpmRunner := &privilegePackageRunnerStub{
		authority: privilegePackageExecutableAuthority(t, dnfAuthority, argvprocess.ExecutableRoleRPMQuery),
		result:    argvprocess.Result{StandardOutput: []byte(privilegeRPMQueryOutput(dnfAuthority))},
	}
	probe, err = NewNativePrivilegePackageStateProbe(rpmRunner)
	if err != nil {
		t.Fatal(err)
	}
	if matches, matchError := probe.PrivilegePackageStateMatches(t.Context(), dnfAuthority); matchError != nil || !matches {
		t.Fatalf("RPM matches=%t error=%v", matches, matchError)
	}
}

func TestPF006NativePrivilegePackageProbeDistinguishesAbsentMismatchAndMalformedState(t *testing.T) {
	t.Parallel()
	_, authority, _, _ := privilegeCodecFixture(t)
	executable := privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleDPKGQuery)
	for name, test := range map[string]struct {
		result    argvprocess.Result
		runError  error
		wantMatch bool
		wantError bool
	}{
		"absent": {
			result: argvprocess.Result{ExitCode: 1}, runError: errors.New("not installed"),
		},
		"version mismatch": {
			result: argvprocess.Result{StandardOutput: []byte(strings.Replace(
				privilegeAPTQueryOutput(authority), authority.Packages()[0].Version(), "0:foreign", 1,
			))},
		},
		"malformed": {
			result: argvprocess.Result{StandardOutput: []byte("unexpected\n")}, wantError: true,
		},
		"unexpected exit": {
			result: argvprocess.Result{ExitCode: 2}, runError: errors.New("database failure"), wantError: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &privilegePackageRunnerStub{authority: executable, result: test.result, err: test.runError}
			probe, err := NewNativePrivilegePackageStateProbe(runner)
			if err != nil {
				t.Fatal(err)
			}
			matches, callError := probe.PrivilegePackageStateMatches(t.Context(), authority)
			if matches != test.wantMatch || (callError != nil) != test.wantError {
				t.Fatalf("matches=%t error=%v", matches, callError)
			}
		})
	}
}

func TestPF001NativePrivilegePackageProbeRequiresEveryManagedPackageAbsent(t *testing.T) {
	t.Parallel()
	_, authority, _, _ := privilegeCodecFixture(t)
	executable := privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleDPKGQuery)
	managed, _ := runtimeport.ManagedRuntimePackages(authority)
	absentResults := make([]privilegePackageRunResult, len(managed))
	for index := range absentResults {
		absentResults[index] = privilegePackageRunResult{
			result: argvprocess.Result{ExitCode: 1}, err: errors.New("not installed"),
		}
	}
	runner := &privilegePackageRunnerStub{authority: executable, results: absentResults}
	probe, err := NewNativePrivilegePackageStateProbe(runner)
	if err != nil {
		t.Fatal(err)
	}
	if absent, err := probe.PrivilegeManagedPackagesAbsent(t.Context(), authority); err != nil || !absent || runner.calls != len(managed) {
		t.Fatalf("absent=%t calls=%d error=%v", absent, runner.calls, err)
	}
	partial := slices.Clone(absentResults)
	partial[0] = privilegePackageRunResult{result: argvprocess.Result{
		StandardOutput: []byte(managed[0].Name() + "\t" + managed[0].Version() + "\tinstalled\n"),
	}}
	runner = &privilegePackageRunnerStub{authority: executable, results: partial}
	probe, _ = NewNativePrivilegePackageStateProbe(runner)
	if absent, err := probe.PrivilegeManagedPackagesAbsent(t.Context(), authority); err != nil || absent {
		t.Fatalf("partial absent=%t error=%v", absent, err)
	}
	malformed := slices.Clone(absentResults)
	malformed[0] = privilegePackageRunResult{result: argvprocess.Result{StandardOutput: []byte("malformed\n")}}
	runner = &privilegePackageRunnerStub{authority: executable, results: malformed}
	probe, _ = NewNativePrivilegePackageStateProbe(runner)
	if absent, err := probe.PrivilegeManagedPackagesAbsent(t.Context(), authority); err == nil || absent {
		t.Fatalf("malformed absent=%t error=%v", absent, err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	runner = &privilegePackageRunnerStub{authority: executable, results: absentResults}
	probe, _ = NewNativePrivilegePackageStateProbe(runner)
	if absent, err := probe.PrivilegeManagedPackagesAbsent(cancelled, authority); !errors.Is(err, context.Canceled) || absent {
		t.Fatalf("cancelled absent=%t error=%v", absent, err)
	}
	var unavailable *NativePrivilegePackageStateProbe
	if absent, err := unavailable.PrivilegeManagedPackagesAbsent(t.Context(), authority); err == nil || absent {
		t.Fatalf("nil probe absent=%t error=%v", absent, err)
	}
}

func TestPF001NativePrivilegePackageProbeMatchesOnlyExactManagedRuntimeSet(t *testing.T) {
	t.Parallel()
	_, authority, _, _ := privilegeCodecFixture(t)
	executable := privilegePackageExecutableAuthority(t, authority, argvprocess.ExecutableRoleDPKGQuery)
	managed, err := runtimeport.ManagedRuntimePackages(authority)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	wantedNames := make([]string, 0, len(managed))
	for _, pkg := range managed {
		wantedNames = append(wantedNames, pkg.Name())
		output.WriteString(pkg.Name() + "\t" + pkg.Version() + "\tinstalled\n")
	}
	slices.Sort(wantedNames)
	runner := &privilegePackageRunnerStub{authority: executable, result: argvprocess.Result{
		StandardOutput: []byte(output.String()),
	}}
	probe, err := NewNativePrivilegePackageStateProbe(runner)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := probe.PrivilegeManagedPackageStateMatches(t.Context(), authority)
	arguments := runner.invocation.Arguments()
	if err != nil || !matches || len(arguments) != len(wantedNames)+3 ||
		!slices.Equal(arguments[3:], wantedNames) || slices.Contains(arguments, "uidmap") {
		t.Fatalf("matches=%t arguments=%v error=%v", matches, runner.invocation.Arguments(), err)
	}

	runner = &privilegePackageRunnerStub{
		authority: executable, result: argvprocess.Result{ExitCode: 1}, err: errors.New("not installed"),
	}
	probe, _ = NewNativePrivilegePackageStateProbe(runner)
	if matches, err := probe.PrivilegeManagedPackageStateMatches(t.Context(), authority); err != nil || matches {
		t.Fatalf("missing matches=%t error=%v", matches, err)
	}

	runner = &privilegePackageRunnerStub{authority: executable, result: argvprocess.Result{
		StandardOutput: []byte("substituted\t1\tinstalled\n"),
	}}
	probe, _ = NewNativePrivilegePackageStateProbe(runner)
	if matches, err := probe.PrivilegeManagedPackageStateMatches(t.Context(), authority); err == nil || matches {
		t.Fatalf("substituted matches=%t error=%v", matches, err)
	}
	var unavailable *NativePrivilegePackageStateProbe
	if matches, err := unavailable.PrivilegeManagedPackageStateMatches(t.Context(), authority); err == nil || matches {
		t.Fatalf("nil probe matches=%t error=%v", matches, err)
	}
}

func privilegePackageTransaction(
	t testing.TB,
	request runtimeport.PrivilegeRequest,
) PrivilegeArtifactTransaction {
	t.Helper()
	root := path.Join(linuxPrivilegeTransactionRoot, request.Digest().String())
	packages := request.Authority().Packages()
	artifacts := make([]PrivilegeTransactionArtifact, 0, len(packages))
	for _, pkg := range packages {
		digest := runtimeinstall.Sum([]byte(pkg.Name()))
		artifacts = append(artifacts, PrivilegeTransactionArtifact{
			artifactID: pkg.Name(), targetPath: path.Join(root, pkg.Name()+"-"+digest.String()+".deb"),
			sha256: digest, size: 1, packageSet: true,
		})
	}
	return PrivilegeArtifactTransaction{root: root, artifacts: artifacts}
}

func privilegePackageExecutableAuthority(
	t testing.TB,
	authority runtimeport.LinuxAuthority,
	role argvprocess.ExecutableRole,
) argvprocess.ExecutableAuthority {
	t.Helper()
	path := map[argvprocess.ExecutableRole]string{
		argvprocess.ExecutableRoleAPTTransaction: "/usr/bin/apt-get",
		argvprocess.ExecutableRoleDNFTransaction: "/usr/bin/dnf5",
		argvprocess.ExecutableRoleDPKGQuery:      "/usr/bin/dpkg-query",
		argvprocess.ExecutableRoleRPMQuery:       "/usr/bin/rpm",
		argvprocess.ExecutableRoleLoginCTL:       "/usr/bin/loginctl",
		argvprocess.ExecutableRoleSystemCTL:      "/usr/bin/systemctl",
	}[role]
	executable, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: string(role), CanonicalPath: path, SHA256: runtimeinstall.Sum([]byte(role)),
		OwnerIdentity: "uid:0", PublisherIdentity: "package:test", PublisherPolicyID: "linux:package-receipt:v1",
		PublisherTrustDigest:  runtimeinstall.Sum([]byte("publisher")),
		ReleaseManifestDigest: runtimeinstall.Sum([]byte("release")), RuntimePlanDigest: authority.PlanDigest(),
		Role: role, Platform: "linux", Architecture: authority.Architecture().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func privilegeAPTQueryOutput(authority runtimeport.LinuxAuthority) string {
	var result strings.Builder
	for _, pkg := range authority.Packages() {
		result.WriteString(pkg.Name() + "\t" + pkg.Version() + "\tinstalled\n")
	}
	return result.String()
}

func privilegeRPMQueryOutput(authority runtimeport.LinuxAuthority) string {
	var result strings.Builder
	for _, pkg := range authority.Packages() {
		version := pkg.Version()
		epoch := "0"
		if separator := strings.IndexByte(version, ':'); separator >= 0 {
			epoch, version = version[:separator], version[separator+1:]
		}
		release := strings.LastIndexByte(version, '-')
		result.WriteString(pkg.Name() + "\t" + epoch + "\t" + version[:release] + "\t" + version[release+1:] + "\n")
	}
	return result.String()
}

func privilegeDNFAuthority(
	t testing.TB,
	apt runtimeport.LinuxAuthority,
) runtimeport.LinuxAuthority {
	t.Helper()
	input := apt.TransportInput()
	input.Distribution, input.VersionID, input.Codename = "fedora", "42", "42"
	input.PackageManager, input.PackageManagerVersion = runtimeport.PackageManagerDNF, "5.2.15.0"
	input.Repository.URL, input.Repository.Suite = "https://download.docker.com/linux/fedora", "42"
	input.Packages[len(input.Packages)-1].Name = "shadow-utils"
	input.Packages[len(input.Packages)-1].Version = "4.15.1-12.fc42"
	input.Packages[len(input.Packages)-1].NativeReceiptDigest = runtimeinstall.Sum([]byte("shadow-utils receipt"))
	input.PrivilegeToolPackage = "polkit"
	input.PrivilegeToolPackageVersion = "126-3.fc42.2"
	input.PrivilegeToolPackageReceiptDigest = runtimeinstall.Sum([]byte("polkit receipt"))
	input.RPMKeysPath = "/usr/bin/rpmkeys"
	input.RPMKeysSHA256 = runtimeinstall.Sum([]byte("rpmkeys"))
	input.RPMKeysPackageVersion = "4.20.1-1.fc42"
	input.RPMKeysPackageReceiptDigest = runtimeinstall.Sum([]byte("rpm package receipt"))
	input.HelperTools = []runtimeport.HelperToolInput{
		{Role: runtimeport.HelperToolDNF5, Path: "/usr/bin/dnf5", SHA256: runtimeinstall.Sum([]byte("dnf5")), Package: "dnf5", PackageVersion: "5.2.15.0-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("dnf5 receipt"))},
		{Role: runtimeport.HelperToolLoginCTL, Path: "/usr/bin/loginctl", SHA256: runtimeinstall.Sum([]byte("loginctl")), Package: "systemd", PackageVersion: "257.7-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
		{Role: runtimeport.HelperToolRPMQuery, Path: "/usr/bin/rpm", SHA256: runtimeinstall.Sum([]byte("rpm")), Package: "rpm", PackageVersion: "4.20.1-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("rpm receipt"))},
		{Role: runtimeport.HelperToolSystemCTL, Path: "/usr/bin/systemctl", SHA256: runtimeinstall.Sum([]byte("systemctl")), Package: "systemd", PackageVersion: "257.7-1.fc42", PackageReceiptDigest: runtimeinstall.Sum([]byte("systemd receipt"))},
	}
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

type privilegePackageRunnerStub struct {
	authority  argvprocess.ExecutableAuthority
	invocation argvprocess.Invocation
	result     argvprocess.Result
	err        error
	results    []privilegePackageRunResult
	calls      int
}

func (s *privilegePackageRunnerStub) ExecutableAuthority() argvprocess.ExecutableAuthority {
	return s.authority
}

func (s *privilegePackageRunnerStub) Run(
	_ context.Context,
	invocation argvprocess.Invocation,
) (argvprocess.Result, error) {
	index := s.calls
	s.calls++
	s.invocation = invocation
	if index < len(s.results) {
		return s.results[index].result, s.results[index].err
	}
	return s.result, s.err
}

type privilegePackageRunResult struct {
	result argvprocess.Result
	err    error
}

type privilegePackageStateProbeStub struct {
	matches        []bool
	managedMatches []bool
	managedAbsent  []bool
	err            error
	calls          int
	managedCalls   int
	absentCalls    int
}

func (s *privilegePackageStateProbeStub) PrivilegeManagedPackageStateMatches(
	context.Context,
	runtimeport.LinuxAuthority,
) (bool, error) {
	index := s.managedCalls
	s.managedCalls++
	if s.err != nil {
		return false, s.err
	}
	if index >= len(s.managedMatches) {
		return false, nil
	}
	return s.managedMatches[index], nil
}

func (s *privilegePackageStateProbeStub) PrivilegeManagedPackagesAbsent(
	context.Context,
	runtimeport.LinuxAuthority,
) (bool, error) {
	index := s.absentCalls
	s.absentCalls++
	if s.err != nil {
		return false, s.err
	}
	if index >= len(s.managedAbsent) {
		return false, nil
	}
	return s.managedAbsent[index], nil
}

func (s *privilegePackageStateProbeStub) PrivilegePackageStateMatches(
	context.Context,
	runtimeport.LinuxAuthority,
) (bool, error) {
	index := s.calls
	s.calls++
	if s.err != nil {
		return false, s.err
	}
	if index >= len(s.matches) {
		return false, nil
	}
	return s.matches[index], nil
}

var _ argvprocess.Runner = (*privilegePackageRunnerStub)(nil)
var _ PrivilegePackageStateProbe = (*privilegePackageStateProbeStub)(nil)
