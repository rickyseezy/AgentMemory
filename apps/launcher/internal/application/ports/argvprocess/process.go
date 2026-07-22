// Package argvprocess defines the constrained unprivileged process boundary.
package argvprocess

import (
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const (
	maximumStandardInputBytes    = 1024 * 1024
	maximumConversationSteps     = 32
	maximumPrivilegeRequestBytes = 64 * 1024 * 1024
	maximumInvocationArguments   = 1024
	maximumPackageArtifacts      = 512
	linuxTransactionRoot         = "/var/lib/agentmemory/runtime-helper/transactions"
)

// ErrInvalidInvocation rejects an unsafe executable or argument contract.
var ErrInvalidInvocation = errors.New("invalid argv process invocation")

// ErrOutputLimit means output exceeded the bounded diagnostic capture.
var ErrOutputLimit = errors.New("argv process output exceeded limit")

// ErrConversation means a lifecycle-ordered local protocol exchange ended,
// framed, or responded unexpectedly.
var ErrConversation = errors.New("argv process conversation failed")

// Invocation contains an exact executable, argv, and optional bounded standard
// input. It intentionally contains no shell string, environment map, inherited
// working directory, or ambient stdin.
type Invocation struct {
	executable  string
	arguments   []string
	standardIn  []byte
	environment []string
	profile     EnvironmentProfile
}

// EnvironmentProfile is a closed sanitized execution environment.
type EnvironmentProfile uint8

const (
	// EnvironmentProfileDefault supplies only C locale.
	EnvironmentProfileDefault EnvironmentProfile = iota
	// EnvironmentProfileRootlessSetup supplies only the fixed variables needed
	// by Docker's packaged per-user setup tool.
	EnvironmentProfileRootlessSetup
	// EnvironmentProfilePrivilegeBroker marks the fixed pkexec/helper stdin
	// contract. The process runner admits it only for the privilege-broker role.
	EnvironmentProfilePrivilegeBroker
	// EnvironmentProfileAPTTransaction supplies only the noninteractive APT
	// variables required by the fixed, network-disabled package transaction.
	EnvironmentProfileAPTTransaction
	// EnvironmentProfileDNFTransaction supplies the fixed root package-manager
	// environment without inheriting proxy, repository, or plugin variables.
	EnvironmentProfileDNFTransaction
	// EnvironmentProfilePackageQuery admits only the exact installed-package
	// query constructors for the signed dpkg-query or rpm helper role.
	EnvironmentProfilePackageQuery
	// EnvironmentProfileLoginCTL admits only numeric-UID linger operations.
	EnvironmentProfileLoginCTL
	// EnvironmentProfileSystemCTL admits only the fixed local user-manager
	// reload, enable/start, and machine-readable observation operations.
	EnvironmentProfileSystemCTL
)

// NewInvocation validates bounded, NUL-free argv values. The outbound adapter
// additionally enforces an absolute, regular, non-symlink executable path.
func NewInvocation(executable string, arguments []string) (Invocation, error) {
	return newInvocation(executable, arguments, nil)
}

// NewInvocationWithStandardInput constructs an exact invocation whose copied,
// bounded bytes are the child's complete stdin. It is intended for verified
// machine-readable input and must not carry secrets.
func NewInvocationWithStandardInput(
	executable string,
	arguments []string,
	standardInput []byte,
) (Invocation, error) {
	if len(standardInput) == 0 || len(standardInput) > maximumStandardInputBytes {
		return Invocation{}, ErrInvalidInvocation
	}
	return newInvocation(executable, arguments, standardInput)
}

// NewRootlessSetupInvocation creates the only non-default process environment.
// Variable names, PATH, Docker endpoint, D-Bus endpoint, and isolated Docker
// CLI state directory are fixed; callers cannot add a value, change the user's
// global Docker context, or inherit ambient credentials/proxy configuration.
func NewRootlessSetupInvocation(
	executable string,
	arguments []string,
	homeDirectory string,
	runtimeDirectory string,
	uid uint32,
) (Invocation, error) {
	wantedRuntime := "/run/user/" + strconv.FormatUint(uint64(uid), 10)
	if uid == 0 || runtimeDirectory != wantedRuntime || !safeLinuxDirectory(homeDirectory) ||
		homeDirectory == "/tmp" || strings.HasPrefix(homeDirectory, "/tmp/") {
		return Invocation{}, ErrInvalidInvocation
	}
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileRootlessSetup
	invocation.environment = []string{
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtimeDirectory + "/bus",
		"DOCKER_CONFIG=" + runtimeDirectory + "/agentmemory-docker-cli",
		"DOCKER_HOST=unix://" + runtimeDirectory + "/docker.sock",
		"HOME=" + homeDirectory,
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"XDG_RUNTIME_DIR=" + runtimeDirectory,
	}
	return invocation, nil
}

// NewPrivilegeBrokerInvocation constructs the only authorized Polkit
// elevation shape. The request is bounded machine-readable stdin; neither a
// password nor caller-controlled argv/environment crosses this boundary.
func NewPrivilegeBrokerInvocation(
	pkexecPath string,
	helperPath string,
	request []byte,
) (Invocation, error) {
	if pkexecPath != "/usr/bin/pkexec" ||
		helperPath != "/usr/libexec/agentmemory/agentmemory-runtime-helper" ||
		len(request) == 0 || len(request) > maximumPrivilegeRequestBytes {
		return Invocation{}, ErrInvalidInvocation
	}
	invocation, err := newInvocation(pkexecPath, []string{
		"--disable-internal-agent", helperPath, "--request-stdin",
	}, request)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfilePrivilegeBroker
	return invocation, nil
}

// NewAPTInstallInvocation constructs the only admitted APT mutation. Every
// package must already live in the root-owned transaction directory; APT may
// neither download, remove, recommend, retry, nor select a caller argument.
func NewAPTInstallInvocation(executable string, packages []string) (Invocation, error) {
	if executable != "/usr/bin/apt-get" || !validLinuxTransactionArtifacts(packages, ".deb") {
		return Invocation{}, ErrInvalidInvocation
	}
	arguments := make([]string, 0, 11+len(packages))
	arguments = append(arguments,
		"--assume-yes", "--no-download", "--no-remove", "--no-install-recommends",
		"-o", "Acquire::Retries=0", "-o", "APT::Get::List-Cleanup=false", "-o", "Dpkg::Use-Pty=0",
		"install",
	)
	arguments = append(arguments, packages...)
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileAPTTransaction
	invocation.environment = []string{
		"DEBIAN_FRONTEND=noninteractive", "HOME=/root", "LANG=C", "LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	return invocation, nil
}

// NewDNFInstallInvocation constructs the only admitted DNF5 mutation. It uses
// only the exact local RPM set with plugins and repositories disabled.
func NewDNFInstallInvocation(executable string, packages []string) (Invocation, error) {
	if executable != "/usr/bin/dnf5" || !validLinuxTransactionArtifacts(packages, ".rpm") {
		return Invocation{}, ErrInvalidInvocation
	}
	arguments := make([]string, 0, 7+len(packages))
	arguments = append(arguments,
		"--assumeyes", "--cacheonly", "--no-plugins", "--disable-repo=*",
		"--setopt=localpkg_gpgcheck=True", "--setopt=keepcache=False", "install",
	)
	arguments = append(arguments, packages...)
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileDNFTransaction
	invocation.environment = []string{
		"HOME=/root", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	return invocation, nil
}

// NewAPTRemoveInvocation purges only the exact sorted managed package names.
// It neither autoremoves dependencies nor deletes Docker/containerd data.
func NewAPTRemoveInvocation(executable string, packages []string) (Invocation, error) {
	if executable != "/usr/bin/apt-get" || !validLinuxPackageNames(packages) {
		return Invocation{}, ErrInvalidInvocation
	}
	arguments := make([]string, 0, 9+len(packages))
	arguments = append(arguments,
		"--assume-yes", "--no-download", "-o", "Acquire::Retries=0", "-o", "Dpkg::Use-Pty=0",
		"purge", "--",
	)
	arguments = append(arguments, packages...)
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileAPTTransaction
	invocation.environment = []string{
		"DEBIAN_FRONTEND=noninteractive", "HOME=/root", "LANG=C", "LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	return invocation, nil
}

// NewDNFRemoveInvocation removes only the exact sorted managed package names
// with repositories/plugins disabled and preserves runtime data directories.
func NewDNFRemoveInvocation(executable string, packages []string) (Invocation, error) {
	if executable != "/usr/bin/dnf5" || !validLinuxPackageNames(packages) {
		return Invocation{}, ErrInvalidInvocation
	}
	arguments := make([]string, 0, 8+len(packages))
	arguments = append(arguments,
		"--assumeyes", "--cacheonly", "--no-plugins", "--disable-repo=*", "--setopt=keepcache=False",
		"remove", "--",
	)
	arguments = append(arguments, packages...)
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileDNFTransaction
	invocation.environment = []string{
		"HOME=/root", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
	return invocation, nil
}

// NewDPKGQueryInvocation constructs the only admitted Debian installed-state
// query. The machine-readable record contains exact package, version, and
// status fields; callers cannot select another format or database operation.
func NewDPKGQueryInvocation(executable string, packages []string) (Invocation, error) {
	if executable != "/usr/bin/dpkg-query" || !validLinuxPackageNames(packages) {
		return Invocation{}, ErrInvalidInvocation
	}
	arguments := make([]string, 0, 3+len(packages))
	arguments = append(arguments, "--show", "--showformat=${Package}\\t${Version}\\t${db:Status-Status}\\n", "--")
	arguments = append(arguments, packages...)
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfilePackageQuery
	return invocation, nil
}

// NewRPMQueryInvocation constructs the only admitted RPM installed-state
// query. Epoch, version, and release remain separate so the adapter can
// reconstruct the catalog's complete native version without ambiguity.
func NewRPMQueryInvocation(executable string, packages []string) (Invocation, error) {
	if executable != "/usr/bin/rpm" || !validLinuxPackageNames(packages) {
		return Invocation{}, ErrInvalidInvocation
	}
	arguments := make([]string, 0, 4+len(packages))
	arguments = append(arguments,
		"--query", "--queryformat", "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\n", "--",
	)
	arguments = append(arguments, packages...)
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfilePackageQuery
	return invocation, nil
}

// NewLoginctlEnableLingerInvocation enables only the signed numeric user and
// explicitly forbids an interactive authorization prompt.
func NewLoginctlEnableLingerInvocation(executable string, uid uint32) (Invocation, error) {
	if executable != "/usr/bin/loginctl" || uid == 0 {
		return Invocation{}, ErrInvalidInvocation
	}
	invocation, err := newInvocation(executable, []string{
		"--no-ask-password", "enable-linger", strconv.FormatUint(uint64(uid), 10),
	}, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileLoginCTL
	return invocation, nil
}

// NewLoginctlShowLingerInvocation queries only the persistent linger property
// for the signed numeric user in a pager-free machine-readable form.
func NewLoginctlShowLingerInvocation(executable string, uid uint32) (Invocation, error) {
	if executable != "/usr/bin/loginctl" || uid == 0 {
		return Invocation{}, ErrInvalidInvocation
	}
	invocation, err := newInvocation(executable, []string{
		"--no-pager", "--property=Linger", "--value", "show-user", strconv.FormatUint(uint64(uid), 10),
	}, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileLoginCTL
	return invocation, nil
}

// NewSystemctlUserDaemonReloadInvocation reloads only the verified local
// account's user manager via systemd's explicit user@.host bus transport.
func NewSystemctlUserDaemonReloadInvocation(executable string, account string) (Invocation, error) {
	return newSystemctlUserInvocation(executable, account, []string{"daemon-reload"})
}

// NewSystemctlUserEnableNowInvocation enables and starts only docker.service
// for the verified local account's user manager.
func NewSystemctlUserEnableNowInvocation(executable string, account string) (Invocation, error) {
	return newSystemctlUserInvocation(executable, account, []string{"enable", "--now", "docker.service"})
}

// NewSystemctlUserDisableNowInvocation stops and disables only docker.service
// in the signed invoking account's user manager.
func NewSystemctlUserDisableNowInvocation(executable string, account string) (Invocation, error) {
	return newSystemctlUserInvocation(executable, account, []string{"disable", "--now", "docker.service"})
}

// NewSystemctlUserShowInvocation observes only load, enablement, and active
// state for docker.service using stable key=value output.
func NewSystemctlUserShowInvocation(executable string, account string) (Invocation, error) {
	return newSystemctlUserInvocation(executable, account, []string{
		"show", "--property=LoadState,UnitFileState,ActiveState", "docker.service",
	})
}

func newSystemctlUserInvocation(
	executable string,
	account string,
	operation []string,
) (Invocation, error) {
	if executable != "/usr/bin/systemctl" || !validSystemdAccount(account) || len(operation) == 0 {
		return Invocation{}, ErrInvalidInvocation
	}
	arguments := make([]string, 0, 4+len(operation))
	arguments = append(arguments,
		"--user", "--machine="+account+"@.host", "--no-pager", "--no-ask-password",
	)
	arguments = append(arguments, operation...)
	invocation, err := newInvocation(executable, arguments, nil)
	if err != nil {
		return Invocation{}, err
	}
	invocation.profile = EnvironmentProfileSystemCTL
	return invocation, nil
}

func validSystemdAccount(account string) bool {
	if account == "" || len(account) > 64 {
		return false
	}
	for index, character := range account {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("_.-", character) {
			continue
		}
		return false
	}
	return true
}

func validLinuxPackageNames(packages []string) bool {
	if len(packages) == 0 || len(packages) > maximumPackageArtifacts || !slices.IsSorted(packages) {
		return false
	}
	for index, name := range packages {
		if index > 0 && packages[index-1] == name || !validPackageArtifactID(name) {
			return false
		}
	}
	return true
}

func validLinuxTransactionArtifacts(paths []string, extension string) bool {
	if len(paths) == 0 || len(paths) > maximumPackageArtifacts ||
		!slices.IsSorted(paths) || extension != ".deb" && extension != ".rpm" {
		return false
	}
	for index, value := range paths {
		if index > 0 && paths[index-1] == value || !validLinuxTransactionArtifact(value, extension) {
			return false
		}
	}
	return true
}

func validLinuxTransactionArtifact(value string, extension string) bool {
	if value == "" || len(value) > 4096 || !safeClosedLinuxPath(value) ||
		!strings.HasPrefix(value, linuxTransactionRoot+"/") || !strings.HasSuffix(value, extension) ||
		strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	relative, err := filepathRel(linuxTransactionRoot, value)
	if err != nil {
		return false
	}
	components := strings.Split(relative, "/")
	if len(components) != 2 || !canonicalLowerSHA256(components[0]) {
		return false
	}
	stem := strings.TrimSuffix(components[1], extension)
	separator := strings.LastIndexByte(stem, '-')
	return separator > 0 && validPackageArtifactID(stem[:separator]) && canonicalLowerSHA256(stem[separator+1:])
}

func safeClosedLinuxPath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}

func filepathRel(base string, target string) (string, error) {
	if !strings.HasPrefix(target, base+"/") {
		return "", ErrInvalidInvocation
	}
	return strings.TrimPrefix(target, base+"/"), nil
}

func canonicalLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return value != strings.Repeat("0", 64)
}

func validPackageArtifactID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && strings.ContainsRune("+.-_", character) {
			continue
		}
		return false
	}
	return true
}

func safeLinuxDirectory(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") ||
		strings.ContainsAny(value, "\x00\r\n") || len(value) > 4096 {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}

func newInvocation(executable string, arguments []string, standardInput []byte) (Invocation, error) {
	if strings.TrimSpace(executable) == "" || len(executable) > 4096 || strings.IndexByte(executable, 0) >= 0 {
		return Invocation{}, ErrInvalidInvocation
	}
	if len(arguments) > maximumInvocationArguments {
		return Invocation{}, ErrInvalidInvocation
	}
	copied := make([]string, len(arguments))
	for index, argument := range arguments {
		if len(argument) > 32*1024 || strings.IndexByte(argument, 0) >= 0 {
			return Invocation{}, ErrInvalidInvocation
		}
		copied[index] = argument
	}
	return Invocation{
		executable: executable,
		arguments:  copied,
		standardIn: append([]byte(nil), standardInput...),
	}, nil
}

// Executable returns the exact configured binary path.
func (i Invocation) Executable() string { return i.executable }

// Arguments returns an immutable-by-copy argv excluding argv[0].
func (i Invocation) Arguments() []string { return append([]string(nil), i.arguments...) }

// StandardInput returns a caller-owned copy of the explicit child stdin.
func (i Invocation) StandardInput() []byte { return append([]byte(nil), i.standardIn...) }

// EnvironmentProfile returns the closed environment class.
func (i Invocation) EnvironmentProfile() EnvironmentProfile { return i.profile }

// Environment returns a caller-owned copy of the fixed sanitized environment.
func (i Invocation) Environment() []string { return append([]string(nil), i.environment...) }

// Result contains bounded, non-authoritative diagnostic bytes. Callers must
// parse only a documented machine-readable stdout contract and must never
// expose stderr directly to users.
type Result struct {
	ExitCode        int
	StandardOutput  []byte
	StandardError   []byte
	OutputTruncated bool
}

// Streams binds a child's standard streams without granting environment,
// working-directory, executable, or argument authority.
type Streams struct {
	input       io.Reader
	output      io.Writer
	diagnostics io.Writer
}

// NewStreams rejects nil and typed-nil streams before process creation.
func NewStreams(input io.Reader, output, diagnostics io.Writer) (Streams, error) {
	if nilStream(input) || nilStream(output) || nilStream(diagnostics) {
		return Streams{}, ErrInvalidInvocation
	}
	return Streams{input: input, output: output, diagnostics: diagnostics}, nil
}

// Input returns the exact caller-owned standard input stream.
func (s Streams) Input() io.Reader { return s.input }

// Output returns the exact caller-owned standard output stream.
func (s Streams) Output() io.Writer { return s.output }

// Diagnostics returns the exact caller-owned standard error stream.
func (s Streams) Diagnostics() io.Writer { return s.diagnostics }

// Valid reports whether every stream capability is present.
func (s Streams) Valid() bool {
	return !nilStream(s.input) && !nilStream(s.output) && !nilStream(s.diagnostics)
}

// ConversationStep is one immutable newline-delimited request or
// notification in a sequential local protocol exchange. AwaitResponse keeps
// lifecycle ordering in the process adapter instead of pre-buffering later
// requests before the peer's response.
type ConversationStep struct {
	request       []byte
	awaitResponse bool
}

// NewConversationStep validates one complete, non-secret machine-readable
// line. Embedded newlines are forbidden so response boundaries stay exact.
func NewConversationStep(request []byte, awaitResponse bool) (ConversationStep, error) {
	if len(request) < 2 || len(request) > maximumStandardInputBytes || request[len(request)-1] != '\n' ||
		strings.ContainsAny(string(request[:len(request)-1]), "\r\n") {
		return ConversationStep{}, ErrInvalidInvocation
	}
	return ConversationStep{request: append([]byte(nil), request...), awaitResponse: awaitResponse}, nil
}

// Request returns a caller-owned exact protocol line.
func (s ConversationStep) Request() []byte { return append([]byte(nil), s.request...) }

// AwaitResponse reports whether the next request is gated on one complete
// response line from this step.
func (s ConversationStep) AwaitResponse() bool { return s.awaitResponse }

// LineConversation is an immutable bounded sequence for request/response
// protocols such as MCP stdio.
type LineConversation struct {
	steps []ConversationStep
}

// NewLineConversation rejects empty, response-free, oversized, or forged
// steps and copy-owns every request.
func NewLineConversation(steps []ConversationStep) (LineConversation, error) {
	if len(steps) == 0 || len(steps) > maximumConversationSteps {
		return LineConversation{}, ErrInvalidInvocation
	}
	total, awaits := 0, false
	copied := make([]ConversationStep, len(steps))
	for index, step := range steps {
		request := step.Request()
		validated, err := NewConversationStep(request, step.AwaitResponse())
		if err != nil || total > maximumStandardInputBytes-len(request) {
			return LineConversation{}, ErrInvalidInvocation
		}
		total += len(request)
		awaits = awaits || validated.awaitResponse
		copied[index] = validated
	}
	if !awaits {
		return LineConversation{}, ErrInvalidInvocation
	}
	return LineConversation{steps: copied}, nil
}

// Steps returns a deep caller-owned copy of the sequence.
func (c LineConversation) Steps() []ConversationStep {
	result := make([]ConversationStep, len(c.steps))
	for index, step := range c.steps {
		result[index] = ConversationStep{request: step.Request(), awaitResponse: step.awaitResponse}
	}
	return result
}

// Runner executes one constrained unprivileged local process.
type Runner interface {
	// ExecutableAuthority returns the immutable signed authority this runner is
	// incapable of exceeding. Callers use it to bind cooperating executables.
	ExecutableAuthority() ExecutableAuthority
	Run(context.Context, Invocation) (Result, error)
}

// ConversationRunner executes a lifecycle-ordered newline protocol exchange
// through the same immutable executable authority as Runner.
type ConversationRunner interface {
	Runner
	RunLineConversation(context.Context, Invocation, LineConversation) (Result, error)
}

// StreamingRunner attaches caller-owned stdio to one constrained process.
type StreamingRunner interface {
	Runner
	RunStreaming(context.Context, Invocation, Streams) error
}

func nilStream(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable concrete stream implementations are valid.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
