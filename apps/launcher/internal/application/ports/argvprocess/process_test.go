package argvprocess

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestPF001ArgvInvocationRejectsNULAndBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		executable string
		arguments  []string
	}{
		{name: "empty executable"},
		{name: "oversized executable", executable: strings.Repeat("x", 4097)},
		{name: "NUL executable", executable: "/bin/x\x00"},
		{name: "NUL argument", executable: "/bin/x", arguments: []string{"a\x00b"}},
		{name: "oversized argument", executable: "/bin/x", arguments: []string{strings.Repeat("a", 32*1024+1)}},
		{name: "too many arguments", executable: "/bin/x", arguments: make([]string, maximumInvocationArguments+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewInvocation(test.executable, test.arguments); !errors.Is(err, ErrInvalidInvocation) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPF001ArgvInvocationCopiesInputAndOutputArguments(t *testing.T) {
	t.Parallel()

	input := []string{"compose", "version"}
	invocation, err := NewInvocation(" /Applications/Docker.app/Contents/Resources/bin/docker ", input)
	if err != nil {
		t.Fatalf("NewInvocation() error = %v", err)
	}
	input[0] = "substituted"
	first := invocation.Arguments()
	first[1] = "substituted"
	second := invocation.Arguments()
	if invocation.Executable() != " /Applications/Docker.app/Contents/Resources/bin/docker " ||
		len(second) != 2 || second[0] != "compose" || second[1] != "version" {
		t.Fatalf("Invocation exposed mutable argv: executable=%q arguments=%q", invocation.Executable(), second)
	}
}

func TestPF001ArgvInvocationCarriesOnlyBoundedCopiedStandardInput(t *testing.T) {
	t.Parallel()

	input := []byte("authenticated compose bytes")
	invocation, err := NewInvocationWithStandardInput("/absolute/docker", []string{"compose", "--file", "-"}, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	first := invocation.StandardInput()
	first[0] = 'Y'
	if got := string(invocation.StandardInput()); got != "authenticated compose bytes" {
		t.Fatalf("StandardInput() = %q", got)
	}
	if _, err := NewInvocationWithStandardInput(
		"/absolute/docker", nil, []byte(strings.Repeat("x", maximumStandardInputBytes+1)),
	); !errors.Is(err, ErrInvalidInvocation) {
		t.Fatalf("oversized standard input error = %v", err)
	}
}

func TestPF006RootlessSetupInvocationHasOnlyClosedSanitizedEnvironment(t *testing.T) {
	t.Parallel()
	invocation, err := NewRootlessSetupInvocation(
		"/usr/bin/dockerd-rootless-setuptool.sh", []string{"install"},
		"/home/agentmemory", "/run/user/1000", 1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	wanted := []string{
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"DOCKER_CONFIG=/run/user/1000/agentmemory-docker-cli",
		"DOCKER_HOST=unix:///run/user/1000/docker.sock",
		"HOME=/home/agentmemory", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin",
		"XDG_RUNTIME_DIR=/run/user/1000",
	}
	if invocation.EnvironmentProfile() != EnvironmentProfileRootlessSetup ||
		!slices.Equal(invocation.Environment(), wanted) {
		t.Fatalf("rootless environment = %v", invocation.Environment())
	}
	environment := invocation.Environment()
	environment[0] = "LD_PRELOAD=attacker"
	if invocation.Environment()[0] != wanted[0] {
		t.Fatal("rootless environment projection was mutable")
	}
	for _, test := range []struct {
		home    string
		runtime string
		uid     uint32
	}{
		{home: "/tmp/user", runtime: "/run/user/1000", uid: 1000},
		{home: "/home/user", runtime: "/run/user/1001", uid: 1000},
		{home: "/home/../root", runtime: "/run/user/1000", uid: 1000},
		{home: "/home/user", runtime: "/run/user/0", uid: 0},
	} {
		if _, err := NewRootlessSetupInvocation("/usr/bin/tool", nil, test.home, test.runtime, test.uid); !errors.Is(err, ErrInvalidInvocation) {
			t.Fatalf("unsafe rootless environment %+v error = %v", test, err)
		}
	}
}

func TestPF006PrivilegeBrokerInvocationIsFixedAndStdinOnly(t *testing.T) {
	t.Parallel()
	request := []byte(`{"schemaVersion":1,"request":"signed"}`)
	invocation, err := NewPrivilegeBrokerInvocation(
		"/usr/bin/pkexec", "/usr/libexec/agentmemory/agentmemory-runtime-helper", request,
	)
	if err != nil {
		t.Fatal(err)
	}
	request[0] = 'X'
	wantedArguments := []string{
		"--disable-internal-agent", "/usr/libexec/agentmemory/agentmemory-runtime-helper", "--request-stdin",
	}
	if invocation.Executable() != "/usr/bin/pkexec" ||
		!slices.Equal(invocation.Arguments(), wantedArguments) ||
		invocation.EnvironmentProfile() != EnvironmentProfilePrivilegeBroker ||
		len(invocation.Environment()) != 0 || invocation.StandardInput()[0] != '{' {
		t.Fatalf("privilege invocation=%+v", invocation)
	}
	for _, input := range []struct {
		pkexec string
		helper string
		body   []byte
	}{
		{pkexec: "pkexec", helper: "/usr/libexec/agentmemory/agentmemory-runtime-helper", body: []byte("x")},
		{pkexec: "/usr/bin/pkexec", helper: "/tmp/helper", body: []byte("x")},
		{pkexec: "/usr/bin/pkexec", helper: "/usr/libexec/agentmemory/agentmemory-runtime-helper"},
		{pkexec: "/usr/bin/pkexec", helper: "/usr/libexec/agentmemory/agentmemory-runtime-helper", body: make([]byte, maximumPrivilegeRequestBytes+1)},
	} {
		if _, err := NewPrivilegeBrokerInvocation(input.pkexec, input.helper, input.body); !errors.Is(err, ErrInvalidInvocation) {
			t.Fatalf("unsafe privilege invocation=%+v error=%v", input, err)
		}
	}
}

func TestPF006LinuxPackageTransactionInvocationsAreOfflineAndClosed(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 64)
	root := "/var/lib/agentmemory/runtime-helper/transactions/" + digest
	deb := root + "/docker-ce-" + digest + ".deb"
	rpm := root + "/docker-ce-" + digest + ".rpm"
	apt, err := NewAPTInstallInvocation("/usr/bin/apt-get", []string{deb})
	wantAPT := []string{
		"--assume-yes", "--no-download", "--no-remove", "--no-install-recommends",
		"-o", "Acquire::Retries=0", "-o", "APT::Get::List-Cleanup=false", "-o", "Dpkg::Use-Pty=0",
		"install", deb,
	}
	if err != nil || apt.Executable() != "/usr/bin/apt-get" || !slices.Equal(apt.Arguments(), wantAPT) ||
		apt.EnvironmentProfile() != EnvironmentProfileAPTTransaction {
		t.Fatalf("APT invocation=%+v error=%v", apt, err)
	}
	dnf, err := NewDNFInstallInvocation("/usr/bin/dnf5", []string{rpm})
	wantDNF := []string{
		"--assumeyes", "--cacheonly", "--no-plugins", "--disable-repo=*",
		"--setopt=localpkg_gpgcheck=True", "--setopt=keepcache=False", "install", rpm,
	}
	if err != nil || dnf.Executable() != "/usr/bin/dnf5" || !slices.Equal(dnf.Arguments(), wantDNF) ||
		dnf.EnvironmentProfile() != EnvironmentProfileDNFTransaction {
		t.Fatalf("DNF invocation=%+v error=%v", dnf, err)
	}
	for name, invoke := range map[string]func() error{
		"APT path": func() error { _, callErr := NewAPTInstallInvocation("apt-get", []string{deb}); return callErr },
		"APT artifact": func() error {
			_, callErr := NewAPTInstallInvocation("/usr/bin/apt-get", []string{"/tmp/x.deb"})
			return callErr
		},
		"APT extension": func() error { _, callErr := NewAPTInstallInvocation("/usr/bin/apt-get", []string{rpm}); return callErr },
		"DNF path":      func() error { _, callErr := NewDNFInstallInvocation("/usr/bin/dnf", []string{rpm}); return callErr },
		"DNF artifact": func() error {
			_, callErr := NewDNFInstallInvocation("/usr/bin/dnf5", []string{"/tmp/x.rpm"})
			return callErr
		},
		"DNF extension": func() error { _, callErr := NewDNFInstallInvocation("/usr/bin/dnf5", []string{deb}); return callErr },
	} {
		if err := invoke(); !errors.Is(err, ErrInvalidInvocation) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
}

func TestPF006LinuxPackageQueryInvocationsHaveFixedMachineReadableContracts(t *testing.T) {
	t.Parallel()
	packages := []string{"containerd.io", "docker-ce"}
	dpkg, err := NewDPKGQueryInvocation("/usr/bin/dpkg-query", packages)
	wantDPKG := []string{
		"--show", "--showformat=${Package}\\t${Version}\\t${db:Status-Status}\\n", "--",
		"containerd.io", "docker-ce",
	}
	if err != nil || !slices.Equal(dpkg.Arguments(), wantDPKG) ||
		dpkg.EnvironmentProfile() != EnvironmentProfilePackageQuery {
		t.Fatalf("dpkg query=%+v error=%v", dpkg, err)
	}
	rpm, err := NewRPMQueryInvocation("/usr/bin/rpm", packages)
	wantRPM := []string{
		"--query", "--queryformat", "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\n", "--",
		"containerd.io", "docker-ce",
	}
	if err != nil || !slices.Equal(rpm.Arguments(), wantRPM) ||
		rpm.EnvironmentProfile() != EnvironmentProfilePackageQuery {
		t.Fatalf("rpm query=%+v error=%v", rpm, err)
	}
	for name, invoke := range map[string]func() error{
		"dpkg path": func() error {
			_, callErr := NewDPKGQueryInvocation("dpkg-query", packages)
			return callErr
		},
		"rpm path": func() error {
			_, callErr := NewRPMQueryInvocation("/bin/rpm", packages)
			return callErr
		},
		"unsorted": func() error {
			_, callErr := NewDPKGQueryInvocation("/usr/bin/dpkg-query", []string{"z", "a"})
			return callErr
		},
		"duplicate": func() error {
			_, callErr := NewRPMQueryInvocation("/usr/bin/rpm", []string{"a", "a"})
			return callErr
		},
		"unsafe name": func() error {
			_, callErr := NewRPMQueryInvocation("/usr/bin/rpm", []string{"--erase"})
			return callErr
		},
	} {
		if callError := invoke(); !errors.Is(callError, ErrInvalidInvocation) {
			t.Fatalf("%s error=%v", name, callError)
		}
	}
}

func TestPF006SystemdUserServiceInvocationsAreIdentityAndCapabilityClosed(t *testing.T) {
	t.Parallel()
	linger, err := NewLoginctlEnableLingerInvocation("/usr/bin/loginctl", 1001)
	if err != nil || !slices.Equal(linger.Arguments(), []string{"--no-ask-password", "enable-linger", "1001"}) ||
		linger.EnvironmentProfile() != EnvironmentProfileLoginCTL {
		t.Fatalf("enable linger=%+v error=%v", linger, err)
	}
	showLinger, err := NewLoginctlShowLingerInvocation("/usr/bin/loginctl", 1001)
	if err != nil || !slices.Equal(showLinger.Arguments(), []string{
		"--no-pager", "--property=Linger", "--value", "show-user", "1001",
	}) || showLinger.EnvironmentProfile() != EnvironmentProfileLoginCTL {
		t.Fatalf("show linger=%+v error=%v", showLinger, err)
	}
	prefix := []string{"--user", "--machine=agentmemory@.host", "--no-pager", "--no-ask-password"}
	reload, err := NewSystemctlUserDaemonReloadInvocation("/usr/bin/systemctl", "agentmemory")
	if err != nil || !slices.Equal(reload.Arguments(), append(append([]string(nil), prefix...), "daemon-reload")) {
		t.Fatalf("daemon reload=%+v error=%v", reload, err)
	}
	enable, err := NewSystemctlUserEnableNowInvocation("/usr/bin/systemctl", "agentmemory")
	if err != nil || !slices.Equal(enable.Arguments(), append(append([]string(nil), prefix...),
		"enable", "--now", "docker.service")) {
		t.Fatalf("enable service=%+v error=%v", enable, err)
	}
	show, err := NewSystemctlUserShowInvocation("/usr/bin/systemctl", "agentmemory")
	if err != nil || !slices.Equal(show.Arguments(), append(append([]string(nil), prefix...),
		"show", "--property=LoadState,UnitFileState,ActiveState", "docker.service")) ||
		show.EnvironmentProfile() != EnvironmentProfileSystemCTL {
		t.Fatalf("show service=%+v error=%v", show, err)
	}
	for name, invoke := range map[string]func() error{
		"loginctl path": func() error {
			_, callErr := NewLoginctlEnableLingerInvocation("loginctl", 1001)
			return callErr
		},
		"root uid": func() error {
			_, callErr := NewLoginctlShowLingerInvocation("/usr/bin/loginctl", 0)
			return callErr
		},
		"systemctl path": func() error {
			_, callErr := NewSystemctlUserShowInvocation("systemctl", "agentmemory")
			return callErr
		},
		"account injection": func() error {
			_, callErr := NewSystemctlUserEnableNowInvocation("/usr/bin/systemctl", "root@foreign")
			return callErr
		},
	} {
		if callError := invoke(); !errors.Is(callError, ErrInvalidInvocation) {
			t.Fatalf("%s error=%v", name, callError)
		}
	}
}
