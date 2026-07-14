package runtimeprovision

import (
	"errors"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestStrictOSReleaseParserRejectsShellSyntaxDuplicatesAndAmbiguity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		raw          string
		distribution string
		version      string
		valid        bool
	}{
		{name: "canonical quoted", raw: "NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\n", distribution: "ubuntu", version: "24.04", valid: true},
		{name: "canonical bare", raw: "ID=debian\nVERSION_ID=13\n", distribution: "debian", version: "13", valid: true},
		{name: "duplicate", raw: "ID=ubuntu\nID=debian\nVERSION_ID=24.04\n"},
		{name: "command substitution", raw: "ID=$(id)\nVERSION_ID=24.04\n"},
		{name: "escape", raw: "ID=ubuntu\\nVERSION_ID=24.04\n"},
		{name: "unterminated quote", raw: "ID=ubuntu\nVERSION_ID=\"24.04\n"},
		{name: "whitespace", raw: "ID =ubuntu\nVERSION_ID=24.04\n"},
		{name: "missing version", raw: "ID=ubuntu\n"},
		{name: "nul", raw: "ID=ubuntu\x00\nVERSION_ID=24.04\n"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			distribution, version, err := parseOSRelease([]byte(test.raw))
			if test.valid {
				if err != nil || distribution != test.distribution || version != test.version {
					t.Fatalf("parseOSRelease() = %q %q %v", distribution, version, err)
				}
				return
			}
			if !errors.Is(err, ErrProbeFailed) {
				t.Fatalf("parseOSRelease() error = %v", err)
			}
		})
	}
}

func TestSubordinateIDParserRejectsCollisionOverflowAndMalformedAuthority(t *testing.T) {
	t.Parallel()
	valid := []byte("alice:100000:65536\nbob:200000:65536\nalice:300000:65536\n")
	ranges, err := parseSubordinateRanges(valid)
	if err != nil {
		t.Fatal(err)
	}
	count, err := subordinateCount(ranges, "alice")
	if err != nil || count != 131072 {
		t.Fatalf("subordinateCount() = %d, %v", count, err)
	}
	invalid := []string{
		"alice:100000:65536\nbob:120000:65536\n",
		"alice:4294967295:2\n",
		"alice:0:65536\n",
		"alice:100000:0\n",
		"ali:ce:100000:65536\n",
		"alice:100000:+65536\n",
		"alice:100000:65536:extra\n",
	}
	for _, raw := range invalid {
		if _, parseError := parseSubordinateRanges([]byte(raw)); !errors.Is(parseError, ErrProbeFailed) {
			t.Fatalf("parseSubordinateRanges(%q) error = %v", raw, parseError)
		}
	}
}

func TestDockerGroupParserRejectsActiveNamedAndAmbiguousMembership(t *testing.T) {
	t.Parallel()
	raw := []byte("root:x:0:\nusers:x:100:agentmemory\ndocker:x:998:other\n")
	absent, err := dockerGroupAbsent(raw, "agentmemory", map[uint32]struct{}{100: {}})
	if err != nil || !absent {
		t.Fatalf("unrelated group membership = absent:%t error:%v", absent, err)
	}
	for _, test := range []struct {
		name    string
		raw     []byte
		account string
		groups  map[uint32]struct{}
	}{
		{name: "active gid", raw: raw, account: "agentmemory", groups: map[uint32]struct{}{998: {}}},
		{name: "named member", raw: []byte("docker:x:998:other\n"), account: "other", groups: map[uint32]struct{}{}},
	} {
		absent, err := dockerGroupAbsent(test.raw, test.account, test.groups)
		if err != nil || absent {
			t.Fatalf("%s = absent:%t error:%v", test.name, absent, err)
		}
	}
	for _, raw := range [][]byte{
		[]byte("docker:x:998:other\ndocker:x:999:\n"),
		[]byte("docker:x:0:\n"),
		[]byte("docker:x:not-a-gid:\n"),
		[]byte("docker:x:998:other,other\n"),
		[]byte("docker:x:998:bad member\n"),
		[]byte("docker:x:998:other\x00\n"),
	} {
		if _, err := dockerGroupAbsent(raw, "agentmemory", map[uint32]struct{}{}); !errors.Is(err, ErrProbeFailed) {
			t.Fatalf("dockerGroupAbsent(%q) error = %v", raw, err)
		}
	}
}

func TestProcParsersRequireStableIdentityAndListeningSocketInodes(t *testing.T) {
	t.Parallel()
	parent, uid, err := parseProcStatus([]byte("Name:\tdockerd\nPPid:\t55\nUid:\t1000\t1000\t1000\t1000\n"))
	if err != nil || parent != 55 || uid != 1000 {
		t.Fatalf("parseProcStatus() = %d %d %v", parent, uid, err)
	}
	for _, raw := range []string{
		"PPid:\t55\nUid:\t1000\t0\t1000\t1000\n",
		"PPid:\t55\nPPid:\t56\nUid:\t1000\t1000\t1000\t1000\n",
		"Uid:\t1000\t1000\t1000\t1000\n",
	} {
		if _, _, parseError := parseProcStatus([]byte(raw)); !errors.Is(parseError, ErrProbeFailed) {
			t.Fatalf("parseProcStatus(%q) error = %v", raw, parseError)
		}
	}

	table := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"0: 0100007F:094B 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n" +
		"1: 0100007F:1234 0100007F:5678 01 00000000:00000000 00:00000000 00000000 1000 0 99999\n"
	inodes, err := parseListeningTCPInodes([]byte(table))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := inodes[12345]; !present || len(inodes) != 1 {
		t.Fatalf("unexpected listening inodes: %#v", inodes)
	}
}

func TestKernelAndResourceParsersAreCanonicalAndOverflowSafe(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{"kernel", ".6.8", "6..8", "4294967296.1"} {
		if validKernel(invalid) {
			t.Fatalf("validKernel(%q) accepted malformed numeric prefix", invalid)
		}
	}
	if compareKernel("6.8.0-101-generic", "6.8.0") != 0 || compareKernel("6.7.12", "6.8.0") >= 0 ||
		compareKernel("6.10.0", "6.9.99") <= 0 {
		t.Fatal("kernel comparison did not use numeric components")
	}
	available, err := parseMemAvailable([]byte("MemTotal: 100000 kB\nMemAvailable: 50000 kB\n"))
	if err != nil || available != 50000*1024 {
		t.Fatalf("parseMemAvailable() = %d %v", available, err)
	}
	for _, raw := range []string{"", "MemAvailable: +1 kB\n", "MemAvailable: 1 MB\n", "MemAvailable: 1 kB\nMemAvailable: 2 kB\n"} {
		if _, parseError := parseMemAvailable([]byte(raw)); !errors.Is(parseError, ErrProbeFailed) {
			t.Fatalf("parseMemAvailable(%q) error = %v", raw, parseError)
		}
	}
}

func TestHostAndRuntimeEvidenceDecisionTableFailsClosed(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	host, err := NewHostEvidence(HostEvidenceInput{
		Distribution: authority.Distribution(), VersionID: authority.VersionID(), Kernel: authority.MinimumKernel(),
		Architecture: authority.Architecture(), UID: authority.InvokingUID(), GID: authority.InvokingGID(),
		CPUs: authority.MinimumCPUs(), TotalMemory: authority.MinimumTotalMemory(),
		AvailableMemory: authority.MinimumAvailableMemory(), FreeDisk: authority.MinimumFreeDisk(),
		UserNamespaces: true, UserSystemd: true, LocalFilesystem: true, DockerGroupAbsent: true,
		SELinuxEnforcing: true,
		SubordinateUIDs:  authority.SubordinateIDCount(), SubordinateGIDs: authority.SubordinateIDCount(),
		MachineDigest: authority.MachineDigest(),
	})
	if err != nil || host.Supports(authority) != nil || !host.HasSubordinateIDs(authority) {
		t.Fatalf("valid host evidence rejected: %v", err)
	}
	unsupported := host
	unsupported.availableMemory--
	unsupported.digest = unsupported.computeDigest()
	if !errors.Is(unsupported.Supports(authority), ErrUnsupportedHost) {
		t.Fatal("resource drift did not block the host")
	}
	dockerGroupMember := host
	dockerGroupMember.dockerGroupAbsent = false
	dockerGroupMember.digest = dockerGroupMember.computeDigest()
	if !errors.Is(dockerGroupMember.Supports(authority), ErrUnsupportedHost) {
		t.Fatal("rootful docker-group authority did not block the host")
	}
	admin := host
	admin.userSystemd = false
	admin.digest = admin.computeDigest()
	if !errors.Is(admin.Supports(authority), ErrAdministratorRequired) {
		t.Fatal("missing user systemd did not require administrator action")
	}

	endpoint, _ := NewEndpointEvidence(true, 99, 0o660, true)
	runtimeEvidence, err := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: authority.RuntimeVersion(), ComposeVersion: authority.ComposeVersion(),
		Architecture: authority.Architecture(), Rootless: true, LinuxContainers: true,
		Workloads: authority.UnrelatedWorkloads(),
	})
	if err != nil || !runtimeEvidence.Compatible(authority) || !authority.ValidFor(plan) {
		t.Fatalf("valid runtime evidence rejected: %v", err)
	}
	runtimeEvidence.cloudOffload = true
	if runtimeEvidence.Compatible(authority) {
		t.Fatal("cloud offload retained local runtime compatibility")
	}
}

func TestContainerInventoryParserRejectsAmbiguousOrInjectedOutput(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	if count, err := parseContainerIDs([]byte(id + "\n")); err != nil || count != 1 {
		t.Fatalf("parseContainerIDs(valid) = %d %v", count, err)
	}
	for _, raw := range []string{
		id + "\n" + id + "\n",
		strings.Repeat("A", 64) + "\n",
		id + ";touch /tmp/x\n",
		strings.Repeat("a", 63) + "\n",
		id + "\n\n",
	} {
		if _, err := parseContainerIDs([]byte(raw)); !errors.Is(err, ErrProbeFailed) {
			t.Fatalf("parseContainerIDs(%q) error = %v", raw, err)
		}
	}
}

func TestParsePositiveUintRequiresOneCanonicalPositiveInteger(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{name: "canonical", raw: "65536\n", valid: true},
		{name: "zero", raw: "0\n"},
		{name: "sign", raw: "+1\n"},
		{name: "space", raw: " 1\n"},
		{name: "multiple lines", raw: "1\n2\n"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value, err := parsePositiveUint([]byte(test.raw))
			if test.valid && (err != nil || value != 65536) {
				t.Fatalf("parsePositiveUint(%q) = %d, %v", test.raw, value, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("parsePositiveUint(%q) unexpectedly succeeded with %d", test.raw, value)
			}
		})
	}
}
