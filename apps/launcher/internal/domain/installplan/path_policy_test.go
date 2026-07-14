package installplan

import (
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001CanonicalHostPathPolicyRejectsAmbiguousUnixAndWindowsForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		unix  bool
		valid bool
	}{
		{value: "/var/lib/agentmemory/releases", unix: true, valid: true},
		{value: `C:\ProgramData\AgentMemory\releases`, valid: true},
		{value: ""},
		{value: " /var/lib/agentmemory"},
		{value: "/"},
		{value: "//var/lib/agentmemory"},
		{value: "/var/lib/agentmemory/"},
		{value: `/var\lib`},
		{value: "/var/../agentmemory"},
		{value: "/var//agentmemory"},
		{value: "/var/" + strings.Repeat("a", 256)},
		{value: `c:\ProgramData\AgentMemory`},
		{value: `C:ProgramData\AgentMemory`},
		{value: `C:\ProgramData\\AgentMemory`},
		{value: `C:\ProgramData\AgentMemory\`},
		{value: `C:\ProgramData\bad:name`},
		{value: `C:\ProgramData\trailing.`},
		{value: "C:\\ProgramData\\trailing "},
		{value: "C:\\ProgramData\nAgentMemory"},
		{value: strings.Repeat("a", 4097)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			identity, unix, valid := canonicalHostPath(test.value)
			if valid != test.valid || valid && unix != test.unix {
				t.Fatalf("canonicalHostPath(%q)=(%+v,%t,%t)", test.value, identity, unix, valid)
			}
		})
	}
}

func TestPF001StrictHostDescendantPolicyIsRootAndComponentBound(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		parent string
		child  string
		want   bool
	}{
		{parent: "/var/lib/agentmemory", child: "/var/lib/agentmemory/releases/v1", want: true},
		{parent: `C:\ProgramData\AgentMemory`, child: `C:\ProgramData\AgentMemory\releases\v1`, want: true},
		{parent: "/var/lib/agentmemory", child: "/var/lib/agentmemory"},
		{parent: "/var/lib/agentmemory", child: "/var/lib/agentmemory-other/release"},
		{parent: "/var/lib/agentmemory", child: `C:\ProgramData\AgentMemory\release`},
		{parent: "relative", child: "/var/lib/agentmemory"},
		{parent: "/var/lib/agentmemory", child: "/var/../agentmemory/release"},
	} {
		if got := strictHostPathChild(test.parent, test.child); got != test.want {
			t.Fatalf("strictHostPathChild(%q,%q)=%t want %t", test.parent, test.child, got, test.want)
		}
	}
}

func TestPF001LocalRuntimeEndpointAndOwnershipGrammarIsClosed(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]bool{
		"unix:///run/user/1000/docker.sock": true,
		"unix:///run/user/1000/":            false,
		"unix:////run/user/1000/socket":     false,
		"unix:///run/../docker.sock":        false,
		"npipe:////./pipe/docker_engine":    true,
		"npipe:////./pipe/":                 false,
		"npipe:////./pipe/..":               false,
		"npipe:////./pipe/nested/name":      false,
		"tcp://127.0.0.1:2375":              false,
		"":                                  false,
	} {
		if got := validLocalEndpoint(value); got != want {
			t.Fatalf("validLocalEndpoint(%q)=%t want %t", value, got, want)
		}
	}
	for value, want := range map[string]bool{
		"http://127.0.0.1:1":     true,
		"http://[::1]:65535":     true,
		"http://127.0.0.1:0":     false,
		"http://127.0.0.1:08080": false,
		"http://127.0.0.1:65536": false,
		"https://127.0.0.1:8080": false,
	} {
		if got := validLoopbackCoreEndpoint(value); got != want {
			t.Fatalf("validLoopbackCoreEndpoint(%q)=%t want %t", value, got, want)
		}
	}
	for _, ownership := range []install.RuntimeOwnership{
		install.RuntimeOwnershipUndetermined,
		install.RuntimeOwnershipReusedExternal,
		install.RuntimeOwnershipProvisionedByAgentMemory,
	} {
		parsed, ok := parseOwnership(ownership.String())
		if !ok || parsed != ownership {
			t.Fatalf("parseOwnership(%q)=(%s,%t)", ownership.String(), parsed, ok)
		}
	}
	if parsed, ok := parseOwnership("foreign"); ok || parsed != install.RuntimeOwnershipUnknown {
		t.Fatalf("foreign ownership=(%s,%t)", parsed, ok)
	}
}
