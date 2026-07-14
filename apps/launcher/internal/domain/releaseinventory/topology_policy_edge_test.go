package releaseinventory

import (
	"strings"
	"testing"
)

func TestPF001HealthProbeTargetGrammarRejectsShellAndCrossKindAmbiguity(t *testing.T) {
	t.Parallel()
	execArguments := []string{"/usr/local/bin/health", "--ready"}
	for _, test := range []struct {
		input HealthProbeInput
		want  bool
	}{
		{input: HealthProbeInput{Kind: HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080}, want: true},
		{input: HealthProbeInput{Kind: HealthProbeKindHTTP, HTTPPath: "/ready", Port: 8080, Arguments: []string{"curl"}}},
		{input: HealthProbeInput{Kind: HealthProbeKindHTTP, HTTPPath: "relative", Port: 8080}},
		{input: HealthProbeInput{Kind: HealthProbeKindHTTP, HTTPPath: "/ready"}},
		{input: HealthProbeInput{Kind: HealthProbeKindExec, Arguments: execArguments}, want: true},
		{input: HealthProbeInput{Kind: HealthProbeKindExec, HTTPPath: "/ready", Arguments: execArguments}},
		{input: HealthProbeInput{Kind: HealthProbeKindExec, Port: 8080, Arguments: execArguments}},
		{input: HealthProbeInput{Kind: HealthProbeKindExec}},
		{input: HealthProbeInput{Kind: HealthProbeKindExec, Arguments: []string{"relative"}}},
		{input: HealthProbeInput{Kind: HealthProbeKindExec, Arguments: []string{"/bin/probe", "unsafe\nargument"}}},
		{input: HealthProbeInput{Kind: HealthProbeKindExec, Arguments: make([]string, 33)}},
		{input: HealthProbeInput{Kind: "foreign"}},
	} {
		if got := validProbeTarget(test.input); got != test.want {
			t.Fatalf("validProbeTarget(%+v)=%t want %t", test.input, got, test.want)
		}
	}
}

func TestPF001TopologyCollectionPoliciesAreCanonicalAndDuplicateSafe(t *testing.T) {
	t.Parallel()
	ports, err := validatedPortBindings([]PortBindingInput{
		{Host: "::1", HostPort: 8443, ContainerPort: 443},
		{Host: "127.0.0.1", HostPort: 8080, ContainerPort: 80},
		{Host: "127.0.0.1", HostPort: 7070, ContainerPort: 70},
	}, make(map[string]struct{}))
	if err != nil || len(ports) != 3 || ports[0].HostPort() != 7070 || ports[2].Host() != "::1" {
		t.Fatalf("canonical port bindings=%+v,%v", ports, err)
	}
	for _, input := range []PortBindingInput{
		{Host: "0.0.0.0", HostPort: 1, ContainerPort: 1},
		{Host: "127.0.0.1", ContainerPort: 1},
		{Host: "127.0.0.1", HostPort: 1},
	} {
		if _, err := validatedPortBindings([]PortBindingInput{input}, make(map[string]struct{})); err == nil {
			t.Fatalf("unsafe port binding accepted: %+v", input)
		}
	}
	occupied := map[string]struct{}{"127.0.0.1:8080": {}}
	if _, err := validatedPortBindings([]PortBindingInput{{Host: "127.0.0.1", HostPort: 8080, ContainerPort: 80}}, occupied); err == nil {
		t.Fatal("duplicate published port accepted")
	}

	if !validLabelKey("com.agentmemory.release-id") || validLabelKey("com.agentmemory.Bad") ||
		validLabelKey(strings.Repeat("a", 129)) {
		t.Fatal("topology label-key grammar drifted")
	}
	if optional, err := validatedIdentifierSet(nil, false); err != nil || len(optional) != 0 {
		t.Fatalf("empty optional identifier set=%v,%v", optional, err)
	}
	if sorted, err := validatedIdentifierSet([]string{"worker", "core"}, true); err != nil ||
		len(sorted) != 2 || sorted[0] != "core" {
		t.Fatalf("canonical identifier set=%v,%v", sorted, err)
	}
	for _, values := range [][]string{nil, {"bad value"}, {"core", "core"}} {
		if _, err := validatedIdentifierSet(values, true); err == nil {
			t.Fatalf("unsafe identifier set accepted: %q", values)
		}
	}
}
