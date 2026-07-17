//go:build !darwin || cgo

package dockercli

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

func TestPF001RenderedComposeRejectsMalformedCanonicalShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong project", mutate: func(document map[string]any) { document["name"] = "other" }},
		{name: "missing core", mutate: func(document map[string]any) { delete(document["services"].(map[string]any), "core") }},
		{name: "bad identity", mutate: func(document map[string]any) {
			coreService(document)["labels"].(map[string]string)[composeplan.LabelGeneration] = "not-a-generation"
		}},
		{name: "external volume", mutate: mutateTopResource("volumes", "state", "external", true)},
		{name: "volume driver", mutate: mutateTopResource("volumes", "state", "driver", "nfs")},
		{name: "volume options", mutate: mutateTopResource("volumes", "state", "driver_opts", map[string]any{"device": "/host"})},
		{name: "duplicate physical volume", mutate: func(document map[string]any) {
			state := document["volumes"].(map[string]any)["state"].(map[string]any)
			document["volumes"].(map[string]any)["state-alias"] = state
		}},
		{name: "attachable network", mutate: mutateTopResource("networks", "am_internal", "attachable", true)},
		{name: "network driver", mutate: mutateTopResource("networks", "am_internal", "driver", "overlay")},
		{name: "network options", mutate: mutateTopResource("networks", "am_internal", "driver_opts", map[string]any{"host_binding_ipv4": "0.0.0.0"})},
		{name: "network ipam", mutate: mutateTopResource("networks", "am_internal", "ipam", map[string]any{"driver": "default"})},
		{name: "network ipv6", mutate: mutateTopResource("networks", "am_internal", "enable_ipv6", true)},
		{name: "secret environment", mutate: mutateTopResource("secrets", composeplan.SecretInstallationKey, "environment", "SECRET")},
		{name: "secret content", mutate: mutateTopResource("secrets", composeplan.SecretInstallationKey, "content", "private")},
		{name: "secret driver", mutate: mutateTopResource("secrets", composeplan.SecretInstallationKey, "driver", "other")},
		{name: "pull policy", mutate: mutateCoreService("pull_policy", "always")},
		{name: "non-null entrypoint", mutate: mutateCoreService("entrypoint", []any{"/bin/sh"})},
		{name: "missing deploy", mutate: func(document map[string]any) { delete(coreService(document), "deploy") }},
		{name: "missing limits", mutate: func(document map[string]any) {
			delete(coreService(document)["deploy"].(map[string]any)["resources"].(map[string]any), "limits")
		}},
		{name: "network aliases", mutate: func(document map[string]any) {
			coreService(document)["networks"] = map[string]any{"am_internal": map[string]any{"aliases": []any{"other"}}}
		}},
		{name: "invalid stop grace", mutate: mutateCoreService("stop_grace_period", "forever")},
		{name: "bad secret mode", mutate: func(document map[string]any) {
			document["services"].(map[string]any)[string(composeplan.ServiceSecretProjector)].(map[string]any)["secrets"].([]any)[0].(map[string]any)["mode"] = "0777"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, document := validComposePolicyFixture(t)
			test.mutate(document)
			if _, err := decodeRenderedPolicy(marshalRenderedFixture(t, document), composePolicyProject); err == nil {
				t.Fatal("malformed canonical Compose shape was accepted")
			}
		})
	}
}

func TestPF001RenderedComposePrimitiveNormalizersAreClosedAndBounded(t *testing.T) {
	t.Parallel()

	if limits, err := normalizeLimits(renderedComposeLimits{CPUs: json.Number("1.25"), Memory: "1024", PIDs: 5}); err != nil || limits.CPUsMilli != 1250 || limits.MemoryBytes != 1024 || limits.PIDs != 5 {
		t.Fatalf("normalized limits = %+v, %v", limits, err)
	}
	for _, limits := range []renderedComposeLimits{
		{CPUs: json.Number("nan"), Memory: "1024", PIDs: 1},
		{CPUs: json.Number("0.0001"), Memory: "1024", PIDs: 1},
		{CPUs: json.Number("1"), Memory: "1GiB", PIDs: 1},
		{CPUs: json.Number("1"), Memory: "1024", PIDs: 0},
	} {
		if _, err := normalizeLimits(limits); err == nil {
			t.Fatalf("invalid limits accepted: %+v", limits)
		}
	}
	if port, err := normalizeRenderedPort(renderedComposePort{
		Mode: "ingress", HostIP: "127.0.0.1", Target: 9411, Published: "9411", Protocol: "tcp",
	}); err != nil || port.HostPort != 9411 {
		t.Fatalf("normalized port = %+v, %v", port, err)
	}
	for _, port := range []renderedComposePort{
		{Target: 9411, Published: "range"},
		{Name: "public", Target: 9411, Published: "9411"},
		{Target: 65536, Published: "9411"},
	} {
		if _, err := normalizeRenderedPort(port); err == nil {
			t.Fatalf("invalid port accepted: %+v", port)
		}
	}
	if tmpfs, err := parseRenderedTmpfs("/tmp:mode=448,size=67108864"); err != nil || tmpfs.Mode != 0o700 {
		t.Fatalf("normalized tmpfs = %+v, %v", tmpfs, err)
	}
	for _, value := range []string{
		"/tmp", "/tmp:size", "/tmp:size=1,size=2,mode=448", "/tmp:unknown=1,size=2", "/tmp:size=x,mode=448",
	} {
		if _, err := parseRenderedTmpfs(value); err == nil {
			t.Fatalf("invalid tmpfs %q accepted", value)
		}
	}
}

func TestPF001RenderedComposeMountNormalizerRejectsExpansion(t *testing.T) {
	t.Parallel()

	logical := map[string]string{"state": "physical-state"}
	mount, tmpfs, err := normalizeRenderedMount(renderedComposeServiceVolume{
		Type: "volume", Source: "state", Target: "/data", Volume: &renderedComposeVolumeOptions{},
	}, logical)
	if err != nil || tmpfs != nil || mount.Kind != composeplan.MountVolume || mount.Source != "physical-state" {
		t.Fatalf("volume normalization = %+v %+v %v", mount, tmpfs, err)
	}
	mount, _, err = normalizeRenderedMount(renderedComposeServiceVolume{
		Type: "bind", Source: "/var/run/docker.sock", Target: "/socket",
	}, logical)
	if err != nil || mount.Kind != composeplan.MountBind {
		t.Fatalf("bind normalization = %+v %v", mount, err)
	}
	_, tmpfs, err = normalizeRenderedMount(renderedComposeServiceVolume{
		Type: "tmpfs", Target: "/tmp", Tmpfs: &renderedComposeTmpfsOptions{Size: "4096", Mode: 0o700},
	}, logical)
	if err != nil || tmpfs == nil || tmpfs.SizeBytes != 4096 {
		t.Fatalf("long tmpfs normalization = %+v %v", tmpfs, err)
	}
	for _, raw := range []renderedComposeServiceVolume{
		{},
		{Type: "volume", Source: "missing", Target: "/data"},
		{Type: "volume", Source: "state", Target: "/data", Volume: &renderedComposeVolumeOptions{NoCopy: true}},
		{Type: "tmpfs", Target: "/tmp", Tmpfs: &renderedComposeTmpfsOptions{Size: "bad", Mode: 0o700}},
		{Type: "image", Source: "image", Target: "/data"},
	} {
		if _, _, err := normalizeRenderedMount(raw, logical); err == nil {
			t.Fatalf("expanded mount accepted: %+v", raw)
		}
	}
}

func mutateTopResource(section string, resource string, key string, value any) func(map[string]any) {
	return func(document map[string]any) {
		document[section].(map[string]any)[resource].(map[string]any)[key] = value
	}
}

func TestPF001RenderedComposeBoundsInventoryCardinality(t *testing.T) {
	t.Parallel()

	_, _, _, document := validComposePolicyFixture(t)
	services := document["services"].(map[string]any)
	for index := 0; index < maximumRenderedEntries; index++ {
		services["extra-"+strconv.Itoa(index)] = coreService(document)
	}
	if _, err := decodeRenderedPolicy(marshalRenderedFixture(t, document), composePolicyProject); err == nil {
		t.Fatal("oversized rendered inventory was accepted")
	}
}
