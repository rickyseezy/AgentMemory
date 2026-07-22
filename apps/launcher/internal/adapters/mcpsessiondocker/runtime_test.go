package mcpsessiondocker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF005RuntimeStartsAndProvesExactActiveRelease(t *testing.T) {
	t.Parallel()
	authority, pointer := runtimeFixture(t)
	docker := &processPort{captureResults: [][]byte{
		[]byte(`"28.3.1"`),
		networkInspection(t, authority, pointer),
		imageInspection(t, authority.image),
	}}
	compose := &processPort{captureResults: [][]byte{nil}}
	readiness := &runtimeReadiness{ready: true}
	activator := &runtimeActivator{}
	controller, err := NewRuntimeController(docker, compose, readiness, activator, authority)
	if err != nil {
		t.Fatal(err)
	}
	release, err := controller.EnsureReady(t.Context(), pointer)
	if err != nil {
		t.Fatalf("EnsureReady() error = %v", err)
	}
	if release.Image() != authority.image || release.Network() != authority.network || readiness.calls != 1 ||
		activator.calls != 1 || !activator.pointer.Digest().Equal(pointer.Digest()) {
		t.Fatalf("release=%+v readiness calls=%d activator=%+v", release, readiness.calls, activator)
	}
	wantDocker := [][]string{
		{"--host", pointer.RuntimeEndpoint(), "version", "--format", "{{json .Server.Version}}"},
		{"--host", pointer.RuntimeEndpoint(), "network", "inspect", authority.network},
		{"--host", pointer.RuntimeEndpoint(), "image", "inspect", authority.image},
	}
	wantCompose := [][]string{{
		"--host", pointer.RuntimeEndpoint(), "--ansi", "never", "--progress", "quiet",
		"--project-name", authority.projectName, "--project-directory", authority.projectDir,
		"--file", authority.composeFile, "--env-file", authority.emptyEnvFile,
		"up", "--detach", "--wait", "--wait-timeout", "120",
	}}
	if !reflect.DeepEqual(docker.captureArguments, wantDocker) ||
		!reflect.DeepEqual(compose.captureArguments, wantCompose) {
		t.Fatalf("docker argv=%#v compose argv=%#v", docker.captureArguments, compose.captureArguments)
	}
}

func TestPF005RuntimeRejectsTamperedComposeAndRuntimeInspection(t *testing.T) {
	t.Parallel()
	authority, pointer := runtimeFixture(t)
	if err := os.WriteFile(authority.composeFile, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	process := &processPort{}
	controller, _ := NewRuntimeController(
		process, &processPort{}, &runtimeReadiness{ready: true}, &runtimeActivator{}, authority,
	)
	if _, err := controller.EnsureReady(t.Context(), pointer); err == nil {
		t.Fatal("tampered Compose was accepted")
	}
	if len(process.captureArguments) != 0 {
		t.Fatal("tampered Compose reached Docker")
	}

	authority, pointer = runtimeFixture(t)
	badNetwork := networkInspection(t, authority, pointer)
	badNetwork = []byte(strings.Replace(string(badNetwork), `"Internal":true`, `"Internal":false`, 1))
	process = &processPort{captureResults: [][]byte{[]byte(`"28.3.1"`), badNetwork}}
	controller, _ = NewRuntimeController(
		process, &processPort{captureResults: [][]byte{nil}},
		&runtimeReadiness{ready: true}, &runtimeActivator{}, authority,
	)
	if _, err := controller.EnsureReady(t.Context(), pointer); err == nil {
		t.Fatal("non-internal network was accepted")
	}
}

func TestPF005RuntimeAuthorityRejectsAmbientAndForeignInputs(t *testing.T) {
	t.Parallel()
	authority, pointer := runtimeFixture(t)
	if _, err := NewRuntimeController(
		nil, &processPort{}, &runtimeReadiness{ready: true}, &runtimeActivator{}, authority,
	); err == nil {
		t.Fatal("nil Docker process accepted")
	}
	if _, err := NewRuntimeController(
		&processPort{}, nil, &runtimeReadiness{ready: true}, &runtimeActivator{}, authority,
	); err == nil {
		t.Fatal("nil Compose process accepted")
	}
	if _, err := NewRuntimeAuthority(
		pointer, "foreign", authority.projectDir, authority.composeFile, authority.emptyEnvFile,
		authority.image, authority.network,
	); err == nil {
		t.Fatal("foreign project accepted")
	}
	// A independently valid pointer cannot substitute for construction authority.
	changed, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID: pointer.InstallationID(), ReleaseID: pointer.ReleaseID(),
		GenerationID: pointer.GenerationID(), ManifestDigest: pointer.ManifestDigest(),
		ComposeDigest: pointer.ComposeDigest(), ReadinessReceiptDigest: pointer.ReadinessReceiptDigest(),
		RuntimeEndpoint: pointer.RuntimeEndpoint(), ReleaseSequence: pointer.ReleaseSequence(),
		ResourceInventoryVersion: pointer.ResourceInventoryVersion(),
		ResourceInventoryDigest:  pointer.ResourceInventoryDigest(), SecurityEpoch: pointer.SecurityEpoch() + 1,
		ActivatedAt: pointer.ActivatedAt(),
	})
	if err != nil {
		t.Fatal(err)
	}
	controller, _ := NewRuntimeController(
		&processPort{}, &processPort{}, &runtimeReadiness{ready: true}, &runtimeActivator{}, authority,
	)
	if _, err := controller.EnsureReady(context.Background(), changed); err == nil {
		t.Fatal("foreign pointer accepted")
	}
}

func TestPF005RuntimeFailureMatrixFailsClosedAtEveryRecoveryBoundary(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{
		"desktop_or_rootless_activation_failed",
		"daemon_unhealthy",
		"compose_recovery_failed",
		"network_substituted",
		"image_substituted",
		"core_not_ready",
		"core_probe_failed",
	} {
		scenario := scenario
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			authority, pointer := runtimeFixture(t)
			docker := &processPort{captureResults: [][]byte{
				[]byte(`"28.3.1"`),
				networkInspection(t, authority, pointer),
				imageInspection(t, authority.image),
			}}
			compose := &processPort{captureResults: [][]byte{nil}}
			readiness := &runtimeReadiness{ready: true}
			activator := &runtimeActivator{}
			switch scenario {
			case "desktop_or_rootless_activation_failed":
				activator.err = context.DeadlineExceeded
			case "daemon_unhealthy":
				docker.captureError = context.DeadlineExceeded
			case "compose_recovery_failed":
				compose.captureError = context.DeadlineExceeded
			case "network_substituted":
				docker.captureResults[1] = []byte(`[]`)
			case "image_substituted":
				docker.captureResults[2] = []byte(`[{"RepoDigests":[]}]`)
			case "core_not_ready":
				readiness.ready = false
			case "core_probe_failed":
				readiness.err = context.DeadlineExceeded
			default:
				t.Fatal("unknown test scenario")
			}
			controller, err := NewRuntimeController(
				docker, compose, readiness, activator, authority,
			)
			if err != nil {
				t.Fatal(err)
			}
			if release, err := controller.EnsureReady(t.Context(), pointer); err == nil ||
				!release.Pointer().IsZero() {
				t.Fatalf("unsafe release=%+v error=%v", release, err)
			}
			if activator.calls != 1 {
				t.Fatalf("activator calls=%d", activator.calls)
			}
			if scenario == "desktop_or_rootless_activation_failed" &&
				(len(docker.captureArguments) != 0 || len(compose.captureArguments) != 0) {
				t.Fatal("Docker ran after endpoint activation failure")
			}
			if scenario == "daemon_unhealthy" && len(compose.captureArguments) != 0 {
				t.Fatal("Compose ran against an unhealthy daemon")
			}
			if scenario == "compose_recovery_failed" && readiness.calls != 0 {
				t.Fatal("Core readiness ran after Compose failure")
			}
		})
	}
}

type runtimeReadiness struct {
	ready bool
	err   error
	calls int
}

type runtimeActivator struct {
	pointer activerelease.Pointer
	err     error
	calls   int
}

func (a *runtimeActivator) EnsureEndpoint(_ context.Context, pointer activerelease.Pointer) error {
	a.calls++
	a.pointer = pointer
	return a.err
}

func (r *runtimeReadiness) Ready(context.Context) (bool, error) {
	r.calls++
	return r.ready, r.err
}

func runtimeFixture(t testing.TB) (RuntimeAuthority, activerelease.Pointer) {
	t.Helper()
	root := t.TempDir()
	compose := []byte("{\"name\":\"signed\"}\n")
	composePath := filepath.Join(root, "compose.json")
	envPath := filepath.Join(root, "empty.env")
	if err := os.WriteFile(composePath, compose, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	installationID := "019d2b4e-7a11-7def-8abc-0123456789ab"
	pointer, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID: installationID, ReleaseID: "v1.0.0",
		GenerationID:           "019d2b4e-7a12-7def-8abc-0123456789ab",
		ManifestDigest:         install.DigestBytes([]byte("manifest")),
		ComposeDigest:          install.DigestBytes(compose),
		ReadinessReceiptDigest: install.DigestBytes([]byte("ready")),
		RuntimeEndpoint:        "unix:///var/run/docker.sock", ReleaseSequence: 1,
		ResourceInventoryVersion: 1, ResourceInventoryDigest: install.DigestBytes([]byte("inventory")),
		SecurityEpoch: 1, ActivatedAt: time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	project := "agentmemory_" + strings.ReplaceAll(installationID, "-", "")
	image := "registry.local/agentmemory/mcp-session@sha256:" + strings.Repeat("b", sha256.Size*2)
	authority, err := NewRuntimeAuthority(
		pointer, project, root, composePath, envPath, image, project+"_internal",
	)
	if err != nil {
		t.Fatal(err)
	}
	return authority, pointer
}

func networkInspection(
	t testing.TB,
	authority RuntimeAuthority,
	pointer activerelease.Pointer,
) []byte {
	t.Helper()
	payload, err := json.Marshal([]map[string]any{{
		"Name": authority.network, "Internal": true,
		"Labels": map[string]string{
			"io.agentmemory.installation": pointer.InstallationID(),
			"io.agentmemory.release":      pointer.ReleaseID(),
			"io.agentmemory.generation":   pointer.GenerationID(),
			"io.agentmemory.purpose":      "internal", "io.agentmemory.managed": "true",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func imageInspection(t testing.TB, image string) []byte {
	t.Helper()
	payload, err := json.Marshal([]map[string]any{{"RepoDigests": []string{image}}})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
