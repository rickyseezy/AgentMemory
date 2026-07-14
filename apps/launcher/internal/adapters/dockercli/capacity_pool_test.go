package dockercli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001DockerCapacityPoolProbeBindsStableLocalDaemonIdentity(t *testing.T) {
	t.Parallel()
	runner := &capacityRunner{result: argvprocess.Result{StandardOutput: []byte(validCapacityInfo())}}
	probe, err := NewCapacityPoolProbe(testExecutorsForDocker(t, runner))
	if err != nil {
		t.Fatal(err)
	}

	engine, err := probe.AttestDockerPool(context.Background(), artifactapp.CapacityTarget{
		Kind: artifactapp.CapacityDockerEngine, Locator: "unix:///var/run/docker.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := probe.AttestDockerPool(context.Background(), artifactapp.CapacityTarget{
		Kind: artifactapp.CapacityDockerDataVolume, Locator: "unix:///var/run/docker.sock",
	})
	if err != nil || !engine.Valid() || !volume.Valid() || engine.ID() != volume.ID() ||
		engine.Kind() != artifactapp.CapacityDockerEngine || volume.Kind() != artifactapp.CapacityDockerDataVolume {
		t.Fatalf("capacity pools = %+v / %+v, error = %v", engine, volume, err)
	}

	want := []string{"--host", "unix:///var/run/docker.sock", "info", "--format", capacityInfoTemplate}
	if len(runner.invocations) != 2 || !reflect.DeepEqual(runner.invocations[0].Arguments(), want) ||
		runner.invocations[0].Executable() != testPlatformToolPath("/verified/docker") {
		t.Fatalf("capacity invocation = %+v", runner.invocations)
	}
}

func TestPF001DockerCapacityPoolProbeAcceptsCertifiedDesktopContainerdStore(t *testing.T) {
	t.Parallel()
	desktop := `{"ID":"daemon-1","DockerRootDir":"/var/lib/docker","Driver":"overlayfs","DriverStatus":[["driver-type","io.containerd.snapshotter.v1"]],"OperatingSystem":"Docker Desktop","OSType":"linux","Architecture":"aarch64","Name":"docker-desktop","ServerVersion":"29.6.1"}`
	runner := &capacityRunner{result: argvprocess.Result{StandardOutput: []byte(desktop)}}
	probe, err := NewCapacityPoolProbe(testExecutorsForDocker(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if pool, err := probe.AttestDockerPool(context.Background(), capacityTarget()); err != nil || !pool.Valid() {
		t.Fatalf("desktop capacity pool = %+v, %v", pool, err)
	}
}

func TestPF001DockerCapacityPoolProbeRejectsAmbiguousOrUntrustedObservations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target artifactapp.CapacityTarget
		result argvprocess.Result
		runErr error
	}{
		{name: "nil context", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(validCapacityInfo())}},
		{name: "foreign kind", target: artifactapp.CapacityTarget{Kind: "foreign", Locator: "unix:///var/run/docker.sock"}, result: argvprocess.Result{StandardOutput: []byte(validCapacityInfo())}},
		{name: "remote endpoint", target: artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: "tcp://127.0.0.1:2375"}, result: argvprocess.Result{StandardOutput: []byte(validCapacityInfo())}},
		{name: "duplicate JSON", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `"ID":"daemon-1"`, `"ID":"daemon-1","ID":"daemon-2"`, 1))}},
		{name: "unknown JSON", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `}`, `,"Foreign":true}`, 1))}},
		{name: "Windows containers", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `"OSType":"linux"`, `"OSType":"windows"`, 1))}},
		{name: "relative root", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `"DockerRootDir":"/var/lib/docker"`, `"DockerRootDir":"var/lib/docker"`, 1))}},
		{name: "snapshot-prone backing store", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `"Backing Filesystem","extfs"`, `"Backing Filesystem","btrfs"`, 1))}},
		{name: "missing d_type", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `"Supports d_type","true"`, `"Supports d_type","false"`, 1))}},
		{name: "duplicate driver fact", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `[["Backing Filesystem","extfs"],["Supports d_type","true"]]`, `[["Backing Filesystem","extfs"],["Backing Filesystem","xfs"],["Supports d_type","true"]]`, 1))}},
		{name: "missing daemon identity", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Replace(validCapacityInfo(), `"ID":"daemon-1"`, `"ID":""`, 1))}},
		{name: "failed command", target: capacityTarget(), result: argvprocess.Result{ExitCode: 1}},
		{name: "truncated command", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(validCapacityInfo()), OutputTruncated: true}},
		{name: "oversized output", target: capacityTarget(), result: argvprocess.Result{StandardOutput: []byte(strings.Repeat("x", maximumDockerJSON+1))}},
		{name: "runner failure", target: capacityTarget(), runErr: errors.New("unavailable")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runner := &capacityRunner{result: test.result, err: test.runErr}
			probe, err := NewCapacityPoolProbe(testExecutorsForDocker(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if test.name == "nil context" {
				ctx = nil
			}
			if _, err := probe.AttestDockerPool(ctx, test.target); !errors.Is(err, artifactapp.ErrReservationUnsupported) &&
				!errors.Is(err, artifactapp.ErrReservationOperation) {
				t.Fatalf("AttestDockerPool() error = %v", err)
			}
			if (test.name == "foreign kind" || test.name == "remote endpoint" || test.name == "nil context") &&
				len(runner.invocations) != 0 {
				t.Fatalf("invalid input reached Docker: %d invocation(s)", len(runner.invocations))
			}
		})
	}
}

func TestPF001DockerCapacityPoolProbeRejectsIncompleteComposition(t *testing.T) {
	t.Parallel()
	if _, err := NewCapacityPoolProbe(Executors{}); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("NewCapacityPoolProbe() error = %v", err)
	}
}

type capacityRunner struct {
	result      argvprocess.Result
	err         error
	invocations []argvprocess.Invocation
}

func (r *capacityRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.invocations = append(r.invocations, invocation)
	return r.result, r.err
}

func capacityTarget() artifactapp.CapacityTarget {
	return artifactapp.CapacityTarget{Kind: artifactapp.CapacityDockerEngine, Locator: "unix:///var/run/docker.sock"}
}

func validCapacityInfo() string {
	return `{"ID":"daemon-1","DockerRootDir":"/var/lib/docker","Driver":"overlay2","DriverStatus":[["Backing Filesystem","extfs"],["Supports d_type","true"]],"OperatingSystem":"Docker","OSType":"linux","Architecture":"amd64","Name":"local-engine","ServerVersion":"29.6.1"}`
}
