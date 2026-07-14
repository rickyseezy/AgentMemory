package dockercli

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/capacityhelper"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001DockerCapacityLeasesReserveReplayTransferAndAuthorizedRelease(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseRollback)

	receipt, err := adapter.ReserveLease(context.Background(), lease)
	if err != nil || !receipt.Present() || receipt.Token() == "" {
		t.Fatalf("ReserveLease()=%+v,%v", receipt, err)
	}
	if replay, err := adapter.ReserveLease(context.Background(), lease); err != nil || replay.Token() != receipt.Token() {
		t.Fatalf("ReserveLease replay=%+v,%v", replay, err)
	}
	assertHardenedCapacityRun(t, runner.invocations)

	aggregate, err := artifactacquisition.NewCapacityAggregate("install-capacity", lease.PlanDigest(), []artifactacquisition.CapacityLease{lease})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aggregate.RecordReserved(lease, receipt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := aggregate.BeginTransfer(lease.ID(), "generation-1"); err != nil {
		t.Fatal(err)
	}
	proof, err := adapter.TransferLease(context.Background(), lease, "generation-1")
	if err != nil || proof.Owner() != "generation-1" || proof.Receipt().Present() {
		t.Fatalf("TransferLease()=%+v,%v", proof, err)
	}
	if _, err := aggregate.RecordTransferred(lease.ID(), proof); err != nil {
		t.Fatal(err)
	}
	authorizations, err := aggregate.BeginUninstall("generation-1", "installation-1")
	if err != nil || len(authorizations) != 1 {
		t.Fatalf("BeginUninstall()=%+v,%v", authorizations, err)
	}
	released, err := adapter.ReleaseCapacity(context.Background(), authorizations[0])
	if err != nil || released.Present() || len(runner.volumes) != 0 {
		t.Fatalf("ReleaseCapacity()=%+v,%v volumes=%+v", released, err, runner.volumes)
	}
	if replay, err := adapter.ReleaseCapacity(context.Background(), authorizations[0]); err != nil || replay.Present() {
		t.Fatalf("ReleaseCapacity replay=%+v,%v", replay, err)
	}
}

func TestPF001DockerCapacityProjectionUsesFinalIdentityLabelsAndActivatesToEmptyVolume(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseSecretProjection)
	receipt, err := adapter.ReserveLease(context.Background(), lease)
	if err != nil || !receipt.Present() {
		t.Fatalf("ReserveLease()=%+v,%v", receipt, err)
	}
	volume, exists := runner.volumes[lease.ArtifactID()]
	if !exists || len(volume.labels) != 5 ||
		volume.labels["io.agentmemory.installation"] != lease.ProjectionInstallationID() ||
		volume.labels["io.agentmemory.release"] != lease.ProjectionReleaseID() ||
		volume.labels["io.agentmemory.generation"] != lease.ProjectionGenerationID() ||
		volume.labels["io.agentmemory.purpose"] != lease.ResourcePurpose() ||
		volume.labels["io.agentmemory.managed"] != "true" {
		t.Fatalf("projection volume=%+v", volume)
	}
	for label := range volume.labels {
		if strings.HasPrefix(label, "io.agentmemory.capacity.") {
			t.Fatalf("immutable final volume carries transient label %q", label)
		}
	}
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		"install-capacity", lease.PlanDigest(), []artifactacquisition.CapacityLease{lease},
	)
	_, _ = aggregate.RecordReserved(lease, receipt)
	_, _, _ = aggregate.BeginTransfer(lease.ID(), lease.ProjectionGenerationID())
	proof, err := adapter.TransferLease(context.Background(), lease, lease.ProjectionGenerationID())
	if err != nil || proof.Receipt().Present() || proof.Owner() != lease.ProjectionGenerationID() ||
		volume.metadata.SchemaVersion != 0 {
		t.Fatalf("TransferLease()=%+v,%v volume=%+v", proof, err, volume)
	}
	if _, err := aggregate.RecordTransferred(lease.ID(), proof); err != nil {
		t.Fatal(err)
	}
	authorizations, err := aggregate.BeginUninstall(lease.ProjectionGenerationID(), lease.ProjectionInstallationID())
	if err != nil || len(authorizations) != 1 {
		t.Fatalf("BeginUninstall()=%+v,%v", authorizations, err)
	}
	if released, releaseError := adapter.ReleaseCapacity(context.Background(), authorizations[0]); releaseError != nil || released.Present() || len(runner.volumes) != 0 {
		t.Fatalf("ReleaseCapacity()=%+v,%v volumes=%+v", released, releaseError, runner.volumes)
	}
}

func TestPF001DockerCapacityProjectionCompensationReconcilesActivationCrashWindow(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseSecretProjection)
	receipt, err := adapter.ReserveLease(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		"install-capacity", lease.PlanDigest(), []artifactacquisition.CapacityLease{lease},
	)
	_, _ = aggregate.RecordReserved(lease, receipt)
	_, _, _ = aggregate.BeginTransfer(lease.ID(), lease.ProjectionGenerationID())
	authorizations, _ := aggregate.BeginCompensation()
	if len(authorizations) != 1 || authorizations[0].FromState() != artifactacquisition.LeaseTransferPending {
		t.Fatalf("authorizations=%+v", authorizations)
	}
	if released, releaseError := adapter.ReleaseCapacity(context.Background(), authorizations[0]); releaseError != nil || released.Present() || len(runner.volumes) != 0 {
		t.Fatalf("ReleaseCapacity()=%+v,%v volumes=%+v", released, releaseError, runner.volumes)
	}
}

func TestPF001DockerCapacityLeasesReconcileCrashAndExactLowSpace(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	runner.failHelper = 1
	adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseSafety)
	if _, err := adapter.ReserveLease(context.Background(), lease); err == nil || len(runner.volumes) != 1 {
		t.Fatalf("interrupted ReserveLease error=%v volumes=%d", err, len(runner.volumes))
	}
	if receipt, err := adapter.ReserveLease(context.Background(), lease); err != nil || !receipt.Present() || len(runner.volumes) != 1 {
		t.Fatalf("ReserveLease replay=%+v,%v volumes=%d", receipt, err, len(runner.volumes))
	}

	pendingRunner := newCapacityLeaseRunner(t)
	pendingAdapter, pendingLease := newCapacityLeaseAdapter(t, pendingRunner, artifactacquisition.LeaseRollback)
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		"install-capacity", pendingLease.PlanDigest(), []artifactacquisition.CapacityLease{pendingLease},
	)
	authorizations, err := aggregate.BeginCompensation()
	if err != nil || len(authorizations) != 1 {
		t.Fatal(err)
	}
	receipt, err := pendingAdapter.ReleaseCapacity(context.Background(), authorizations[0])
	if err != nil || receipt.Present() || len(pendingRunner.volumes) != 0 {
		t.Fatalf("pending ReleaseCapacity()=%+v,%v", receipt, err)
	}
}

func TestPF001DockerCapacityLeasesRejectTamperAndPoolSubstitution(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseRollback)
	if _, err := adapter.ReserveLease(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	volume := onlyCapacityVolume(t, runner)
	volume.labels["io.agentmemory.capacity.pool"] = strings.Repeat("f", 64)
	if _, err := adapter.RevalidateLease(context.Background(), lease); err == nil {
		t.Fatal("foreign volume labels accepted")
	}
	volume.labels["io.agentmemory.capacity.pool"] = adapterLabels(t, adapter, lease)["io.agentmemory.capacity.pool"]
	volume.options["type"] = "nfs"
	if _, err := adapter.RevalidateLease(context.Background(), lease); err == nil {
		t.Fatal("volume plugin options accepted")
	}
	delete(volume.options, "type")
	runner.duplicateVolumeList = true
	if _, err := adapter.RevalidateLease(context.Background(), lease); err == nil {
		t.Fatal("duplicate Docker list output accepted")
	}
	runner.duplicateVolumeList = false
	runner.tamperHelperReceipt = true
	if _, err := adapter.RevalidateLease(context.Background(), lease); err == nil {
		t.Fatal("substituted helper receipt accepted")
	}

	foreignPool, _ := artifactacquisition.NewStoragePool("d-"+strings.Repeat("e", 64), artifactapp.CapacityDockerEngine)
	foreignLease, _ := artifactacquisition.NewCapacityLease(
		"install-capacity", artifactacquisition.LeaseRollback, "install-capacity", "", foreignPool,
		lease.Bytes(), lease.PlanDigest(), releaseinventory.Digest{}, 0, releaseinventory.Digest{},
	)
	before := len(runner.invocations)
	if _, err := adapter.ReserveLease(context.Background(), foreignLease); err == nil || len(runner.invocations) != before {
		t.Fatalf("pool substitution error=%v invocations=%d", err, len(runner.invocations)-before)
	}
}

func TestPF001DockerCapacityLeasesRejectMissingOrForeignHelperBeforeVolumeMutation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"missing", "foreign", "duplicate-json", "unknown-json", "windows"} {
		t.Run(mode, func(t *testing.T) {
			runner := newCapacityLeaseRunner(t)
			runner.imageMode = mode
			adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseRollback)
			if _, err := adapter.ReserveLease(context.Background(), lease); err == nil || len(runner.volumes) != 0 {
				t.Fatalf("mode=%s error=%v volumes=%d", mode, err, len(runner.volumes))
			}
		})
	}
}

func TestPF001DockerCapacityLeasesRejectExpandedTransferAndIncompleteComposition(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	adapter, expanded := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseExpanded)
	if _, err := adapter.TransferLease(context.Background(), expanded, "generation-1"); !errors.Is(err, artifactapp.ErrReservationUnsupported) || len(runner.invocations) != 0 {
		t.Fatalf("expanded transfer error=%v invocations=%d", err, len(runner.invocations))
	}

	validRunner := newCapacityLeaseRunner(t)
	executors := testExecutorsForDocker(t, validRunner)
	helper := capacityHelperAuthorityForTest(capacityHelperResource(t, executors))
	endpoint, _ := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	manifestDigest := releaseinventory.Digest(executors.dockerAuthority.ReleaseManifestDigest())
	pool, _ := artifactacquisition.NewStoragePool("d-"+strings.Repeat("d", 64), artifactapp.CapacityDockerEngine)
	wrongKind, _ := artifactacquisition.NewStoragePool("d-"+strings.Repeat("d", 64), "docker-data-volume")
	if _, err := NewCapacityLeases(executors, endpoint, appreleaseverify.VerifiedInventory{}, pool); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
		t.Fatalf("unverified inventory constructor error=%v", err)
	}
	for name, construct := range map[string]func() (*CapacityLeases, error){
		"executors": func() (*CapacityLeases, error) {
			return newCapacityLeases(Executors{}, endpoint, helper, manifestDigest, pool)
		},
		"endpoint": func() (*CapacityLeases, error) {
			return newCapacityLeases(executors, containerengine.Endpoint{}, helper, manifestDigest, pool)
		},
		"manifest": func() (*CapacityLeases, error) {
			return newCapacityLeases(executors, endpoint, helper, releaseinventory.DigestBytes([]byte("other")), pool)
		},
		"pool kind": func() (*CapacityLeases, error) {
			return newCapacityLeases(executors, endpoint, helper, manifestDigest, wrongKind)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := construct(); !errors.Is(err, artifactapp.ErrReservationUnsupported) {
				t.Fatalf("constructor error=%v", err)
			}
		})
	}
}

func TestPF001DockerCapacityLeasesReleaseRejectsUnknownPendingVolume(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseRollback)
	_, name, labels, err := adapter.requestForLease(capacityhelper.OperationReserve, lease, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	runner.volumes[name] = &fakeCapacityVolume{labels: labels, options: map[string]string{}, malformedMetadata: true}
	aggregate, _ := artifactacquisition.NewCapacityAggregate(
		"install-capacity", lease.PlanDigest(), []artifactacquisition.CapacityLease{lease},
	)
	authorizations, _ := aggregate.BeginCompensation()
	if _, err := adapter.ReleaseCapacity(context.Background(), authorizations[0]); err == nil || len(runner.volumes) != 1 {
		t.Fatalf("unknown pending state error=%v volumes=%d", err, len(runner.volumes))
	}
}

func FuzzPF001DockerCapacityLeaseOutputStrictDecoder(f *testing.F) {
	f.Add([]byte(`{"Architecture":"amd64","Id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Os":"linux","RepoDigests":["registry.example/agentmemory/capacity-helper@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}`))
	f.Add([]byte(`{"Name":"x","Name":"y"}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) > maximumDockerJSON+1 {
			data = data[:maximumDockerJSON+1]
		}
		_ = rejectDuplicateJSONKeys(data)
		var image capacityImageDocument
		_ = decodeStrictJSON(data, &image)
		var volume capacityVolumeDocument
		_ = decodeStrictJSON(data, &volume)
	})
}

type fakeCapacityVolume struct {
	labels            map[string]string
	options           map[string]string
	metadata          capacityhelper.Metadata
	malformedMetadata bool
}

type capacityLeaseRunner struct {
	t                   *testing.T
	imageRef            string
	architecture        string
	imageMode           string
	failHelper          int
	tamperHelperReceipt bool
	duplicateVolumeList bool
	volumes             map[string]*fakeCapacityVolume
	invocations         []argvprocess.Invocation
}

func newCapacityLeaseRunner(t *testing.T) *capacityLeaseRunner {
	t.Helper()
	return &capacityLeaseRunner{t: t, architecture: runtime.GOARCH, volumes: make(map[string]*fakeCapacityVolume)}
}

func (r *capacityLeaseRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.invocations = append(r.invocations, invocation)
	arguments := invocation.Arguments()
	if len(arguments) < 3 || arguments[0] != "--host" || arguments[1] != "unix:///var/run/docker.sock" {
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("invalid endpoint")}, nil
	}
	switch arguments[2] {
	case "image":
		return r.imageInspect()
	case "volume":
		return r.volumeOperation(arguments)
	case "run":
		return r.helperRun(arguments)
	default:
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("unsupported")}, nil
	}
}

func (r *capacityLeaseRunner) imageInspect() (argvprocess.Result, error) {
	if r.imageMode == "missing" {
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("missing")}, nil
	}
	document := capacityImageDocument{
		Architecture: r.architecture, ID: "sha256:" + strings.Repeat("a", 64),
		OS: "linux", RepoDigests: []string{r.imageRef},
	}
	if r.imageMode == "foreign" {
		document.RepoDigests[0] = "registry.example/foreign@sha256:" + strings.Repeat("b", 64)
	}
	if r.imageMode == "windows" {
		document.OS = "windows"
	}
	encoded, _ := json.Marshal(document)
	if r.imageMode == "duplicate-json" {
		encoded = []byte(strings.Replace(string(encoded), `"Os":"linux"`, `"Os":"linux","Os":"linux"`, 1))
	}
	if r.imageMode == "unknown-json" {
		encoded = append(encoded[:len(encoded)-1], []byte(`,"Foreign":true}`)...)
	}
	return argvprocess.Result{StandardOutput: append(encoded, '\n')}, nil
}

func (r *capacityLeaseRunner) volumeOperation(arguments []string) (argvprocess.Result, error) {
	if len(arguments) < 4 {
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("bad volume command")}, nil
	}
	switch arguments[3] {
	case "ls":
		filter := arguments[len(arguments)-1]
		name := strings.TrimSuffix(strings.TrimPrefix(filter, "name=^"), "$")
		if _, exists := r.volumes[name]; !exists {
			return argvprocess.Result{}, nil
		}
		output := name + "\n"
		if r.duplicateVolumeList {
			output += name + "\n"
		}
		return argvprocess.Result{StandardOutput: []byte(output)}, nil
	case "create":
		name := arguments[len(arguments)-1]
		if arguments[len(arguments)-2] != "--name" {
			return argvprocess.Result{ExitCode: 1, StandardError: []byte("name")}, nil
		}
		if _, exists := r.volumes[name]; exists {
			return argvprocess.Result{ExitCode: 1, StandardError: []byte("exists")}, nil
		}
		labels := make(map[string]string)
		for index := 4; index < len(arguments)-2; index++ {
			if arguments[index] != "--label" {
				continue
			}
			key, value, found := strings.Cut(arguments[index+1], "=")
			if !found {
				return argvprocess.Result{ExitCode: 1, StandardError: []byte("label")}, nil
			}
			labels[key] = value
			index++
		}
		r.volumes[name] = &fakeCapacityVolume{labels: labels, options: make(map[string]string)}
		return argvprocess.Result{StandardOutput: []byte(name + "\n")}, nil
	case "inspect":
		name := arguments[len(arguments)-1]
		volume, exists := r.volumes[name]
		if !exists {
			return argvprocess.Result{ExitCode: 1, StandardError: []byte("missing")}, nil
		}
		encoded, _ := json.Marshal(capacityVolumeDocument{
			Driver: "local", Labels: cloneCapacityLabels(volume.labels), Name: name,
			Options: cloneCapacityLabels(volume.options), Scope: "local",
		})
		return argvprocess.Result{StandardOutput: append(encoded, '\n')}, nil
	case "rm":
		name := arguments[len(arguments)-1]
		if _, exists := r.volumes[name]; !exists {
			return argvprocess.Result{ExitCode: 1, StandardError: []byte("missing")}, nil
		}
		delete(r.volumes, name)
		return argvprocess.Result{StandardOutput: []byte(name + "\n")}, nil
	default:
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("unknown volume operation")}, nil
	}
}

func (r *capacityLeaseRunner) helperRun(arguments []string) (argvprocess.Result, error) {
	if r.failHelper > 0 {
		r.failHelper--
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("capacity failed")}, nil
	}
	imageIndex := -1
	for index, argument := range arguments {
		if argument == r.imageRef {
			imageIndex = index
			break
		}
	}
	if imageIndex < 0 || imageIndex+1 >= len(arguments) {
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("image")}, nil
	}
	request, err := capacityhelper.ParseArguments(arguments[imageIndex+1:])
	if err != nil {
		return argvprocess.Result{}, errors.New("parse capacity request")
	}
	volumeName := ""
	for index, argument := range arguments {
		if argument == "--mount" && index+1 < len(arguments) {
			for _, field := range strings.Split(arguments[index+1], ",") {
				if strings.HasPrefix(field, "source=") {
					volumeName = strings.TrimPrefix(field, "source=")
				}
			}
		}
	}
	volume := r.volumes[volumeName]
	if volume == nil || volume.malformedMetadata {
		return argvprocess.Result{ExitCode: 1, StandardError: []byte("metadata")}, nil
	}
	owner, responseState := request.Owner(), "reserved"
	metadataState := capacityhelper.MetadataReserved
	switch request.Operation() {
	case capacityhelper.OperationReserve:
		metadataState = capacityhelper.MetadataReserved
	case capacityhelper.OperationInspect:
		if volume.metadata.SchemaVersion == 0 {
			return argvprocess.Result{ExitCode: 1, StandardError: []byte("missing metadata")}, nil
		}
		metadataState = capacityhelper.MetadataState(volume.metadata.State)
		owner = volume.metadata.Owner
	case capacityhelper.OperationTransfer:
		metadataState, owner, responseState = capacityhelper.MetadataTransferred, request.NewOwner(), "transferred"
	case capacityhelper.OperationActivateProjection:
		if volume.metadata.SchemaVersion != 0 &&
			(volume.metadata.State != string(capacityhelper.MetadataReserved) || volume.metadata.Owner != request.Owner()) {
			return argvprocess.Result{ExitCode: 1, StandardError: []byte("projection metadata")}, nil
		}
		metadataState, owner, responseState = capacityhelper.MetadataTransferred, request.NewOwner(), "projection-ready"
	case capacityhelper.OperationDeleteProof:
		responseState = "delete-approved"
		if volume.metadata.SchemaVersion == 0 {
			metadataState = capacityhelper.MetadataReservePending
		} else {
			metadataState = capacityhelper.MetadataState(volume.metadata.State)
			owner = volume.metadata.Owner
		}
	}
	metadata, err := capacityhelper.NewMetadata(request, owner, metadataState)
	if err != nil {
		return argvprocess.Result{}, errors.New("construct capacity metadata")
	}
	if request.Operation() != capacityhelper.OperationDeleteProof &&
		request.Operation() != capacityhelper.OperationActivateProjection {
		volume.metadata = metadata
	} else if request.Operation() == capacityhelper.OperationActivateProjection {
		volume.metadata = capacityhelper.Metadata{}
	}
	metadataDigest, _ := capacityhelper.MetadataDigest(metadata)
	fileSize, allocated := request.Bytes(), request.Bytes()
	if metadataState == capacityhelper.MetadataReservePending {
		fileSize, allocated = 0, 0
	}
	present := true
	if request.Operation() == capacityhelper.OperationActivateProjection {
		fileSize, allocated, present = 0, 0, false
	}
	receiptToken := request.ReceiptToken()
	if r.tamperHelperReceipt {
		receiptToken = "r-" + strings.Repeat("f", 64)
	}
	line, err := capacityhelper.CanonicalResponseLine(capacityhelper.Response{
		AllocatedBlockBytes: allocated, AvailableBytes: 1 << 30, Bytes: request.Bytes(),
		FileSizeBytes: fileSize, LeaseID: request.LeaseID(), MetadataDigest: metadataDigest,
		Operation: string(request.Operation()), Owner: owner, PlanDigest: request.PlanDigest(),
		PoolID: request.PoolID(), PoolKind: request.PoolKind(), Present: present,
		ReceiptToken: receiptToken, SchemaVersion: capacityhelper.ProtocolVersion, State: responseState,
	})
	if err != nil {
		return argvprocess.Result{}, errors.New("construct capacity response")
	}
	return argvprocess.Result{StandardOutput: line}, nil
}

func newCapacityLeaseAdapter(
	t *testing.T,
	runner *capacityLeaseRunner,
	purpose artifactacquisition.LeasePurpose,
) (*CapacityLeases, artifactacquisition.CapacityLease) {
	t.Helper()
	executors := testExecutorsForDocker(t, runner)
	helper := capacityHelperAuthorityForTest(capacityHelperResource(t, executors))
	runner.imageRef = helper.sourceRef
	endpoint, err := containerengine.NewEndpoint("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := artifactacquisition.NewStoragePool("d-"+strings.Repeat("d", 64), artifactapp.CapacityDockerEngine)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := releaseinventory.Digest(executors.dockerAuthority.ReleaseManifestDigest())
	adapter, err := newCapacityLeases(executors, endpoint, helper, manifestDigest, pool)
	if err != nil {
		t.Fatal(err)
	}
	artifactID := ""
	sourceDigest := releaseinventory.Digest{}
	sourceBytes := uint64(0)
	expectedTarget := releaseinventory.Digest{}
	if purpose == artifactacquisition.LeaseExpanded {
		artifactID = "core"
		sourceDigest, sourceBytes = releaseinventory.DigestBytes([]byte("source")), 4096
		expectedTarget = releaseinventory.DigestBytes([]byte("expanded"))
	}
	var lease artifactacquisition.CapacityLease
	switch purpose {
	case artifactacquisition.LeaseExpanded:
		expectedTarget = sourceDigest
		lease, err = artifactacquisition.NewExpandedCapacityLease(
			"install-capacity", "install-capacity", artifactID, pool, 4096,
			releaseinventory.DigestBytes([]byte("capacity-plan")), sourceDigest, sourceBytes, expectedTarget,
			artifactacquisition.ExpandedLeaseTarget{
				Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml",
				AuthorityDigest: mustExpandedAuthorityDigest(t, sourceDigest, sourceBytes), Root: "/releases/release-1",
			},
		)
	case artifactacquisition.LeaseSecretProjection:
		lease, err = artifactacquisition.NewSecretProjectionCapacityLease(
			"install-capacity", "install-capacity",
			"agentmemory_019f5f2012347abc81230123456789ab_protected-core_019f5f2156787def9123abcdef012345",
			"protected-core", pool, 4096, releaseinventory.DigestBytes([]byte("capacity-plan")),
			artifactacquisition.SecretProjectionLeaseAuthority{
				InstallationID: "019f5f20-1234-7abc-8123-0123456789ab",
				ReleaseID:      "agentmemory-1.0.0", GenerationID: "019f5f21-5678-7def-9123-abcdef012345",
			},
		)
	case artifactacquisition.LeaseRollback, artifactacquisition.LeaseSafety:
		lease, err = artifactacquisition.NewCapacityLease(
			"install-capacity", purpose, "install-capacity", artifactID, pool, 4096,
			releaseinventory.DigestBytes([]byte("capacity-plan")), sourceDigest, sourceBytes, expectedTarget,
		)
	default:
		t.Fatalf("unsupported lease purpose %q", purpose)
	}
	if err != nil {
		t.Fatal(err)
	}
	return adapter, lease
}

func mustExpandedAuthorityDigest(t *testing.T, digest releaseinventory.Digest, bytes uint64) releaseinventory.Digest {
	t.Helper()
	target, err := releaseinventory.NewReleaseExpandedTarget(digest, bytes, releaseinventory.ReleaseExpandedTargetInput{
		Kind: releaseinventory.ExpandedTargetComposeBundle, StorageID: "compose/compose.yaml", Digest: digest, Bytes: bytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return target.AuthorityDigest()
}

func capacityHelperResource(t *testing.T, executors Executors) releaseinventory.Resource {
	t.Helper()
	digest := releaseinventory.DigestBytes([]byte("capacity-helper-image"))
	indexDigest := releaseinventory.DigestBytes([]byte("capacity-helper-index"))
	platform, err := releaseinventory.NewPlatform("linux", executors.dockerAuthority.Architecture())
	if err != nil {
		t.Fatal(err)
	}
	reference := "registry.example/agentmemory/capacity-helper@sha256:" + digest.Hex()
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: CapacityHelperResourceID, Kind: releaseinventory.ResourceKindOCIImage,
		Purpose:   releaseinventory.ResourcePurposeOCIPlatformManifest,
		MediaType: releaseinventory.MediaTypeOCIManifest, Platform: platform, Digest: digest,
		OCIIndexDigest: indexDigest, OCIIndexResourceID: "capacity-helper-index", Size: 1,
		SourceRef: reference, SourceAllowlist: []string{reference},
		CycloneDXSBOMResourceID: "capacity-helper-cyclonedx", SPDXSBOMResourceID: "capacity-helper-spdx",
		ProvenanceResourceID: "capacity-helper-provenance", LicenseResourceID: "capacity-helper-license",
		VulnerabilityResourceID: "capacity-helper-vulnerability",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func capacityHelperAuthorityForTest(resource releaseinventory.Resource) capacityHelperAuthority {
	return capacityHelperAuthority{
		id: resource.ID(), kind: resource.Kind(), purpose: resource.Purpose(), platform: resource.Platform(),
		digest: resource.Digest(), sourceRef: resource.SourceRef(),
	}
}

func assertHardenedCapacityRun(t *testing.T, invocations []argvprocess.Invocation) {
	t.Helper()
	var run []string
	for _, invocation := range invocations {
		arguments := invocation.Arguments()
		if len(arguments) > 2 && arguments[2] == "run" {
			run = arguments
			break
		}
	}
	if len(run) == 0 {
		t.Fatal("missing Docker helper run")
	}
	for _, pair := range [][2]string{
		{"--network", "none"}, {"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"},
		{"--pids-limit", capacityHelperPIDs}, {"--memory", capacityHelperMemory}, {"--cpus", capacityHelperCPUs},
		{"--entrypoint", capacityhelper.Entrypoint}, {"--pull", "never"},
	} {
		if !hasAdjacentArguments(run, pair[0], pair[1]) {
			t.Fatalf("missing hardened pair %q %q in %v", pair[0], pair[1], run)
		}
	}
	if countArgument(run, "--mount") != 1 || countArgument(run, "--read-only") != 1 ||
		countArgument(run, "--rm") != 1 || countArgument(run, "--env") != 0 ||
		containsArgument(run, "sh") || containsArgument(run, "-c") {
		t.Fatalf("unsafe helper invocation=%v", run)
	}
	mount := argumentAfter(run, "--mount")
	if !strings.HasPrefix(mount, "type=volume,source="+capacityVolumePrefix) ||
		!strings.HasSuffix(mount, ",target=/capacity,volume-nocopy") || strings.Contains(mount, "bind") ||
		strings.Contains(mount, "docker.sock") {
		t.Fatalf("unsafe capacity mount=%q", mount)
	}
}

func onlyCapacityVolume(t *testing.T, runner *capacityLeaseRunner) *fakeCapacityVolume {
	t.Helper()
	if len(runner.volumes) != 1 {
		t.Fatalf("volumes=%d", len(runner.volumes))
	}
	for _, volume := range runner.volumes {
		return volume
	}
	return nil
}

func adapterLabels(t *testing.T, adapter *CapacityLeases, lease artifactacquisition.CapacityLease) map[string]string {
	t.Helper()
	_, _, labels, err := adapter.requestForLease(capacityhelper.OperationReserve, lease, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return labels
}

func cloneCapacityLabels(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func hasAdjacentArguments(arguments []string, left, right string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == left && arguments[index+1] == right {
			return true
		}
	}
	return false
}

func countArgument(arguments []string, expected string) int {
	count := 0
	for _, argument := range arguments {
		if argument == expected {
			count++
		}
	}
	return count
}

func containsArgument(arguments []string, expected string) bool {
	return countArgument(arguments, expected) != 0
}

func argumentAfter(arguments []string, expected string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == expected {
			return arguments[index+1]
		}
	}
	return ""
}

func TestPF001CapacityLeaseVolumeLabelsAreDeterministicAndSorted(t *testing.T) {
	t.Parallel()
	runner := newCapacityLeaseRunner(t)
	adapter, lease := newCapacityLeaseAdapter(t, runner, artifactacquisition.LeaseRollback)
	request, name, labels, err := adapter.requestForLease(capacityhelper.OperationReserve, lease, "", "", "")
	if err != nil || !strings.HasPrefix(name, capacityVolumePrefix) || len(labels) != 7 {
		t.Fatalf("projection=%+v,%q,%+v,%v", request, name, labels, err)
	}
	request2, name2, labels2, _ := adapter.requestForLease(capacityhelper.OperationReserve, lease, "", "", "")
	if request2 != request || name2 != name || !reflect.DeepEqual(labels2, labels) {
		t.Fatal("capacity identity projection is not deterministic")
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !sort.StringsAreSorted(keys) {
		t.Fatal("test precondition failed")
	}
}
