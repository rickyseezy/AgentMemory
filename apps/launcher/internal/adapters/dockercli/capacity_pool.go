package dockercli

import (
	"context"
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const capacityInfoTemplate = `{"ID":{{json .ID}},"DockerRootDir":{{json .DockerRootDir}},"Driver":{{json .Driver}},"DriverStatus":{{json .DriverStatus}},"OperatingSystem":{{json .OperatingSystem}},"OSType":{{json .OSType}},"Architecture":{{json .Architecture}},"Name":{{json .Name}},"ServerVersion":{{json .ServerVersion}}}`

// CapacityPoolProbe resolves a stable Docker allocation-pool identity through
// the exact release-bound CLI and explicitly local daemon endpoint. It does
// not claim that bytes have been reserved; the independent CapacityLeasePort
// must prove each physical allocation before this identity becomes useful.
type CapacityPoolProbe struct {
	executors Executors
}

// NewCapacityPoolProbe rejects a Docker executor that is not independently
// bound to the authenticated release and runtime plan.
func NewCapacityPoolProbe(executors Executors) (*CapacityPoolProbe, error) {
	if !executors.valid() {
		return nil, artifactapp.ErrReservationUnsupported
	}
	return &CapacityPoolProbe{executors: executors}, nil
}

// AttestDockerPool observes the local daemon storage identity without using
// the ambient Docker context. Engine and data-volume targets intentionally
// derive the same ID; the application rejects them if separate observations
// disagree.
func (p *CapacityPoolProbe) AttestDockerPool(
	ctx context.Context,
	target artifactapp.CapacityTarget,
) (artifactacquisition.StoragePool, error) {
	if ctx == nil {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationOperation
	}
	if err := ctx.Err(); err != nil {
		return artifactacquisition.StoragePool{}, errors.Join(artifactapp.ErrReservationOperation, err)
	}
	if target.Kind != artifactapp.CapacityDockerEngine && target.Kind != artifactapp.CapacityDockerDataVolume {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
	endpoint, err := containerengine.NewEndpoint(target.Locator)
	if err != nil {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}

	raw, err := p.observeCapacityInfo(ctx, endpoint)
	if err != nil {
		return artifactacquisition.StoragePool{}, err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
	var document capacityInfoDocument
	if err := decodeStrictJSON(raw, &document); err != nil {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
	storageProof, valid := document.storageProof()
	if !valid || !document.valid() {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}

	identity := strings.Join([]string{
		"agentmemory-docker-capacity-pool-v1",
		document.ID,
		document.DockerRootDir,
		document.Driver,
		storageProof,
		document.OSType,
		normalizeDockerArchitecture(document.Architecture),
	}, "\x00")
	poolID := "d-" + releaseinventory.DigestBytes([]byte(identity)).Hex()
	pool, err := artifactacquisition.NewStoragePool(poolID, target.Kind)
	if err != nil {
		return artifactacquisition.StoragePool{}, artifactapp.ErrReservationUnsupported
	}
	return pool, nil
}

func (p *CapacityPoolProbe) observeCapacityInfo(
	ctx context.Context,
	endpoint containerengine.Endpoint,
) ([]byte, error) {
	runner, executable, err := p.executors.dockerBinding()
	if err != nil {
		return nil, artifactapp.ErrReservationUnsupported
	}
	arguments := []string{"--host", endpoint.String(), "info", "--format", capacityInfoTemplate}
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		return nil, artifactapp.ErrReservationUnsupported
	}
	result, err := runner.Run(ctx, invocation)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.Join(artifactapp.ErrReservationOperation, err)
		}
		return nil, artifactapp.ErrReservationOperation
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) == 0 ||
		len(result.StandardOutput) > maximumDockerJSON || len(result.StandardError) > maximumDockerJSON {
		return nil, artifactapp.ErrReservationOperation
	}
	return append([]byte(nil), result.StandardOutput...), nil
}

type capacityInfoDocument struct {
	ID              string     `json:"ID"`
	DockerRootDir   string     `json:"DockerRootDir"`
	Driver          string     `json:"Driver"`
	DriverStatus    [][]string `json:"DriverStatus"`
	OperatingSystem string     `json:"OperatingSystem"`
	OSType          string     `json:"OSType"`
	Architecture    string     `json:"Architecture"`
	Name            string     `json:"Name"`
	ServerVersion   string     `json:"ServerVersion"`
}

func (d capacityInfoDocument) valid() bool {
	return validCapacityText(d.ID) && validCapacityRoot(d.DockerRootDir) &&
		(d.Driver == "overlay2" || d.Driver == "overlayfs") && d.OSType == "linux" &&
		normalizeDockerArchitecture(d.Architecture) != "" && validCapacityText(d.OperatingSystem) &&
		validCapacityText(d.Name) && validVersionString(d.ServerVersion)
}

func (d capacityInfoDocument) storageProof() (string, bool) {
	if len(d.DriverStatus) == 0 || len(d.DriverStatus) > 64 {
		return "", false
	}
	facts := make(map[string]string, len(d.DriverStatus))
	for _, fact := range d.DriverStatus {
		if len(fact) != 2 || !validCapacityText(fact[0]) || !validCapacityText(fact[1]) {
			return "", false
		}
		if _, duplicate := facts[fact[0]]; duplicate {
			return "", false
		}
		facts[fact[0]] = fact[1]
	}
	backing := facts["Backing Filesystem"]
	if (backing == "extfs" || backing == "xfs") && facts["Supports d_type"] == "true" {
		return "backing-" + backing, true
	}
	if len(facts) == 1 && facts["driver-type"] == "io.containerd.snapshotter.v1" &&
		d.OperatingSystem == "Docker Desktop" {
		return "docker-desktop-containerd", true
	}
	return "", false
}

func normalizeDockerArchitecture(value string) string {
	switch value {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return ""
	}
}

func validCapacityText(value string) bool {
	if value == "" || len(value) > 256 || value != strings.TrimSpace(value) ||
		strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func validCapacityRoot(path string) bool {
	if len(path) < 2 || len(path) > 4096 || !strings.HasPrefix(path, "/") ||
		strings.HasSuffix(path, "/") || strings.Contains(path, "//") ||
		path != strings.TrimSpace(path) || strings.ContainsAny(path, "\x00\r\n") {
		return false
	}
	for _, component := range strings.Split(path, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}
