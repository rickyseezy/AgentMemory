// Package dockercli implements explicitly addressed argv-only Docker adapters.
package dockercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
)

const maximumDockerJSON = 1024 * 1024

// Probe uses the exact verified Docker executable and never reads or changes
// the user's global Docker context.
type Probe struct {
	executors Executors
}

// NewProbe constructs a read-only Engine/Compose capability adapter.
func NewProbe(executors Executors) (*Probe, error) {
	if !executors.valid() {
		return nil, errInvalidExecutors
	}
	return &Probe{executors: executors}, nil
}

// Probe addresses every command with --host and parses only documented,
// explicitly formatted fields.
func (p *Probe) Probe(ctx context.Context, endpoint containerengine.Endpoint) (containerengine.ProbeResult, error) {
	versionTemplate := `{"ClientVersion":{{json .Client.Version}},"ServerVersion":{{json .Server.Version}},"APIVersion":{{json .Server.APIVersion}}}`
	versionBytes, err := p.runDockerBounded(ctx, endpoint, []string{"version", "--format", versionTemplate})
	if err != nil {
		return containerengine.ProbeResult{}, fmt.Errorf("probe Docker Engine version: %w", err)
	}
	infoTemplate := `{"OperatingSystem":{{json .OperatingSystem}},"Architecture":{{json .Architecture}},"OSType":{{json .OSType}},"SecurityOptions":{{json .SecurityOptions}},"NCPU":{{json .NCPU}},"MemTotal":{{json .MemTotal}}}`
	infoBytes, err := p.runDockerBounded(ctx, endpoint, []string{"info", "--format", infoTemplate})
	if err != nil {
		return containerengine.ProbeResult{}, fmt.Errorf("probe Docker Engine info: %w", err)
	}
	composeBytes, err := p.runComposeBounded(ctx, endpoint, []string{"version", "--short"})
	if err != nil {
		return containerengine.ProbeResult{}, fmt.Errorf("probe Docker Compose version: %w", err)
	}

	var version versionDocument
	if err := decodeStrictJSON(versionBytes, &version); err != nil {
		return containerengine.ProbeResult{}, fmt.Errorf("decode Docker Engine version: %w", err)
	}
	var info infoDocument
	if err := decodeStrictJSON(infoBytes, &info); err != nil {
		return containerengine.ProbeResult{}, fmt.Errorf("decode Docker Engine info: %w", err)
	}
	composeVersion := strings.TrimSpace(string(composeBytes))
	architecture := normalizeDockerArchitecture(info.Architecture)
	if version.ClientVersion == "" || version.ServerVersion == "" || version.APIVersion == "" ||
		!validVersionString(composeVersion) ||
		info.OSType != "linux" || architecture == "" ||
		info.NCPU <= 0 || info.MemTotal <= 0 {
		return containerengine.ProbeResult{}, errors.New("docker capability response is incomplete or not Linux-container mode")
	}
	return containerengine.ProbeResult{
		ClientVersion:   version.ClientVersion,
		ServerVersion:   version.ServerVersion,
		APIVersion:      version.APIVersion,
		ComposeVersion:  composeVersion,
		OperatingSystem: info.OperatingSystem,
		Architecture:    architecture,
		OSType:          info.OSType,
		SecurityOptions: append([]string(nil), info.SecurityOptions...),
		CPUs:            info.NCPU,
		MemoryBytes:     info.MemTotal,
	}, nil
}

func validVersionString(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '-' || character == '+' {
			continue
		}
		return false
	}
	return true
}

func (p *Probe) runDockerBounded(ctx context.Context, endpoint containerengine.Endpoint, operation []string) ([]byte, error) {
	runner, executable, err := p.executors.dockerBinding()
	if err != nil {
		return nil, err
	}
	return runBounded(ctx, runner, executable, endpoint, operation)
}

func (p *Probe) runComposeBounded(ctx context.Context, endpoint containerengine.Endpoint, operation []string) ([]byte, error) {
	runner, executable, err := p.executors.composeBinding()
	if err != nil {
		return nil, err
	}
	return runBounded(ctx, runner, executable, endpoint, operation)
}

func runBounded(
	ctx context.Context,
	runner argvprocess.Runner,
	executable string,
	endpoint containerengine.Endpoint,
	operation []string,
) ([]byte, error) {
	if endpoint.String() == "" {
		return nil, containerengine.ErrInvalidEndpoint
	}
	arguments := make([]string, 0, 2+len(operation))
	arguments = append(arguments, "--host", endpoint.String())
	arguments = append(arguments, operation...)
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		return nil, err
	}
	result, err := runner.Run(ctx, invocation)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) == 0 ||
		len(result.StandardOutput) > maximumDockerJSON {
		return nil, errors.New("docker capability command returned an invalid bounded result")
	}
	return append([]byte(nil), result.StandardOutput...), nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing Docker JSON data is not allowed")
	}
	return nil
}

type versionDocument struct {
	ClientVersion string `json:"ClientVersion"`
	ServerVersion string `json:"ServerVersion"`
	APIVersion    string `json:"APIVersion"`
}

type infoDocument struct {
	OperatingSystem string   `json:"OperatingSystem"`
	Architecture    string   `json:"Architecture"`
	OSType          string   `json:"OSType"`
	SecurityOptions []string `json:"SecurityOptions"`
	NCPU            int      `json:"NCPU"`
	MemTotal        int64    `json:"MemTotal"`
}
