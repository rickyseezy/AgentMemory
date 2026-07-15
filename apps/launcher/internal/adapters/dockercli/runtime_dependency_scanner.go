package dockercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

const maximumRuntimeInventoryRecords = 100_000

// ActiveClientObservation is a native, stable count of processes currently
// connected to the exact local socket or named pipe.
type ActiveClientObservation struct {
	Count          uint64
	EvidenceDigest runtimeinstall.Hash
}

// ActiveRuntimeClientScanner supplies the platform-native seventh category;
// Docker CLI inventory alone cannot prove connected clients are absent.
type ActiveRuntimeClientScanner interface {
	ScanActiveRuntimeClients(context.Context, containerengine.Endpoint) (ActiveClientObservation, error)
}

// RuntimeDependencyScanner performs the exhaustive fixed-command removal scan.
type RuntimeDependencyScanner struct {
	executors     Executors
	activeClients ActiveRuntimeClientScanner
}

var _ runtimeremovalapp.DependencyScanner = (*RuntimeDependencyScanner)(nil)

// NewRuntimeDependencyScanner binds signed Docker/Compose executors and a
// platform-native active-client observer.
func NewRuntimeDependencyScanner(
	executors Executors,
	activeClients ActiveRuntimeClientScanner,
) (*RuntimeDependencyScanner, error) {
	if !executors.valid() || nilInterface(activeClients) {
		return nil, errors.New("runtime dependency scanner authority is incomplete")
	}
	return &RuntimeDependencyScanner{executors: executors, activeClients: activeClients}, nil
}

// ScanRuntimeDependencies fails closed unless all seven exact categories can
// be bounded, parsed, canonicalized, and bound to the finalized ownership record.
func (s *RuntimeDependencyScanner) ScanRuntimeDependencies(
	ctx context.Context,
	request runtimeremovalapp.ScanRequest,
) (runtimeremoval.DependencyScan, error) {
	endpoint, err := containerengine.NewEndpoint(request.Endpoint)
	if err != nil || request.Ownership.Endpoint() != request.Endpoint ||
		request.Ownership.Status() != runtimeinstall.OwnershipStatusFinalized ||
		request.Ownership.Disposition() != runtimeinstall.OwnershipProvisionedByAgentMemory ||
		request.Ownership.Digest().IsZero() {
		return runtimeremoval.DependencyScan{}, runtimeremovalapp.ErrScanUncertain
	}
	queries := []inventoryQuery{
		{kind: runtimeremoval.DependencyContainers, args: []string{"container", "ls", "--all", "--no-trunc", "--format", "json"}},
		{kind: runtimeremoval.DependencyImages, args: []string{"image", "ls", "--all", "--no-trunc", "--digests", "--format", "json"}},
		{kind: runtimeremoval.DependencyVolumes, args: []string{"volume", "ls", "--format", "json"}},
		{kind: runtimeremoval.DependencyNetworks, args: []string{"network", "ls", "--no-trunc", "--format", "json"}, filter: networkDependsOnRuntime},
		{kind: runtimeremoval.DependencyContexts, args: []string{"context", "ls", "--format", "json"}, filter: contextDependsOnEndpoint(endpoint.String())},
	}
	proofs := make([]runtimeremoval.DependencyProofInput, 0, len(runtimeremoval.OrderedDependencyKinds()))
	for _, query := range queries {
		output, runError := s.runDockerInventory(ctx, endpoint, query.args)
		if runError != nil {
			return runtimeremoval.DependencyScan{}, runtimeremovalapp.ErrScanUncertain
		}
		count, evidence, parseError := inventoryEvidence(query.kind, output, query.filter)
		if parseError != nil {
			return runtimeremoval.DependencyScan{}, runtimeremovalapp.ErrScanUncertain
		}
		proofs = append(proofs, runtimeremoval.DependencyProofInput{
			Kind: query.kind, Count: count, EvidenceDigest: evidence, Complete: true,
		})
	}
	composeOutput, err := s.runComposeInventory(ctx, endpoint, []string{"ls", "--all", "--format", "json"})
	if err != nil {
		return runtimeremoval.DependencyScan{}, runtimeremovalapp.ErrScanUncertain
	}
	composeCount, composeEvidence, err := inventoryEvidence(
		runtimeremoval.DependencyComposeProjects, composeOutput, nil,
	)
	if err != nil {
		return runtimeremoval.DependencyScan{}, runtimeremovalapp.ErrScanUncertain
	}
	proofs = append(proofs, runtimeremoval.DependencyProofInput{
		Kind: runtimeremoval.DependencyComposeProjects, Count: composeCount,
		EvidenceDigest: composeEvidence, Complete: true,
	})
	active, err := s.activeClients.ScanActiveRuntimeClients(ctx, endpoint)
	if err != nil || active.EvidenceDigest.IsZero() {
		return runtimeremoval.DependencyScan{}, runtimeremovalapp.ErrScanUncertain
	}
	proofs = append(proofs, runtimeremoval.DependencyProofInput{
		Kind: runtimeremoval.DependencyActiveClients, Count: active.Count,
		EvidenceDigest: active.EvidenceDigest, Complete: true,
	})
	return runtimeremoval.NewDependencyScan(runtimeremoval.DependencyScanInput{
		OwnershipRecordDigest: request.Ownership.Digest(), Endpoint: endpoint.String(), Proofs: proofs,
	})
}

type inventoryQuery struct {
	kind   runtimeremoval.DependencyKind
	args   []string
	filter func(map[string]json.RawMessage) (bool, error)
}

func (s *RuntimeDependencyScanner) runDockerInventory(
	ctx context.Context,
	endpoint containerengine.Endpoint,
	operation []string,
) ([]byte, error) {
	runner, executable, err := s.executors.dockerBinding()
	if err != nil {
		return nil, err
	}
	return runBoundedInventory(ctx, runner, executable, endpoint, operation)
}

func (s *RuntimeDependencyScanner) runComposeInventory(
	ctx context.Context,
	endpoint containerengine.Endpoint,
	operation []string,
) ([]byte, error) {
	runner, executable, err := s.executors.composeBinding()
	if err != nil {
		return nil, err
	}
	return runBoundedInventory(ctx, runner, executable, endpoint, operation)
}

func runBoundedInventory(
	ctx context.Context,
	runner argvprocess.Runner,
	executable string,
	endpoint containerengine.Endpoint,
	operation []string,
) ([]byte, error) {
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
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumDockerJSON {
		return nil, errors.New("runtime inventory command returned an invalid bounded result")
	}
	return append([]byte(nil), result.StandardOutput...), nil
}

func inventoryEvidence(
	kind runtimeremoval.DependencyKind,
	output []byte,
	filter func(map[string]json.RawMessage) (bool, error),
) (uint64, runtimeinstall.Hash, error) {
	records, err := decodeInventoryRecords(output)
	if err != nil {
		return 0, runtimeinstall.Hash{}, err
	}
	canonical := make([]string, 0, len(records))
	for _, record := range records {
		included := true
		if filter != nil {
			included, err = filter(record)
			if err != nil {
				return 0, runtimeinstall.Hash{}, err
			}
		}
		if !included {
			continue
		}
		encoded, marshalError := json.Marshal(record)
		if marshalError != nil {
			return 0, runtimeinstall.Hash{}, marshalError
		}
		canonical = append(canonical, string(encoded))
	}
	sort.Strings(canonical)
	evidence := sha256.Sum256([]byte(kind.String() + "\n" + strings.Join(canonical, "\n")))
	return uint64(len(canonical)), evidence, nil
}

func decodeInventoryRecords(output []byte) ([]map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return []map[string]json.RawMessage{}, nil
	}
	encodedRecords := make([]json.RawMessage, 0)
	if trimmed[0] == '[' {
		if rejectInventoryDuplicateKeys(trimmed) != nil {
			return nil, errors.New("runtime inventory JSON contains duplicate keys")
		}
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		if err := decoder.Decode(&encodedRecords); err != nil || requireInventoryJSONEnd(decoder) != nil {
			return nil, errors.New("runtime inventory array is invalid")
		}
	} else {
		for _, line := range bytes.Split(trimmed, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || rejectInventoryDuplicateKeys(line) != nil {
				return nil, errors.New("runtime inventory record is invalid")
			}
			encodedRecords = append(encodedRecords, bytes.Clone(line))
			if len(encodedRecords) > maximumRuntimeInventoryRecords {
				return nil, errors.New("runtime inventory record count exceeds its limit")
			}
		}
	}
	if len(encodedRecords) > maximumRuntimeInventoryRecords {
		return nil, errors.New("runtime inventory record count exceeds its limit")
	}
	records := make([]map[string]json.RawMessage, 0, len(encodedRecords))
	for _, encoded := range encodedRecords {
		var record map[string]json.RawMessage
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		if err := decoder.Decode(&record); err != nil || requireInventoryJSONEnd(decoder) != nil || record == nil {
			return nil, errors.New("runtime inventory item is not an object")
		}
		records = append(records, record)
	}
	return records, nil
}

func networkDependsOnRuntime(record map[string]json.RawMessage) (bool, error) {
	name, err := requiredInventoryString(record, "Name")
	if err != nil {
		return false, err
	}
	return !slices.Contains([]string{"bridge", "host", "none"}, name), nil
}

func contextDependsOnEndpoint(endpoint string) func(map[string]json.RawMessage) (bool, error) {
	return func(record map[string]json.RawMessage) (bool, error) {
		name, nameError := requiredInventoryString(record, "Name")
		dockerEndpoint, endpointError := requiredInventoryString(record, "DockerEndpoint")
		if nameError != nil || endpointError != nil {
			return false, errors.New("runtime context record is incomplete")
		}
		return name != "default" && dockerEndpoint == endpoint, nil
	}
}

func requiredInventoryString(record map[string]json.RawMessage, name string) (string, error) {
	encoded, ok := record[name]
	if !ok {
		return "", fmt.Errorf("runtime inventory field %s is missing", name)
	}
	var value string
	if err := json.Unmarshal(encoded, &value); err != nil || value == "" || len(value) > 4096 ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("runtime inventory field %s is invalid", name)
	}
	return value, nil
}

func rejectInventoryDuplicateKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := scanInventoryJSONValue(decoder); err != nil {
		return err
	}
	return requireInventoryJSONEnd(decoder)
}

func scanInventoryJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, delimited := token.(json.Delim)
	if !delimited {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			key, ok := keyToken.(string)
			if keyError != nil || !ok {
				return errors.New("runtime inventory object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("runtime inventory object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if valueError := scanInventoryJSONValue(decoder); valueError != nil {
				return valueError
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if valueError := scanInventoryJSONValue(decoder); valueError != nil {
				return valueError
			}
		}
		_, err = decoder.Token()
		return err
	case '}', ']':
		return errors.New("runtime inventory JSON starts with a closing delimiter")
	default:
		return errors.New("runtime inventory JSON delimiter is unsupported")
	}
}

func requireInventoryJSONEnd(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("runtime inventory JSON contains trailing data")
		}
		return err
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	default:
		return false
	}
}
