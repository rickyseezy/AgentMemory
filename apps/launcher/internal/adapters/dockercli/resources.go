package dockercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/resourceinventory"
)

const (
	volumeInspectTemplate  = `{"Name":{{json .Name}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},"Labels":{{json .Labels}},"Options":{{json .Options}}}`
	networkInspectTemplate = `{"Name":{{json .Name}},"ID":{{json .ID}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},"Internal":{{json .Internal}},"Attachable":{{json .Attachable}},"Ingress":{{json .Ingress}},"ConfigOnly":{{json .ConfigOnly}},"Labels":{{json .Labels}},"Options":{{json .Options}}}`
)

// ManagedResources implements only the exact PF-001 network/volume commands.
// Every invocation addresses the selected local endpoint through argv.
type ManagedResources struct {
	executors Executors
}

// NewManagedResources constructs the constrained Docker resource adapter.
func NewManagedResources(executors Executors) (*ManagedResources, error) {
	if !executors.valid() {
		return nil, containerengine.ErrManagedResourceOperation
	}
	return &ManagedResources{executors: executors}, nil
}

// Inspect proves exact-name existence through a successful bounded list, then
// strictly decodes the baseline and compares every expected identity field.
func (m *ManagedResources) Inspect(
	ctx context.Context,
	endpoint containerengine.Endpoint,
	spec resourceinventory.Spec,
) (resourceinventory.Observed, error) {
	observed, err := m.inspectNamed(ctx, endpoint, spec.Kind(), spec.Name())
	if err != nil {
		return resourceinventory.Observed{}, err
	}
	if observed.Kind() != spec.Kind() || observed.Name() != spec.Name() || !sameLabels(observed.Labels(), spec.Labels()) {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceCollision
	}
	return observed, nil
}

// Create performs a second exact-name absence check, creates one closed-policy
// object, and immediately inspects its object ID, labels, driver, and scope.
func (m *ManagedResources) Create(
	ctx context.Context,
	endpoint containerengine.Endpoint,
	spec resourceinventory.Spec,
) (resourceinventory.Observed, error) {
	if endpoint.String() == "" || spec.Name() == "" || len(spec.Labels()) != 5 {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	_, inspectError := m.inspectNamed(ctx, endpoint, spec.Kind(), spec.Name())
	if inspectError == nil {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceCollision
	}
	if !errors.Is(inspectError, containerengine.ErrManagedResourceNotFound) {
		return resourceinventory.Observed{}, inspectError
	}

	arguments := []string{"--host", endpoint.String()}
	switch spec.Kind() {
	case resourceinventory.KindVolume:
		arguments = append(arguments, "volume", "create", "--driver", "local")
	case resourceinventory.KindNetwork:
		arguments = append(arguments, "network", "create", "--driver", "bridge", "--internal")
	case resourceinventory.KindUnknown:
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	default:
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	labels := spec.Labels()
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		arguments = append(arguments, "--label", key+"="+labels[key])
	}
	if spec.Kind() == resourceinventory.KindVolume {
		arguments = append(arguments, "--name", spec.Name())
	} else {
		arguments = append(arguments, spec.Name())
	}
	result, err := m.run(ctx, arguments)
	if err != nil {
		return resourceinventory.Observed{}, err
	}
	creationIdentity := strings.TrimSpace(string(result.StandardOutput))
	if (spec.Kind() == resourceinventory.KindVolume && creationIdentity != spec.Name()) ||
		(spec.Kind() == resourceinventory.KindNetwork && !lowerHexResourceID(creationIdentity)) {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	observed, err := m.Inspect(ctx, endpoint, spec)
	if err != nil {
		return resourceinventory.Observed{}, err
	}
	if spec.Kind() == resourceinventory.KindNetwork && observed.ObjectID() != creationIdentity {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceCollision
	}
	return observed, nil
}

// Remove re-inspects the exact ID and five labels represented by the
// inventory-minted token before using non-force removal and confirming absence.
func (m *ManagedResources) Remove(
	ctx context.Context,
	endpoint containerengine.Endpoint,
	authorization resourceinventory.RemovalAuthorization,
) error {
	if !authorization.Valid() || endpoint.String() == "" {
		return containerengine.ErrManagedResourceCollision
	}
	observed, err := m.inspectNamed(ctx, endpoint, authorization.Kind(), authorization.Name())
	if err != nil {
		return err
	}
	if observed.ObjectID() != authorization.ObjectID() || !sameLabels(observed.Labels(), authorization.Labels()) {
		return containerengine.ErrManagedResourceCollision
	}
	var arguments []string
	switch authorization.Kind() {
	case resourceinventory.KindVolume:
		arguments = []string{"--host", endpoint.String(), "volume", "rm", "--", authorization.Name()}
	case resourceinventory.KindNetwork:
		arguments = []string{"--host", endpoint.String(), "network", "rm", "--", authorization.Name()}
	case resourceinventory.KindUnknown:
		return containerengine.ErrManagedResourceCollision
	default:
		return containerengine.ErrManagedResourceCollision
	}
	if _, err := m.run(ctx, arguments); err != nil {
		return err
	}
	_, err = m.inspectNamed(ctx, endpoint, authorization.Kind(), authorization.Name())
	if !errors.Is(err, containerengine.ErrManagedResourceNotFound) {
		if err == nil {
			return containerengine.ErrManagedResourceCollision
		}
		return err
	}
	return nil
}

func (m *ManagedResources) inspectNamed(
	ctx context.Context,
	endpoint containerengine.Endpoint,
	kind resourceinventory.Kind,
	name string,
) (resourceinventory.Observed, error) {
	if endpoint.String() == "" || !safeManagedName(name) {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	resource, template := "", ""
	switch kind {
	case resourceinventory.KindVolume:
		resource, template = "volume", volumeInspectTemplate
	case resourceinventory.KindNetwork:
		resource, template = "network", networkInspectTemplate
	case resourceinventory.KindUnknown:
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	default:
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	listResult, err := m.run(ctx, []string{
		"--host", endpoint.String(), resource, "ls", "--format", "{{.Name}}", "--filter", "name=^" + name + "$",
	})
	if err != nil {
		return resourceinventory.Observed{}, err
	}
	listed := strings.Fields(string(listResult.StandardOutput))
	if len(listed) == 0 {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceNotFound
	}
	if len(listed) != 1 || listed[0] != name {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	inspectResult, err := m.run(ctx, []string{
		"--host", endpoint.String(), resource, "inspect", "--format", template, "--", name,
	})
	if err != nil {
		return resourceinventory.Observed{}, err
	}
	if err := rejectDuplicateJSONKeys(inspectResult.StandardOutput); err != nil {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	if kind == resourceinventory.KindVolume {
		if !hasExactJSONFields(inspectResult.StandardOutput, "Name", "Driver", "Scope", "Labels", "Options") {
			return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
		}
		var document volumeResourceDocument
		if err := decodeStrictJSON(inspectResult.StandardOutput, &document); err != nil {
			return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
		}
		if document.Name != name || document.Driver != "local" || document.Scope != "local" || len(document.Options) != 0 {
			return resourceinventory.Observed{}, containerengine.ErrManagedResourceCollision
		}
		observed, observedError := resourceinventory.NewObserved(kind, document.Name, document.Name, document.Labels)
		if observedError != nil {
			return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
		}
		return observed, nil
	}
	if !hasExactJSONFields(
		inspectResult.StandardOutput,
		"Name", "ID", "Driver", "Scope", "Internal", "Attachable", "Ingress", "ConfigOnly", "Labels", "Options",
	) {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	var document networkResourceDocument
	if err := decodeStrictJSON(inspectResult.StandardOutput, &document); err != nil {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	if document.Name != name || document.Driver != "bridge" || document.Scope != "local" || !document.Internal ||
		document.Attachable || document.Ingress || document.ConfigOnly || len(document.Options) != 0 {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceCollision
	}
	observed, observedError := resourceinventory.NewObserved(kind, document.Name, document.ID, document.Labels)
	if observedError != nil {
		return resourceinventory.Observed{}, containerengine.ErrManagedResourceResponse
	}
	return observed, nil
}

func (m *ManagedResources) run(ctx context.Context, arguments []string) (argvprocess.Result, error) {
	if ctx == nil {
		return argvprocess.Result{}, errors.Join(containerengine.ErrManagedResourceOperation, context.Canceled)
	}
	runner, executable, err := m.executors.dockerBinding()
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrManagedResourceOperation
	}
	invocation, err := argvprocess.NewInvocation(executable, arguments)
	if err != nil {
		return argvprocess.Result{}, containerengine.ErrManagedResourceOperation
	}
	result, err := runner.Run(ctx, invocation)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return argvprocess.Result{}, errors.Join(containerengine.ErrManagedResourceOperation, err)
		}
		return argvprocess.Result{}, containerengine.ErrManagedResourceOperation
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) > maximumDockerJSON ||
		len(result.StandardError) > maximumDockerJSON {
		return argvprocess.Result{}, containerengine.ErrManagedResourceOperation
	}
	return result, nil
}

type volumeResourceDocument struct {
	Name    string            `json:"Name"`
	Driver  string            `json:"Driver"`
	Scope   string            `json:"Scope"`
	Labels  map[string]string `json:"Labels"`
	Options map[string]string `json:"Options"`
}

type networkResourceDocument struct {
	Name       string            `json:"Name"`
	ID         string            `json:"ID"`
	Driver     string            `json:"Driver"`
	Scope      string            `json:"Scope"`
	Internal   bool              `json:"Internal"`
	Attachable bool              `json:"Attachable"`
	Ingress    bool              `json:"Ingress"`
	ConfigOnly bool              `json:"ConfigOnly"`
	Labels     map[string]string `json:"Labels"`
	Options    map[string]string `json:"Options"`
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	state := jsonBoundState{}
	if err := consumeUniqueJSONValue(decoder, 0, &state); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("trailing JSON value")
	}
	return nil
}

const (
	maximumJSONDepth       = 32
	maximumJSONValues      = 65536
	maximumJSONObjectKey   = 256
	maximumJSONStringValue = 65536
)

type jsonBoundState struct {
	values uint32
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth uint32, state *jsonBoundState) error {
	if depth > maximumJSONDepth || state.values >= maximumJSONValues {
		return errors.New("JSON structural bound exceeded")
	}
	state.values++
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if value, ok := token.(string); ok && len(value) > maximumJSONStringValue {
			return errors.New("JSON string bound exceeded")
		}
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			if keyError != nil {
				return keyError
			}
			key, ok := keyToken.(string)
			if !ok || len(key) == 0 || len(key) > maximumJSONObjectKey {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, depth+1, state); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid object closing token")
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, depth+1, state); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid array closing token")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func sameLabels(left map[string]string, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func hasExactJSONFields(data []byte, fields ...string) bool {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil || len(document) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := document[field]; !exists {
			return false
		}
	}
	return true
}

func safeManagedName(value string) bool {
	if value == "" || len(value) > 255 || !strings.HasPrefix(value, "agentmemory_") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func lowerHexResourceID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

var _ containerengine.ManagedResourcePort = (*ManagedResources)(nil)
