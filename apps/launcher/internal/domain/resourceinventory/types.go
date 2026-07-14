// Package resourceinventory defines the authenticated ownership model for
// Docker resources managed by one AgentMemory installation.
package resourceinventory

import (
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
)

// Kind is the closed Docker resource type vocabulary used by PF-001.
type Kind uint8

const (
	// KindUnknown is the invalid zero value.
	KindUnknown Kind = iota
	// KindVolume identifies a local Docker named volume.
	KindVolume
	// KindNetwork identifies an internal Docker bridge network.
	KindNetwork
)

// String returns the persistence token for the resource kind.
func (k Kind) String() string {
	switch k {
	case KindVolume:
		return "volume"
	case KindNetwork:
		return "network"
	case KindUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// ParseKind parses the closed persistence token.
func ParseKind(value string) (Kind, error) {
	switch value {
	case "volume":
		return KindVolume, nil
	case "network":
		return KindNetwork, nil
	default:
		return KindUnknown, ErrInvalidResource
	}
}

// Purpose is the closed PF-001 managed-resource purpose vocabulary.
type Purpose string

const (
	// PurposeState stores canonical SQLite state for one generation.
	PurposeState Purpose = "state"
	// PurposeArtifacts stores encrypted CAS artifacts for one generation.
	PurposeArtifacts Purpose = "artifacts"
	// PurposeNeo4j stores the rebuildable Neo4j projection for one generation.
	PurposeNeo4j Purpose = "neo4j"
	// PurposeJournal stores installation audit and deletion journals.
	PurposeJournal Purpose = "journal"
	// PurposeModels stores verified local-provider artifacts.
	PurposeModels Purpose = "models"
	// PurposeTelemetry stores bounded local telemetry.
	PurposeTelemetry Purpose = "telemetry"
	// PurposeInternal identifies the default-deny internal bridge.
	PurposeInternal Purpose = "internal"
)

const stableGeneration = "stable"

var (
	// ErrInvalidResource means a value is outside the closed ADR-017 model.
	ErrInvalidResource = errors.New("invalid managed resource")
	// ErrInventoryIntegrity means authenticated inventory content contradicts
	// the closed ownership model and must not be used for mutation.
	ErrInventoryIntegrity = errors.New("managed resource inventory integrity violation")
	// ErrInventoryConflict means an operation contradicts an existing intent or
	// recorded ownership entry.
	ErrInventoryConflict = errors.New("managed resource inventory conflict")
	// ErrRemovalUnauthorized means no exact inventory-and-observation proof
	// authorizes a destructive Docker operation.
	ErrRemovalUnauthorized = errors.New("managed resource removal is not authorized")
)

// Spec is an immutable expected Docker resource and its exact five labels.
type Spec struct {
	kind    Kind
	purpose Purpose
	name    string
	labels  map[string]string
}

// BuildPlan derives the exact internal network and six required volumes. User,
// repository, project, and path text are not accepted as inputs.
func BuildPlan(installationID string, generationID string, release string) ([]Spec, error) {
	identity, err := composeplan.NewIdentity(installationID, generationID)
	if err != nil || !validRelease(release) {
		return nil, ErrInvalidResource
	}
	inputs := []struct {
		kind       Kind
		purpose    Purpose
		name       string
		generation string
	}{
		{KindNetwork, PurposeInternal, identity.NetworkName(string(PurposeInternal)), identity.Generation()},
		{KindVolume, PurposeState, identity.VolumeName(string(PurposeState)), identity.Generation()},
		{KindVolume, PurposeArtifacts, identity.VolumeName(string(PurposeArtifacts)), identity.Generation()},
		{KindVolume, PurposeNeo4j, identity.VolumeName(string(PurposeNeo4j)), identity.Generation()},
		{KindVolume, PurposeJournal, identity.StableVolumeName(string(PurposeJournal)), stableGeneration},
		{KindVolume, PurposeModels, identity.StableVolumeName(string(PurposeModels)), stableGeneration},
		{KindVolume, PurposeTelemetry, identity.StableVolumeName(string(PurposeTelemetry)), stableGeneration},
	}
	plan := make([]Spec, 0, len(inputs))
	for _, input := range inputs {
		plan = append(plan, Spec{
			kind:    input.kind,
			purpose: input.purpose,
			name:    input.name,
			labels: map[string]string{
				composeplan.LabelInstallation: identity.InstallationID(),
				composeplan.LabelRelease:      release,
				composeplan.LabelGeneration:   input.generation,
				composeplan.LabelPurpose:      string(input.purpose),
				composeplan.LabelManaged:      "true",
			},
		})
	}
	return plan, nil
}

// Kind returns the closed Docker resource kind.
func (s Spec) Kind() Kind { return s.kind }

// Purpose returns the closed resource purpose.
func (s Spec) Purpose() Purpose { return s.purpose }

// Name returns the UUID-derived physical Docker name.
func (s Spec) Name() string { return s.name }

// Labels returns an immutable-by-copy exact label set.
func (s Spec) Labels() map[string]string { return cloneLabels(s.labels) }

func (s Spec) validFor(installationID string) bool {
	if s.name == "" || s.labels[composeplan.LabelInstallation] != installationID ||
		len(s.labels) != 5 || s.labels[composeplan.LabelManaged] != "true" ||
		s.labels[composeplan.LabelPurpose] != string(s.purpose) || !validRelease(s.labels[composeplan.LabelRelease]) {
		return false
	}
	generation := s.labels[composeplan.LabelGeneration]
	if generation == stableGeneration {
		if s.kind != KindVolume || (s.purpose != PurposeJournal && s.purpose != PurposeModels && s.purpose != PurposeTelemetry) {
			return false
		}
		plans, err := BuildPlan(installationID, "00000000-0000-7000-8000-000000000000", s.labels[composeplan.LabelRelease])
		if err != nil {
			return false
		}
		for _, candidate := range plans {
			if candidate.purpose == s.purpose {
				return s.equal(candidate)
			}
		}
		return false
	}
	plans, err := BuildPlan(installationID, generation, s.labels[composeplan.LabelRelease])
	if err != nil {
		return false
	}
	for _, candidate := range plans {
		if candidate.purpose == s.purpose {
			return s.equal(candidate)
		}
	}
	return false
}

func (s Spec) equal(other Spec) bool {
	return s.kind == other.kind && s.purpose == other.purpose && s.name == other.name && equalLabels(s.labels, other.labels)
}

// Observed is the bounded identity projection returned by a Docker inspect.
type Observed struct {
	kind     Kind
	name     string
	objectID string
	labels   map[string]string
}

// NewObserved constructs a resource observation. Docker volumes use their
// immutable engine name as object identity because Docker exposes no separate
// volume ID; networks require the full lowercase 256-bit Docker object ID.
func NewObserved(kind Kind, name string, objectID string, labels map[string]string) (Observed, error) {
	if !validDockerName(name) || len(labels) != 5 {
		return Observed{}, ErrInvalidResource
	}
	switch kind {
	case KindVolume:
		if objectID != name {
			return Observed{}, ErrInvalidResource
		}
	case KindNetwork:
		if !lowerHex(objectID, 64) {
			return Observed{}, ErrInvalidResource
		}
	case KindUnknown:
		return Observed{}, ErrInvalidResource
	default:
		return Observed{}, ErrInvalidResource
	}
	for key, value := range labels {
		if key == "" || len(key) > 128 || value == "" || len(value) > 256 || strings.ContainsAny(key+value, "\x00\r\n") {
			return Observed{}, ErrInvalidResource
		}
	}
	return Observed{kind: kind, name: name, objectID: objectID, labels: cloneLabels(labels)}, nil
}

// Kind returns the observed resource kind.
func (o Observed) Kind() Kind { return o.kind }

// Name returns the observed physical name.
func (o Observed) Name() string { return o.name }

// ObjectID returns the engine object identity.
func (o Observed) ObjectID() string { return o.objectID }

// Labels returns an immutable-by-copy observed label set.
func (o Observed) Labels() map[string]string { return cloneLabels(o.labels) }

func (o Observed) matches(spec Spec) bool {
	return o.kind == spec.kind && o.name == spec.name && equalLabels(o.labels, spec.labels) &&
		((o.kind == KindVolume && o.objectID == o.name) || (o.kind == KindNetwork && lowerHex(o.objectID, 64)))
}

// RemovalAuthorization is an inventory-minted destructive-operation token.
// It has no public constructor; name or labels alone cannot create one.
type RemovalAuthorization struct {
	kind     Kind
	name     string
	objectID string
	labels   map[string]string
}

// Kind returns the authorized resource kind.
func (a RemovalAuthorization) Kind() Kind { return a.kind }

// Name returns the authorized UUID-derived resource name.
func (a RemovalAuthorization) Name() string { return a.name }

// ObjectID returns the exact inventoried Docker object identity.
func (a RemovalAuthorization) ObjectID() string { return a.objectID }

// Labels returns the exact inventoried labels by defensive copy.
func (a RemovalAuthorization) Labels() map[string]string { return cloneLabels(a.labels) }

// Valid reports whether the token contains the minimum structural proof. The
// Docker adapter still re-inspects and compares all fields before mutation.
func (a RemovalAuthorization) Valid() bool {
	observed, err := NewObserved(a.kind, a.name, a.objectID, a.labels)
	return err == nil && observed.objectID != ""
}

func validRelease(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '-' || character == '_')) {
			continue
		}
		return false
	}
	return true
}

func validOperation(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validDockerName(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '_' || character == '.' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func lowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func cloneLabels(labels map[string]string) map[string]string {
	copyOfLabels := make(map[string]string, len(labels))
	for key, value := range labels {
		copyOfLabels[key] = value
	}
	return copyOfLabels
}

func equalLabels(left map[string]string, right map[string]string) bool {
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
