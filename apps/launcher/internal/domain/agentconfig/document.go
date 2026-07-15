package agentconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const maximumJSONDepth = 64

type document struct {
	root    map[string]json.RawMessage
	servers map[string]json.RawMessage
}

type marker struct {
	ManagedBy      string `json:"managed_by"`
	SchemaVersion  uint32 `json:"schema_version"`
	InstallationID string `json:"installation_id"`
	EntryID        string `json:"entry_id"`
	LauncherSHA256 string `json:"launcher_sha256"`
}

type managedEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Marker  marker   `json:"_agentmemory"`
}

// ValidateDocument verifies the supported host-neutral JSON contract. JSON
// comments are unsupported and object member order is non-semantic.
func ValidateDocument(contents []byte) error {
	_, err := parseDocument(contents)
	return err
}

// ValidateDocumentFor applies the selected host's documented syntax without
// guessing a format from content.
func ValidateDocumentFor(host AgentHost, contents []byte) error {
	if !host.Valid() {
		return ErrInvalidTarget
	}
	if host == AgentHostCodex || host == AgentHostCustom {
		return ErrInvalidTarget
	}
	return ValidateDocument(contents)
}

func parseDocument(contents []byte) (document, error) {
	if len(contents) == 0 || len(contents) > MaxDocumentBytes || !utf8.Valid(contents) {
		return document{}, ErrInvalidDocument
	}
	if err := validateJSONTokens(contents); err != nil {
		return document{}, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(contents, &root); err != nil || root == nil {
		return document{}, ErrInvalidDocument
	}
	servers := make(map[string]json.RawMessage)
	if encodedServers, found := root["mcpServers"]; found {
		if err := json.Unmarshal(encodedServers, &servers); err != nil || servers == nil {
			return document{}, ErrInvalidDocument
		}
	}
	return document{root: cloneRawMap(root), servers: cloneRawMap(servers)}, nil
}

func validateJSONTokens(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return ErrInvalidDocument
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidDocument
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maximumJSONDepth {
		return ErrInvalidDocument
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidDocument
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidDocument
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return ErrInvalidDocument
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return ErrInvalidDocument
		}
		return nil
	default:
		return ErrInvalidDocument
	}
}

func (d document) withManagedEntry(encoded json.RawMessage) ([]byte, error) {
	root := cloneRawMap(d.root)
	servers := cloneRawMap(d.servers)
	servers[managedServerName] = append(json.RawMessage(nil), encoded...)
	encodedServers, err := json.Marshal(servers)
	if err != nil {
		return nil, ErrInvalidDocument
	}
	root["mcpServers"] = encodedServers
	result, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, ErrInvalidDocument
	}
	result = append(result, '\n')
	if len(result) > MaxDocumentBytes {
		return nil, ErrInvalidDocument
	}
	return result, nil
}

func desiredEntry(target Target) (json.RawMessage, Digest, error) {
	entry := managedEntry{
		Command: target.Command(),
		Args:    target.Arguments(),
		Marker: marker{
			ManagedBy:      managedByValue,
			SchemaVersion:  markerVersion,
			InstallationID: target.InstallationID(),
			EntryID:        target.EntryID(),
			LauncherSHA256: target.LauncherDigest().String(),
		},
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return nil, Digest{}, fmt.Errorf("%w: encode managed entry", ErrInvalidTarget)
	}
	canonical, err := canonicalJSON(encoded)
	if err != nil {
		return nil, Digest{}, fmt.Errorf("%w: canonicalize managed entry", ErrInvalidTarget)
	}
	return encoded, DigestBytes(canonical), nil
}

func inspectManagedEntry(encoded json.RawMessage) (marker, Digest, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil || object == nil {
		return marker{}, Digest{}, ErrAmbiguousOwnership
	}
	markerBytes, found := object["_agentmemory"]
	if !found {
		return marker{}, Digest{}, ErrAmbiguousOwnership
	}
	decoder := json.NewDecoder(bytes.NewReader(markerBytes))
	decoder.DisallowUnknownFields()
	var ownership marker
	if err := decoder.Decode(&ownership); err != nil {
		return marker{}, Digest{}, ErrAmbiguousOwnership
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return marker{}, Digest{}, ErrAmbiguousOwnership
	}
	launcherDigest, digestErr := DigestFromHex(ownership.LauncherSHA256)
	if ownership.ManagedBy != managedByValue || ownership.SchemaVersion != markerVersion ||
		!validUUIDv7(ownership.InstallationID) || !validUUIDv7(ownership.EntryID) ||
		digestErr != nil || launcherDigest.IsZero() {
		return marker{}, Digest{}, ErrAmbiguousOwnership
	}
	canonical, err := canonicalJSON(encoded)
	if err != nil {
		return marker{}, Digest{}, ErrAmbiguousOwnership
	}
	return ownership, DigestBytes(canonical), nil
}

func claimsAgentMemoryOwnership(encoded json.RawMessage) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil || object == nil {
		return false
	}
	encodedMarker, found := object["_agentmemory"]
	if !found {
		return false
	}
	var ownershipHint struct {
		ManagedBy string `json:"managed_by"`
	}
	return json.Unmarshal(encodedMarker, &ownershipHint) == nil && ownershipHint.ManagedBy == managedByValue
}

func canonicalJSON(encoded []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidDocument
	}
	return json.Marshal(value)
}

func cloneRawMap(source map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		result[key] = append(json.RawMessage(nil), value...)
	}
	return result
}
