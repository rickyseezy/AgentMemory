// Package adapter provides the dependency-free AgentMemory public adapter SDK v1.
package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
)

// SchemaVersion is the only public adapter contract revision accepted by this SDK.
const SchemaVersion = 1

var (
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	protocolPattern  = regexp.MustCompile(`^[1-9][0-9]{0,4}\.(0|[1-9][0-9]{0,4})$`)
)

// Kind selects the agent or provider port without vendor identity.
type Kind string

const (
	// KindAgent selects the canonical AgentEvent capture boundary.
	KindAgent Kind = "agent"
	// KindProvider selects the embedding/reranking/extraction boundary.
	KindProvider Kind = "provider"
)

// ProbeRequest is the strict replay-resistant live conformance challenge.
type ProbeRequest struct {
	SchemaVersion  int      `json:"schema_version"`
	Challenge      string   `json:"challenge"`
	ManifestDigest string   `json:"manifest_digest"`
	PackageDigest  string   `json:"package_digest"`
	Protocol       string   `json:"protocol"`
	Kind           Kind     `json:"kind"`
	Capabilities   []string `json:"capabilities"`
}

// ProbeResponse echoes every security identity and capability exactly.
type ProbeResponse struct {
	Capabilities   []string `json:"capabilities"`
	Challenge      string   `json:"challenge"`
	ManifestDigest string   `json:"manifest_digest"`
	PackageDigest  string   `json:"package_digest"`
	Protocol       string   `json:"protocol"`
	SchemaVersion  int      `json:"schema_version"`
	Status         string   `json:"status"`
}

// DecodeProbeRequest rejects duplicate, unknown, trailing, or malformed input.
func DecodeProbeRequest(value []byte) (ProbeRequest, error) {
	if len(value) == 0 || len(value) > 64*1024 {
		return ProbeRequest{}, errors.New("probe request size is invalid")
	}
	if err := rejectDuplicateKeys(value); err != nil {
		return ProbeRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var request ProbeRequest
	if err := decoder.Decode(&request); err != nil {
		return ProbeRequest{}, fmt.Errorf("decode probe request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return ProbeRequest{}, errors.New("probe request has trailing JSON")
	}
	if err := request.Validate(); err != nil {
		return ProbeRequest{}, err
	}
	return request, nil
}

// Validate enforces exact v1 identities and canonical capabilities.
func (request ProbeRequest) Validate() error {
	if request.SchemaVersion != SchemaVersion || !challengePattern.MatchString(request.Challenge) ||
		!digestPattern.MatchString(request.ManifestDigest) || !digestPattern.MatchString(request.PackageDigest) ||
		!protocolPattern.MatchString(request.Protocol) || (request.Kind != KindAgent && request.Kind != KindProvider) ||
		len(request.Capabilities) == 0 {
		return errors.New("probe request is invalid")
	}
	canonical := append([]string(nil), request.Capabilities...)
	sort.Strings(canonical)
	for index, capability := range canonical {
		if capability == "" || capability != request.Capabilities[index] ||
			(index > 0 && canonical[index-1] == capability) {
			return errors.New("probe capabilities are not canonical")
		}
	}
	return nil
}

// Response returns the exact successful response to this challenge.
func (request ProbeRequest) Response() ProbeResponse {
	return ProbeResponse{
		Capabilities:   append([]string(nil), request.Capabilities...),
		Challenge:      request.Challenge,
		ManifestDigest: request.ManifestDigest,
		PackageDigest:  request.PackageDigest,
		Protocol:       request.Protocol,
		SchemaVersion:  SchemaVersion,
		Status:         "passed",
	}
}

func rejectDuplicateKeys(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("probe request must be an object")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		rawKey, keyErr := decoder.Token()
		key, ok := rawKey.(string)
		if keyErr != nil || !ok {
			return errors.New("probe request key is invalid")
		}
		if _, exists := seen[key]; exists {
			return errors.New("probe request contains duplicate key")
		}
		seen[key] = struct{}{}
		var field json.RawMessage
		if err := decoder.Decode(&field); err != nil {
			return fmt.Errorf("decode probe field: %w", err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("close probe object: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("probe request has trailing JSON")
	}
	return nil
}
