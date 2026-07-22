package provideradapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const maximumManifestBytes = 256 * 1024

type manifestDocument struct {
	SchemaVersion uint16                            `json:"schema_version"`
	AdapterID     string                            `json:"adapter_id"`
	Image         string                            `json:"image"`
	ImageDigest   string                            `json:"image_digest"`
	Protocol      struct{ Minimum, Maximum uint16 } `json:"protocol"`
	Transport     Transport                         `json:"transport"`
	Operations    []Operation                       `json:"operations"`
	Permissions   struct {
		GatewayAccess     bool `json:"gateway_access"`
		HostNetwork       bool `json:"host_network"`
		PublishPort       bool `json:"publish_port"`
		DockerSocket      bool `json:"docker_socket"`
		ProjectMount      bool `json:"project_mount"`
		WritableMount     bool `json:"writable_mount"`
		AdditionalSecrets bool `json:"additional_secrets"`
		DirectEgress      bool `json:"direct_egress"`
		Privileged        bool `json:"privileged"`
	} `json:"permissions"`
	Limits struct {
		CPUsMilli           uint32 `json:"cpus_milli"`
		MemoryBytes         uint64 `json:"memory_bytes"`
		PIDs                uint32 `json:"pids"`
		TimeoutMilliseconds uint32 `json:"timeout_milliseconds"`
		ScratchBytes        uint64 `json:"scratch_bytes"`
	} `json:"limits"`
	Evidence struct {
		SignatureBundle string `json:"signature_bundle"`
		CycloneDXSBOM   string `json:"cyclonedx_sbom"`
		SPDXSBOM        string `json:"spdx_sbom"`
		Provenance      string `json:"provenance"`
		License         string `json:"license"`
		Vulnerability   string `json:"vulnerability"`
	} `json:"evidence"`
}

// ParseManifestJSON decodes the external schema into the immutable domain model.
func ParseManifestJSON(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > maximumManifestBytes || duplicateManifestKey(raw) != nil {
		return Manifest{}, ErrInvalidManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document manifestDocument
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.SchemaVersion != 1 {
		return Manifest{}, ErrInvalidManifest
	}
	imageDigest, err := ParseDigest(document.ImageDigest)
	if err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	digestValues := []string{document.Evidence.SignatureBundle, document.Evidence.CycloneDXSBOM,
		document.Evidence.SPDXSBOM, document.Evidence.Provenance, document.Evidence.License, document.Evidence.Vulnerability}
	digests := make([]Digest, len(digestValues))
	for index, value := range digestValues {
		digests[index], err = ParseDigest(value)
		if err != nil {
			return Manifest{}, ErrInvalidManifest
		}
	}
	return NewManifest(ManifestInput{
		AdapterID: document.AdapterID, Image: document.Image, ImageDigest: imageDigest,
		Protocol:  ProtocolRangeInput{Minimum: document.Protocol.Minimum, Maximum: document.Protocol.Maximum},
		Transport: document.Transport, Operations: document.Operations,
		Permissions: PermissionInput{GatewayAccess: document.Permissions.GatewayAccess, HostNetwork: document.Permissions.HostNetwork,
			PublishPort: document.Permissions.PublishPort, DockerSocket: document.Permissions.DockerSocket,
			ProjectMount: document.Permissions.ProjectMount, WritableMount: document.Permissions.WritableMount,
			AdditionalSecrets: document.Permissions.AdditionalSecrets, DirectEgress: document.Permissions.DirectEgress,
			Privileged: document.Permissions.Privileged},
		Limits: LimitInput{CPUsMilli: document.Limits.CPUsMilli, MemoryBytes: document.Limits.MemoryBytes,
			PIDs: document.Limits.PIDs, TimeoutMilliseconds: document.Limits.TimeoutMilliseconds, ScratchBytes: document.Limits.ScratchBytes},
		Evidence: EvidenceInput{SignatureBundle: digests[0], CycloneDXSBOM: digests[1], SPDXSBOM: digests[2],
			Provenance: digests[3], License: digests[4], Vulnerability: digests[5]},
	})
}

func duplicateManifestKey(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var visit func() error
	visit = func() error {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalidManifest
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				token, tokenErr := decoder.Token()
				name, ok := token.(string)
				if tokenErr != nil || !ok {
					return ErrInvalidManifest
				}
				if _, exists := seen[name]; exists {
					return ErrInvalidManifest
				}
				seen[name] = struct{}{}
				if visit() != nil {
					return ErrInvalidManifest
				}
			}
		case '[':
			for decoder.More() {
				if visit() != nil {
					return ErrInvalidManifest
				}
			}
		default:
			return ErrInvalidManifest
		}
		_, err = decoder.Token()
		return err
	}
	if visit() != nil {
		return ErrInvalidManifest
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidManifest
	}
	return nil
}
