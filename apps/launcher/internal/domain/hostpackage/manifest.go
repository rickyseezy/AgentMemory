// Package hostpackage defines the closed agent-host package manifests and
// detached package record. It owns no filesystem, archive, signing, or network
// capability.
package hostpackage

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// Host is a supported package contract.
type Host string

const (
	// HostClaude is the MCPB binary-server package contract.
	HostClaude Host = "claude"
	// HostGemini is the Gemini CLI extension-directory contract.
	HostGemini Host = "gemini"
	// HostGeneric is the path-neutral stdio registration contract.
	HostGeneric Host = "generic"
)

// Target is one certified package execution cell.
type Target struct {
	OperatingSystem string
	Architecture    string
}

// ManifestInput contains the identity shared by every host projection.
type ManifestInput struct {
	Host       Host
	Target     Target
	Version    string
	Executable string
}

type authorDocument struct {
	Name string `json:"name"`
}

type mcpConfigDocument struct {
	Args    []string `json:"args"`
	Command string   `json:"command"`
}

type serverDocument struct {
	EntryPoint string            `json:"entry_point"`
	MCPConfig  mcpConfigDocument `json:"mcp_config"`
	Type       string            `json:"type"`
}

type compatibilityDocument struct {
	Platforms []string `json:"platforms"`
}

type claudeManifest struct {
	Schema          string                `json:"$schema"`
	Author          authorDocument        `json:"author"`
	Compatibility   compatibilityDocument `json:"compatibility"`
	Description     string                `json:"description"`
	DisplayName     string                `json:"display_name"`
	License         string                `json:"license"`
	ManifestVersion string                `json:"manifest_version"`
	Name            string                `json:"name"`
	Server          serverDocument        `json:"server"`
	Version         string                `json:"version"`
}

type geminiServerDocument struct {
	Args    []string `json:"args"`
	Command string   `json:"command"`
	CWD     string   `json:"cwd"`
}

type geminiManifest struct {
	Description string                          `json:"description"`
	MCPServers  map[string]geminiServerDocument `json:"mcpServers"`
	Name        string                          `json:"name"`
	Version     string                          `json:"version"`
}

type genericServerDocument struct {
	Args      []string `json:"args"`
	Command   string   `json:"command"`
	Transport string   `json:"transport"`
}

type genericManifest struct {
	Name          string                `json:"name"`
	SchemaVersion uint16                `json:"schema_version"`
	Server        genericServerDocument `json:"server"`
	Version       string                `json:"version"`
}

// ManifestName returns the exact root manifest leaf for a host package.
func ManifestName(host Host) (string, error) {
	switch host {
	case HostClaude:
		return "manifest.json", nil
	case HostGemini:
		return "gemini-extension.json", nil
	case HostGeneric:
		return "agentmemory-mcp.json", nil
	default:
		return "", errors.New("host package contract is unsupported")
	}
}

// EncodeManifest returns one canonical host manifest. The Claude projection is
// pinned to MCPB manifest v0.4; Gemini uses its documented extension path
// placeholder and directory separator placeholder.
func EncodeManifest(input ManifestInput) ([]byte, error) {
	if !validTarget(input.Target) || !validVersion(input.Version) || !validExecutable(input.Executable) {
		return nil, errors.New("host package manifest identity is invalid")
	}
	var document any
	switch input.Host {
	case HostClaude:
		platform := input.Target.OperatingSystem
		if platform == "windows" {
			platform = "win32"
		}
		command := "${__dirname}/bin/" + input.Executable
		document = claudeManifest{
			Schema: "https://raw.githubusercontent.com/modelcontextprotocol/mcpb/70fe3b34cd6dff1b3bba046638edc72a6467a4fb/schemas/mcpb-manifest-v0.4.schema.json",
			Author: authorDocument{Name: "AgentMemory"}, Compatibility: compatibilityDocument{Platforms: []string{platform}},
			Description: "Persistent local memory for MCP-compatible AI agents", DisplayName: "AgentMemory",
			License: "Apache-2.0", ManifestVersion: "0.4", Name: "agentmemory", Version: input.Version,
			Server: serverDocument{Type: "binary", EntryPoint: "bin/" + input.Executable,
				MCPConfig: mcpConfigDocument{Command: command, Args: []string{"mcp", "--agent", "claude"}}},
		}
	case HostGemini:
		command := "${extensionPath}${/}bin${/}" + input.Executable
		document = geminiManifest{
			Name: "agentmemory", Version: input.Version,
			Description: "Persistent local memory for MCP-compatible AI agents",
			MCPServers: map[string]geminiServerDocument{"agentmemory": {
				Command: command, Args: []string{"mcp", "--agent", "gemini"}, CWD: "${extensionPath}",
			}},
		}
	case HostGeneric:
		document = genericManifest{
			Name: "agentmemory", SchemaVersion: 1, Version: input.Version,
			Server: genericServerDocument{Command: "bin/" + input.Executable,
				Args: []string{"mcp", "--agent", "custom"}, Transport: "stdio"},
		}
	default:
		return nil, errors.New("host package contract is unsupported")
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, errors.New("encode host package manifest")
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func validTarget(target Target) bool {
	switch target.OperatingSystem + "/" + target.Architecture {
	case "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64":
		return true
	default:
		return false
	}
}

func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validExecutable(value string) bool {
	return value == "agentmemory-bootstrap" || value == "agentmemory-bootstrap.exe"
}

// RecordInput binds one archive to every authority byte needed before its
// detached signature can be produced.
type RecordInput struct {
	SchemaVersion              uint16
	Host                       Host
	Target                     Target
	Version                    string
	SourceCommit               string
	SourceEpoch                int64
	FileName                   string
	ArchiveDigest              releaseinventory.Digest
	ArchiveSize                uint64
	BootstrapDigest            releaseinventory.Digest
	PublicationDigest          releaseinventory.Digest
	PublicationSignatureDigest releaseinventory.Digest
}

type canonicalRecord struct {
	Architecture               string `json:"architecture"`
	ArchiveSHA256              string `json:"archive_sha256"`
	ArchiveSize                uint64 `json:"archive_size"`
	BootstrapSHA256            string `json:"bootstrap_sha256"`
	FileName                   string `json:"file_name"`
	Host                       string `json:"host"`
	OperatingSystem            string `json:"operating_system"`
	PublicationSHA256          string `json:"publication_sha256"`
	PublicationSignatureSHA256 string `json:"publication_signature_sha256"`
	SchemaVersion              uint16 `json:"schema_version"`
	SourceCommit               string `json:"source_commit"`
	SourceEpoch                int64  `json:"source_epoch"`
	Version                    string `json:"version"`
}

// EncodeRecord validates and encodes a detached canonical host-package record.
func EncodeRecord(input RecordInput) ([]byte, error) {
	if input.SchemaVersion != 1 || !validTarget(input.Target) || !validVersion(input.Version) ||
		len(input.SourceCommit) != 40 || input.SourceEpoch <= 0 || input.ArchiveSize == 0 ||
		input.ArchiveDigest.IsZero() || input.BootstrapDigest.IsZero() || input.PublicationDigest.IsZero() ||
		input.PublicationSignatureDigest.IsZero() || !validRecordFileName(input.Host, input.FileName) {
		return nil, errors.New("host package record is invalid")
	}
	for _, character := range input.SourceCommit {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return nil, errors.New("host package record source is invalid")
		}
	}
	document := canonicalRecord{
		Architecture: input.Target.Architecture, ArchiveSHA256: input.ArchiveDigest.Hex(),
		ArchiveSize: input.ArchiveSize, BootstrapSHA256: input.BootstrapDigest.Hex(), FileName: input.FileName,
		Host: string(input.Host), OperatingSystem: input.Target.OperatingSystem,
		PublicationSHA256:          input.PublicationDigest.Hex(),
		PublicationSignatureSHA256: input.PublicationSignatureDigest.Hex(), SchemaVersion: input.SchemaVersion,
		SourceCommit: input.SourceCommit, SourceEpoch: input.SourceEpoch, Version: input.Version,
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, errors.New("encode host package record")
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func validRecordFileName(host Host, value string) bool {
	if value == "" || strings.ContainsAny(value, `/\\<>:\"|?*`) {
		return false
	}
	switch host {
	case HostClaude:
		return strings.HasSuffix(value, ".mcpb")
	case HostGemini, HostGeneric:
		return strings.HasSuffix(value, ".zip")
	default:
		return false
	}
}
