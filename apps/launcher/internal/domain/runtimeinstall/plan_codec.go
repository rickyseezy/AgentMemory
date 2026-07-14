package runtimeinstall

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	// SupportedPlanSchemaMajor is the only runtime-plan schema this launcher may execute.
	SupportedPlanSchemaMajor = uint16(1)
	maximumPlanBytes         = 64 * 1024
	maximumPlanJSONDepth     = 16
	maximumPlanSafeJSONInt   = uint64(1<<53 - 1)
)

var (
	// ErrPlanMalformed means the input is not one bounded JSON object.
	ErrPlanMalformed = errors.New("runtime installation plan JSON is malformed")
	// ErrPlanDuplicateKey means an object repeats a JSON member at any depth.
	ErrPlanDuplicateKey = errors.New("runtime installation plan contains a duplicate JSON key")
	// ErrPlanUnknownField means schema v1 does not understand an input member.
	ErrPlanUnknownField = errors.New("runtime installation plan contains an unknown field")
	// ErrPlanUnsupportedSchema means the declared runtime-plan schema is not v1.
	ErrPlanUnsupportedSchema = errors.New("runtime installation plan schema is unsupported")
	// ErrPlanNonCanonical means values were not encoded as the exact canonical bytes.
	ErrPlanNonCanonical = errors.New("runtime installation plan is not canonical")
	// ErrPlanIntegrity means a required decision input or derived binding is contradictory.
	ErrPlanIntegrity = errors.New("runtime installation plan integrity validation failed")
)

// NewPlanV1 derives immutable execution authority from verified typed facts.
func NewPlanV1(host HostCapabilities, discovery RuntimeDiscovery, catalog CertifiedRuntime) (Plan, error) {
	document, err := runtimePlanDocument(host, discovery, catalog)
	if err != nil {
		return Plan{}, ErrPlanIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return Plan{}, ErrPlanIntegrity
	}
	return Plan{
		action:             parsePlanAction(document.Action),
		decisionCode:       parseDecisionCode(document.DecisionCode),
		digest:             Sum(canonical),
		canonical:          canonical,
		platform:           catalog.platform,
		product:            catalog.product,
		version:            catalog.version,
		catalogHash:        catalog.catalogDigest,
		termsHash:          catalog.terms.digest,
		termsID:            catalog.terms.id,
		termsVersion:       catalog.terms.version,
		termsURL:           catalog.terms.url,
		termsPresentation:  catalog.terms.presentation,
		downloadBytes:      catalog.downloadBytes,
		expandedBytes:      catalog.expandedBytes,
		hostOSVersion:      host.osVersion,
		unrelatedWorkloads: discovery.unrelatedWorkloads,
	}, nil
}

// DecodePlanV1 accepts only exact canonical bytes whose action and decision
// can be re-derived from every persisted host, discovery, and catalog fact.
func DecodePlanV1(raw []byte) (Plan, error) {
	if len(raw) == 0 || len(raw) > maximumPlanBytes {
		return Plan{}, ErrPlanMalformed
	}
	if err := rejectPlanDuplicateKeys(raw); err != nil {
		return Plan{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document canonicalRuntimePlan
	if err := decoder.Decode(&document); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Plan{}, ErrPlanUnknownField
		}
		return Plan{}, ErrPlanMalformed
	}
	if err := requirePlanJSONEOF(decoder); err != nil {
		return Plan{}, ErrPlanMalformed
	}
	if document.SchemaVersion != SupportedPlanSchemaMajor {
		return Plan{}, ErrPlanUnsupportedSchema
	}
	host, discovery, catalog, err := runtimeFactsFromDocument(document)
	if err != nil {
		return Plan{}, ErrPlanIntegrity
	}
	plan, err := NewPlanV1(host, discovery, catalog)
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(raw, plan.canonical) {
		if document.Action != plan.Action().String() || document.DecisionCode != plan.DecisionCode().String() {
			return Plan{}, ErrPlanIntegrity
		}
		return Plan{}, ErrPlanNonCanonical
	}
	return plan, nil
}

// ParseHash parses one canonical lowercase non-zero SHA-256 binding.
func ParseHash(value string) (Hash, error) {
	if len(value) != 64 {
		return Hash{}, ErrPlanIntegrity
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return Hash{}, ErrPlanIntegrity
	}
	var hash Hash
	copy(hash[:], decoded)
	if hash.IsZero() {
		return Hash{}, ErrPlanIntegrity
	}
	return hash, nil
}

func runtimePlanDocument(
	host HostCapabilities,
	discovery RuntimeDiscovery,
	catalog CertifiedRuntime,
) (canonicalRuntimePlan, error) {
	if !validHostFacts(host) || !validDiscoveryFacts(discovery) || !validCatalogFacts(catalog) ||
		host.totalMemory > maximumPlanSafeJSONInt || host.availableMemory > maximumPlanSafeJSONInt ||
		host.freeDisk > maximumPlanSafeJSONInt || catalog.catalogSequence > maximumPlanSafeJSONInt ||
		catalog.downloadBytes > maximumPlanSafeJSONInt || catalog.expandedBytes > maximumPlanSafeJSONInt {
		return canonicalRuntimePlan{}, ErrPlanIntegrity
	}
	action, code := decideRuntimeAction(host, discovery, catalog)
	return canonicalRuntimePlan{
		Action: action.String(),
		Catalog: canonicalRuntimeCatalog{
			Architecture:      catalog.architecture.String(),
			CatalogDigest:     catalog.catalogDigest.String(),
			CatalogSequence:   catalog.catalogSequence,
			Channel:           catalog.channel,
			DownloadBytes:     catalog.downloadBytes,
			ExpandedBytes:     catalog.expandedBytes,
			Platform:          catalog.platform.String(),
			Product:           catalog.product,
			TermsDigest:       catalog.terms.digest.String(),
			TermsID:           catalog.terms.id,
			TermsPresentation: catalog.terms.presentation,
			TermsURL:          catalog.terms.url,
			TermsVersion:      catalog.terms.version,
			Version:           catalog.version,
		},
		DecisionCode: code.String(),
		Discovery: canonicalRuntimeDiscovery{
			CapabilitiesVerified: discovery.capabilitiesVerified,
			Condition:            runtimeConditionString(discovery.condition),
			Endpoint:             discovery.endpoint,
			LocalEndpoint:        discovery.localEndpoint,
			Ownership:            runtimeOwnershipString(discovery.ownership),
			Product:              discovery.product,
			PublisherVerified:    discovery.publisherVerified,
			UnrelatedWorkloads:   discovery.unrelatedWorkloads,
			Version:              discovery.version,
		},
		Host: canonicalRuntimeHost{
			Architecture:         host.architecture.String(),
			AtRestEncryption:     host.atRestEncryption,
			AvailableMemoryBytes: host.availableMemory,
			Certified:            host.certified,
			CPUs:                 host.cpus,
			FreeDiskBytes:        host.freeDisk,
			LocalFilesystem:      host.localFilesystem,
			OSVersion:            host.osVersion,
			Platform:             host.platform.String(),
			TotalMemoryBytes:     host.totalMemory,
			Virtualization:       host.virtualization,
		},
		SchemaVersion: SupportedPlanSchemaMajor,
	}, nil
}

func runtimeFactsFromDocument(
	document canonicalRuntimePlan,
) (HostCapabilities, RuntimeDiscovery, CertifiedRuntime, error) {
	platform, ok := parseRuntimePlatform(document.Host.Platform)
	if !ok {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, ErrPlanIntegrity
	}
	architecture, ok := parseRuntimeArchitecture(document.Host.Architecture)
	if !ok {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, ErrPlanIntegrity
	}
	host, err := NewHostCapabilities(
		platform, architecture, document.Host.OSVersion, document.Host.Certified,
		document.Host.Virtualization, document.Host.LocalFilesystem, document.Host.AtRestEncryption,
		document.Host.CPUs, document.Host.TotalMemoryBytes, document.Host.AvailableMemoryBytes,
		document.Host.FreeDiskBytes,
	)
	if err != nil {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, ErrPlanIntegrity
	}
	discovery, err := discoveryFromDocument(document.Discovery)
	if err != nil {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, err
	}
	catalogPlatform, ok := parseRuntimePlatform(document.Catalog.Platform)
	if !ok {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, ErrPlanIntegrity
	}
	catalogArchitecture, ok := parseRuntimeArchitecture(document.Catalog.Architecture)
	if !ok {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, ErrPlanIntegrity
	}
	catalogDigest, err := ParseHash(document.Catalog.CatalogDigest)
	if err != nil {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, err
	}
	termsDigest, err := ParseHash(document.Catalog.TermsDigest)
	if err != nil {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, err
	}
	catalog, err := NewCertifiedRuntime(
		catalogPlatform, catalogArchitecture, document.Catalog.Product, document.Catalog.Version,
		document.Catalog.Channel, document.Catalog.CatalogSequence, catalogDigest, RuntimeTermsInput{
			ID: document.Catalog.TermsID, Version: document.Catalog.TermsVersion,
			URL: document.Catalog.TermsURL, Digest: termsDigest,
			Presentation: document.Catalog.TermsPresentation,
		},
		document.Catalog.DownloadBytes, document.Catalog.ExpandedBytes,
	)
	if err != nil {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, ErrPlanIntegrity
	}
	if document.Action != parsePlanAction(document.Action).String() ||
		document.DecisionCode != parseDecisionCode(document.DecisionCode).String() {
		return HostCapabilities{}, RuntimeDiscovery{}, CertifiedRuntime{}, ErrPlanIntegrity
	}
	return host, discovery, catalog, nil
}

func validHostFacts(host HostCapabilities) bool {
	if _, ok := parseRuntimePlatform(host.platform.String()); !ok {
		return false
	}
	if _, ok := parseRuntimeArchitecture(host.architecture.String()); !ok {
		return false
	}
	restored, err := NewHostCapabilities(
		host.platform, host.architecture, host.osVersion, host.certified, host.virtualization,
		host.localFilesystem, host.atRestEncryption, host.cpus, host.totalMemory,
		host.availableMemory, host.freeDisk,
	)
	return err == nil && restored.platform == host.platform
}

func validDiscoveryFacts(discovery RuntimeDiscovery) bool {
	if discovery.condition == RuntimeConditionAbsent {
		return discovery.product == "" && discovery.version == "" && discovery.endpoint == "" &&
			!discovery.localEndpoint && !discovery.publisherVerified && !discovery.capabilitiesVerified &&
			discovery.ownership == OwnershipUnknown && discovery.unrelatedWorkloads == 0
	}
	if parseRuntimeCondition(runtimeConditionString(discovery.condition)) == RuntimeConditionUnknown ||
		parseRuntimeOwnership(runtimeOwnershipString(discovery.ownership)) == OwnershipUnknown {
		return false
	}
	_, err := NewRuntimeDiscovery(
		discovery.condition, discovery.product, discovery.version, discovery.endpoint,
		discovery.localEndpoint, discovery.publisherVerified, discovery.capabilitiesVerified,
		discovery.ownership, discovery.unrelatedWorkloads,
	)
	return err == nil
}

func validCatalogFacts(catalog CertifiedRuntime) bool {
	if _, ok := parseRuntimePlatform(catalog.platform.String()); !ok {
		return false
	}
	if _, ok := parseRuntimeArchitecture(catalog.architecture.String()); !ok {
		return false
	}
	restored, err := NewCertifiedRuntime(
		catalog.platform, catalog.architecture, catalog.product, catalog.version, catalog.channel,
		catalog.catalogSequence, catalog.catalogDigest, RuntimeTermsInput{
			ID: catalog.terms.id, Version: catalog.terms.version, URL: catalog.terms.url,
			Digest: catalog.terms.digest, Presentation: catalog.terms.presentation,
		},
		catalog.downloadBytes, catalog.expandedBytes,
	)
	return err == nil && restored.catalogDigest == catalog.catalogDigest
}

func discoveryFromDocument(document canonicalRuntimeDiscovery) (RuntimeDiscovery, error) {
	condition := parseRuntimeCondition(document.Condition)
	ownership := parseRuntimeOwnership(document.Ownership)
	if condition == RuntimeConditionAbsent {
		discovery := NewAbsentRuntimeDiscovery()
		if document.Product != "" || document.Version != "" || document.Endpoint != "" ||
			document.LocalEndpoint || document.PublisherVerified || document.CapabilitiesVerified ||
			ownership != OwnershipUnknown || document.UnrelatedWorkloads != 0 {
			return RuntimeDiscovery{}, ErrPlanIntegrity
		}
		return discovery, nil
	}
	if condition == RuntimeConditionUnknown || ownership == OwnershipUnknown {
		return RuntimeDiscovery{}, ErrPlanIntegrity
	}
	discovery, err := NewRuntimeDiscovery(
		condition, document.Product, document.Version, document.Endpoint, document.LocalEndpoint,
		document.PublisherVerified, document.CapabilitiesVerified, ownership, document.UnrelatedWorkloads,
	)
	if err != nil {
		return RuntimeDiscovery{}, ErrPlanIntegrity
	}
	return discovery, nil
}

func parseRuntimePlatform(value string) (Platform, bool) {
	switch value {
	case PlatformDarwin.String():
		return PlatformDarwin, true
	case PlatformLinux.String():
		return PlatformLinux, true
	case PlatformWindows.String():
		return PlatformWindows, true
	default:
		return PlatformUnknown, false
	}
}

func parseRuntimeArchitecture(value string) (Architecture, bool) {
	switch value {
	case ArchitectureAMD64.String():
		return ArchitectureAMD64, true
	case ArchitectureARM64.String():
		return ArchitectureARM64, true
	default:
		return ArchitectureUnknown, false
	}
}

func runtimeConditionString(value RuntimeCondition) string {
	switch value {
	case RuntimeConditionAbsent:
		return "absent"
	case RuntimeConditionRunning:
		return "running"
	case RuntimeConditionStopped:
		return "stopped"
	case RuntimeConditionIncompatible:
		return "incompatible"
	case RuntimeConditionDamaged:
		return "damaged"
	case RuntimeConditionUnknown:
	}
	return "unknown"
}

func parseRuntimeCondition(value string) RuntimeCondition {
	switch value {
	case "absent":
		return RuntimeConditionAbsent
	case "running":
		return RuntimeConditionRunning
	case "stopped":
		return RuntimeConditionStopped
	case "incompatible":
		return RuntimeConditionIncompatible
	case "damaged":
		return RuntimeConditionDamaged
	default:
		return RuntimeConditionUnknown
	}
}

func runtimeOwnershipString(value OwnershipDisposition) string {
	switch value {
	case OwnershipReusedExternal:
		return "reused_external"
	case OwnershipProvisionedByAgentMemory:
		return "provisioned_by_agentmemory"
	case OwnershipUnknown:
	}
	return "unknown"
}

func parseRuntimeOwnership(value string) OwnershipDisposition {
	switch value {
	case "reused_external":
		return OwnershipReusedExternal
	case "provisioned_by_agentmemory":
		return OwnershipProvisionedByAgentMemory
	case "unknown":
		return OwnershipUnknown
	default:
		return OwnershipUnknown
	}
}

func parsePlanAction(value string) PlanAction {
	switch value {
	case PlanActionAdoptCompatible.String():
		return PlanActionAdoptCompatible
	case PlanActionStartCompatible.String():
		return PlanActionStartCompatible
	case PlanActionInstallCertified.String():
		return PlanActionInstallCertified
	case PlanActionRepairManaged.String():
		return PlanActionRepairManaged
	case PlanActionBlock.String():
		return PlanActionBlock
	default:
		return PlanActionUnknown
	}
}

func parseDecisionCode(value string) DecisionCode {
	for code := DecisionOK; code <= DecisionCatalogMismatch; code++ {
		if code.String() == value {
			return code
		}
	}
	return DecisionCode(255)
}

func rejectPlanDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanPlanJSONValue(decoder, 0); err != nil {
		return err
	}
	if err := requirePlanJSONEOF(decoder); err != nil {
		return ErrPlanMalformed
	}
	return nil
}

func scanPlanJSONValue(decoder *json.Decoder, depth uint32) error {
	if depth > maximumPlanJSONDepth {
		return ErrPlanMalformed
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrPlanMalformed
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			key, ok := keyToken.(string)
			if keyError != nil || !ok {
				return ErrPlanMalformed
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrPlanDuplicateKey
			}
			seen[key] = struct{}{}
			if err := scanPlanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return ErrPlanMalformed
		}
	case '[':
		for decoder.More() {
			if err := scanPlanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return ErrPlanMalformed
		}
	default:
		return ErrPlanMalformed
	}
	return nil
}

func requirePlanJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	}
	return ErrPlanMalformed
}

type canonicalRuntimePlan struct {
	Action        string                    `json:"action"`
	Catalog       canonicalRuntimeCatalog   `json:"catalog"`
	DecisionCode  string                    `json:"decision_code"`
	Discovery     canonicalRuntimeDiscovery `json:"discovery"`
	Host          canonicalRuntimeHost      `json:"host"`
	SchemaVersion uint16                    `json:"schema_version"`
}

type canonicalRuntimeCatalog struct {
	Architecture      string `json:"architecture"`
	CatalogDigest     string `json:"catalog_digest"`
	CatalogSequence   uint64 `json:"catalog_sequence"`
	Channel           string `json:"channel"`
	DownloadBytes     uint64 `json:"download_bytes"`
	ExpandedBytes     uint64 `json:"expanded_bytes"`
	Platform          string `json:"platform"`
	Product           string `json:"product"`
	TermsDigest       string `json:"terms_digest"`
	TermsID           string `json:"terms_id"`
	TermsPresentation string `json:"terms_presentation"`
	TermsURL          string `json:"terms_url"`
	TermsVersion      string `json:"terms_version"`
	Version           string `json:"version"`
}

type canonicalRuntimeDiscovery struct {
	CapabilitiesVerified bool   `json:"capabilities_verified"`
	Condition            string `json:"condition"`
	Endpoint             string `json:"endpoint"`
	LocalEndpoint        bool   `json:"local_endpoint"`
	Ownership            string `json:"ownership"`
	Product              string `json:"product"`
	PublisherVerified    bool   `json:"publisher_verified"`
	UnrelatedWorkloads   uint32 `json:"unrelated_workloads"`
	Version              string `json:"version"`
}

type canonicalRuntimeHost struct {
	Architecture         string `json:"architecture"`
	AtRestEncryption     bool   `json:"at_rest_encryption"`
	AvailableMemoryBytes uint64 `json:"available_memory_bytes"`
	Certified            bool   `json:"certified"`
	CPUs                 uint16 `json:"cpus"`
	FreeDiskBytes        uint64 `json:"free_disk_bytes"`
	LocalFilesystem      bool   `json:"local_filesystem"`
	OSVersion            string `json:"os_version"`
	Platform             string `json:"platform"`
	TotalMemoryBytes     uint64 `json:"total_memory_bytes"`
	Virtualization       bool   `json:"virtualization"`
}
