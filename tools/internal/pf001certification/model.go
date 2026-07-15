// Package pf001certification verifies the closed PF-001 native support matrix
// and externally signed clean-host campaign evidence used by release CI.
package pf001certification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const (
	// SupportMatrixSchemaVersion is the only accepted support-matrix contract version.
	SupportMatrixSchemaVersion = 1
	// CertificationSchemaVersion is the only accepted clean-host report contract version.
	CertificationSchemaVersion = 1
	// SignatureSchemaVersion is the only accepted detached-signature contract version.
	SignatureSchemaVersion = 1
	// MaximumEvidenceFiles bounds one certification campaign against archive exhaustion.
	MaximumEvidenceFiles = 4096
	// MaximumEvidenceFileBytes bounds each raw or archived evidence object.
	MaximumEvidenceFileBytes = uint64(1 << 30)
	// MaximumEvidenceTotalBytes bounds the declared evidence payload for one campaign.
	MaximumEvidenceTotalBytes = uint64(16 << 30)
)

var requiredAgentHosts = []string{"claude", "codex", "cursor", "gemini", "generic-custom"}

var requiredCellIDs = []string{
	"darwin-amd64-macos-tahoe-apfs",
	"darwin-arm64-macos-tahoe-apfs",
	"linux-amd64-fedora-44-xfs",
	"linux-amd64-ubuntu-24.04-ext4",
	"linux-arm64-fedora-44-xfs",
	"linux-arm64-ubuntu-24.04-ext4",
	"windows-amd64-11-25h2-ntfs",
}

var requiredScenarioIDs = []string{
	"agent-host-integration",
	"fail-closed-host-conditions",
	"install-lifecycle",
	"interruption-recovery",
	"linux-apt-native",
	"linux-dnf-native",
	"local-semantic-no-egress",
	"macos-native-security",
	"network-adversarial",
	"upgrade-removal",
	"usability-accessibility",
	"windows-native-security",
	"windows-wsl-prerequisites",
}

var requiredScenarioVariants = map[string][]string{
	"agent-host-integration": {
		"claude-mcpb-install", "codex-config-install", "config-preservation", "cursor-config-install",
		"first-mcp-timeout-status", "gemini-extension-install", "generic-custom-contract", "reboot-reconnect",
	},
	"fail-closed-host-conditions": {
		"decline-elevation", "decline-license", "failed-semantic-smoke", "incompatible-migration",
		"invalid-provenance", "invalid-sbom", "invalid-signature", "low-disk", "low-memory",
		"managed-device-denial", "port-collision", "remote-docker-context", "unavailable-project-mount",
		"unsafe-secret-permissions", "unsupported-hardware", "unsupported-os", "virtualization-disabled",
	},
	"install-lifecycle": {
		"existing-running-online", "existing-stopped-online", "physical-capacity-reservation",
		"pristine-offline", "pristine-online", "repeat-already-ready",
	},
	"interruption-recovery": {
		"daemon-failure-every-checkpoint", "logout-every-checkpoint", "network-loss-every-checkpoint",
		"power-loss-every-checkpoint", "process-kill-every-checkpoint", "reboot-every-checkpoint",
	},
	"linux-apt-native": {
		"package-signature-receipts", "polkit-denial-retry", "rootless-subid-missing", "systemd-user-missing", "uninstall-package-state",
	},
	"linux-dnf-native": {
		"package-signature-receipts", "polkit-denial-retry", "rootless-subid-missing", "selinux-enforcing",
		"systemd-user-missing", "uninstall-package-state",
	},
	"local-semantic-no-egress": {"index-rerank-extract-recall"},
	"macos-native-security": {
		"authorization-denial-retry", "developer-id-notarization", "keychain-acl-rollback", "package-uninstall", "path-swap-hardlink",
	},
	"network-adversarial": {
		"captive-portal", "partial-resume", "proxy-authentication", "redirect-substitution", "tls-interception",
	},
	"upgrade-removal": {
		"preserve-reused-runtime", "rollback-generation", "uninstall-managed-runtime", "upgrade-shadow-activation",
	},
	"usability-accessibility": {"novice-no-technical-choice", "wcag-keyboard-screenreader-localization"},
	"windows-native-security": {
		"authenticode-leaf-match", "credential-manager-dpapi", "dacl-reparse-hardlink", "package-uninstall", "uac-denial-retry",
	},
	"windows-wsl-prerequisites": {"wsl-absent-reboot", "wsl-current", "wsl-distribution-absent", "wsl-outdated-reboot"},
}

var requiredScenarioEvidence = map[string][]string{
	"agent-host-integration":      {"host-attestation", "journal", "result", "security-report", "transcript"},
	"fail-closed-host-conditions": {"host-attestation", "journal", "result", "security-report", "transcript"},
	"install-lifecycle":           {"egress-report", "host-attestation", "journal", "result", "transcript"},
	"interruption-recovery":       {"host-attestation", "journal", "recovery-trace", "result", "transcript"},
	"linux-apt-native":            {"host-attestation", "journal", "result", "security-report", "transcript"},
	"linux-dnf-native":            {"host-attestation", "journal", "result", "security-report", "transcript"},
	"local-semantic-no-egress":    {"egress-report", "host-attestation", "journal", "packet-capture", "result", "transcript"},
	"macos-native-security":       {"host-attestation", "journal", "result", "security-report", "transcript"},
	"network-adversarial":         {"egress-report", "host-attestation", "journal", "packet-capture", "result", "security-report", "transcript"},
	"upgrade-removal":             {"host-attestation", "journal", "recovery-trace", "result", "transcript"},
	"usability-accessibility":     {"accessibility-report", "host-attestation", "journal", "result", "study-record", "transcript"},
	"windows-native-security":     {"host-attestation", "journal", "result", "security-report", "transcript"},
	"windows-wsl-prerequisites":   {"host-attestation", "journal", "recovery-trace", "result", "security-report", "transcript"},
}

type scenarioScope struct {
	platforms     []string
	distributions []string
}

var requiredScenarioScopes = map[string]scenarioScope{
	"agent-host-integration":      {},
	"fail-closed-host-conditions": {},
	"install-lifecycle":           {},
	"interruption-recovery":       {},
	"linux-apt-native":            {platforms: []string{"linux"}, distributions: []string{"ubuntu-24.04"}},
	"linux-dnf-native":            {platforms: []string{"linux"}, distributions: []string{"fedora-44"}},
	"local-semantic-no-egress":    {},
	"macos-native-security":       {platforms: []string{"darwin"}, distributions: []string{"macos-tahoe"}},
	"network-adversarial":         {},
	"upgrade-removal":             {},
	"usability-accessibility":     {},
	"windows-native-security": {
		platforms: []string{"windows"}, distributions: []string{"windows-11-25h2"},
	},
	"windows-wsl-prerequisites": {
		platforms: []string{"windows"}, distributions: []string{"windows-11-25h2"},
	},
}

var evidenceMediaTypes = map[string]string{
	"accessibility-report": "application/pdf",
	"egress-report":        "application/json",
	"host-attestation":     "application/json",
	"journal":              "application/json",
	"packet-capture":       "application/vnd.tcpdump.pcap",
	"recovery-trace":       "application/json",
	"result":               "application/json",
	"security-report":      "application/json",
	"study-record":         "application/json",
	"transcript":           "text/plain",
}

var evidenceExtensions = map[string]string{
	"accessibility-report": "pdf",
	"egress-report":        "json",
	"host-attestation":     "json",
	"journal":              "json",
	"packet-capture":       "pcap",
	"recovery-trace":       "json",
	"result":               "json",
	"security-report":      "json",
	"study-record":         "json",
	"transcript":           "txt",
}

// SupportMatrix is the sole executable declaration of PF-001 native support.
type SupportMatrix struct {
	SchemaVersion         int               `json:"schema_version"`
	MatrixID              string            `json:"matrix_id"`
	Story                 string            `json:"story"`
	Owner                 string            `json:"owner"`
	ProcedureVersion      string            `json:"procedure_version"`
	MaximumEvidenceAgeSec int64             `json:"maximum_evidence_age_seconds"`
	AgentHosts            []string          `json:"agent_hosts"`
	Cells                 []SupportCell     `json:"cells"`
	Scenarios             []SupportScenario `json:"scenarios"`
}

// SupportCell declares one exact OS, architecture, distribution, storage, and
// clean-image authority cell.
type SupportCell struct {
	ID                    string     `json:"id"`
	Owner                 string     `json:"owner"`
	Status                string     `json:"status"`
	OperatingSystem       string     `json:"operating_system"`
	Architecture          string     `json:"architecture"`
	Distribution          string     `json:"distribution"`
	MinimumOSVersion      string     `json:"minimum_os_version"`
	MaximumOSVersion      string     `json:"maximum_os_version"`
	MinimumBuild          uint64     `json:"minimum_build"`
	MaximumBuild          uint64     `json:"maximum_build"`
	Filesystem            string     `json:"filesystem"`
	StockImage            StockImage `json:"stock_image"`
	RunnerLabels          []string   `json:"runner_labels"`
	RuntimeStates         []string   `json:"runtime_states"`
	PrivilegeExpectations []string   `json:"privilege_expectations"`
	RebootExpectation     string     `json:"reboot_expectation"`
	VendorChannel         string     `json:"vendor_channel"`
	OfflinePolicy         string     `json:"offline_redistribution_policy"`
	FixtureSuites         []string   `json:"fixture_suites"`
}

// StockImage binds a cell to an official clean-image acquisition and reset
// procedure. The campaign records the exact release-specific image digest.
type StockImage struct {
	Authority    string `json:"authority"`
	Source       string `json:"source"`
	ResetMethod  string `json:"reset_method"`
	IdentityKind string `json:"identity_kind"`
}

// SupportScenario declares all variants and evidence kinds required for every
// applicable cell. Empty platform/distribution lists mean all cells.
type SupportScenario struct {
	ID            string   `json:"id"`
	Platforms     []string `json:"platforms"`
	Distributions []string `json:"distributions"`
	Variants      []string `json:"variants"`
	EvidenceKinds []string `json:"evidence_kinds"`
}

// CertificationReport is the canonical statement signed by the independent
// native-certification authority after clean-host execution.
type CertificationReport struct {
	SchemaVersion              int                       `json:"schema_version"`
	MatrixID                   string                    `json:"matrix_id"`
	MatrixSHA256               string                    `json:"matrix_sha256"`
	Version                    string                    `json:"version"`
	SourceCommit               string                    `json:"source_commit"`
	PublicationSHA256          string                    `json:"publication_sha256"`
	DistributionManifestSHA256 string                    `json:"distribution_manifest_sha256"`
	ReleaseTrustSHA256         string                    `json:"release_trust_sha256"`
	CampaignID                 string                    `json:"campaign_id"`
	AuthorityKeyID             string                    `json:"authority_key_id"`
	ProcedureVersion           string                    `json:"procedure_version"`
	StartedAt                  string                    `json:"started_at"`
	CompletedAt                string                    `json:"completed_at"`
	NoWaivers                  bool                      `json:"no_waivers"`
	Cells                      []CertificationCellResult `json:"cells"`
}

// CertificationCellResult records the exact clean host and all required
// trials for one declared support cell.
type CertificationCellResult struct {
	CellID           string                     `json:"cell_id"`
	ObservedVersion  string                     `json:"observed_os_version"`
	ObservedBuild    uint64                     `json:"observed_build"`
	Filesystem       string                     `json:"filesystem"`
	StockImageSHA256 string                     `json:"stock_image_sha256"`
	HardwareSHA256   string                     `json:"hardware_sha256"`
	Trials           []CertificationTrialResult `json:"trials"`
}

// CertificationTrialResult is one no-skip result from one freshly reset host.
type CertificationTrialResult struct {
	ScenarioID  string                  `json:"scenario_id"`
	Variant     string                  `json:"variant"`
	SnapshotID  string                  `json:"snapshot_id"`
	Status      string                  `json:"status"`
	StartedAt   string                  `json:"started_at"`
	CompletedAt string                  `json:"completed_at"`
	RebootCount uint32                  `json:"reboot_count"`
	Evidence    []CertificationEvidence `json:"evidence"`
}

// CertificationEvidence binds one required attachment to its exact bytes.
type CertificationEvidence struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      uint64 `json:"size"`
	MediaType string `json:"media_type"`
}

// DetachedSignature is the canonical detached Ed25519 signature envelope.
type DetachedSignature struct {
	SchemaVersion int    `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	ReportSHA256  string `json:"report_sha256"`
	Signature     string `json:"signature"`
}

// PublicationBinding is the release identity extracted from an independently
// verified canonical publication record.
type PublicationBinding struct {
	Version                    string
	SourceCommit               string
	SHA256                     string
	DistributionManifestSHA256 string
	ReleaseTrustSHA256         string
}

// Trial identifies one exact scenario/variant required for a support cell.
type Trial struct {
	CellID        string
	ScenarioID    string
	Variant       string
	EvidenceKinds []string
}

func (m SupportMatrix) validate() error {
	if m.SchemaVersion != SupportMatrixSchemaVersion || m.Story != "PF-001" ||
		!safeID(m.MatrixID) || !safeID(m.Owner) || !safeID(m.ProcedureVersion) ||
		m.MaximumEvidenceAgeSec < 3600 || m.MaximumEvidenceAgeSec > 30*24*60*60 {
		return errors.New("support matrix authority is incomplete")
	}
	if !slices.Equal(m.AgentHosts, requiredAgentHosts) {
		return errors.New("support matrix agent-host set is incomplete or unordered")
	}
	if len(m.Cells) != len(requiredCellIDs) ||
		len(m.Scenarios) != len(requiredScenarioIDs) {
		return errors.New("support matrix cell or scenario set is incomplete")
	}
	for index, cell := range m.Cells {
		if cell.ID != requiredCellIDs[index] || cell.validate() != nil {
			return fmt.Errorf("support cell %q is invalid or unordered", cell.ID)
		}
	}
	for index, scenario := range m.Scenarios {
		scope := requiredScenarioScopes[scenario.ID]
		if scenario.ID != requiredScenarioIDs[index] || scenario.validate() != nil ||
			!slices.Equal(scenario.Variants, requiredScenarioVariants[scenario.ID]) ||
			!slices.Equal(scenario.EvidenceKinds, requiredScenarioEvidence[scenario.ID]) ||
			!slices.Equal(scenario.Platforms, scope.platforms) ||
			!slices.Equal(scenario.Distributions, scope.distributions) {
			return fmt.Errorf("support scenario %q is invalid or unordered", scenario.ID)
		}
	}
	for _, cell := range m.Cells {
		count := 0
		for _, scenario := range m.Scenarios {
			if scenario.applies(cell) {
				count += len(scenario.Variants)
			}
		}
		if count < 40 {
			return fmt.Errorf("support cell %q has an incomplete trial campaign", cell.ID)
		}
	}
	return nil
}

func (c SupportCell) validate() error {
	if !safeID(c.ID) || !safeID(c.Owner) || c.Status != "required" ||
		!slices.Contains([]string{"darwin", "linux", "windows"}, c.OperatingSystem) ||
		!slices.Contains([]string{"amd64", "arm64"}, c.Architecture) ||
		!safeID(c.Distribution) || !validNumericVersion(c.MinimumOSVersion) ||
		!validNumericVersion(c.MaximumOSVersion) || compareNumericVersions(c.MinimumOSVersion, c.MaximumOSVersion) > 0 ||
		c.MinimumBuild == 0 || c.MaximumBuild < c.MinimumBuild || !safeID(c.Filesystem) ||
		c.StockImage.validate() != nil || c.VendorChannel != "stable" ||
		!slices.Contains([]string{"redistributable", "user-supplied-official"}, c.OfflinePolicy) ||
		!slices.Contains([]string{"optional", "required-when-prerequisite-changes"}, c.RebootExpectation) {
		return errors.New("support cell fields are invalid")
	}
	if c.ID != canonicalCellID(c) {
		return errors.New("support cell identity does not match its platform projection")
	}
	if c.OperatingSystem == "darwin" && (c.Distribution != "macos-tahoe" || c.Filesystem != "apfs") ||
		c.OperatingSystem == "windows" && (c.Architecture != "amd64" || c.Distribution != "windows-11-25h2" || c.Filesystem != "ntfs") ||
		c.OperatingSystem == "linux" &&
			(!slices.Contains([]string{"ubuntu-24.04", "fedora-44"}, c.Distribution) ||
				c.Distribution == "ubuntu-24.04" && c.Filesystem != "ext4" ||
				c.Distribution == "fedora-44" && c.Filesystem != "xfs") {
		return errors.New("support cell platform projection is invalid")
	}
	if !sortedUniqueSafe(c.RunnerLabels, 5) || !slices.Contains(c.RunnerLabels, "self-hosted") ||
		!slices.Contains(c.RunnerLabels, "pf001-pristine") || !slices.Contains(c.RunnerLabels, c.ID) ||
		!slices.Equal(c.RuntimeStates, []string{"absent", "compatible-running", "compatible-stopped"}) ||
		!sortedUniqueSafe(c.PrivilegeExpectations, 1) || !sortedUniqueSafe(c.FixtureSuites, 8) {
		return errors.New("support cell execution contract is incomplete")
	}
	return nil
}

func canonicalCellID(cell SupportCell) string {
	distribution := cell.Distribution
	if cell.OperatingSystem == "windows" {
		distribution = strings.TrimPrefix(distribution, "windows-")
	}
	return strings.Join([]string{
		cell.OperatingSystem, cell.Architecture, distribution, cell.Filesystem,
	}, "-")
}

func (s StockImage) validate() error {
	parsed, err := url.Parse(s.Source)
	if !safeID(s.Authority) || err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		!safeID(s.ResetMethod) || !safeID(s.IdentityKind) {
		return errors.New("stock image authority is invalid")
	}
	return nil
}

func (s SupportScenario) validate() error {
	if !safeID(s.ID) || !sortedUniqueSafe(s.Platforms, 0) || !sortedUniqueSafe(s.Distributions, 0) ||
		!sortedUniqueSafe(s.Variants, 1) || !sortedUniqueSafe(s.EvidenceKinds, 4) {
		return errors.New("scenario fields are invalid")
	}
	for _, platform := range s.Platforms {
		if !slices.Contains([]string{"darwin", "linux", "windows"}, platform) {
			return errors.New("scenario platform is invalid")
		}
	}
	for _, kind := range s.EvidenceKinds {
		if _, present := evidenceMediaTypes[kind]; !present {
			return errors.New("scenario evidence kind is invalid")
		}
	}
	for _, required := range []string{"host-attestation", "journal", "result", "transcript"} {
		if !slices.Contains(s.EvidenceKinds, required) {
			return errors.New("scenario baseline evidence is incomplete")
		}
	}
	return nil
}

func (s SupportScenario) applies(cell SupportCell) bool {
	return (len(s.Platforms) == 0 || slices.Contains(s.Platforms, cell.OperatingSystem)) &&
		(len(s.Distributions) == 0 || slices.Contains(s.Distributions, cell.Distribution))
}

// Trials derives the complete no-skip trial set in canonical order.
func (m SupportMatrix) Trials(cellID string) ([]Trial, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	var selected *SupportCell
	for index := range m.Cells {
		if m.Cells[index].ID == cellID {
			selected = &m.Cells[index]
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("support cell %q is not declared", cellID)
	}
	trials := make([]Trial, 0, 64)
	for _, scenario := range m.Scenarios {
		if !scenario.applies(*selected) {
			continue
		}
		for _, variant := range scenario.Variants {
			trials = append(trials, Trial{
				CellID: cellID, ScenarioID: scenario.ID, Variant: variant,
				EvidenceKinds: append([]string(nil), scenario.EvidenceKinds...),
			})
		}
	}
	return trials, nil
}

// GitHubMatrix emits the exact include matrix used by certification CI.
func (m SupportMatrix) GitHubMatrix() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	type entry struct {
		CellID       string `json:"cell_id"`
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Distribution string `json:"distribution"`
		TrialCount   int    `json:"trial_count"`
	}
	document := struct {
		Include []entry `json:"include"`
	}{Include: make([]entry, 0, len(m.Cells))}
	for _, cell := range m.Cells {
		trials, _ := m.Trials(cell.ID)
		document.Include = append(document.Include, entry{
			CellID: cell.ID, OS: cell.OperatingSystem, Architecture: cell.Architecture,
			Distribution: cell.Distribution, TrialCount: len(trials),
		})
	}
	return json.Marshal(document)
}

func expectedEvidencePath(trial Trial, kind string) string {
	return strings.Join([]string{
		"evidence", trial.CellID, trial.ScenarioID, trial.Variant,
		kind + "." + evidenceExtensions[kind],
	}, "/")
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func sortedUniqueSafe(values []string, minimum int) bool {
	if len(values) < minimum || len(values) > 128 {
		return false
	}
	previous := ""
	for _, value := range values {
		if !safeID(value) {
			return false
		}
		if previous != "" && previous >= value {
			return false
		}
		previous = value
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value != strings.Repeat("0", sha256.Size*2)
}

func validNumericVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 5 {
			return false
		}
		if parsed, err := strconv.ParseUint(part, 10, 16); err != nil || parsed > 65535 {
			return false
		}
	}
	return true
}

func compareNumericVersions(left, right string) int {
	l := strings.Split(left, ".")
	r := strings.Split(right, ".")
	for len(l) < 4 {
		l = append(l, "0")
	}
	for len(r) < 4 {
		r = append(r, "0")
	}
	for index := range 4 {
		lv, _ := strconv.Atoi(l[index])
		rv, _ := strconv.Atoi(r[index])
		if lv < rv {
			return -1
		}
		if lv > rv {
			return 1
		}
	}
	return 0
}
