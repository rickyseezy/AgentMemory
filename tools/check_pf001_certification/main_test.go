package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/tools/internal/pf001certification"
)

func TestPF001CertificationCommandValidatesAndGeneratesReviewedMatrix(t *testing.T) {
	t.Parallel()
	path := commandMatrixPath(t)
	for name, args := range map[string][]string{
		"validate": {"-matrix", path},
		"generate": {"-matrix", path, "-emit-github-matrix"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("run()=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if name == "validate" && !strings.HasPrefix(stdout.String(), "PF-001 support matrix check passed:") {
				t.Fatalf("validation output=%q", stdout.String())
			}
			if name == "generate" && !strings.Contains(stdout.String(), `"windows-amd64-11-25h2-ntfs"`) {
				t.Fatalf("matrix output=%q", stdout.String())
			}
		})
	}
}

func TestPF001CertificationCommandCanonicalizesOnlyStrictReportJSON(t *testing.T) {
	t.Parallel()
	report := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(report, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-matrix", commandMatrixPath(t), "-canonicalize-report", report}, &stdout, &stderr); code != 0 ||
		!strings.HasSuffix(stdout.String(), "\n") || !strings.Contains(stdout.String(), `"schema_version":0`) {
		t.Fatalf("run(canonicalize)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := os.WriteFile(report, []byte(`{"foreign":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-matrix", commandMatrixPath(t), "-canonicalize-report", report}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "certification check failed") {
		t.Fatalf("run(foreign)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001CertificationCommandAssemblesExternalSignatureEnvelope(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	reportPath := filepath.Join(directory, "report.json")
	rawSignaturePath := filepath.Join(directory, "report.ed25519")
	var canonical, canonicalErrors bytes.Buffer
	inputPath := filepath.Join(directory, "input.json")
	if err := os.WriteFile(inputPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-matrix", commandMatrixPath(t), "-canonicalize-report", inputPath}, &canonical, &canonicalErrors); code != 0 {
		t.Fatalf("canonicalize=%d stderr=%q", code, canonicalErrors.String())
	}
	if err := os.WriteFile(reportPath, canonical.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rawSignaturePath, ed25519.Sign(privateKey, canonical.Bytes()), 0o600); err != nil {
		t.Fatal(err)
	}
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKey)
	var keyIDOutput, keyIDErrors bytes.Buffer
	if code := run([]string{
		"-matrix", commandMatrixPath(t), "-print-authority-key-id", "-public-key-base64", encodedPublicKey,
	}, &keyIDOutput, &keyIDErrors); code != 0 ||
		!strings.HasPrefix(keyIDOutput.String(), "native-certification-") || keyIDErrors.Len() != 0 {
		t.Fatalf("key ID=%d stdout=%q stderr=%q", code, keyIDOutput.String(), keyIDErrors.String())
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-matrix", commandMatrixPath(t),
		"-assemble-signature-report", reportPath,
		"-raw-signature", rawSignaturePath,
		"-public-key-base64", encodedPublicKey,
	}, &stdout, &stderr)
	var envelope struct {
		SchemaVersion int    `json:"schema_version"`
		Algorithm     string `json:"algorithm"`
	}
	if code != 0 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &envelope) != nil ||
		envelope.SchemaVersion != 1 || envelope.Algorithm != "ed25519" {
		t.Fatalf("assemble=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-matrix", commandMatrixPath(t), "-raw-signature", rawSignaturePath}, &stdout, &stderr); code != 2 {
		t.Fatalf("unpaired raw signature=%d stderr=%q", code, stderr.String())
	}
}

func TestPF001CertificationCommandRejectsAmbiguousOrIncompleteInvocation(t *testing.T) {
	t.Parallel()
	matrix := commandMatrixPath(t)
	for name, args := range map[string][]string{
		"positional":       {"-matrix", matrix, "foreign"},
		"mixed modes":      {"-matrix", matrix, "-emit-github-matrix", "-bundle", "bundle.zip"},
		"matrix extras":    {"-matrix", matrix, "-emit-github-matrix", "-output", "foreign.zip"},
		"campaign missing": {"-matrix", matrix, "-campaign-root", t.TempDir()},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 || stderr.Len() == 0 {
				t.Fatalf("run()=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-matrix", filepath.Join(t.TempDir(), "missing.json")}, &stdout, &stderr); code != 1 {
		t.Fatalf("run(missing matrix)=%d stderr=%q", code, stderr.String())
	}
}

func TestPF001CertificationCommandVerifiesAndBundlesCompleteCampaign(t *testing.T) {
	t.Parallel()
	fixture := newCommandCampaignFixture(t)
	common := []string{
		"-matrix", commandMatrixPath(t),
		"-publication", fixture.publication,
		"-public-key-base64", fixture.publicKey,
		"-expected-version", fixture.version,
		"-expected-source-commit", fixture.commit,
		"-verification-time-unix", fmt.Sprint(fixture.verificationTime.Unix()),
	}
	bundle := filepath.Join(t.TempDir(), "campaign.zip")
	for name, arguments := range map[string][]string{
		"root":   append(append([]string(nil), common...), "-campaign-root", fixture.root),
		"create": append(append([]string(nil), common...), "-campaign-root", fixture.root, "-output", bundle),
	} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 0 || stderr.Len() != 0 ||
			!strings.Contains(stdout.String(), "native certification check passed") {
			t.Fatalf("%s=%d stdout=%q stderr=%q", name, code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	bundleArguments := append(append([]string(nil), common...), "-bundle", bundle)
	if code := run(bundleArguments, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("bundle=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001CertificationCommandMapsClosedFailureModes(t *testing.T) {
	t.Parallel()
	fixture := newCommandCampaignFixture(t)
	common := []string{
		"-matrix", commandMatrixPath(t), "-publication", fixture.publication,
		"-public-key-base64", fixture.publicKey, "-expected-version", fixture.version,
		"-expected-source-commit", fixture.commit,
		"-verification-time-unix", fmt.Sprint(fixture.verificationTime.Unix()),
	}
	validBundle := filepath.Join(t.TempDir(), "valid.zip")
	var ignored, setupErrors bytes.Buffer
	create := append(append([]string(nil), common...), "-campaign-root", fixture.root, "-output", validBundle)
	if code := run(create, &ignored, &setupErrors); code != 0 {
		t.Fatalf("setup bundle=%d stderr=%q", code, setupErrors.String())
	}
	report := filepath.Join(fixture.root, "native-certification.json")
	invalidSignature := filepath.Join(t.TempDir(), "invalid.ed25519")
	if err := os.WriteFile(invalidSignature, make([]byte, ed25519.SignatureSize), 0o600); err != nil {
		t.Fatal(err)
	}
	existingOutput := filepath.Join(t.TempDir(), "existing.zip")
	if err := os.WriteFile(existingOutput, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	badBundle := filepath.Join(t.TempDir(), "bad.zip")
	if err := os.WriteFile(badBundle, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		arguments []string
		stdout    *failingWriter
		expected  int
	}{
		{name: "flag parse", arguments: []string{"-unknown"}, expected: 2},
		{name: "matrix stdout", arguments: []string{"-matrix", commandMatrixPath(t)}, stdout: &failingWriter{}, expected: 1},
		{name: "generated matrix extras", arguments: []string{"-matrix", commandMatrixPath(t), "-emit-github-matrix", "-publication", fixture.publication}, expected: 2},
		{name: "generated matrix stdout", arguments: []string{"-matrix", commandMatrixPath(t), "-emit-github-matrix"}, stdout: &failingWriter{}, expected: 1},
		{name: "key ID ambiguous", arguments: []string{"-matrix", commandMatrixPath(t), "-print-authority-key-id"}, expected: 2},
		{name: "key ID invalid", arguments: []string{"-matrix", commandMatrixPath(t), "-print-authority-key-id", "-public-key-base64", "invalid"}, expected: 1},
		{name: "key ID stdout", arguments: []string{"-matrix", commandMatrixPath(t), "-print-authority-key-id", "-public-key-base64", fixture.publicKey}, stdout: &failingWriter{}, expected: 1},
		{name: "canonical extras", arguments: []string{"-matrix", commandMatrixPath(t), "-canonicalize-report", report, "-publication", fixture.publication}, expected: 2},
		{name: "canonical missing", arguments: []string{"-matrix", commandMatrixPath(t), "-canonicalize-report", filepath.Join(t.TempDir(), "missing")}, expected: 1},
		{name: "canonical stdout", arguments: []string{"-matrix", commandMatrixPath(t), "-canonicalize-report", report}, stdout: &failingWriter{}, expected: 1},
		{name: "signature ambiguous", arguments: []string{"-matrix", commandMatrixPath(t), "-assemble-signature-report", report, "-raw-signature", invalidSignature}, expected: 2},
		{name: "signature missing", arguments: []string{"-matrix", commandMatrixPath(t), "-assemble-signature-report", filepath.Join(t.TempDir(), "missing"), "-raw-signature", invalidSignature, "-public-key-base64", fixture.publicKey}, expected: 1},
		{name: "signature invalid", arguments: []string{"-matrix", commandMatrixPath(t), "-assemble-signature-report", report, "-raw-signature", invalidSignature, "-public-key-base64", fixture.publicKey}, expected: 1},
		{name: "publication mismatch", arguments: append(append([]string(nil), common...), "-campaign-root", fixture.root, "-expected-version", "9.9.9"), expected: 1},
		{name: "campaign key invalid", arguments: append(append([]string(nil), common...), "-campaign-root", fixture.root, "-public-key-base64", "invalid"), expected: 1},
		{name: "root verification", arguments: append(append([]string(nil), common...), "-campaign-root", fixture.root, "-required-cell", "foreign-cell"), expected: 1},
		{name: "bundle create", arguments: append(append([]string(nil), common...), "-campaign-root", fixture.root, "-output", existingOutput), expected: 1},
		{name: "bundle output", arguments: append(append([]string(nil), common...), "-bundle", validBundle, "-output", existingOutput), expected: 2},
		{name: "bundle invalid", arguments: append(append([]string(nil), common...), "-bundle", badBundle), expected: 1},
		{name: "success stdout", arguments: append(append([]string(nil), common...), "-bundle", validBundle), stdout: &failingWriter{}, expected: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout := io.Writer(&bytes.Buffer{})
			if test.stdout != nil {
				stdout = test.stdout
			}
			var stderr bytes.Buffer
			if code := run(test.arguments, stdout, &stderr); code != test.expected {
				t.Fatalf("run()=%d want=%d stderr=%q", code, test.expected, stderr.String())
			}
		})
	}
}

type failingWriter struct{}

func (*failingWriter) Write([]byte) (int, error) { return 0, errors.New("writer failed") }

type commandCampaignFixture struct {
	root, publication, publicKey, version, commit string
	verificationTime                              time.Time
}

func newCommandCampaignFixture(t testing.TB) commandCampaignFixture {
	t.Helper()
	matrix, matrixDigest, err := pf001certification.LoadSupportMatrix(commandMatrixPath(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	version := "1.2.3"
	commit := strings.Repeat("a", 40)
	publicationRaw := []byte(fmt.Sprintf(
		`{"schema_version":1,"version":%q,"source_commit":%q,"distribution_manifest_sha256":%q,"release_trust_sha256":%q}`,
		version, commit, strings.Repeat("b", 64), strings.Repeat("c", 64),
	))
	publication := filepath.Join(t.TempDir(), "publication.json")
	if err := os.WriteFile(publication, publicationRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := pf001certification.AuthorityKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	report := pf001certification.CertificationReport{
		SchemaVersion: 1, MatrixID: matrix.MatrixID, MatrixSHA256: matrixDigest,
		Version: version, SourceCommit: commit, PublicationSHA256: commandSHA256(publicationRaw),
		DistributionManifestSHA256: strings.Repeat("b", 64), ReleaseTrustSHA256: strings.Repeat("c", 64),
		CampaignID: "campaign-command-test", AuthorityKeyID: keyID, ProcedureVersion: matrix.ProcedureVersion,
		StartedAt: start.Format(time.RFC3339), CompletedAt: start.Add(time.Hour).Format(time.RFC3339), NoWaivers: true,
		Cells: make([]pf001certification.CertificationCellResult, 0, len(matrix.Cells)),
	}
	snapshot := 0
	for _, cell := range matrix.Cells {
		trials, trialError := matrix.Trials(cell.ID)
		if trialError != nil {
			t.Fatal(trialError)
		}
		cellResult := pf001certification.CertificationCellResult{
			CellID: cell.ID, ObservedVersion: cell.MinimumOSVersion, ObservedBuild: cell.MinimumBuild,
			Filesystem: cell.Filesystem, StockImageSHA256: commandSHA256([]byte("image-" + cell.ID)),
			HardwareSHA256: commandSHA256([]byte("hardware-" + cell.ID)),
			Trials:         make([]pf001certification.CertificationTrialResult, 0, len(trials)),
		}
		for _, trial := range trials {
			snapshot++
			trialResult := pf001certification.CertificationTrialResult{
				ScenarioID: trial.ScenarioID, Variant: trial.Variant, SnapshotID: fmt.Sprintf("snapshot-%04d", snapshot),
				Status: "passed", StartedAt: start.Add(time.Minute).Format(time.RFC3339),
				CompletedAt: start.Add(2 * time.Minute).Format(time.RFC3339),
				Evidence:    make([]pf001certification.CertificationEvidence, 0, len(trial.EvidenceKinds)),
			}
			if strings.Contains(trial.Variant, "reboot") {
				trialResult.RebootCount = 1
			}
			for _, kind := range trial.EvidenceKinds {
				extension, mediaType := commandEvidenceType(kind)
				path := strings.Join([]string{"evidence", cell.ID, trial.ScenarioID, trial.Variant, kind + "." + extension}, "/")
				contents := []byte("command certification evidence: " + path)
				target := filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, contents, 0o600); err != nil {
					t.Fatal(err)
				}
				trialResult.Evidence = append(trialResult.Evidence, pf001certification.CertificationEvidence{
					Kind: kind, Path: path, SHA256: commandSHA256(contents), Size: uint64(len(contents)), MediaType: mediaType,
				})
			}
			cellResult.Trials = append(cellResult.Trials, trialResult)
		}
		report.Cells = append(report.Cells, cellResult)
	}
	draft, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := pf001certification.CanonicalizeReport(draft)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "native-certification.json"), canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	envelope, err := pf001certification.AssembleDetachedSignature(canonical, publicKey, ed25519.Sign(privateKey, canonical))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "native-certification.signature.json"), envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	return commandCampaignFixture{
		root: root, publication: publication, publicKey: base64.StdEncoding.EncodeToString(publicKey),
		version: version, commit: commit, verificationTime: start.Add(2 * time.Hour),
	}
}

func commandEvidenceType(kind string) (string, string) {
	values := map[string][2]string{
		"accessibility-report": {"pdf", "application/pdf"},
		"egress-report":        {"json", "application/json"},
		"host-attestation":     {"json", "application/json"},
		"journal":              {"json", "application/json"},
		"packet-capture":       {"pcap", "application/vnd.tcpdump.pcap"},
		"recovery-trace":       {"json", "application/json"},
		"result":               {"json", "application/json"},
		"security-report":      {"json", "application/json"},
		"study-record":         {"json", "application/json"},
		"transcript":           {"txt", "text/plain"},
	}
	return values[kind][0], values[kind][1]
}

func commandSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func commandMatrixPath(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "contracts", "pf001", "support-matrix-v1.json"))
}
