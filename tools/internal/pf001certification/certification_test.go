package pf001certification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPF001SupportMatrixGeneratesEveryRequiredCellAndTrial(t *testing.T) {
	t.Parallel()
	matrix, digest, err := LoadSupportMatrix(matrixFixturePath(t))
	if err != nil || !validSHA256(digest) || len(matrix.Cells) != 7 {
		t.Fatalf("LoadSupportMatrix() cells=%d digest=%q error=%v", len(matrix.Cells), digest, err)
	}
	raw, err := matrix.GitHubMatrix()
	if err != nil || !json.Valid(raw) || !strings.Contains(string(raw), `"trial_count":58`) {
		t.Fatalf("GitHubMatrix()=%s,%v", raw, err)
	}
	for _, cell := range matrix.Cells {
		trials, err := matrix.Trials(cell.ID)
		if err != nil || len(trials) < 40 {
			t.Fatalf("Trials(%s)=%d,%v", cell.ID, len(trials), err)
		}
		for _, trial := range trials {
			for _, kind := range trial.EvidenceKinds {
				if !safeArchivePath(expectedEvidencePath(trial, kind)) {
					t.Fatalf("unsafe derived evidence path for %+v/%s", trial, kind)
				}
			}
		}
	}
}

func TestPF001AssembleDetachedSignatureAcceptsOnlyExactExternalSignature(t *testing.T) {
	t.Parallel()
	report, err := CanonicalizeReport([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawSignature := ed25519.Sign(privateKey, report)
	envelope, err := AssembleDetachedSignature(report, publicKey, rawSignature)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCanonicalSignature(envelope)
	keyID, _ := AuthorityKeyID(publicKey)
	if err != nil || decoded.KeyID != keyID || decoded.ReportSHA256 != sha256Hex(report) {
		t.Fatalf("signature=%+v error=%v", decoded, err)
	}
	for name, input := range map[string]struct {
		report    []byte
		publicKey ed25519.PublicKey
		signature []byte
	}{
		"noncanonical report": {report: bytes.TrimSpace(report), publicKey: publicKey, signature: rawSignature},
		"wrong key":           {report: report, publicKey: append(ed25519.PublicKey(nil), publicKey...), signature: append([]byte(nil), rawSignature...)},
		"short signature":     {report: report, publicKey: publicKey, signature: rawSignature[:len(rawSignature)-1]},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "wrong key" {
				input.publicKey[0] ^= 0xff
			}
			if raw, assembleError := AssembleDetachedSignature(input.report, input.publicKey, input.signature); assembleError == nil || raw != nil {
				t.Fatalf("AssembleDetachedSignature() raw=%q error=%v", raw, assembleError)
			}
		})
	}
}

func TestPF001SupportMatrixRejectsSemanticSchemaAndTransportDrift(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(matrixFixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{
		"duplicate key":    []byte(strings.Replace(string(raw), `"schema_version": 1`, `"schema_version": 1, "schema_version": 1`, 1)),
		"unknown field":    []byte(strings.Replace(string(raw), `"story": "PF-001"`, `"story": "PF-001", "waiver": true`, 1)),
		"missing cell":     []byte(strings.Replace(string(raw), `"status": "required"`, `"status": "skipped"`, 1)),
		"unstable vendor":  []byte(strings.Replace(string(raw), `"vendor_channel": "stable"`, `"vendor_channel": "beta"`, 1)),
		"missing host":     []byte(strings.Replace(string(raw), "    \"codex\",\n", "", 1)),
		"removed trial":    []byte(strings.Replace(string(raw), "        \"codex-config-install\",\n", "", 1)),
		"foreign evidence": []byte(strings.Replace(string(raw), `"transcript"`, `"terminal-secret-dump"`, 1)),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if matrix, digest, err := DecodeSupportMatrix(mutated); err == nil || digest != "" || matrix.MatrixID != "" {
				t.Fatalf("DecodeSupportMatrix(mutated)=%+v,%q,%v", matrix, digest, err)
			}
		})
	}
}

func TestPF001SupportMatrixRejectsCellAndScenarioScopeSubstitution(t *testing.T) {
	t.Parallel()
	matrix, _, err := LoadSupportMatrix(matrixFixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*SupportMatrix){
		"additional cell": func(candidate *SupportMatrix) {
			clone := candidate.Cells[0]
			clone.ID = "darwin-amd64-macos-tahoe-extra-apfs"
			candidate.Cells = append(candidate.Cells, clone)
		},
		"missing distribution cell": func(candidate *SupportMatrix) {
			candidate.Cells[3].Distribution = "fedora-44"
			candidate.Cells[3].Filesystem = "xfs"
		},
		"wrong native filesystem": func(candidate *SupportMatrix) {
			candidate.Cells[2].Filesystem = "ext4"
		},
		"broadened apt scope": func(candidate *SupportMatrix) {
			candidate.Scenarios[4].Platforms = nil
			candidate.Scenarios[4].Distributions = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := matrix
			candidate.Cells = append([]SupportCell(nil), matrix.Cells...)
			candidate.Scenarios = append([]SupportScenario(nil), matrix.Scenarios...)
			mutate(&candidate)
			raw, marshalError := json.Marshal(candidate)
			if marshalError != nil {
				t.Fatal(marshalError)
			}
			if decoded, digest, decodeError := DecodeSupportMatrix(raw); decodeError == nil ||
				digest != "" || decoded.MatrixID != "" {
				t.Fatalf("DecodeSupportMatrix(substituted)=%+v,%q,%v", decoded, digest, decodeError)
			}
		})
	}
}

func TestPF001NativeCertificationVerifiesExactRootAndCanonicalBundle(t *testing.T) {
	t.Parallel()
	fixture := newCertificationFixture(t)
	verification, err := VerifyRoot(fixture.root, fixture.options)
	if err != nil || len(verification.Paths) < 300 || verification.Report.CampaignID != "campaign-release-1" {
		t.Fatalf("VerifyRoot() paths=%d report=%+v error=%v", len(verification.Paths), verification.Report, err)
	}
	bundle := filepath.Join(t.TempDir(), "native-certification.zip")
	if err := CreateBundle(fixture.root, bundle, fixture.options); err != nil {
		t.Fatal(err)
	}
	bundled, err := VerifyBundle(bundle, fixture.options)
	if err != nil || !json.Valid(bundled.ReportRaw) || len(bundled.Paths) != len(verification.Paths) {
		t.Fatalf("VerifyBundle() paths=%d error=%v", len(bundled.Paths), err)
	}
	if err := CreateBundle(fixture.root, bundle, fixture.options); err == nil {
		t.Fatal("CreateBundle() replaced an existing output")
	}
}

func TestPF001NativeCertificationRejectsEveryTrustBoundarySubstitution(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*testing.T, *certificationFixture){
		"evidence bytes": func(t *testing.T, fixture *certificationFixture) {
			path := fixture.report.Cells[0].Trials[0].Evidence[0].Path
			if err := os.WriteFile(filepath.Join(fixture.root, filepath.FromSlash(path)), []byte("substituted"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"foreign file": func(t *testing.T, fixture *certificationFixture) {
			if err := os.WriteFile(filepath.Join(fixture.root, "foreign.txt"), []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"skip": func(t *testing.T, fixture *certificationFixture) {
			fixture.report.Cells[0].Trials[0].Status = "skipped"
			fixture.rewriteAuthority(t)
		},
		"reused snapshot": func(t *testing.T, fixture *certificationFixture) {
			fixture.report.Cells[0].Trials[1].SnapshotID = fixture.report.Cells[0].Trials[0].SnapshotID
			fixture.rewriteAuthority(t)
		},
		"wrong publication": func(_ *testing.T, fixture *certificationFixture) {
			fixture.options.Publication.SHA256 = hashString("other-publication")
		},
		"wrong matrix": func(_ *testing.T, fixture *certificationFixture) {
			fixture.options.MatrixSHA256 = hashString("other-matrix")
		},
		"wrong public key": func(t *testing.T, fixture *certificationFixture) {
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			fixture.options.PublicKey = public
		},
		"stale": func(_ *testing.T, fixture *certificationFixture) {
			fixture.options.VerificationTime = fixture.options.VerificationTime.Add(8 * 24 * time.Hour)
		},
		"missing required cell": func(_ *testing.T, fixture *certificationFixture) {
			fixture.options.RequiredCell = "foreign-cell"
		},
		"noncanonical report": func(t *testing.T, fixture *certificationFixture) {
			raw, err := os.ReadFile(filepath.Join(fixture.root, reportPath))
			if err != nil {
				t.Fatal(err)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, raw, "", "  "); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixture.root, reportPath), pretty.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newCertificationFixture(t)
			mutate(t, fixture)
			if _, err := VerifyRoot(fixture.root, fixture.options); err == nil {
				t.Fatal("VerifyRoot() accepted substituted native evidence")
			}
		})
	}
}

func TestPF001CertificationCodecsRejectAmbiguousAuthority(t *testing.T) {
	t.Parallel()
	fixture := newCertificationFixture(t)
	reportRaw, err := os.ReadFile(filepath.Join(fixture.root, reportPath))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(reportRaw, &document); err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(document, "", "  ")
	canonical, err := CanonicalizeReport(pretty)
	if err != nil || string(canonical) != string(reportRaw) {
		t.Fatalf("CanonicalizeReport() mismatch error=%v", err)
	}
	publicationRaw := publicationFixtureRaw()
	binding, err := DecodePublicationBinding(publicationRaw)
	if err != nil || binding.Version != "1.2.3" || !validSHA256(binding.SHA256) {
		t.Fatalf("DecodePublicationBinding()=%+v,%v", binding, err)
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(publicationRaw), `"version":"1.2.3"`, `"version":"1.2.3","version":"1.2.4"`, 1)),
		append(append([]byte(nil), publicationRaw...), []byte("{}")...),
	} {
		if _, err := DecodePublicationBinding(raw); err == nil {
			t.Fatal("DecodePublicationBinding() accepted ambiguous JSON")
		}
	}
	if _, err := DecodePublicKeyBase64("invalid"); err == nil {
		t.Fatal("DecodePublicKeyBase64() accepted invalid authority")
	}
	if _, err := AuthorityKeyID(nil); err == nil {
		t.Fatal("AuthorityKeyID() accepted absent authority")
	}
	publicationPath := filepath.Join(t.TempDir(), "publication.json")
	if err := os.WriteFile(publicationPath, publicationRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadPublicationBinding(publicationPath); err != nil || loaded != binding {
		t.Fatalf("LoadPublicationBinding()=%+v,%v", loaded, err)
	}
	if _, err := LoadPublicationBinding(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("LoadPublicationBinding() accepted missing authority")
	}
}

func TestPF001CertificationPrimitiveValidatorsRemainClosed(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "Uppercase", "contains_underscore", strings.Repeat("a", 129)} {
		if safeID(value) {
			t.Fatalf("safeID(%q)=true", value)
		}
	}
	if safeID("campaign-2026.1") == false || sortedUniqueSafe([]string{"a", "b"}, 2) == false ||
		sortedUniqueSafe([]string{"b", "a"}, 2) || sortedUniqueSafe([]string{"a", "a"}, 1) {
		t.Fatal("safe identifier sequence validation drifted")
	}
	for _, value := range []string{"1.2", "01.2.3", "1.2.x", "1.2.3.4"} {
		if validStableVersion(value) {
			t.Fatalf("validStableVersion(%q)=true", value)
		}
	}
	for _, value := range []string{"1", "1.2.3.4.5", "1.-2", "70000.1"} {
		if validNumericVersion(value) {
			t.Fatalf("validNumericVersion(%q)=true", value)
		}
	}
	for _, value := range []string{"", "/absolute", "dot/../path", "back\\slash", ".hidden/file", "directory/"} {
		if safeArchivePath(value) {
			t.Fatalf("safeArchivePath(%q)=true", value)
		}
	}
	if _, err := exactUTC("2026-07-15T10:00:00+04:00"); err == nil {
		t.Fatal("exactUTC() accepted a non-UTC timestamp")
	}
}

type certificationFixture struct {
	root       string
	report     CertificationReport
	privateKey ed25519.PrivateKey
	options    VerifyOptions
}

func newCertificationFixture(t testing.TB) *certificationFixture {
	t.Helper()
	matrix, matrixDigest, err := LoadSupportMatrix(matrixFixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	publication, err := DecodePublicationBinding(publicationFixtureRaw())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := AuthorityKeyID(publicKey)
	verificationTime := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	start := verificationTime.Add(-3 * time.Hour)
	end := verificationTime.Add(-time.Hour)
	report := CertificationReport{
		SchemaVersion: CertificationSchemaVersion, MatrixID: matrix.MatrixID, MatrixSHA256: matrixDigest,
		Version: publication.Version, SourceCommit: publication.SourceCommit, PublicationSHA256: publication.SHA256,
		DistributionManifestSHA256: publication.DistributionManifestSHA256,
		ReleaseTrustSHA256:         publication.ReleaseTrustSHA256,
		CampaignID:                 "campaign-release-1", AuthorityKeyID: keyID, ProcedureVersion: matrix.ProcedureVersion,
		StartedAt: start.Format(time.RFC3339), CompletedAt: end.Format(time.RFC3339), NoWaivers: true,
		Cells: make([]CertificationCellResult, 0, len(matrix.Cells)),
	}
	root := t.TempDir()
	snapshot := 0
	for _, cell := range matrix.Cells {
		trials, err := matrix.Trials(cell.ID)
		if err != nil {
			t.Fatal(err)
		}
		result := CertificationCellResult{
			CellID: cell.ID, ObservedVersion: cell.MinimumOSVersion, ObservedBuild: cell.MinimumBuild,
			Filesystem: cell.Filesystem, StockImageSHA256: hashString("stock-" + cell.ID),
			HardwareSHA256: hashString("hardware-" + cell.ID),
			Trials:         make([]CertificationTrialResult, 0, len(trials)),
		}
		for trialIndex, trial := range trials {
			snapshot++
			trialStart := start.Add(time.Duration(trialIndex+1) * time.Second)
			observed := CertificationTrialResult{
				ScenarioID: trial.ScenarioID, Variant: trial.Variant,
				SnapshotID: "snapshot-" + strings.ReplaceAll(cell.ID, ".", "-") + "-" + padSnapshot(snapshot),
				Status:     "passed", StartedAt: trialStart.Format(time.RFC3339),
				CompletedAt: trialStart.Add(time.Second).Format(time.RFC3339),
				Evidence:    make([]CertificationEvidence, 0, len(trial.EvidenceKinds)),
			}
			if strings.Contains(trial.Variant, "reboot") {
				observed.RebootCount = 1
			}
			for _, kind := range trial.EvidenceKinds {
				path := expectedEvidencePath(trial, kind)
				content := []byte("PF-001 evidence\n" + path + "\n")
				target := filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, content, 0o600); err != nil {
					t.Fatal(err)
				}
				observed.Evidence = append(observed.Evidence, CertificationEvidence{
					Kind: kind, Path: path, SHA256: hashBytes(content), Size: uint64(len(content)),
					MediaType: evidenceMediaTypes[kind],
				})
			}
			result.Trials = append(result.Trials, observed)
		}
		report.Cells = append(report.Cells, result)
	}
	fixture := &certificationFixture{
		root: root, report: report, privateKey: privateKey,
		options: VerifyOptions{
			Matrix: matrix, MatrixSHA256: matrixDigest, Publication: publication, PublicKey: publicKey,
			VerificationTime: verificationTime,
		},
	}
	fixture.rewriteAuthority(t)
	return fixture
}

func (f *certificationFixture) rewriteAuthority(t testing.TB) {
	t.Helper()
	raw, err := json.Marshal(f.report)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	signature, err := signReportForTest(raw, f.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, reportPath), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, signaturePath), signature, 0o600); err != nil {
		t.Fatal(err)
	}
}

func publicationFixtureRaw() []byte {
	return []byte(`{"schema_version":1,"version":"1.2.3","source_commit":"1234567890abcdef1234567890abcdef12345678","distribution_manifest_sha256":"` +
		hashString("distribution") + `","release_trust_sha256":"` + hashString("trust") + `"}` + "\n")
}

func matrixFixturePath(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "contracts", "pf001", "support-matrix-v1.json"))
}

func hashString(value string) string { return hashBytes([]byte(value)) }

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func padSnapshot(value int) string {
	return fmt.Sprintf("%04d", value)
}
