package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/testsupport/releasefixture"
)

func TestPF001ReleaseEnvelopePublishesOnlyCompilerAcceptedCanonicalBytes(t *testing.T) {
	t.Parallel()
	fixture := newEnvelopeFixture(t, "key_id")
	want := []byte(`{"canonical":"signed-envelope"}`)
	var observed envelopeParts
	err := BuildEnvelope(context.Background(), fixture.options, func(parts envelopeParts) ([]byte, error) {
		observed = parts.clone()
		return want, nil
	})
	if err != nil {
		t.Fatalf("BuildEnvelope() error=%v", err)
	}
	content, err := os.ReadFile(fixture.output)
	info, statErr := os.Lstat(fixture.output)
	if err != nil || statErr != nil || !bytes.Equal(content, want) ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) ||
		info.ModTime().Unix() != fixture.options.SourceEpoch {
		t.Fatalf("output=%q info=%+v errors=(%v,%v)", content, info, err, statErr)
	}
	if observed.trustMode != "key_id" || observed.trustRootID != "agentmemory-root-2026" ||
		!bytes.Equal(observed.manifest, fixture.manifest) || !bytes.Equal(observed.signature, fixture.signature) ||
		len(observed.sigstoreBundle) != 0 || !bytes.Equal(observed.revocationSet, fixture.revocations) ||
		!bytes.Equal(observed.trustedTime, fixture.trustedTime) {
		t.Fatalf("parts=%+v", observed)
	}
	observed.manifest[0] ^= 0xff
	if bytes.Equal(observed.manifest, fixture.manifest) {
		t.Fatal("compiler projection was not independently copied")
	}
}

func TestPF001ReleaseEnvelopeSupportsOnlyOneCompleteTrustMode(t *testing.T) {
	t.Parallel()
	certificate := newEnvelopeFixture(t, "certificate_transparency")
	var observed envelopeParts
	if err := BuildEnvelope(context.Background(), certificate.options, func(parts envelopeParts) ([]byte, error) {
		observed = parts.clone()
		return []byte(`{"ct":true}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(observed.signature) != 0 || !bytes.Equal(observed.sigstoreBundle, certificate.sigstore) {
		t.Fatalf("certificate-transparency parts=%+v", observed)
	}

	for name, mutate := range map[string]func(*envelopeFixture){
		"mode":  func(fixture *envelopeFixture) { fixture.options.TrustMode = "future" },
		"root":  func(fixture *envelopeFixture) { fixture.options.TrustRootID = "" },
		"epoch": func(fixture *envelopeFixture) { fixture.options.SourceEpoch = 0 },
		"missing manifest": func(fixture *envelopeFixture) {
			fixture.options.Manifest = filepath.Join(filepath.Dir(fixture.output), "missing")
		},
		"missing signature":   func(fixture *envelopeFixture) { fixture.options.Signature = "" },
		"split key mode":      func(fixture *envelopeFixture) { fixture.options.SigstoreBundle = fixture.options.RevocationSet },
		"missing revocations": func(fixture *envelopeFixture) { fixture.options.RevocationSet = "" },
		"missing time":        func(fixture *envelopeFixture) { fixture.options.TrustedTimeEvidence = "" },
		"existing output":     func(fixture *envelopeFixture) { _ = os.WriteFile(fixture.output, []byte("existing"), 0o600) },
		"output parent": func(fixture *envelopeFixture) {
			fixture.options.Output = filepath.Join(fixture.output, "missing", "envelope")
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newEnvelopeFixture(t, "key_id")
			mutate(fixture)
			if err := BuildEnvelope(context.Background(), fixture.options,
				func(envelopeParts) ([]byte, error) { return []byte(`{"unexpected":true}`), nil }); err == nil {
				t.Fatal("BuildEnvelope() error=nil")
			}
		})
	}
	for name, mutate := range map[string]func(*envelopeFixture){
		"missing bundle":         func(fixture *envelopeFixture) { fixture.options.SigstoreBundle = "" },
		"split certificate mode": func(fixture *envelopeFixture) { fixture.options.Signature = fixture.options.RevocationSet },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newEnvelopeFixture(t, "certificate_transparency")
			mutate(fixture)
			if err := BuildEnvelope(context.Background(), fixture.options,
				func(envelopeParts) ([]byte, error) { return []byte(`{"unexpected":true}`), nil }); err == nil {
				t.Fatal("BuildEnvelope() error=nil")
			}
		})
	}
}

func TestPF001ReleaseEnvelopeRejectsCapabilitiesCompilerAndUnsafeFiles(t *testing.T) {
	t.Parallel()
	fixture := newEnvelopeFixture(t, "key_id")
	if err := BuildEnvelope(context.Background(), fixture.options, nil); err == nil {
		t.Fatal("nil compiler accepted")
	}
	if err := BuildEnvelope(context.Background(), fixture.options,
		func(envelopeParts) ([]byte, error) { return nil, errors.New("compiler") }); err == nil {
		t.Fatal("compiler failure accepted")
	}
	if err := BuildEnvelope(context.Background(), fixture.options,
		func(envelopeParts) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("empty compiler output accepted")
	}
	if err := BuildEnvelope(context.Background(), fixture.options,
		func(envelopeParts) ([]byte, error) { return make([]byte, maximumSignedEnvelopeSize+1), nil }); err == nil {
		t.Fatal("oversized compiler output accepted")
	}
	if !validEnvelopeCompilerOutput([]byte{1}, nil) ||
		!validEnvelopeCompilerOutput(make([]byte, maximumSignedEnvelopeSize), nil) ||
		validEnvelopeCompilerOutput(nil, nil) ||
		validEnvelopeCompilerOutput([]byte{1}, errors.New("compiler")) ||
		validEnvelopeCompilerOutput(make([]byte, maximumSignedEnvelopeSize+1), nil) {
		t.Fatal("compiler output boundary classification changed")
	}
	//lint:ignore SA1012 The envelope boundary must reject an adversarial nil context.
	if err := BuildEnvelope(nil, fixture.options, //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		func(envelopeParts) ([]byte, error) { return []byte(`{}`), nil }); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := os.WriteFile(fixture.options.Signature, bytes.Repeat([]byte{1}, maximumSignatureBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := BuildEnvelope(context.Background(), fixture.options,
		func(envelopeParts) ([]byte, error) { return []byte(`{}`), nil }); err == nil {
		t.Fatal("oversized signature accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := BuildEnvelope(cancelled, fixture.options,
		func(envelopeParts) ([]byte, error) { return []byte(`{}`), nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	duringCompile, cancelDuringCompile := context.WithCancel(context.Background())
	if err := BuildEnvelope(duringCompile, newEnvelopeFixture(t, "key_id").options,
		func(envelopeParts) ([]byte, error) {
			cancelDuringCompile()
			return []byte(`{}`), nil
		}); !errors.Is(err, context.Canceled) {
		t.Fatalf("compiler-time cancellation error=%v", err)
	}
}

func TestPF001ReleaseEnvelopeValuesAndFileBoundariesAreExact(t *testing.T) {
	t.Parallel()
	if maximumManifestBytes != 16*1024*1024 || maximumSignatureBytes != 4*1024 ||
		maximumSigstoreBytes != 16*1024*1024 || maximumRevocationBytes != 4*1024*1024 ||
		maximumTrustedTimeBytes != 4*1024*1024 || maximumSignedEnvelopeSize != 32*1024*1024 {
		t.Fatal("release envelope security boundaries changed")
	}
	parts := envelopeParts{
		manifest: []byte("manifest"), trustMode: "key_id", trustRootID: "root",
		signature: []byte("signature"), sigstoreBundle: []byte("sigstore"),
		revocationSet: []byte("revocations"), trustedTime: []byte("trusted-time"),
	}
	clone := parts.clone()
	for _, value := range [][]byte{clone.manifest, clone.signature, clone.sigstoreBundle, clone.revocationSet, clone.trustedTime} {
		value[0] ^= 0xff
	}
	if bytes.Equal(clone.manifest, parts.manifest) || bytes.Equal(clone.signature, parts.signature) ||
		bytes.Equal(clone.sigstoreBundle, parts.sigstoreBundle) || bytes.Equal(clone.revocationSet, parts.revocationSet) ||
		bytes.Equal(clone.trustedTime, parts.trustedTime) || clone.trustMode != parts.trustMode ||
		clone.trustRootID != parts.trustRootID {
		t.Fatal("envelopeParts.clone() did not preserve an independent exact projection")
	}
	parts.clear()
	for name, value := range map[string][]byte{
		"manifest": parts.manifest, "signature": parts.signature, "sigstore": parts.sigstoreBundle,
		"revocations": parts.revocationSet, "trusted time": parts.trustedTime,
	} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("clear() retained %s", name)
		}
	}

	root := t.TempDir()
	one := filepath.Join(root, "one")
	if err := os.WriteFile(one, []byte{'x'}, 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := readBoundedRegularFile(one, 1)
	if err != nil || string(content) != "x" {
		t.Fatalf("readBoundedRegularFile()=%q,%v", content, err)
	}
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(one, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(root, "missing"), "directory": root, "empty": empty, "link": link} {
		if _, err := readBoundedRegularFile(path, 1); err == nil {
			t.Fatalf("readBoundedRegularFile(%s) accepted", name)
		}
	}
	if _, err := readBoundedRegularFile(one, 0); err == nil {
		t.Fatal("readBoundedRegularFile accepted an over-limit file")
	}
}

func TestPF001ReleaseEnvelopeResolverRejectsEveryInvalidContract(t *testing.T) {
	t.Parallel()
	checks := []struct {
		name string
		mode string
		edit func(*EnvelopeOptions)
		want string
	}{
		{"zero epoch", "key_id", func(value *EnvelopeOptions) { value.SourceEpoch = 0 }, "release epoch and trust-root identity are required"},
		{"negative epoch", "key_id", func(value *EnvelopeOptions) { value.SourceEpoch = -1 }, "release epoch and trust-root identity are required"},
		{"missing root", "key_id", func(value *EnvelopeOptions) { value.TrustRootID = "" }, "release epoch and trust-root identity are required"},
		{"unsupported mode", "key_id", func(value *EnvelopeOptions) { value.TrustMode = "other" }, "release trust mode is unsupported"},
		{"missing manifest", "key_id", func(value *EnvelopeOptions) { value.Manifest = "" }, "release envelope inputs are incomplete"},
		{"missing revocations", "key_id", func(value *EnvelopeOptions) { value.RevocationSet = "" }, "release envelope inputs are incomplete"},
		{"missing time", "key_id", func(value *EnvelopeOptions) { value.TrustedTimeEvidence = "" }, "release envelope inputs are incomplete"},
		{"missing output", "key_id", func(value *EnvelopeOptions) { value.Output = "" }, "release envelope inputs are incomplete"},
		{"missing signature", "key_id", func(value *EnvelopeOptions) { value.Signature = "" }, "key-ID mode requires only a detached signature"},
		{"key mode bundle", "key_id", func(value *EnvelopeOptions) { value.SigstoreBundle = value.Manifest }, "key-ID mode requires only a detached signature"},
		{"missing sigstore", "certificate_transparency", func(value *EnvelopeOptions) { value.SigstoreBundle = "" }, "certificate-transparency mode requires only a Sigstore bundle"},
		{"certificate signature", "certificate_transparency", func(value *EnvelopeOptions) { value.Signature = value.Manifest }, "certificate-transparency mode requires only a Sigstore bundle"},
	}
	for _, check := range checks {
		check := check
		t.Run(check.name, func(t *testing.T) {
			t.Parallel()
			options := newEnvelopeFixture(t, check.mode).options
			check.edit(&options)
			_, err := resolveEnvelopeOptions(options)
			if err == nil || err.Error() != check.want {
				t.Fatalf("resolveEnvelopeOptions() error=%v want=%q", err, check.want)
			}
		})
	}
	minimum := newEnvelopeFixture(t, "key_id").options
	minimum.SourceEpoch = 1
	resolved, err := resolveEnvelopeOptions(minimum)
	if err != nil || resolved.SourceEpoch != 1 || resolved.TrustMode != minimum.TrustMode ||
		resolved.TrustRootID != minimum.TrustRootID || !filepath.IsAbs(resolved.Manifest) ||
		!filepath.IsAbs(resolved.Signature) || resolved.SigstoreBundle != "" ||
		!filepath.IsAbs(resolved.RevocationSet) || !filepath.IsAbs(resolved.TrustedTimeEvidence) ||
		!filepath.IsAbs(resolved.Output) {
		t.Fatalf("resolveEnvelopeOptions(minimum)=%+v,%v", resolved, err)
	}
}

func TestPF001ReleaseEnvelopePreservesWrappedReadFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		edit   func(*EnvelopeOptions)
		prefix string
	}{
		{"manifest", func(value *EnvelopeOptions) { value.Manifest += ".missing" }, "read canonical release manifest: "},
		{"revocations", func(value *EnvelopeOptions) { value.RevocationSet += ".missing" }, "read revocation evidence: "},
		{"trusted time", func(value *EnvelopeOptions) { value.TrustedTimeEvidence += ".missing" }, "read trusted-time evidence: "},
		{"signature", func(value *EnvelopeOptions) { value.Signature += ".missing" }, "read detached release signature: "},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := newEnvelopeFixture(t, "key_id").options
			test.edit(&options)
			err := BuildEnvelope(context.Background(), options, func(envelopeParts) ([]byte, error) { return []byte(`{}`), nil })
			if err == nil || errors.Unwrap(err) == nil || !strings.HasPrefix(err.Error(), test.prefix) {
				t.Fatalf("BuildEnvelope() error=%v", err)
			}
		})
	}
	options := newEnvelopeFixture(t, "certificate_transparency").options
	options.SigstoreBundle += ".missing"
	err := BuildEnvelope(context.Background(), options, func(envelopeParts) ([]byte, error) { return []byte(`{}`), nil })
	if err == nil || errors.Unwrap(err) == nil || !strings.HasPrefix(err.Error(), "read official Sigstore bundle: ") {
		t.Fatalf("BuildEnvelope(sigstore) error=%v", err)
	}
}

func TestPF001PublishEnvelopeReportsStageAndCommitFailures(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing", "envelope.json")
	if err := publishEnvelope(missing, []byte(`{}`), time.Unix(1, 0)); err == nil ||
		!strings.HasPrefix(err.Error(), "create private envelope stage: ") {
		t.Fatalf("publishEnvelope(missing parent) error=%v", err)
	}
	root := t.TempDir()
	outputDirectory := filepath.Join(root, "existing-directory")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishEnvelope(outputDirectory, []byte(`{}`), time.Unix(1, 0)); err == nil ||
		!strings.HasPrefix(err.Error(), "publish release envelope: ") {
		t.Fatalf("publishEnvelope(existing directory) error=%v", err)
	}
}

func TestPF001ReleaseEnvelopeProductionCompilerAndCommandFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := compileProductionEnvelope(envelopeParts{}); err == nil {
		t.Fatal("empty production parts accepted")
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), nil, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Release envelope creation failed") {
		t.Fatalf("run(invalid)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001ReleaseEnvelopeProductionCompilerAndCommandPublishCanonicalAuthority(t *testing.T) {
	t.Parallel()
	fixture := newEnvelopeFixture(t, "key_id")
	manifest, err := releasefixture.CanonicalManifest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.options.Manifest, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.options.TrustRootID = "release-root-2026"
	if err := BuildEnvelope(t.Context(), fixture.options, compileProductionEnvelope); err != nil {
		t.Fatalf("BuildEnvelope(production) error=%v", err)
	}
	raw, err := os.ReadFile(fixture.output)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := releaseinventory.DecodeSignedManifestV1(raw)
	if err != nil {
		t.Fatalf("DecodeSignedManifestV1() error=%v", err)
	}
	if signed.Manifest().ReleaseID() != releasefixture.ReleaseID ||
		signed.Manifest().Version() != releasefixture.Version ||
		signed.Manifest().BuildID() != releasefixture.BuildID ||
		signed.Manifest().SourceCommit() != releasefixture.SourceCommit ||
		signed.Manifest().BuildTimestamp().Unix() != releasefixture.SourceEpoch ||
		signed.TrustMode() != releaseinventory.SignatureTrustModeKeyID ||
		signed.TrustRootID() != "release-root-2026" ||
		!bytes.Equal(signed.Signature(), fixture.signature) ||
		!bytes.Equal(signed.RevocationSet(), fixture.revocations) ||
		!bytes.Equal(signed.TrustedTimeEvidence(), fixture.trustedTime) {
		t.Fatal("production envelope lost signed manifest authority")
	}
	info, err := os.Stat(fixture.output)
	if err != nil || info.ModTime().Unix() != fixture.options.SourceEpoch || info.ModTime().Nanosecond() != 0 {
		t.Fatalf("production envelope timestamp=%v error=%v", info, err)
	}

	command := newEnvelopeFixture(t, "key_id")
	if err := os.WriteFile(command.options.Manifest, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	command.options.TrustRootID = "release-root-2026"
	args := []string{
		"-manifest", command.options.Manifest,
		"-trust-mode", command.options.TrustMode,
		"-trust-root-id", command.options.TrustRootID,
		"-signature", command.options.Signature,
		"-revocation-set", command.options.RevocationSet,
		"-trusted-time", command.options.TrustedTimeEvidence,
		"-output", command.options.Output,
		"-source-date-epoch", "1784073600",
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), args, &stdout, &stderr); code != 0 ||
		stdout.String() != command.options.Output+"\n" || stderr.Len() != 0 {
		t.Fatalf("run(production)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001ReleaseEnvelopeCommandParsesTheCompleteContract(t *testing.T) {
	t.Parallel()
	fixture := newEnvelopeFixture(t, "key_id")
	args := []string{
		"-manifest", fixture.options.Manifest,
		"-trust-mode", fixture.options.TrustMode,
		"-trust-root-id", fixture.options.TrustRootID,
		"-signature", fixture.options.Signature,
		"-sigstore-bundle", "",
		"-revocation-set", fixture.options.RevocationSet,
		"-trusted-time", fixture.options.TrustedTimeEvidence,
		"-output", fixture.options.Output,
		"-source-date-epoch", "1784073600",
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr); code != 1 || stdout.Len() != 0 ||
		!strings.HasPrefix(stderr.String(), "Release envelope creation failed: ") {
		t.Fatalf("run(full contract)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"-unknown"}, &stdout, &stderr); code != 2 || stderr.Len() == 0 {
		t.Fatalf("run(unknown)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

type envelopeFixture struct {
	options               EnvelopeOptions
	output                string
	manifest, signature   []byte
	sigstore, revocations []byte
	trustedTime           []byte
}

func newEnvelopeFixture(t testing.TB, mode string) *envelopeFixture {
	t.Helper()
	root := t.TempDir()
	manifest := []byte(`{"release":"canonical"}`)
	signature := bytes.Repeat([]byte{0x42}, 64)
	sigstore := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	revocations := []byte(`{"schema_version":1,"sequence":1}`)
	trustedTime := []byte(`{"schema_version":1,"issued_at":1784116800}`)
	write := func(name string, content []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	options := EnvelopeOptions{
		Manifest: write("manifest.json", manifest), TrustMode: mode, TrustRootID: "agentmemory-root-2026",
		RevocationSet:       write("revocations.json", revocations),
		TrustedTimeEvidence: write("trusted-time.json", trustedTime),
		Output:              filepath.Join(root, "distribution-manifest.json"), SourceEpoch: 1_784_073_600,
	}
	if mode == "key_id" {
		options.Signature = write("manifest.sig", signature)
	} else {
		options.SigstoreBundle = write("manifest.sigstore.json", sigstore)
	}
	return &envelopeFixture{
		options: options, output: options.Output, manifest: manifest, signature: signature,
		sigstore: sigstore, revocations: revocations, trustedTime: trustedTime,
	}
}
