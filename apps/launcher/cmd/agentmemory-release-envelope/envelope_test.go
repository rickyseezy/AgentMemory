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
