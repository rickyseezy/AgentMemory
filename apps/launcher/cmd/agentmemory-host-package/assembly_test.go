package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostpackage"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001HostPackageStaticLimitsAreExact(t *testing.T) {
	t.Parallel()
	if maximumHostAuthorityBytes != 64*1024*1024 || maximumHostTrustBytes != 128*1024 ||
		maximumBootstrapBytes != 512*1024*1024 || maximumHostObjectBytes != int64(1<<53-1) {
		t.Fatal("host package security boundaries changed")
	}
}

func TestPF001HostPackageBuildsVerifiedDeterministicVendorArchives(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		host, operatingSystem, architecture, extension, manifest string
	}{
		{"claude", "darwin", "arm64", ".mcpb", "manifest.json"},
		{"gemini", "linux", "amd64", ".zip", "gemini-extension.json"},
		{"generic", "windows", "amd64", ".zip", "agentmemory-mcp.json"},
	} {
		test := test
		t.Run(test.host+"-"+test.operatingSystem, func(t *testing.T) {
			t.Parallel()
			fixture := newHostPackageFixture(t, test.host, test.operatingSystem, test.architecture, test.extension)
			verifiers := &verifierSet{}
			if err := AssembleHostPackage(context.Background(), fixture.options, verifiers.factory); err != nil {
				t.Fatalf("AssembleHostPackage() error=%v", err)
			}
			if verifiers.publication.calls != 1 || verifiers.object.calls < 2 {
				t.Fatalf("signature calls publication/object=%d/%d", verifiers.publication.calls, verifiers.object.calls)
			}
			archive, err := zip.OpenReader(fixture.options.Output)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = archive.Close() }()
			names := make([]string, 0, len(archive.File))
			contents := make(map[string][]byte, len(archive.File))
			for _, file := range archive.File {
				names = append(names, file.Name)
				if file.Method != zip.Store || file.Modified.Unix() != fixture.options.SourceEpoch {
					t.Fatalf("%s method/timestamp=%d/%v", file.Name, file.Method, file.Modified)
				}
				wantMode := os.FileMode(0o644)
				if file.Name == "bin/"+fixture.executable {
					wantMode = 0o755
				}
				if file.Mode().Perm() != wantMode {
					t.Fatalf("%s mode=%o want=%o", file.Name, file.Mode().Perm(), wantMode)
				}
				reader, err := file.Open()
				if err != nil {
					t.Fatal(err)
				}
				contents[file.Name], err = io.ReadAll(reader)
				_ = reader.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			expected := expectedHostArchive(t, fixture, test.manifest)
			expectedNames := make([]string, 0, len(expected))
			for name := range expected {
				expectedNames = append(expectedNames, name)
			}
			sort.Strings(expectedNames)
			if !sort.StringsAreSorted(names) || !reflect.DeepEqual(names, expectedNames) || !reflect.DeepEqual(contents, expected) {
				t.Fatalf("archive names/content=%v/%v want=%v/%v", names, contents, expectedNames, expected)
			}
			record, recordErr := os.ReadFile(fixture.options.RecordOutput)
			first, err := os.ReadFile(fixture.options.Output)
			if err != nil {
				t.Fatal(err)
			}
			assertHostPackageRecord(t, fixture, first, record, recordErr)
			if len(verifiers.publication.digests) != 1 || len(verifiers.object.digests) != expectedHostObjectVerifications(test.operatingSystem) {
				t.Fatalf("signature calls publication/object=%v/%v", verifiers.publication.digests, verifiers.object.digests)
			}
			second := newHostPackageFixture(t, test.host, test.operatingSystem, test.architecture, test.extension)
			if err := AssembleHostPackage(context.Background(), second.options, (&verifierSet{}).factory); err != nil {
				t.Fatal(err)
			}
			secondRaw, _ := os.ReadFile(second.options.Output)
			if !bytes.Equal(first, secondRaw) {
				t.Fatal("identical host package inputs were not reproducible")
			}
		})
	}
}

func TestPF001HostPackageRejectsSubstitutionAndInvalidAuthority(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*hostPackageFixture, *verifierSet){
		"publication identity":  func(f *hostPackageFixture, _ *verifierSet) { f.options.Version = "1.2.4" },
		"publication signature": func(_ *hostPackageFixture, v *verifierSet) { v.publication.err = errors.New("bad") },
		"bootstrap signature":   func(_ *hostPackageFixture, v *verifierSet) { v.object.failCall = 1 },
		"bootstrap link": func(f *hostPackageFixture, _ *verifierSet) {
			_ = os.Remove(f.options.Bootstrap)
			_ = os.Symlink(f.options.TrustDocument, f.options.Bootstrap)
		},
		"native object": func(f *hostPackageFixture, _ *verifierSet) {
			_ = os.WriteFile(filepath.Join(f.options.CandidateRoot, "objects", "agentmemory-linux-amd64-deb.deb"), []byte("changed"), 0o600)
		},
		"native evidence": func(f *hostPackageFixture, _ *verifierSet) {
			_ = os.WriteFile(filepath.Join(f.options.CandidateRoot, "evidence", "agentmemory-linux-amd64-deb.sigstore.json"), []byte("changed"), 0o600)
		},
		"trust factory": func(_ *hostPackageFixture, v *verifierSet) { v.factoryErr = errors.New("trust") },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newHostPackageFixture(t, "gemini", "linux", "amd64", ".zip")
			verifiers := &verifierSet{}
			mutate(fixture, verifiers)
			if err := AssembleHostPackage(context.Background(), fixture.options, verifiers.factory); err == nil {
				t.Fatal("substitution was accepted")
			}
			if _, err := os.Lstat(fixture.options.Output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed package was published: %v", err)
			}
		})
	}
}

func TestPF001HostPackageRejectsCapabilitiesPathsAndCancellation(t *testing.T) {
	t.Parallel()
	fixture := newHostPackageFixture(t, "claude", "darwin", "amd64", ".mcpb")
	//lint:ignore SA1012 The command boundary must reject an adversarial nil context.
	if err := AssembleHostPackage(nil, fixture.options, (&verifierSet{}).factory); err == nil { //nolint:staticcheck // Boundary fixture; owner=release expiry=2027-07-15.
		t.Fatal("nil context accepted")
	}
	if err := AssembleHostPackage(context.Background(), fixture.options, nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AssembleHostPackage(cancelled, fixture.options, (&verifierSet{}).factory); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	for name, mutate := range map[string]func(*PackageOptions){
		"root":                  func(value *PackageOptions) { value.CandidateRoot = "" },
		"publication":           func(value *PackageOptions) { value.Publication = "" },
		"publication signature": func(value *PackageOptions) { value.PublicationSigstore = "" },
		"bootstrap":             func(value *PackageOptions) { value.Bootstrap = "" },
		"bootstrap signature":   func(value *PackageOptions) { value.BootstrapSigstore = "" },
		"trust":                 func(value *PackageOptions) { value.TrustDocument = "" },
		"output":                func(value *PackageOptions) { value.Output = "" },
		"record output":         func(value *PackageOptions) { value.RecordOutput = "" },
		"source epoch zero":     func(value *PackageOptions) { value.SourceEpoch = 0 },
		"source epoch negative": func(value *PackageOptions) { value.SourceEpoch = -1 },
		"host":                  func(value *PackageOptions) { value.Host = "future" },
		"cell":                  func(value *PackageOptions) { value.Architecture = "386" },
		"version":               func(value *PackageOptions) { value.Version = "" },
		"output extension":      func(value *PackageOptions) { value.Output += ".zip" },
		"record extension":      func(value *PackageOptions) { value.RecordOutput += ".txt" },
		"split output":          func(value *PackageOptions) { value.RecordOutput = filepath.Join(t.TempDir(), "record.json") },
		"same output":           func(value *PackageOptions) { value.RecordOutput = value.Output },
		"existing output":       func(value *PackageOptions) { _ = os.WriteFile(value.Output, []byte("exists"), 0o600) },
		"existing record":       func(value *PackageOptions) { _ = os.WriteFile(value.RecordOutput, []byte("exists"), 0o600) },
	} {
		value := newHostPackageFixture(t, "claude", "darwin", "amd64", ".mcpb")
		mutate(&value.options)
		if err := AssembleHostPackage(context.Background(), value.options, (&verifierSet{}).factory); err == nil {
			t.Fatalf("%s invalid options accepted", name)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"positional"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(positional)=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), nil, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "Host package assembly failed") {
		t.Fatalf("run(invalid)=%d stderr=%q", code, stderr.String())
	}
	commandFixture := newHostPackageFixture(t, "gemini", "linux", "amd64", ".zip")
	stdout.Reset()
	stderr.Reset()
	arguments := hostPackageArguments(commandFixture.options)
	if code := run(context.Background(), arguments, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "Host package assembly failed") {
		t.Fatalf("run(complete flags)=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPF001HostPackageOptionAndTrustValidationIsExact(t *testing.T) {
	t.Parallel()
	for name, clearField := range map[string]func(*PackageOptions){
		"candidate root":          func(value *PackageOptions) { value.CandidateRoot = "" },
		"publication":             func(value *PackageOptions) { value.Publication = "" },
		"publication sigstore":    func(value *PackageOptions) { value.PublicationSigstore = "" },
		"bootstrap":               func(value *PackageOptions) { value.Bootstrap = "" },
		"bootstrap sigstore":      func(value *PackageOptions) { value.BootstrapSigstore = "" },
		"trust":                   func(value *PackageOptions) { value.TrustDocument = "" },
		"output":                  func(value *PackageOptions) { value.Output = "" },
		"record output":           func(value *PackageOptions) { value.RecordOutput = "" },
		"nonpositive source time": func(value *PackageOptions) { value.SourceEpoch = 0 },
	} {
		fixture := newHostPackageFixture(t, "gemini", "linux", "amd64", ".zip")
		clearField(&fixture.options)
		resolved, err := resolvePackageOptions(fixture.options)
		if resolved.options != (PackageOptions{}) || err == nil || err.Error() != "host package inputs are incomplete" {
			t.Fatalf("%s resolved=%+v error=%v", name, resolved, err)
		}
	}
	for name, configure := range map[string]func(*verifierSet){
		"factory error":            func(value *verifierSet) { value.factoryErr = errors.New("factory") },
		"nil publication verifier": func(value *verifierSet) { value.nilPublication = true },
		"nil object verifier":      func(value *verifierSet) { value.nilObject = true },
	} {
		fixture := newHostPackageFixture(t, "gemini", "linux", "amd64", ".zip")
		verifiers := &verifierSet{}
		configure(verifiers)
		err := AssembleHostPackage(t.Context(), fixture.options, verifiers.factory)
		if err == nil || err.Error() != "host package trust is invalid" {
			t.Fatalf("%s error=%v", name, err)
		}
	}
}

func TestPF001HostPackageResolverClassifiesEveryPathAndOutputContract(t *testing.T) {
	t.Parallel()
	valid := newHostPackageFixture(t, "generic", "windows", "amd64", ".zip")
	resolved, err := resolvePackageOptions(valid.options)
	if err != nil || resolved.host != hostpackage.HostGeneric ||
		resolved.target != (hostpackage.Target{OperatingSystem: "windows", Architecture: "amd64"}) ||
		resolved.executable != "agentmemory-bootstrap.exe" || resolved.options.Version != valid.options.Version ||
		resolved.options.SourceCommit != valid.options.SourceCommit || resolved.options.SourceEpoch != valid.options.SourceEpoch {
		t.Fatalf("resolvePackageOptions(valid)=%+v,%v", resolved, err)
	}
	for _, path := range []string{
		resolved.options.CandidateRoot, resolved.options.Publication, resolved.options.PublicationSigstore,
		resolved.options.Bootstrap, resolved.options.BootstrapSigstore, resolved.options.TrustDocument,
		resolved.options.Output, resolved.options.RecordOutput,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatalf("resolved path=%q", path)
		}
	}

	tests := []struct {
		name string
		edit func(*hostPackageFixture)
		want string
	}{
		{"missing candidate", func(f *hostPackageFixture) { f.options.CandidateRoot += ".missing" }, "host package candidate root is invalid"},
		{"candidate file", func(f *hostPackageFixture) { f.options.CandidateRoot = f.options.Publication }, "host package candidate root is invalid"},
		{"candidate link", func(f *hostPackageFixture) {
			link := filepath.Join(filepath.Dir(f.options.CandidateRoot), "candidate-link")
			if err := os.Symlink(f.options.CandidateRoot, link); err != nil {
				t.Fatal(err)
			}
			f.options.CandidateRoot = link
		}, "host package candidate root is invalid"},
		{"different parents", func(f *hostPackageFixture) {
			f.options.RecordOutput = filepath.Join(t.TempDir(), "record.json")
		}, "host package outputs must be distinct siblings"},
		{"same output", func(f *hostPackageFixture) { f.options.RecordOutput = f.options.Output }, "host package outputs must be distinct siblings"},
		{"existing output", func(f *hostPackageFixture) {
			if err := os.WriteFile(f.options.Output, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "host package output already exists"},
		{"existing record", func(f *hostPackageFixture) {
			if err := os.WriteFile(f.options.RecordOutput, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "host package output already exists"},
		{"missing output parent", func(f *hostPackageFixture) {
			parent := filepath.Join(filepath.Dir(f.options.Output), "missing")
			f.options.Output = filepath.Join(parent, "package.zip")
			f.options.RecordOutput = filepath.Join(parent, "record.json")
		}, "host package output parent is invalid"},
		{"output parent link", func(f *hostPackageFixture) {
			realParent := filepath.Join(filepath.Dir(f.options.Output), "real-parent")
			if err := os.Mkdir(realParent, 0o700); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(filepath.Dir(f.options.Output), "parent-link")
			if err := os.Symlink(realParent, parent); err != nil {
				t.Fatal(err)
			}
			f.options.Output = filepath.Join(parent, "package.zip")
			f.options.RecordOutput = filepath.Join(parent, "record.json")
		}, "host package output parent is invalid"},
		{"output parent file", func(f *hostPackageFixture) {
			parent := filepath.Join(filepath.Dir(f.options.Output), "parent-file")
			if err := os.WriteFile(parent, []byte("file"), 0o600); err != nil {
				t.Fatal(err)
			}
			f.options.Output = filepath.Join(parent, "package.zip")
			f.options.RecordOutput = filepath.Join(parent, "record.json")
		}, "host package output cannot be inspected"},
		{"wrong archive extension", func(f *hostPackageFixture) { f.options.Output += ".invalid" }, "host package output format is invalid"},
		{"wrong record extension", func(f *hostPackageFixture) { f.options.RecordOutput += ".invalid" }, "host package output format is invalid"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newHostPackageFixture(t, "generic", "windows", "amd64", ".zip")
			test.edit(fixture)
			got, err := resolvePackageOptions(fixture.options)
			validError := err != nil && err.Error() == test.want
			if test.name == "output parent file" && err != nil && err.Error() == "host package output parent is invalid" {
				validError = true
			}
			if got.options != (PackageOptions{}) || !validError {
				t.Fatalf("resolvePackageOptions()=%+v,%v want=%q", got, err, test.want)
			}
		})
	}
}

func TestPF001HostPackageInspectionRejectsEachAuthorityLayerExactly(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		mutate func(*resolvedPackage, *verifierSet)
		want   string
	}{
		"version":               {func(p *resolvedPackage, _ *verifierSet) { p.options.Version = "9.9.9" }, "host package publication identity is invalid"},
		"commit":                {func(p *resolvedPackage, _ *verifierSet) { p.options.SourceCommit = strings.Repeat("b", 40) }, "host package publication identity is invalid"},
		"epoch":                 {func(p *resolvedPackage, _ *verifierSet) { p.options.SourceEpoch++ }, "host package publication identity is invalid"},
		"publication signature": {func(_ *resolvedPackage, v *verifierSet) { v.publication.err = errors.New("signature") }, "host package publication signature is invalid"},
		"bootstrap signature":   {func(_ *resolvedPackage, v *verifierSet) { v.object.failCall = 1 }, "host bootstrap signature is invalid"},
	} {
		fixture := newHostPackageFixture(t, "gemini", "linux", "amd64", ".zip")
		resolved, err := resolvePackageOptions(fixture.options)
		if err != nil {
			t.Fatal(err)
		}
		verifiers := &verifierSet{}
		test.mutate(&resolved, verifiers)
		err = resolved.inspect(t.Context(), &verifiers.publication, &verifiers.object)
		if err == nil || err.Error() != test.want {
			t.Fatalf("%s error=%v want=%q", name, err, test.want)
		}
	}
}

func TestPF001HostArchiveHelpersFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, size, err := digestRegular(source, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyVerifiedEntry(io.Discard, archiveEntry{}); err == nil {
		t.Fatal("empty archive entry accepted")
	}
	entry := archiveEntry{path: source, digest: digest, size: size + 1, maximum: 64, verifyRead: true}
	if err := copyVerifiedEntry(io.Discard, entry); err == nil {
		t.Fatal("changed source accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := writeArchive(cancelled, filepath.Join(root, "cancelled.zip"), []archiveEntry{{name: "x", content: []byte("x")}}, time.Unix(1_784_073_600, 0)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled archive error=%v", err)
	}
	if _, err := readRegular(filepath.Join(root, "missing"), 1); err == nil {
		t.Fatal("missing input accepted")
	}
	boundary := filepath.Join(root, "boundary")
	if err := os.WriteFile(boundary, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readRegular(boundary, 4); err != nil || string(raw) != "1234" {
		t.Fatalf("boundary read=%q error=%v", raw, err)
	}
	if _, err := readRegular(boundary, 3); err == nil {
		t.Fatal("oversized regular input accepted")
	}
	if got, gotSize, err := digestRegular(boundary, 4); err != nil || gotSize != 4 || !got.Equal(releaseinventory.DigestBytes([]byte("1234"))) {
		t.Fatalf("boundary digest=%v/%d error=%v", got, gotSize, err)
	}
	if _, _, err := digestRegular(boundary, 3); err == nil {
		t.Fatal("oversized digest input accepted")
	}
	entry = archiveEntry{path: boundary, digest: releaseinventory.DigestBytes([]byte("1234")), size: 4, maximum: 4, verifyRead: true}
	for name, invalid := range map[string]archiveEntry{
		"verification disabled": {path: boundary, digest: entry.digest, size: 4, maximum: 4},
		"missing path":          {digest: entry.digest, size: 4, maximum: 4, verifyRead: true},
		"zero maximum":          {path: boundary, digest: entry.digest, size: 4, verifyRead: true},
		"size above maximum":    {path: boundary, digest: entry.digest, size: 5, maximum: 4, verifyRead: true},
	} {
		if err := copyVerifiedEntry(io.Discard, invalid); err == nil || err.Error() != "host archive entry is invalid" {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	var copied bytes.Buffer
	if err := copyVerifiedEntry(&copied, entry); err != nil || copied.String() != "1234" {
		t.Fatalf("boundary copy=%q error=%v", copied.String(), err)
	}
	entry.digest = releaseinventory.DigestBytes([]byte("4321"))
	if err := copyVerifiedEntry(io.Discard, entry); err == nil {
		t.Fatal("wrong entry digest accepted")
	}
	entry.digest = releaseinventory.DigestBytes([]byte("1234"))
	entry.maximum = 3
	if err := copyVerifiedEntry(io.Discard, entry); err == nil {
		t.Fatal("entry above declared maximum accepted")
	}
	entry.maximum = 0
	if err := copyVerifiedEntry(io.Discard, entry); err == nil {
		t.Fatal("entry with zero maximum accepted")
	}
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(empty, 1); err == nil {
		t.Fatal("empty regular input accepted")
	}
	if _, _, err := digestRegular(empty, 1); err == nil {
		t.Fatal("empty digest input accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(boundary, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(link, 4); err == nil {
		t.Fatal("linked regular input accepted")
	}
	if _, _, err := digestRegular(link, 4); err == nil {
		t.Fatal("linked digest input accepted")
	}
	if _, err := readRegular(root, 4); err == nil {
		t.Fatal("directory input accepted")
	}
	if _, _, err := digestRegular(root, 4); err == nil {
		t.Fatal("directory digest input accepted")
	}
	entry = archiveEntry{path: boundary, digest: releaseinventory.DigestBytes([]byte("1234")), size: 5, maximum: 8, verifyRead: true}
	if err := copyVerifiedEntry(io.Discard, entry); err == nil || err.Error() != "host archive source changed" {
		t.Fatalf("metadata size error=%v", err)
	}
	entry.path = filepath.Join(root, "missing-entry")
	if err := copyVerifiedEntry(io.Discard, entry); err == nil || err.Error() != "host archive source changed" {
		t.Fatalf("missing source error=%v", err)
	}
	entry.path, entry.size = root, 4
	if err := copyVerifiedEntry(io.Discard, entry); err == nil || err.Error() != "host archive source changed" {
		t.Fatalf("directory source error=%v", err)
	}
	entry.path, entry.size = link, 4
	if err := copyVerifiedEntry(io.Discard, entry); err == nil || err.Error() != "host archive source changed" {
		t.Fatalf("linked source error=%v", err)
	}
	entry.path = boundary
	if err := copyVerifiedEntry(hostErrorWriter{}, entry); err == nil || err.Error() != "host archive source changed while reading" {
		t.Fatalf("target write error=%v", err)
	}
}

type hostErrorWriter struct{}

func (hostErrorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type signatureVerifierStub struct {
	calls, failCall int
	err             error
	digests         []releaseinventory.Digest
	bundles         [][]byte
}

func (v *signatureVerifierStub) VerifyArtifactSignature(ctx context.Context, digest releaseinventory.Digest, bundle []byte) error {
	v.calls++
	v.digests = append(v.digests, digest)
	v.bundles = append(v.bundles, append([]byte(nil), bundle...))
	if ctx == nil || v.err != nil || v.failCall == v.calls || digest.IsZero() || len(bundle) == 0 {
		if v.err != nil {
			return v.err
		}
		return errors.New("signature")
	}
	return nil
}

type verifierSet struct {
	publication    signatureVerifierStub
	object         signatureVerifierStub
	factoryErr     error
	nilPublication bool
	nilObject      bool
}

func (v *verifierSet) factory(encoded string) (artifactSignatureVerifier, artifactSignatureVerifier, error) {
	if raw, err := base64.StdEncoding.DecodeString(encoded); err != nil || string(raw) != "trust" {
		return nil, nil, errors.New("encoded trust")
	}
	if v.factoryErr != nil {
		return nil, nil, v.factoryErr
	}
	if v.nilPublication {
		return nil, &v.object, nil
	}
	if v.nilObject {
		return &v.publication, nil, nil
	}
	return &v.publication, &v.object, nil
}

type hostPackageFixture struct {
	options    PackageOptions
	executable string
}

func newHostPackageFixture(t testing.TB, host, operatingSystem, architecture, extension string) *hostPackageFixture {
	t.Helper()
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	if err := os.MkdirAll(filepath.Join(candidate, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(candidate, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, raw []byte) string {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	artifacts := publicationArtifacts(t, candidate, write)
	publication, err := releasepublication.NewPublication(releasepublication.PublicationInput{
		SchemaVersion: 1, ReleaseID: "agentmemory-1.2.3", Version: "1.2.3", BuildID: "build-17",
		SourceCommit: strings.Repeat("a", 40), BuildTimestamp: time.Unix(1_784_073_600, 0).UTC(),
		DistributionEnvelopeDigest: releaseinventory.DigestBytes([]byte("distribution")), DistributionEnvelopeSize: 12,
		ReleaseTrustDigest: releaseinventory.DigestBytes([]byte("release-trust")), ReleaseTrustSize: 13,
		Artifacts: artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicationRaw, err := releasepublication.EncodeV1(publication)
	if err != nil {
		t.Fatal(err)
	}
	executable := "agentmemory-bootstrap"
	if operatingSystem == "windows" {
		executable += ".exe"
	}
	output := filepath.Join(root, "agentmemory-"+host+"-"+operatingSystem+"-"+architecture+extension)
	return &hostPackageFixture{
		executable: executable,
		options: PackageOptions{
			CandidateRoot:       candidate,
			Publication:         write(filepath.Join(root, "publication.json"), publicationRaw),
			PublicationSigstore: write(filepath.Join(root, "publication.sigstore.json"), []byte("publication signature")),
			Bootstrap:           write(filepath.Join(root, executable), []byte("signed bootstrap "+operatingSystem+" "+architecture)),
			BootstrapSigstore:   write(filepath.Join(root, "bootstrap.sigstore.json"), []byte("bootstrap signature")),
			TrustDocument:       write(filepath.Join(root, "release-trust.json"), []byte("trust")),
			Output:              output, RecordOutput: output + ".record.json", Host: host,
			OperatingSystem: operatingSystem, Architecture: architecture, Version: "1.2.3",
			SourceCommit: strings.Repeat("a", 40), SourceEpoch: 1_784_073_600,
		},
	}
}

func publicationArtifacts(t testing.TB, root string, write func(string, []byte) string) []releasepublication.ArtifactInput {
	t.Helper()
	type cell struct {
		id, os, arch, ext string
		format            releasepublication.Format
		policy            releasepublication.NativePublisherPolicy
	}
	cells := []cell{
		{"agentmemory-darwin-amd64-pkg", "darwin", "amd64", "pkg", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized},
		{"agentmemory-darwin-arm64-pkg", "darwin", "arm64", "pkg", releasepublication.FormatPKG, releasepublication.PublisherPolicyAppleNotarized},
		{"agentmemory-linux-amd64-deb", "linux", "amd64", "deb", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-linux-amd64-rpm", "linux", "amd64", "rpm", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-linux-arm64-deb", "linux", "arm64", "deb", releasepublication.FormatDEB, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-linux-arm64-rpm", "linux", "arm64", "rpm", releasepublication.FormatRPM, releasepublication.PublisherPolicyLinuxPackage},
		{"agentmemory-windows-amd64-msi", "windows", "amd64", "msi", releasepublication.FormatMSI, releasepublication.PublisherPolicyMicrosoftAuthenticode},
	}
	artifacts := make([]releasepublication.ArtifactInput, 0, 8)
	for _, cell := range cells {
		object := []byte("object:" + cell.id)
		signature := []byte("signature:" + cell.id)
		write(filepath.Join(root, "objects", cell.id+"."+cell.ext), object)
		write(filepath.Join(root, "evidence", cell.id+".sigstore.json"), signature)
		artifacts = append(artifacts, releasepublication.ArtifactInput{
			ID: cell.id, Kind: releasepublication.ArtifactKindNativePackage, OperatingSystem: cell.os,
			Architecture: cell.arch, Format: cell.format, FileName: cell.id + "." + cell.ext,
			MediaType: "application/octet-stream", Digest: releaseinventory.DigestBytes(object), Size: uint64(len(object)),
			CycloneDXSBOMDigest:   releaseinventory.DigestBytes([]byte("cyclonedx:" + cell.id)),
			ProvenanceDigest:      releaseinventory.DigestBytes([]byte("provenance:" + cell.id)),
			SignatureBundleDigest: releaseinventory.DigestBytes(signature), NativePublisherPolicy: cell.policy,
		})
	}
	id := "agentmemory-offline-bundle"
	artifacts = append(artifacts, releasepublication.ArtifactInput{
		ID: id, Kind: releasepublication.ArtifactKindOfflineBundle, Format: releasepublication.FormatTarZstd,
		FileName: id + ".tar.zst", MediaType: "application/octet-stream",
		Digest: releaseinventory.DigestBytes([]byte("offline")), Size: 7,
		CycloneDXSBOMDigest:   releaseinventory.DigestBytes([]byte("cyclonedx:" + id)),
		ProvenanceDigest:      releaseinventory.DigestBytes([]byte("provenance:" + id)),
		SignatureBundleDigest: releaseinventory.DigestBytes([]byte("signature:" + id)),
		NativePublisherPolicy: releasepublication.PublisherPolicyManifestOnly,
	})
	return artifacts
}

func expectedHostArchive(t testing.TB, fixture *hostPackageFixture, manifestName string) map[string][]byte {
	t.Helper()
	host := hostpackage.Host(fixture.options.Host)
	manifest, err := hostpackage.EncodeManifest(hostpackage.ManifestInput{
		Host:    host,
		Target:  hostpackage.Target{OperatingSystem: fixture.options.OperatingSystem, Architecture: fixture.options.Architecture},
		Version: fixture.options.Version, Executable: fixture.executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string) []byte {
		// #nosec G304 -- every path is constructed from this test-owned fixture root.
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	expected := map[string][]byte{
		manifestName:                manifest,
		"bin/" + fixture.executable: read(fixture.options.Bootstrap),
		"release/agentmemory-release-publication.json":          read(fixture.options.Publication),
		"release/agentmemory-release-publication.sigstore.json": read(fixture.options.PublicationSigstore),
	}
	var formats []string
	switch fixture.options.OperatingSystem {
	case "linux":
		formats = []string{"deb", "rpm"}
	case "windows":
		formats = []string{"msi"}
	default:
		formats = []string{"pkg"}
	}
	for _, format := range formats {
		id := "agentmemory-" + fixture.options.OperatingSystem + "-" + fixture.options.Architecture + "-" + format
		expected["release/objects/"+id+"."+format] = read(filepath.Join(fixture.options.CandidateRoot, "objects", id+"."+format))
		expected["release/evidence/"+id+".sigstore.json"] = read(filepath.Join(fixture.options.CandidateRoot, "evidence", id+".sigstore.json"))
	}
	return expected
}

func expectedHostObjectVerifications(operatingSystem string) int {
	if operatingSystem == "linux" {
		return 3
	}
	return 2
}

func assertHostPackageRecord(t testing.TB, fixture *hostPackageFixture, archive, raw []byte, readErr error) {
	t.Helper()
	if readErr != nil {
		t.Fatal(readErr)
	}
	var got struct {
		Architecture               string `json:"architecture"`
		ArchiveSHA256              string `json:"archive_sha256"`
		ArchiveSize                int64  `json:"archive_size"`
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
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := os.ReadFile(fixture.options.Bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := os.ReadFile(fixture.options.Publication)
	if err != nil {
		t.Fatal(err)
	}
	publicationSignature, err := os.ReadFile(fixture.options.PublicationSigstore)
	if err != nil {
		t.Fatal(err)
	}
	want := got
	want.Architecture = fixture.options.Architecture
	want.ArchiveSHA256 = releaseinventory.DigestBytes(archive).Hex()
	want.ArchiveSize = int64(len(archive))
	want.BootstrapSHA256 = releaseinventory.DigestBytes(bootstrap).Hex()
	want.FileName = filepath.Base(fixture.options.Output)
	want.Host = fixture.options.Host
	want.OperatingSystem = fixture.options.OperatingSystem
	want.PublicationSHA256 = releaseinventory.DigestBytes(publication).Hex()
	want.PublicationSignatureSHA256 = releaseinventory.DigestBytes(publicationSignature).Hex()
	want.SchemaVersion = 1
	want.SourceCommit = fixture.options.SourceCommit
	want.SourceEpoch = fixture.options.SourceEpoch
	want.Version = fixture.options.Version
	if got != want {
		t.Fatalf("record=%+v want=%+v raw=%s", got, want, raw)
	}
}

func hostPackageArguments(options PackageOptions) []string {
	return []string{
		"-candidate-root", options.CandidateRoot,
		"-publication", options.Publication,
		"-publication-sigstore", options.PublicationSigstore,
		"-bootstrap", options.Bootstrap,
		"-bootstrap-sigstore", options.BootstrapSigstore,
		"-trust", options.TrustDocument,
		"-output", options.Output,
		"-record-output", options.RecordOutput,
		"-host", options.Host,
		"-os", options.OperatingSystem,
		"-arch", options.Architecture,
		"-version", options.Version,
		"-source-commit", options.SourceCommit,
		"-source-date-epoch", fmt.Sprintf("%d", options.SourceEpoch),
	}
}
