package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostpackage"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/infrastructure/launcher"
)

// Go statement coverage cannot attribute execution to constant declarations.
// TestPF001HostPackageStaticLimitsAreExact asserts every security boundary.
const (
	// mutator-disable-next-line *
	maximumHostAuthorityBytes = 64 * 1024 * 1024
	// mutator-disable-next-line *
	maximumHostTrustBytes = 128 * 1024
	// mutator-disable-next-line *
	maximumBootstrapBytes = 512 * 1024 * 1024
	// mutator-disable-next-line *
	maximumHostObjectBytes = int64(1<<53 - 1)
)

// PackageOptions identifies one detached, platform-specific host archive.
type PackageOptions struct {
	CandidateRoot       string
	Publication         string
	PublicationSigstore string
	Bootstrap           string
	BootstrapSigstore   string
	TrustDocument       string
	Output              string
	RecordOutput        string
	Host                string
	OperatingSystem     string
	Architecture        string
	Version             string
	SourceCommit        string
	SourceEpoch         int64
}

type artifactSignatureVerifier interface {
	VerifyArtifactSignature(context.Context, releaseinventory.Digest, []byte) error
}

type verifierFactory func(string) (artifactSignatureVerifier, artifactSignatureVerifier, error)

type archiveEntry struct {
	name       string
	path       string
	content    []byte
	mode       os.FileMode
	digest     releaseinventory.Digest
	size       uint64
	maximum    int64
	verifyRead bool
}

type resolvedPackage struct {
	options                  PackageOptions
	host                     hostpackage.Host
	target                   hostpackage.Target
	executable               string
	publication              releasepublication.Publication
	publicationRaw           []byte
	publicationSignature     []byte
	publicationDigest        releaseinventory.Digest
	publicationSignatureHash releaseinventory.Digest
	bootstrapDigest          releaseinventory.Digest
	entries                  []archiveEntry
}

// AssembleHostPackage verifies every authority and object before publishing a
// deterministic host archive plus its detached canonical record.
func AssembleHostPackage(ctx context.Context, options PackageOptions, factory verifierFactory) error {
	if ctx == nil || factory == nil {
		return errors.New("host package capabilities are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolvePackageOptions(options)
	if err != nil {
		return err
	}
	trust, err := readRegular(resolved.options.TrustDocument, maximumHostTrustBytes)
	if err != nil {
		return fmt.Errorf("read host package trust: %w", err)
	}
	publicationVerifier, objectVerifier, err := factory(base64.StdEncoding.EncodeToString(trust))
	clear(trust)
	if err != nil || publicationVerifier == nil || objectVerifier == nil {
		return errors.New("host package trust is invalid")
	}
	if err := resolved.inspect(ctx, publicationVerifier, objectVerifier); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return resolved.publish(ctx)
}

func resolvePackageOptions(options PackageOptions) (resolvedPackage, error) {
	if options.CandidateRoot == "" || options.Publication == "" || options.PublicationSigstore == "" ||
		options.Bootstrap == "" || options.BootstrapSigstore == "" || options.TrustDocument == "" ||
		options.Output == "" || options.RecordOutput == "" || options.SourceEpoch <= 0 {
		return resolvedPackage{}, errors.New("host package inputs are incomplete")
	}
	host := hostpackage.Host(options.Host)
	if _, err := hostpackage.ManifestName(host); err != nil {
		return resolvedPackage{}, err
	}
	target := hostpackage.Target{OperatingSystem: options.OperatingSystem, Architecture: options.Architecture}
	executable := "agentmemory-bootstrap"
	if options.OperatingSystem == "windows" {
		executable += ".exe"
	}
	if _, err := hostpackage.EncodeManifest(hostpackage.ManifestInput{
		Host: host, Target: target, Version: options.Version, Executable: executable,
	}); err != nil {
		return resolvedPackage{}, err
	}
	resolved := options
	for _, value := range []*string{
		&resolved.CandidateRoot, &resolved.Publication, &resolved.PublicationSigstore,
		&resolved.Bootstrap, &resolved.BootstrapSigstore, &resolved.TrustDocument,
		&resolved.Output, &resolved.RecordOutput,
	} {
		absolute, err := filepath.Abs(*value)
		if err != nil {
			return resolvedPackage{}, errors.New("host package path is invalid")
		}
		*value = filepath.Clean(absolute)
	}
	rootInfo, err := os.Lstat(resolved.CandidateRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return resolvedPackage{}, errors.New("host package candidate root is invalid")
	}
	if filepath.Dir(resolved.Output) != filepath.Dir(resolved.RecordOutput) || resolved.Output == resolved.RecordOutput {
		return resolvedPackage{}, errors.New("host package outputs must be distinct siblings")
	}
	for _, output := range []string{resolved.Output, resolved.RecordOutput} {
		if _, err := os.Lstat(output); err == nil {
			return resolvedPackage{}, errors.New("host package output already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return resolvedPackage{}, errors.New("host package output cannot be inspected")
		}
	}
	parent, err := os.Lstat(filepath.Dir(resolved.Output))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return resolvedPackage{}, errors.New("host package output parent is invalid")
	}
	extension := ".zip"
	if host == hostpackage.HostClaude {
		extension = ".mcpb"
	}
	if !strings.HasSuffix(resolved.Output, extension) || !strings.HasSuffix(resolved.RecordOutput, ".json") {
		return resolvedPackage{}, errors.New("host package output format is invalid")
	}
	return resolvedPackage{options: resolved, host: host, target: target, executable: executable}, nil
}

func (p *resolvedPackage) inspect(
	ctx context.Context,
	publicationVerifier artifactSignatureVerifier,
	objectVerifier artifactSignatureVerifier,
) error {
	publicationRaw, err := readRegular(p.options.Publication, maximumHostAuthorityBytes)
	if err != nil {
		return fmt.Errorf("read release publication: %w", err)
	}
	publication, err := releasepublication.DecodeV1(publicationRaw)
	if err != nil || publication.Version() != p.options.Version ||
		publication.SourceCommit() != p.options.SourceCommit || publication.BuildTimestamp().Unix() != p.options.SourceEpoch {
		return errors.New("host package publication identity is invalid")
	}
	publicationSignature, err := readRegular(p.options.PublicationSigstore, maximumHostAuthorityBytes)
	if err != nil {
		return fmt.Errorf("read publication signature: %w", err)
	}
	publicationDigest := releaseinventory.DigestBytes(publicationRaw)
	if err := publicationVerifier.VerifyArtifactSignature(ctx, publicationDigest, publicationSignature); err != nil {
		return errors.New("host package publication signature is invalid")
	}
	bootstrapDigest, bootstrapSize, err := digestRegular(p.options.Bootstrap, maximumBootstrapBytes)
	if err != nil {
		return fmt.Errorf("hash host bootstrap: %w", err)
	}
	bootstrapSignature, err := readRegular(p.options.BootstrapSigstore, maximumHostAuthorityBytes)
	if err != nil || objectVerifier.VerifyArtifactSignature(ctx, bootstrapDigest, bootstrapSignature) != nil {
		return errors.New("host bootstrap signature is invalid")
	}
	manifestName, _ := hostpackage.ManifestName(p.host)
	manifest, err := hostpackage.EncodeManifest(hostpackage.ManifestInput{
		Host: p.host, Target: p.target, Version: p.options.Version, Executable: p.executable,
	})
	if err != nil {
		return err
	}
	p.publication, p.publicationRaw, p.publicationSignature = publication, publicationRaw, publicationSignature
	p.publicationDigest, p.publicationSignatureHash = publicationDigest, releaseinventory.DigestBytes(publicationSignature)
	p.bootstrapDigest = bootstrapDigest
	p.entries = []archiveEntry{
		{name: manifestName, content: manifest, mode: 0o644},
		{name: "bin/" + p.executable, path: p.options.Bootstrap, mode: 0o755,
			digest: bootstrapDigest, size: bootstrapSize, maximum: maximumBootstrapBytes, verifyRead: true},
		{name: "release/agentmemory-release-publication.json", content: publicationRaw, mode: 0o644},
		{name: "release/agentmemory-release-publication.sigstore.json", content: publicationSignature, mode: 0o644},
	}
	formats := []releasepublication.Format{releasepublication.FormatPKG}
	switch p.target.OperatingSystem {
	case "linux":
		formats = []releasepublication.Format{releasepublication.FormatDEB, releasepublication.FormatRPM}
	case "windows":
		formats = []releasepublication.Format{releasepublication.FormatMSI}
	}
	for _, format := range formats {
		artifact, err := publication.NativePackage(p.target.OperatingSystem, p.target.Architecture, format)
		if err != nil {
			// The publication constructor and host target constructor close the
			// same required native cell matrix; this is defense in depth.
			// mutator-disable-next-line *
			return errors.New("host package native cell is unavailable")
		}
		if err := p.addNativeArtifact(ctx, artifact, objectVerifier); err != nil {
			return err
		}
	}
	sort.Slice(p.entries, func(left, right int) bool { return p.entries[left].name < p.entries[right].name })
	return nil
}

func (p *resolvedPackage) addNativeArtifact(
	ctx context.Context,
	artifact releasepublication.Artifact,
	verifier artifactSignatureVerifier,
) error {
	objectPath := filepath.Join(p.options.CandidateRoot, "objects", artifact.FileName())
	digest, size, err := digestRegular(objectPath, maximumHostObjectBytes)
	if err != nil || size != artifact.Size() || !digest.Equal(artifact.Digest()) {
		return errors.New("host package native object does not match publication")
	}
	signaturePath := filepath.Join(p.options.CandidateRoot, "evidence", artifact.ID()+".sigstore.json")
	signature, err := readRegular(signaturePath, maximumHostAuthorityBytes)
	if err != nil || !releaseinventory.DigestBytes(signature).Equal(artifact.SignatureBundleDigest()) ||
		verifier.VerifyArtifactSignature(ctx, artifact.Digest(), signature) != nil {
		return errors.New("host package native object signature is invalid")
	}
	p.entries = append(p.entries,
		archiveEntry{name: "release/objects/" + artifact.FileName(), path: objectPath, mode: 0o644,
			digest: digest, size: size, maximum: maximumHostObjectBytes, verifyRead: true},
		archiveEntry{name: "release/evidence/" + artifact.ID() + ".sigstore.json", content: signature, mode: 0o644},
	)
	return nil
}

func (p *resolvedPackage) publish(ctx context.Context) error {
	parent := filepath.Dir(p.options.Output)
	stage, err := os.MkdirTemp(parent, ".agentmemory-host-package-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	archivePath := filepath.Join(stage, filepath.Base(p.options.Output))
	archiveDigest, archiveSize, err := writeArchive(ctx, archivePath, p.entries, time.Unix(p.options.SourceEpoch, 0).UTC())
	if err != nil {
		return err
	}
	record, err := hostpackage.EncodeRecord(hostpackage.RecordInput{
		SchemaVersion: 1, Host: p.host, Target: p.target, Version: p.options.Version,
		SourceCommit: p.options.SourceCommit, SourceEpoch: p.options.SourceEpoch,
		FileName: filepath.Base(p.options.Output), ArchiveDigest: archiveDigest, ArchiveSize: archiveSize,
		BootstrapDigest: p.bootstrapDigest, PublicationDigest: p.publicationDigest,
		PublicationSignatureDigest: p.publicationSignatureHash,
	})
	if err != nil {
		return err
	}
	recordPath := filepath.Join(stage, filepath.Base(p.options.RecordOutput))
	if err := os.WriteFile(recordPath, record, 0o600); err != nil { // #nosec G306 -- detached record is owner-only until promotion.
		return err
	}
	epoch := time.Unix(p.options.SourceEpoch, 0).UTC()
	if err := os.Chtimes(recordPath, epoch, epoch); err != nil {
		return err
	}
	if err := os.Rename(archivePath, p.options.Output); err != nil {
		return err
	}
	if err := os.Rename(recordPath, p.options.RecordOutput); err != nil {
		_ = os.Remove(p.options.Output)
		return err
	}
	return nil
}

func writeArchive(ctx context.Context, output string, entries []archiveEntry, epoch time.Time) (releaseinventory.Digest, uint64, error) {
	// #nosec G304 -- output is one fixed leaf in a newly-created private staging directory.
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return releaseinventory.Digest{}, 0, err
	}
	writer := zip.NewWriter(file)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			_ = writer.Close()
			_ = file.Close()
			return releaseinventory.Digest{}, 0, err
		}
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		header.SetMode(entry.mode)
		header.Modified = epoch
		target, err := writer.CreateHeader(header)
		if err != nil {
			_ = writer.Close()
			_ = file.Close()
			return releaseinventory.Digest{}, 0, err
		}
		if len(entry.content) != 0 {
			if _, err := target.Write(entry.content); err != nil {
				_ = writer.Close()
				_ = file.Close()
				return releaseinventory.Digest{}, 0, err
			}
			continue
		}
		if err := copyVerifiedEntry(target, entry); err != nil {
			_ = writer.Close()
			_ = file.Close()
			return releaseinventory.Digest{}, 0, err
		}
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		return releaseinventory.Digest{}, 0, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return releaseinventory.Digest{}, 0, err
	}
	if err := file.Close(); err != nil {
		return releaseinventory.Digest{}, 0, err
	}
	if err := os.Chtimes(output, epoch, epoch); err != nil {
		return releaseinventory.Digest{}, 0, err
	}
	return digestRegular(output, maximumHostObjectBytes)
}

func copyVerifiedEntry(target io.Writer, entry archiveEntry) error {
	if !entry.verifyRead || entry.path == "" || entry.maximum <= 0 || entry.size > uint64(entry.maximum) { // #nosec G115 -- maximum is proven positive before conversion.
		return errors.New("host archive entry is invalid")
	}
	info, err := os.Lstat(entry.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || uint64(info.Size()) != entry.size { // #nosec G115 -- nonnegative size is proven in this expression.
		return errors.New("host archive source changed")
	}
	// #nosec G304 -- every path was resolved from a closed authority or explicit release input.
	file, err := os.Open(entry.path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("host archive source changed while opening")
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(target, hash), io.LimitReader(file, entry.maximum+1))
	var digest releaseinventory.Digest
	copy(digest[:], hash.Sum(nil))
	if err != nil || written < 0 || uint64(written) != entry.size || // #nosec G115 -- nonnegative count is proven before conversion.
		!digest.Equal(entry.digest) {
		return errors.New("host archive source changed while reading")
	}
	return nil
}

func digestRegular(path string, maximum int64) (releaseinventory.Digest, uint64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maximum {
		return releaseinventory.Digest{}, 0, errors.New("input is not a bounded regular file")
	}
	// #nosec G304 -- caller supplies a closed release path.
	file, err := os.Open(path)
	if err != nil {
		return releaseinventory.Digest{}, 0, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return releaseinventory.Digest{}, 0, errors.New("input changed while opening")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || written != info.Size() {
		return releaseinventory.Digest{}, 0, errors.New("input changed while hashing")
	}
	var digest releaseinventory.Digest
	copy(digest[:], hash.Sum(nil))
	// #nosec G115 -- written equals the previously validated positive file size.
	return digest, uint64(written), nil
}

func readRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("input is not a bounded regular file")
	}
	// #nosec G304 -- caller supplies a closed release path.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("input changed while reading")
	}
	return content, nil
}

func productionVerifierFactory(encoded string) (artifactSignatureVerifier, artifactSignatureVerifier, error) {
	return launcher.NativeReleaseArtifactVerifiersBase64(encoded)
}
