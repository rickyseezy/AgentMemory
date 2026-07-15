package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

const (
	distributionEnvelopeName = "distribution-manifest.json"
	maximumEvidenceSize      = 64 * 1024 * 1024
	maximumEnvelopeSize      = 32 * 1024 * 1024
	maximumSafeFileSize      = int64(1<<53 - 1)
)

// PublicationOptions identifies one already-qualified candidate set.
type PublicationOptions struct {
	CandidateRoot string
	Output        string
	ReleaseID     string
	Version       string
	BuildID       string
	SourceCommit  string
	SourceEpoch   int64
}

type candidateArtifact struct {
	id, objectPath, cycloneDXPath, provenancePath, signaturePath string
	kind                                                         releasepublication.ArtifactKind
	operatingSystem, architecture                                string
	format                                                       releasepublication.Format
	mediaType                                                    string
	publisherPolicy                                              releasepublication.NativePublisherPolicy
}

func candidate(
	id string,
	operatingSystem string,
	architecture string,
	format releasepublication.Format,
	mediaType string,
	policy releasepublication.NativePublisherPolicy,
) candidateArtifact {
	return candidateArtifact{
		id: id, objectPath: "objects/" + id + "." + string(format),
		cycloneDXPath:  "evidence/" + id + ".cyclonedx.json",
		provenancePath: "evidence/" + id + ".provenance.json",
		signaturePath:  "evidence/" + id + ".sigstore.json",
		kind:           releasepublication.ArtifactKindNativePackage, operatingSystem: operatingSystem,
		architecture: architecture, format: format, mediaType: mediaType, publisherPolicy: policy,
	}
}

var candidateArtifacts = []candidateArtifact{
	candidate("agentmemory-darwin-amd64-pkg", "darwin", "amd64", releasepublication.FormatPKG,
		"application/vnd.apple.installer+xml", releasepublication.PublisherPolicyAppleNotarized),
	candidate("agentmemory-darwin-arm64-pkg", "darwin", "arm64", releasepublication.FormatPKG,
		"application/vnd.apple.installer+xml", releasepublication.PublisherPolicyAppleNotarized),
	candidate("agentmemory-linux-amd64-deb", "linux", "amd64", releasepublication.FormatDEB,
		"application/vnd.debian.binary-package", releasepublication.PublisherPolicyLinuxPackage),
	candidate("agentmemory-linux-amd64-rpm", "linux", "amd64", releasepublication.FormatRPM,
		"application/x-rpm", releasepublication.PublisherPolicyLinuxPackage),
	candidate("agentmemory-linux-arm64-deb", "linux", "arm64", releasepublication.FormatDEB,
		"application/vnd.debian.binary-package", releasepublication.PublisherPolicyLinuxPackage),
	candidate("agentmemory-linux-arm64-rpm", "linux", "arm64", releasepublication.FormatRPM,
		"application/x-rpm", releasepublication.PublisherPolicyLinuxPackage),
	candidate("agentmemory-windows-amd64-msi", "windows", "amd64", releasepublication.FormatMSI,
		"application/x-msi", releasepublication.PublisherPolicyMicrosoftAuthenticode),
	{
		id: "agentmemory-offline-bundle", objectPath: "objects/agentmemory-offline-bundle.tar.zst",
		cycloneDXPath:  "evidence/agentmemory-offline-bundle.cyclonedx.json",
		provenancePath: "evidence/agentmemory-offline-bundle.provenance.json",
		signaturePath:  "evidence/agentmemory-offline-bundle.sigstore.json",
		kind:           releasepublication.ArtifactKindOfflineBundle, format: releasepublication.FormatTarZstd,
		mediaType:       "application/vnd.agentmemory.offline-bundle+zstd",
		publisherPolicy: releasepublication.PublisherPolicyManifestOnly,
	},
}

type publicationParts struct {
	options            PublicationOptions
	distributionDigest releaseinventory.Digest
	distributionSize   uint64
	artifacts          []releasepublication.ArtifactInput
}

func (p publicationParts) clone() publicationParts {
	result := p
	result.artifacts = append([]releasepublication.ArtifactInput(nil), p.artifacts...)
	return result
}

type publicationCompiler func(publicationParts) ([]byte, error)

// AssemblePublication hashes the complete closed candidate tree and atomically
// publishes only compiler-accepted canonical authority bytes.
func AssemblePublication(ctx context.Context, options PublicationOptions, compile publicationCompiler) error {
	if ctx == nil || compile == nil {
		return errors.New("publication assembly capabilities are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolveOptions(options)
	if err != nil {
		return err
	}
	parts, err := inspectCandidate(resolved)
	if err != nil {
		return err
	}
	compiled, err := compile(parts.clone())
	if err != nil || len(compiled) == 0 || len(compiled) > maximumEnvelopeSize {
		return errors.New("publication compiler rejected the qualified candidate")
	}
	publication, err := releasepublication.DecodeV1(compiled)
	if err != nil || !publicationMatchesParts(publication, parts) {
		return errors.New("publication compiler substituted candidate authority")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return publish(resolved.Output, compiled, time.Unix(resolved.SourceEpoch, 0).UTC())
}

func resolveOptions(options PublicationOptions) (PublicationOptions, error) {
	if options.CandidateRoot == "" || options.Output == "" || options.ReleaseID == "" ||
		options.Version == "" || options.BuildID == "" || options.SourceCommit == "" || options.SourceEpoch <= 0 {
		return PublicationOptions{}, errors.New("publication assembly inputs are incomplete")
	}
	resolved := options
	for _, value := range []*string{&resolved.CandidateRoot, &resolved.Output} {
		absolute, err := filepath.Abs(*value)
		if err != nil {
			return PublicationOptions{}, errors.New("publication path is invalid")
		}
		*value = filepath.Clean(absolute)
	}
	rootInfo, err := os.Lstat(resolved.CandidateRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return PublicationOptions{}, errors.New("candidate root must be a non-symlink directory")
	}
	if _, err := os.Lstat(resolved.Output); err == nil {
		return PublicationOptions{}, errors.New("publication output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return PublicationOptions{}, errors.New("publication output cannot be inspected")
	}
	parentInfo, err := os.Lstat(filepath.Dir(resolved.Output))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return PublicationOptions{}, errors.New("publication output parent must be a non-symlink directory")
	}
	return resolved, nil
}

func inspectCandidate(options PublicationOptions) (publicationParts, error) {
	allowedFiles := map[string]struct{}{distributionEnvelopeName: {}}
	allowedDirectories := map[string]struct{}{":root": {}, "objects": {}, "evidence": {}}
	for _, artifact := range candidateArtifacts {
		for _, path := range []string{artifact.objectPath, artifact.cycloneDXPath, artifact.provenancePath, artifact.signaturePath} {
			allowedFiles[path] = struct{}{}
		}
	}
	seenFiles := make(map[string]struct{}, len(allowedFiles))
	err := filepath.WalkDir(options.CandidateRoot, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(options.CandidateRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			relative = ":root"
		} else {
			relative = filepath.ToSlash(relative)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("candidate entry is unavailable or linked")
		}
		if info.IsDir() {
			if _, allowed := allowedDirectories[relative]; !allowed {
				return fmt.Errorf("candidate directory %q is not declared", relative)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("candidate entry %q is not regular", relative)
		}
		if _, allowed := allowedFiles[relative]; !allowed {
			return fmt.Errorf("candidate file %q is not declared", relative)
		}
		seenFiles[relative] = struct{}{}
		return nil
	})
	if err != nil || len(seenFiles) != len(allowedFiles) {
		return publicationParts{}, errors.New("candidate tree is incomplete or open")
	}
	distributionDigest, distributionSize, err := digestRegularFile(
		filepath.Join(options.CandidateRoot, distributionEnvelopeName), maximumEnvelopeSize,
	)
	if err != nil {
		return publicationParts{}, fmt.Errorf("hash distribution envelope: %w", err)
	}
	parts := publicationParts{options: options, distributionDigest: distributionDigest, distributionSize: distributionSize}
	for _, definition := range candidateArtifacts {
		artifact, err := inspectArtifact(options.CandidateRoot, definition)
		if err != nil {
			return publicationParts{}, err
		}
		parts.artifacts = append(parts.artifacts, artifact)
	}
	return parts, nil
}

func inspectArtifact(root string, definition candidateArtifact) (releasepublication.ArtifactInput, error) {
	digest, size, err := digestRegularFile(
		filepath.Join(root, filepath.FromSlash(definition.objectPath)), maximumSafeFileSize,
	)
	if err != nil {
		return releasepublication.ArtifactInput{}, fmt.Errorf("hash candidate %s: %w", definition.id, err)
	}
	evidence := make([]releaseinventory.Digest, 0, 3)
	for _, path := range []string{definition.cycloneDXPath, definition.provenancePath, definition.signaturePath} {
		value, _, err := digestRegularFile(filepath.Join(root, filepath.FromSlash(path)), maximumEvidenceSize)
		if err != nil {
			return releasepublication.ArtifactInput{}, fmt.Errorf("hash candidate evidence %s: %w", definition.id, err)
		}
		evidence = append(evidence, value)
	}
	return releasepublication.ArtifactInput{
		ID: definition.id, Kind: definition.kind, OperatingSystem: definition.operatingSystem,
		Architecture: definition.architecture, Format: definition.format,
		FileName: filepath.Base(definition.objectPath), MediaType: definition.mediaType,
		Digest: digest, Size: size, CycloneDXSBOMDigest: evidence[0], ProvenanceDigest: evidence[1],
		SignatureBundleDigest: evidence[2], NativePublisherPolicy: definition.publisherPolicy,
	}, nil
}

func digestRegularFile(path string, maximum int64) (releaseinventory.Digest, uint64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return releaseinventory.Digest{}, 0, errors.New("input must be a bounded non-empty regular file")
	}
	// #nosec G304 -- path is selected from the closed candidate inventory.
	file, err := os.Open(path)
	if err != nil {
		return releaseinventory.Digest{}, 0, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return releaseinventory.Digest{}, 0, errors.New("candidate changed while opening")
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, file, info.Size())
	if err != nil || written != info.Size() {
		return releaseinventory.Digest{}, 0, errors.New("candidate changed while hashing")
	}
	var trailing [1]byte
	if count, readErr := file.Read(trailing[:]); count != 0 || readErr != io.EOF {
		return releaseinventory.Digest{}, 0, errors.New("candidate grew while hashing")
	}
	var digest releaseinventory.Digest
	copy(digest[:], hash.Sum(nil))
	// #nosec G115 -- size is proven positive and at most maximumSafeFileSize above.
	return digest, uint64(info.Size()), nil
}

func compilePublication(parts publicationParts) ([]byte, error) {
	publication, err := releasepublication.NewPublication(releasepublication.PublicationInput{
		SchemaVersion: releasepublication.SupportedSchemaMajor, ReleaseID: parts.options.ReleaseID,
		Version: parts.options.Version, BuildID: parts.options.BuildID, SourceCommit: parts.options.SourceCommit,
		BuildTimestamp:             time.Unix(parts.options.SourceEpoch, 0).UTC(),
		DistributionEnvelopeDigest: parts.distributionDigest, DistributionEnvelopeSize: parts.distributionSize,
		Artifacts: parts.artifacts,
	})
	if err != nil {
		return nil, err
	}
	return releasepublication.EncodeV1(publication)
}

func publicationMatchesParts(publication releasepublication.Publication, parts publicationParts) bool {
	if publication.ReleaseID() != parts.options.ReleaseID || publication.Version() != parts.options.Version ||
		publication.BuildID() != parts.options.BuildID || publication.SourceCommit() != parts.options.SourceCommit ||
		publication.BuildTimestamp().Unix() != parts.options.SourceEpoch ||
		!publication.DistributionEnvelopeDigest().Equal(parts.distributionDigest) ||
		publication.DistributionEnvelopeSize() != parts.distributionSize {
		return false
	}
	actual := publication.Artifacts()
	expected := append([]releasepublication.ArtifactInput(nil), parts.artifacts...)
	sort.Slice(expected, func(left, right int) bool { return expected[left].ID < expected[right].ID })
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index].ID() != expected[index].ID || !actual[index].Digest().Equal(expected[index].Digest) ||
			actual[index].Size() != expected[index].Size || actual[index].FileName() != expected[index].FileName {
			return false
		}
	}
	return true
}

func publish(output string, content []byte, epoch time.Time) error {
	parent := filepath.Dir(output)
	temporary, err := os.MkdirTemp(parent, ".agentmemory-publication-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	path := filepath.Join(temporary, "publication.json")
	// #nosec G304 -- path is one fixed leaf below a new private stage.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(content) || syncErr != nil || closeErr != nil {
		return errors.New("publication record write failed")
	}
	if err := os.Chtimes(path, epoch, epoch); err != nil {
		return err
	}
	if err := os.Rename(path, output); err != nil {
		return fmt.Errorf("publish publication record: %w", err)
	}
	return nil
}

func digestBytes(value []byte) releaseinventory.Digest { return releaseinventory.DigestBytes(value) }
