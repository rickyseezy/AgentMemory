package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	maximumManifestBytes      = 16 * 1024 * 1024
	maximumSignatureBytes     = 4 * 1024
	maximumSigstoreBytes      = 16 * 1024 * 1024
	maximumRevocationBytes    = 4 * 1024 * 1024
	maximumTrustedTimeBytes   = 4 * 1024 * 1024
	maximumSignedEnvelopeSize = 32 * 1024 * 1024
)

// EnvelopeOptions identifies every exact offline-signature input.
type EnvelopeOptions struct {
	Manifest            string
	TrustMode           string
	TrustRootID         string
	Signature           string
	SigstoreBundle      string
	RevocationSet       string
	TrustedTimeEvidence string
	Output              string
	SourceEpoch         int64
}

type envelopeParts struct {
	manifest       []byte
	trustMode      string
	trustRootID    string
	signature      []byte
	sigstoreBundle []byte
	revocationSet  []byte
	trustedTime    []byte
}

func (p envelopeParts) clone() envelopeParts {
	return envelopeParts{
		manifest: append([]byte(nil), p.manifest...), trustMode: p.trustMode, trustRootID: p.trustRootID,
		signature: append([]byte(nil), p.signature...), sigstoreBundle: append([]byte(nil), p.sigstoreBundle...),
		revocationSet: append([]byte(nil), p.revocationSet...), trustedTime: append([]byte(nil), p.trustedTime...),
	}
}

func (p *envelopeParts) clear() {
	clear(p.manifest)
	clear(p.signature)
	clear(p.sigstoreBundle)
	clear(p.revocationSet)
	clear(p.trustedTime)
}

type envelopeCompiler func(envelopeParts) ([]byte, error)

// BuildEnvelope publishes the schema-owned distribution envelope from exactly
// one complete signature mode and its offline revocation/time evidence.
func BuildEnvelope(ctx context.Context, options EnvelopeOptions, compile envelopeCompiler) error {
	if ctx == nil || compile == nil {
		return errors.New("release envelope capabilities are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolveEnvelopeOptions(options)
	if err != nil {
		return err
	}
	parts := envelopeParts{trustMode: resolved.TrustMode, trustRootID: resolved.TrustRootID}
	defer parts.clear()
	parts.manifest, err = readBoundedRegularFile(resolved.Manifest, maximumManifestBytes)
	if err != nil {
		return fmt.Errorf("read canonical release manifest: %w", err)
	}
	parts.revocationSet, err = readBoundedRegularFile(resolved.RevocationSet, maximumRevocationBytes)
	if err != nil {
		return fmt.Errorf("read revocation evidence: %w", err)
	}
	parts.trustedTime, err = readBoundedRegularFile(resolved.TrustedTimeEvidence, maximumTrustedTimeBytes)
	if err != nil {
		return fmt.Errorf("read trusted-time evidence: %w", err)
	}
	switch resolved.TrustMode {
	case string(releaseinventory.SignatureTrustModeKeyID):
		parts.signature, err = readBoundedRegularFile(resolved.Signature, maximumSignatureBytes)
		if err != nil {
			return fmt.Errorf("read detached release signature: %w", err)
		}
	case string(releaseinventory.SignatureTrustModeCertificateTransparency):
		parts.sigstoreBundle, err = readBoundedRegularFile(resolved.SigstoreBundle, maximumSigstoreBytes)
		if err != nil {
			return fmt.Errorf("read official Sigstore bundle: %w", err)
		}
	default:
		return errors.New("release envelope trust mode is unsupported")
	}
	compilerOutput, err := compile(parts.clone())
	if err != nil || len(compilerOutput) == 0 || len(compilerOutput) > maximumSignedEnvelopeSize {
		return errors.New("release envelope compiler rejected the signing evidence")
	}
	compiled := append([]byte(nil), compilerOutput...)
	defer clear(compiled)
	if err := ctx.Err(); err != nil {
		return err
	}
	return publishEnvelope(resolved.Output, compiled, time.Unix(resolved.SourceEpoch, 0).UTC())
}

func resolveEnvelopeOptions(options EnvelopeOptions) (EnvelopeOptions, error) {
	if options.SourceEpoch <= 0 || options.TrustRootID == "" {
		return EnvelopeOptions{}, errors.New("release epoch and trust-root identity are required")
	}
	if options.TrustMode != string(releaseinventory.SignatureTrustModeKeyID) &&
		options.TrustMode != string(releaseinventory.SignatureTrustModeCertificateTransparency) {
		return EnvelopeOptions{}, errors.New("release trust mode is unsupported")
	}
	if options.Manifest == "" || options.RevocationSet == "" || options.TrustedTimeEvidence == "" || options.Output == "" {
		return EnvelopeOptions{}, errors.New("release envelope inputs are incomplete")
	}
	if options.TrustMode == string(releaseinventory.SignatureTrustModeKeyID) {
		if options.Signature == "" || options.SigstoreBundle != "" {
			return EnvelopeOptions{}, errors.New("key-ID mode requires only a detached signature")
		}
	} else if options.SigstoreBundle == "" || options.Signature != "" {
		return EnvelopeOptions{}, errors.New("certificate-transparency mode requires only a Sigstore bundle")
	}
	resolved := options
	for _, value := range []*string{
		&resolved.Manifest, &resolved.Signature, &resolved.SigstoreBundle,
		&resolved.RevocationSet, &resolved.TrustedTimeEvidence, &resolved.Output,
	} {
		if *value == "" {
			continue
		}
		absolute, err := filepath.Abs(*value)
		if err != nil {
			return EnvelopeOptions{}, errors.New("release envelope path is invalid")
		}
		*value = filepath.Clean(absolute)
	}
	if _, err := os.Lstat(resolved.Output); err == nil {
		return EnvelopeOptions{}, errors.New("release envelope output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return EnvelopeOptions{}, fmt.Errorf("inspect release envelope output: %w", err)
	}
	parentInfo, err := os.Lstat(filepath.Dir(resolved.Output))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return EnvelopeOptions{}, errors.New("release envelope parent must be an existing non-symlink directory")
	}
	return resolved, nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("input must be a bounded non-empty regular file")
	}
	// #nosec G304 -- explicit release input is bounded above and identity-checked below.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("release input changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) != info.Size() || int64(len(content)) > maximum {
		return nil, errors.New("release input changed while reading")
	}
	return content, nil
}

func publishEnvelope(output string, content []byte, epoch time.Time) error {
	parent := filepath.Dir(output)
	temporary, err := os.MkdirTemp(parent, ".agentmemory-release-envelope-")
	if err != nil {
		return fmt.Errorf("create private envelope stage: %w", err)
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	path := filepath.Join(temporary, "distribution-manifest.json")
	// #nosec G304 -- path is one fixed leaf below a new private staging directory.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(content) || syncErr != nil || closeErr != nil {
		return errors.New("release envelope write failed")
	}
	if err := os.Chtimes(path, epoch, epoch); err != nil {
		return err
	}
	if err := os.Rename(path, output); err != nil {
		return fmt.Errorf("publish release envelope: %w", err)
	}
	return nil
}

func compileProductionEnvelope(parts envelopeParts) ([]byte, error) {
	manifest, err := releaseinventory.DecodeManifestV1(parts.manifest)
	if err != nil {
		return nil, err
	}
	signed, err := releaseinventory.NewSignedManifest(manifest, releaseinventory.SignatureBundleInput{
		SchemaVersion: releaseinventory.SupportedSignatureBundleSchemaMajor,
		TrustMode:     releaseinventory.SignatureTrustMode(parts.trustMode), TrustRootID: parts.trustRootID,
		Signature: parts.signature, SigstoreBundle: parts.sigstoreBundle,
		RevocationSet: parts.revocationSet, TrustedTimeEvidence: parts.trustedTime,
	})
	if err != nil {
		return nil, err
	}
	return releaseinventory.EncodeSignedManifestV1(signed)
}
