package launcher

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
)

type nativeReleaseBundleRootResolver func() (string, error)
type nativeReleaseTrustLoader func() (nativeReleaseTrustMaterial, error)

type nativeReleaseAuthorityDependencies struct {
	BundleRoot   nativeReleaseBundleRootResolver
	Trust        nativeReleaseTrustLoader
	Clock        appreleaseverify.Clock
	AntiRollback appreleaseverify.AntiRollbackRepository
}

// nativeReleaseAuthority owns the retained descriptor-rooted bundle and the
// complete verifier stack derived from independently embedded public trust.
// No environment variable, working directory, network locator, or MCP input
// participates in its construction.
type nativeReleaseAuthority struct {
	source *artifactfs.BundleFetcher
	stack  nativeReleaseStack
}

func newNativeReleaseAuthority(
	ctx context.Context,
	dependencies nativeReleaseAuthorityDependencies,
) (*nativeReleaseAuthority, error) {
	if ctx == nil || dependencies.BundleRoot == nil || dependencies.Trust == nil ||
		nilAny(dependencies.Clock) || nilAny(dependencies.AntiRollback) {
		return nil, firststartapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := dependencies.BundleRoot()
	if err != nil || root == "" {
		return nil, firststartapp.ErrUnavailable
	}
	source, err := artifactfs.NewBundleFetcher(root)
	if err != nil {
		return nil, firststartapp.ErrUnavailable
	}
	failed := true
	defer func() {
		if failed {
			_ = source.Close()
		}
	}()
	trust, err := dependencies.Trust()
	if err != nil {
		return nil, firststartapp.ErrIntegrity
	}
	stack, err := newNativeReleaseStack(nativeReleaseStackDependencies{
		Source: source, Clock: dependencies.Clock,
		AntiRollback: dependencies.AntiRollback, Trust: trust,
	})
	if err != nil {
		return nil, firststartapp.ErrIntegrity
	}
	failed = false
	return &nativeReleaseAuthority{source: source, stack: stack}, nil
}

func (a *nativeReleaseAuthority) templates() firststartapp.VerifiedTemplateSource {
	if a == nil || a.stack.templates == nil {
		return nil
	}
	return a.stack.templates
}

func (a *nativeReleaseAuthority) verifier() *appreleaseverify.Application {
	if a == nil {
		return nil
	}
	return a.stack.application
}

func (a *nativeReleaseAuthority) Close(context.Context) error {
	if a == nil || a.source == nil {
		return nil
	}
	if err := a.source.Close(); err != nil {
		return errors.New("native release bundle close failed")
	}
	return nil
}

var _ interface{ Close(context.Context) error } = (*nativeReleaseAuthority)(nil)
