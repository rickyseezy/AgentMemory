package productstackapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestApplicationExecutesOnlyTheOperationAuthorizedByTheParentPlan(t *testing.T) {
	t.Parallel()

	compose := &releaseCompose{rendered: renderedConfiguration(t)}
	application, err := New(compose)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		operation productstack.Operation
		invoke    func(context.Context, productstack.Authorization) (productstack.Receipt, error)
	}{
		{operation: productstack.OperationMigrate, invoke: application.RunMigrations},
		{operation: productstack.OperationStartCoreAndGraph, invoke: application.StartCoreAndGraph},
	} {
		authorization := stackAuthorization(t, test.operation)
		receipt, err := test.invoke(context.Background(), authorization)
		if err != nil || !receipt.ValidFor(authorization) || receipt.OutputDigest().IsZero() {
			t.Fatalf("operation %q receipt/error = %#v/%v", test.operation, receipt, err)
		}
	}
	if compose.migrations != 1 || compose.starts != 1 ||
		compose.last.ConfigurationPath() != stackSource(t).ConfigurationPath() {
		t.Fatalf("compose calls/source = %d/%d/%#v", compose.migrations, compose.starts, compose.last)
	}
}

func TestApplicationRejectsCrossOperationReplayBeforeDocker(t *testing.T) {
	t.Parallel()

	compose := &releaseCompose{rendered: renderedConfiguration(t)}
	application, _ := New(compose)
	if _, err := application.RunMigrations(context.Background(), stackAuthorization(t, productstack.OperationStartCoreAndGraph)); !errors.Is(err, productstack.ErrIntegrity) || compose.migrations != 0 || compose.starts != 0 {
		t.Fatalf("cross-operation result = %v/%d/%d", err, compose.migrations, compose.starts)
	}
	if _, err := application.StartCoreAndGraph(context.Background(), productstack.Authorization{}); !errors.Is(err, productstack.ErrIntegrity) || compose.migrations != 0 || compose.starts != 0 {
		t.Fatalf("invalid authorization result = %v/%d/%d", err, compose.migrations, compose.starts)
	}
}

func TestApplicationSanitizesComposeFailureAndRejectsEmptyEvidence(t *testing.T) {
	t.Parallel()

	compose := &releaseCompose{err: errors.New("/private/path secret raw")}
	application, _ := New(compose)
	if _, err := application.RunMigrations(context.Background(), stackAuthorization(t, productstack.OperationMigrate)); !errors.Is(err, productstack.ErrUnavailable) || err.Error() != productstack.ErrUnavailable.Error() {
		t.Fatalf("compose error escaped boundary = %v", err)
	}
	compose.err = nil
	if _, err := application.RunMigrations(context.Background(), stackAuthorization(t, productstack.OperationMigrate)); !errors.Is(err, productstack.ErrIntegrity) {
		t.Fatalf("empty normalized evidence error = %v", err)
	}
	if _, err := New(nil); err == nil {
		t.Fatal("New accepted a missing Compose capability")
	}
	var typedNil *releaseCompose
	if _, err := New(typedNil); err == nil {
		t.Fatal("New accepted a typed nil Compose capability")
	}
}

type releaseCompose struct {
	rendered   containerengine.RenderedConfiguration
	err        error
	migrations int
	starts     int
	last       containerengine.ComposeReleaseSource
}

func (c *releaseCompose) RunReleaseMigrations(
	_ context.Context,
	source containerengine.ComposeReleaseSource,
) (containerengine.RenderedConfiguration, error) {
	c.migrations++
	c.last = source
	return c.rendered, c.err
}

func (c *releaseCompose) StartReleaseAndWait(
	_ context.Context,
	source containerengine.ComposeReleaseSource,
) (containerengine.RenderedConfiguration, error) {
	c.starts++
	c.last = source
	return c.rendered, c.err
}

func renderedConfiguration(t testing.TB) containerengine.RenderedConfiguration {
	t.Helper()
	rendered, err := containerengine.NewRenderedConfiguration([]byte(`{"name":"agentmemory"}`))
	if err != nil {
		t.Fatal(err)
	}
	return rendered
}

func stackAuthorization(t testing.TB, operation productstack.Operation) productstack.Authorization {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	authorization, err := productstack.NewAuthorization(
		operation, operationID, plan, 1, install.RuntimeOwnershipReusedExternal, stackSource(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func stackSource(t testing.TB) containerengine.ComposeReleaseSource {
	t.Helper()
	endpoint, _ := containerengine.NewEndpoint("unix:///run/user/1000/docker.sock")
	identity, _ := composeplan.NewIdentity(
		"019f5f20-1234-7abc-8123-0123456789ab",
		"019f5f21-5678-7def-9123-abcdef012345",
	)
	source, err := containerengine.NewComposeReleaseSource(
		endpoint, identity, "1.0.0", "/owner/agentmemory/releases/v1/compose",
		"/owner/agentmemory/releases/v1/compose/compose.yaml",
		"/owner/agentmemory/releases/v1/compose/empty.env",
		releaseinventory.DigestBytes([]byte("compose source")), 180,
	)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
