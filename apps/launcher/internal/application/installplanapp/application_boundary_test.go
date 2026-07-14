package installplanapp

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productstack"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001EveryPlanProjectionRejectsAbsentContextAndForeignAuthority(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	foreignDigest, err := install.BindPlan([]byte("foreign plan"))
	if err != nil {
		t.Fatal(err)
	}
	foreignOperation, err := install.NewOperationID("019f5f9f-0000-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		nilCall func() error
		foreign func() error
	}{
		{name: "host", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveHostVerificationPlan(nil, plan.Digest()) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveHostVerificationPlan(context.Background(), foreignDigest)
			return callErr
		}},
		{name: "release", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveReleasePlan(nil, plan.Digest()) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveReleasePlan(context.Background(), foreignDigest)
			return callErr
		}},
		{name: "artifacts", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveArtifactAcquisitionPlan(nil, plan.Digest()) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveArtifactAcquisitionPlan(context.Background(), foreignDigest)
			return callErr
		}},
		{name: "network", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveNetworkVolumePlan(nil, plan.Digest()) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveNetworkVolumePlan(context.Background(), foreignDigest)
			return callErr
		}},
		{name: "directories", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveDirectoryCommand(nil, plan.Digest(), plan.OperationID(), 1) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveDirectoryCommand(context.Background(), plan.Digest(), foreignOperation, 1)
			return callErr
		}},
		{name: "secrets", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveSecretCommand(nil, plan.Digest(), plan.OperationID(), 1) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveSecretCommand(context.Background(), plan.Digest(), foreignOperation, 1)
			return callErr
		}},
		{name: "stack", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveStackAuthorization(nil, plan.Digest(), plan.OperationID(), 1, productstack.OperationMigrate) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveStackAuthorization(context.Background(), plan.Digest(), foreignOperation, 1, productstack.OperationMigrate)
			return callErr
		}},
		{name: "brain", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveBrainBootstrapAuthorization(nil, plan.Digest(), plan.OperationID(), 1) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveBrainBootstrapAuthorization(context.Background(), plan.Digest(), foreignOperation, 1)
			return callErr
		}},
		{name: "readiness", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveReadinessPlan(nil, plan.Digest()) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveReadinessPlan(context.Background(), foreignDigest)
			return callErr
		}},
		{name: "agent", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveAgentConfigurationPlan(nil, plan.Digest(), plan.OperationID(), 1) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveAgentConfigurationPlan(context.Background(), plan.Digest(), foreignOperation, 1)
			return callErr
		}},
		{name: "runtime", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveRuntimePlan(nil, plan.Digest(), plan.OperationID()) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveRuntimePlan(context.Background(), plan.Digest(), foreignOperation)
			return callErr
		}},
		{name: "activation", nilCall: func() error {
			//lint:ignore SA1012 Deliberate absent-context boundary test.
			_, callErr := application.ResolveActivationPlan(nil, plan.Digest(), plan.OperationID()) //nolint:staticcheck // Security boundary fixture.
			return callErr
		}, foreign: func() error {
			_, callErr := application.ResolveActivationPlan(context.Background(), plan.Digest(), foreignOperation)
			return callErr
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if callErr := test.nilCall(); !errors.Is(callErr, ErrPlanIntegrity) {
				t.Fatalf("nil context error = %v", callErr)
			}
			if callErr := test.foreign(); callErr == nil {
				t.Fatal("foreign authority was accepted")
			}
		})
	}
}

func TestPF001EveryAttemptBoundProjectionRejectsZeroAttempt(t *testing.T) {
	t.Parallel()
	plan := applicationPlan(t)
	fixture := newApplicationFixture(t, plan)
	application, err := New(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	calls := []func() error{
		func() error {
			_, callErr := application.ResolveDirectoryCommand(t.Context(), plan.Digest(), plan.OperationID(), 0)
			return callErr
		},
		func() error {
			_, callErr := application.ResolveSecretCommand(t.Context(), plan.Digest(), plan.OperationID(), 0)
			return callErr
		},
		func() error {
			_, callErr := application.ResolveStackAuthorization(t.Context(), plan.Digest(), plan.OperationID(), 0, productstack.OperationMigrate)
			return callErr
		},
		func() error {
			_, callErr := application.ResolveBrainBootstrapAuthorization(t.Context(), plan.Digest(), plan.OperationID(), 0)
			return callErr
		},
		func() error {
			_, callErr := application.ResolveAgentConfigurationPlan(t.Context(), plan.Digest(), plan.OperationID(), 0)
			return callErr
		},
	}
	for index, call := range calls {
		if callErr := call(); !errors.Is(callErr, ErrPlanIntegrity) {
			t.Fatalf("call %d error = %v", index, callErr)
		}
	}
}
