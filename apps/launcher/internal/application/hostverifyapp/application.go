package hostverifyapp

import (
	"context"
	"errors"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// Dependencies is the complete VerifyHost composition contract.
type Dependencies struct {
	Signature PlanSignatureVerifier
	Probe     NativeHostProbe
}

// Application authenticates policy before asking the native probe for evidence.
type Application struct {
	signature PlanSignatureVerifier
	probe     NativeHostProbe
}

// NewApplication rejects absent and typed-nil trust capabilities.
func NewApplication(dependencies Dependencies) (*Application, error) {
	if nilPort(dependencies.Signature) || nilPort(dependencies.Probe) {
		return nil, errors.New("host verification signature and native probe capabilities are required")
	}
	return &Application{signature: dependencies.Signature, probe: dependencies.Probe}, nil
}

// Verify certifies only complete, authenticated, exact native evidence.
func (a *Application) Verify(ctx context.Context, command Command) (Verification, error) {
	if ctx == nil {
		return Verification{}, verificationError(ErrorCodeCancelled)
	}
	if err := ctx.Err(); err != nil {
		return Verification{}, verificationError(ErrorCodeCancelled)
	}
	if command.OperationID.IsZero() || command.ParentPlanDigest.IsZero() || !command.SignedPlan.Valid() {
		return Verification{}, verificationError(ErrorCodeIntegrity)
	}
	plan := command.SignedPlan.Plan()
	if !plan.Valid() {
		return Verification{}, verificationError(ErrorCodeIntegrity)
	}
	if err := a.signature.VerifyHostPlanSignature(ctx, command.SignedPlan); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Verification{}, verificationError(ErrorCodeCancelled)
		}
		if errors.Is(err, ErrUntrustedSigner) || errors.Is(err, ErrSignatureInvalid) {
			return Verification{}, verificationError(ErrorCodeIntegrity)
		}
		return Verification{}, verificationError(ErrorCodeDependency)
	}
	probe, err := a.probe.ProbeHost(ctx, plan)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Verification{}, verificationError(ErrorCodeCancelled)
		}
		return Verification{}, verificationError(ErrorCodeDependency)
	}
	if !probe.Valid() {
		return Verification{}, verificationError(ErrorCodeIntegrity)
	}
	observation, observed := probe.Observation()
	if !observed {
		return newVerification(command, plan, install.DigestBytes([]byte("native-rejection:"+string(probe.Failure()))), probe.Failure()), nil
	}
	reason := plan.Evaluate(observation)
	return newVerification(command, plan, observation.Digest(), reason), nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Array, reflect.Bool, reflect.Complex128, reflect.Complex64, reflect.Float32,
		reflect.Float64, reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int8,
		reflect.Invalid, reflect.String, reflect.Struct, reflect.Uint, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Uint8, reflect.Uintptr, reflect.UnsafePointer:
		return false
	}
	return false
}
