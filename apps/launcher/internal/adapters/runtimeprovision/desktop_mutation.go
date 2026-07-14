package runtimeprovision

import (
	"context"
	"errors"
	"reflect"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

type nativeDesktopMutationDependencies struct {
	Authority runtimeport.DesktopHelperAuthorityResolver
	Publisher runtimeport.DesktopHelperPublisherVerifier
}

// NativeDesktopMutationDependencies are mandatory signed-helper boundaries.
type NativeDesktopMutationDependencies = nativeDesktopMutationDependencies

type nativeDesktopMutationBroker struct {
	authority runtimeport.DesktopHelperAuthorityResolver
	publisher runtimeport.DesktopHelperPublisherVerifier
}

// NewNativeDesktopMutationBroker constructs the production Authorization
// Services or ShellExecuteEx(runas) broker for the current platform.
func NewNativeDesktopMutationBroker(
	dependencies NativeDesktopMutationDependencies,
) (runtimeport.DesktopMutationBroker, error) {
	if desktopMutationNil(dependencies.Authority) || desktopMutationNil(dependencies.Publisher) {
		return nil, ErrProvisionIntegrity
	}
	return &nativeDesktopMutationBroker{authority: dependencies.Authority, publisher: dependencies.Publisher}, nil
}

func desktopMutationNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable implementations are accepted.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}

func (b *nativeDesktopMutationBroker) ExecuteDesktopMutation(
	ctx context.Context,
	request runtimeport.DesktopMutationRequest,
) (runtimeport.DesktopMutationReceipt, error) {
	if b == nil || ctx == nil || ctx.Err() != nil || len(request.CanonicalBytes()) == 0 || request.Digest().IsZero() {
		return runtimeport.DesktopMutationReceipt{}, runtimeport.ErrDesktopMutationIntegrity
	}
	helper, err := b.authority.ResolveDesktopHelperAuthority(ctx, request.Authority())
	if err != nil {
		return runtimeport.DesktopMutationReceipt{}, errors.Join(runtimeport.ErrDesktopMutationUnavailable, err)
	}
	if !helper.ValidFor(request.Authority()) || b.publisher.VerifyDesktopHelperPublisher(ctx, helper) != nil {
		return runtimeport.DesktopMutationReceipt{}, runtimeport.ErrDesktopMutationIntegrity
	}
	exchange, err := createNativeDesktopMutationExchange(ctx, helper, request)
	if err != nil {
		return runtimeport.DesktopMutationReceipt{}, errors.Join(runtimeport.ErrDesktopMutationUnavailable, err)
	}
	defer exchange.cleanup()
	if b.publisher.VerifyDesktopHelperPublisher(ctx, helper) != nil {
		return runtimeport.DesktopMutationReceipt{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := executeNativeDesktopHelper(ctx, helper, exchange.requestPath, request.Operation()); err != nil {
		return runtimeport.DesktopMutationReceipt{}, err
	}
	raw, err := exchange.readReceipt(ctx)
	if err != nil {
		return runtimeport.DesktopMutationReceipt{}, errors.Join(runtimeport.ErrDesktopMutationIntegrity, err)
	}
	receipt, err := runtimeport.DecodeDesktopMutationReceiptV1(raw)
	if err != nil {
		return runtimeport.DesktopMutationReceipt{}, runtimeport.ErrDesktopMutationIntegrity
	}
	return receipt, nil
}

func windowsDesktopMutationExecutionPolicy(
	operation runtimeport.DesktopMutationOperation,
) (string, bool, bool) {
	switch operation {
	case runtimeport.DesktopMutationInstallPrerequisites:
		return "runas", true, true
	case runtimeport.DesktopMutationInstallRuntime:
		return "open", false, true
	default:
		return "", false, false
	}
}

type nativeDesktopMutationExchange struct {
	requestPath string
	receiptPath string
	read        func(context.Context, string) ([]byte, error)
	remove      func(string) error
}

func (e nativeDesktopMutationExchange) readReceipt(ctx context.Context) ([]byte, error) {
	if e.read == nil {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return e.read(ctx, e.receiptPath)
}

func (e nativeDesktopMutationExchange) cleanup() {
	if e.remove == nil {
		return
	}
	_ = e.remove(e.receiptPath)
	_ = e.remove(e.requestPath)
}

var _ runtimeport.DesktopMutationBroker = (*nativeDesktopMutationBroker)(nil)
