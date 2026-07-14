// Package agentconfigapp orchestrates PF-001's portable host-configuration
// transaction. It owns compensation policy while filesystem details remain in
// the Store adapter and JSON merge rules remain in the domain.
package agentconfigapp

import (
	"context"
	"errors"
	"reflect"
	"time"

	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const compensationTimeout = 10 * time.Second

var (
	// ErrInvalidDependency rejects an incomplete composition root.
	ErrInvalidDependency = errors.New("invalid agent configuration dependency")
	// ErrInvalidReceipt rejects evidence inconsistent with the merge plan.
	ErrInvalidReceipt = errors.New("invalid agent configuration receipt")
	// ErrInvocationVerification classifies post-write handshake failure.
	ErrInvocationVerification = errors.New("agent invocation verification failed")
	// ErrCompensationFailed reports that automatic restore could not safely
	// complete. A conflict specifically means a user edit was preserved.
	ErrCompensationFailed = errors.New("agent configuration compensation failed")
)

// Application is the complete portable AgentConfigAdapter implementation.
type Application struct {
	store    port.Store
	verifier port.InvocationVerifier
	policies map[domain.AgentHost]port.DocumentPolicy
}

// New rejects both nil interfaces and typed nil implementations.
func New(store port.Store, verifier port.InvocationVerifier, policies ...port.DocumentPolicy) (*Application, error) {
	if nilInterface(store) || nilInterface(verifier) {
		return nil, ErrInvalidDependency
	}
	registered := make(map[domain.AgentHost]port.DocumentPolicy, len(policies))
	for _, policy := range policies {
		if nilInterface(policy) {
			return nil, ErrInvalidDependency
		}
		matched := domain.AgentHost("")
		for _, host := range []domain.AgentHost{
			domain.AgentHostGeneric, domain.AgentHostCodex, domain.AgentHostClaude,
			domain.AgentHostGemini, domain.AgentHostGLM,
		} {
			if policy.Supports(host) {
				if matched != "" || host != domain.AgentHostCodex {
					return nil, ErrInvalidDependency
				}
				matched = host
			}
		}
		if matched == "" || registered[matched] != nil {
			return nil, ErrInvalidDependency
		}
		registered[matched] = policy
	}
	return &Application{store: store, verifier: verifier, policies: registered}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	}
	return false
}

// MergeRequest is the complete immutable-by-value mutation input.
type MergeRequest struct {
	Location                   port.ConfigLocation
	Target                     domain.Target
	ExpectedManagedEntryDigest domain.Digest
}

// MergeResult exposes the plan and durable apply evidence without mutable data.
type MergeResult struct {
	plan    domain.MergePlan
	receipt port.ApplyReceipt
}

// Changed reports whether this call required a filesystem mutation.
func (r MergeResult) Changed() bool { return r.plan.Changed() }

// Plan returns the immutable merge plan.
func (r MergeResult) Plan() domain.MergePlan { return r.plan }

// Receipt returns durable evidence; it is invalid for an idempotent no-change.
func (r MergeResult) Receipt() port.ApplyReceipt { return r.receipt }

// Merge executes read/validate/plan/CAS-write/verify with automatic safe
// compensation after a post-write failure.
func (a *Application) Merge(ctx context.Context, request MergeRequest) (MergeResult, error) {
	if err := ctx.Err(); err != nil {
		return MergeResult{}, err
	}
	if request.Location.String() == "" || request.Target.Command() == "" {
		return MergeResult{}, port.ErrInvalidArgument
	}
	detection, err := a.Detect(ctx, request.Location)
	if err != nil {
		return MergeResult{}, err
	}
	var original []byte
	if detection.Exists() {
		snapshot, readErr := a.Read(ctx, request.Location)
		if readErr != nil {
			return MergeResult{}, readErr
		}
		original = snapshot.Content()
		policy, policyErr := a.documentPolicy(request.Target.Host())
		if policyErr != nil {
			return MergeResult{}, policyErr
		}
		if validateErr := policy.Validate(original); validateErr != nil {
			return MergeResult{}, validateErr
		}
	}
	plan, err := a.PlanMerge(original, detection.Exists(), request.Target, request.ExpectedManagedEntryDigest)
	if err != nil {
		return MergeResult{}, err
	}
	result := MergeResult{plan: plan}
	if !plan.Changed() {
		if err := a.VerifyInvocation(ctx, request.Location, request.Target); err != nil {
			return result, errors.Join(ErrInvocationVerification, err)
		}
		return result, nil
	}
	receipt, err := a.ApplyAtomic(ctx, request.Location, plan)
	if err != nil {
		return result, err
	}
	result.receipt = receipt
	if !receiptMatchesPlan(receipt, plan) {
		return result, ErrInvalidReceipt
	}
	if verifyErr := a.VerifyInvocation(ctx, request.Location, request.Target); verifyErr != nil {
		restoreContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), compensationTimeout)
		defer cancel()
		restored, restoreErr := a.RestoreBackup(restoreContext, request.Location, receipt)
		if restoreErr == nil && !restoreMatchesPlan(restored, plan) {
			restoreErr = ErrInvalidReceipt
		}
		if restoreErr != nil {
			return result, errors.Join(ErrInvocationVerification, verifyErr, ErrCompensationFailed, restoreErr)
		}
		return result, errors.Join(ErrInvocationVerification, verifyErr)
	}
	return result, nil
}

func restoreMatchesPlan(receipt port.RestoreReceipt, plan domain.MergePlan) bool {
	if !receipt.Valid() || receipt.Exists() != plan.OriginalExisted() {
		return false
	}
	if plan.OriginalExisted() {
		return receipt.Digest().Equal(plan.BeforeDigest())
	}
	return receipt.Digest().IsZero()
}

func receiptMatchesPlan(receipt port.ApplyReceipt, plan domain.MergePlan) bool {
	return receipt.Valid() && receipt.Changed() && receipt.OriginalExisted() == plan.OriginalExisted() &&
		receipt.BeforeDigest().Equal(plan.BeforeDigest()) && receipt.AfterDigest().Equal(plan.AfterDigest()) &&
		receipt.ManagedEntryDigest().Equal(plan.ManagedEntryDigest())
}

// Detect delegates side-effect-free host detection.
func (a *Application) Detect(ctx context.Context, location port.ConfigLocation) (port.Detection, error) {
	return a.store.Detect(ctx, location)
}

// Read returns exact, immutable host bytes.
func (a *Application) Read(ctx context.Context, location port.ConfigLocation) (port.Snapshot, error) {
	return a.store.Read(ctx, location)
}

// Validate delegates strict host-neutral JSON validation.
func (*Application) Validate(content []byte) error { return domain.ValidateDocument(content) }

// PlanMerge delegates to the exact host syntax policy selected by target.
func (a *Application) PlanMerge(content []byte, existed bool, target domain.Target, expected domain.Digest) (domain.MergePlan, error) {
	policy, err := a.documentPolicy(target.Host())
	if err != nil {
		return domain.MergePlan{}, err
	}
	return policy.PlanMerge(content, existed, target, expected)
}

// ApplyAtomic delegates the receipt-bound filesystem transaction.
func (a *Application) ApplyAtomic(ctx context.Context, location port.ConfigLocation, plan domain.MergePlan) (port.ApplyReceipt, error) {
	return a.store.ApplyAtomic(ctx, location, plan)
}

// VerifyInvocation first proves the exact owned entry remains configured and
// then delegates the bounded no-shell launcher handshake.
func (a *Application) VerifyInvocation(ctx context.Context, location port.ConfigLocation, target domain.Target) error {
	snapshot, err := a.store.Read(ctx, location)
	if err != nil {
		return err
	}
	policy, policyErr := a.documentPolicy(target.Host())
	if policyErr != nil {
		return policyErr
	}
	if err := policy.VerifyManagedEntry(snapshot.Content(), target); err != nil {
		return err
	}
	return a.verifier.Verify(ctx, target)
}

func (a *Application) documentPolicy(host domain.AgentHost) (port.DocumentPolicy, error) {
	if !host.Valid() {
		return nil, port.ErrInvalidArgument
	}
	if host == domain.AgentHostCodex {
		policy := a.policies[host]
		if nilInterface(policy) {
			return nil, port.ErrUnsupportedPlatform
		}
		return policy, nil
	}
	return hostNeutralDocumentPolicy{}, nil
}

type hostNeutralDocumentPolicy struct{}

func (hostNeutralDocumentPolicy) Supports(host domain.AgentHost) bool {
	return host.Valid() && host != domain.AgentHostCodex
}

func (hostNeutralDocumentPolicy) Validate(contents []byte) error {
	return domain.ValidateDocument(contents)
}

func (hostNeutralDocumentPolicy) PlanMerge(
	contents []byte,
	existed bool,
	target domain.Target,
	expected domain.Digest,
) (domain.MergePlan, error) {
	return domain.PlanMerge(contents, existed, target, expected)
}

func (hostNeutralDocumentPolicy) VerifyManagedEntry(contents []byte, target domain.Target) error {
	return domain.VerifyManagedEntry(contents, target)
}

// RestoreBackup delegates conflict-safe compare-and-swap compensation.
func (a *Application) RestoreBackup(ctx context.Context, location port.ConfigLocation, receipt port.ApplyReceipt) (port.RestoreReceipt, error) {
	return a.store.RestoreBackup(ctx, location, receipt)
}

var _ port.Adapter = (*Application)(nil)
