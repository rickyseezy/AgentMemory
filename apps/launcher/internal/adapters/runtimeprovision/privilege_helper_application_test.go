package runtimeprovision

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006PrivilegeHelperApplicationBindsExecutesAndSignsClosedRequest(t *testing.T) {
	t.Parallel()
	_, authority, request, receipt := privilegeCodecFixture(t)
	bindings := privilegeCodecArtifactStager(authority).bindings
	envelope := &privilegeRequestEnvelopeStub{request: request, bindings: bindings}
	decoder := &privilegeRequestDecoderStub{envelope: envelope}
	verifier := &privilegeAuthorityVerifierStub{authority: authority, helper: receipt.HelperDigest()}
	copier := &privilegeArtifactCopierStub{}
	store, err := newRootPrivilegeArtifactStore(copier)
	if err != nil {
		t.Fatal(err)
	}
	observation := receipt.TransportInput()
	executor := &privilegeOperationExecutorStub{observation: PrivilegeOperationObservationInput{
		Result: observation.Result, ObservedState: observation.ObservedState,
		PackageStateDigest: observation.PackageStateDigest, RepositoryDigest: observation.RepositoryDigest,
	}}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newProtectedPrivilegeReceiptSigner(&privilegeReceiptSigningKeySourceStub{key: private})
	if err != nil {
		t.Fatal(err)
	}
	clock := &privilegeHelperClockStub{now: request.IssuedAt().Add(time.Second)}
	application, err := NewPrivilegeHelperApplication(PrivilegeHelperDependencies{
		Decoder: decoder, Authority: verifier, Artifacts: store, Executor: executor,
		Replay: &privilegeHelperReplayStub{}, Signer: signer, Clock: clock,
		Encoder: CanonicalPrivilegeReceiptEncoder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := application.ExecutePrivilegeRequest(t.Context(), []byte("canonical request"))
	decoded, decodeError := DecodeCanonicalPrivilegeReceipt(raw)
	if err != nil || decodeError != nil || !decoded.Matches(request, clock.now) ||
		decoded.HelperDigest() != receipt.HelperDigest() || decoder.calls != 1 || verifier.calls != 1 ||
		executor.calls != 1 || copier.calls != 1 || executor.transaction.Root() == "" {
		t.Fatalf(
			"receipt=%+v decoder=%d verifier=%d executor=%d copier=%d error=%v decode=%v",
			decoded, decoder.calls, verifier.calls, executor.calls, copier.calls, err, decodeError,
		)
	}
}

func TestPF006PrivilegeHelperApplicationRejectsEveryUnverifiedBoundary(t *testing.T) {
	t.Parallel()
	_, authority, request, receipt := privilegeCodecFixture(t)
	bindings := privilegeCodecArtifactStager(authority).bindings
	validEnvelope := func() *privilegeRequestEnvelopeStub {
		return &privilegeRequestEnvelopeStub{request: request, bindings: bindings}
	}
	validObservation := receipt.TransportInput()
	for name, configure := range map[string]func(*PrivilegeHelperDependencies){
		"decode": func(input *PrivilegeHelperDependencies) {
			input.Decoder = &privilegeRequestDecoderStub{err: errors.New("decode failed")}
		},
		"authority": func(input *PrivilegeHelperDependencies) {
			input.Authority = &privilegeAuthorityVerifierStub{err: errors.New("authority failed")}
		},
		"binding": func(input *PrivilegeHelperDependencies) {
			input.Decoder = &privilegeRequestDecoderStub{envelope: &privilegeRequestEnvelopeStub{
				request: request, bindings: bindings, err: errors.New("binding failed"),
			}}
		},
		"artifacts": func(input *PrivilegeHelperDependencies) {
			input.Artifacts = &privilegeArtifactPreparerStub{err: errors.New("copy failed")}
		},
		"executor": func(input *PrivilegeHelperDependencies) {
			input.Executor = &privilegeOperationExecutorStub{err: errors.New("operation failed")}
		},
		"replay begin": func(input *PrivilegeHelperDependencies) {
			input.Replay = &privilegeHelperReplayStub{beginError: errors.New("replay begin failed")}
		},
		"replay complete": func(input *PrivilegeHelperDependencies) {
			input.Replay = &privilegeHelperReplayStub{completeError: errors.New("replay complete failed")}
		},
		"signer": func(input *PrivilegeHelperDependencies) {
			input.Signer = &privilegeReceiptSignerStub{err: errors.New("sign failed")}
		},
		"encoder": func(input *PrivilegeHelperDependencies) {
			input.Encoder = &privilegeReceiptEncoderStub{err: errors.New("encode failed")}
		},
		"expired": func(input *PrivilegeHelperDependencies) {
			input.Clock = &privilegeHelperClockStub{now: request.ExpiresAt()}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := PrivilegeHelperDependencies{
				Decoder:   &privilegeRequestDecoderStub{envelope: validEnvelope()},
				Authority: &privilegeAuthorityVerifierStub{authority: authority, helper: receipt.HelperDigest()},
				Artifacts: &privilegeArtifactPreparerStub{transaction: privilegeArtifactTransactionStub{root: "/root/transaction"}},
				Executor: &privilegeOperationExecutorStub{observation: PrivilegeOperationObservationInput{
					Result: validObservation.Result, ObservedState: validObservation.ObservedState,
					PackageStateDigest: validObservation.PackageStateDigest,
					RepositoryDigest:   validObservation.RepositoryDigest,
				}},
				Replay:  &privilegeHelperReplayStub{},
				Signer:  &privilegeReceiptSignerStub{receipt: receipt},
				Clock:   &privilegeHelperClockStub{now: request.IssuedAt().Add(time.Second)},
				Encoder: &privilegeReceiptEncoderStub{raw: []byte(`{"receipt":true}`)},
			}
			configure(&dependencies)
			application, err := NewPrivilegeHelperApplication(dependencies)
			if err != nil {
				t.Fatal(err)
			}
			if raw, executeError := application.ExecutePrivilegeRequest(
				t.Context(), []byte("request"),
			); !errors.Is(executeError, runtimeport.ErrPrivilegeIntegrity) || len(raw) != 0 {
				t.Fatalf("raw=%q error=%v", raw, executeError)
			}
		})
	}
	if application, err := NewPrivilegeHelperApplication(PrivilegeHelperDependencies{}); application != nil || err == nil {
		t.Fatal("missing helper dependencies accepted")
	}
}

func TestPF006PrivilegeHelperApplicationReturnsCompletedReplayWithoutMutation(t *testing.T) {
	t.Parallel()
	_, authority, request, receipt := privilegeCodecFixture(t)
	envelope := &privilegeRequestEnvelopeStub{request: request, bindings: privilegeCodecArtifactStager(authority).bindings}
	replay := &privilegeHelperReplayStub{cached: receipt, completed: true}
	artifacts := &privilegeArtifactPreparerStub{err: errors.New("must not prepare")}
	executor := &privilegeOperationExecutorStub{err: errors.New("must not execute")}
	signer := &privilegeReceiptSignerStub{err: errors.New("must not sign")}
	application, err := NewPrivilegeHelperApplication(PrivilegeHelperDependencies{
		Decoder:   &privilegeRequestDecoderStub{envelope: envelope},
		Authority: &privilegeAuthorityVerifierStub{authority: authority, helper: receipt.HelperDigest()},
		Artifacts: artifacts, Executor: executor, Replay: replay, Signer: signer,
		Clock:   &privilegeHelperClockStub{now: request.IssuedAt().Add(time.Second)},
		Encoder: CanonicalPrivilegeReceiptEncoder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := application.ExecutePrivilegeRequest(t.Context(), []byte("request"))
	decoded, decodeError := DecodeCanonicalPrivilegeReceipt(raw)
	if err != nil || decodeError != nil || decoded.Digest() != receipt.Digest() || replay.beginCalls != 1 ||
		replay.completeCalls != 0 || executor.calls != 0 {
		t.Fatalf("receipt=%x replay=%d/%d executor=%d errors=%v/%v", decoded.Digest(),
			replay.beginCalls, replay.completeCalls, executor.calls, err, decodeError)
	}
}

type privilegeRequestEnvelopeStub struct {
	request  runtimeport.PrivilegeRequest
	bindings []PrivilegeArtifactBinding
	err      error
}

func (s *privilegeRequestEnvelopeStub) BindAuthority(
	runtimeport.LinuxAuthority,
) (runtimeport.PrivilegeRequest, error) {
	return s.request, s.err
}
func (s *privilegeRequestEnvelopeStub) Artifacts() []PrivilegeArtifactBinding {
	return append([]PrivilegeArtifactBinding(nil), s.bindings...)
}
func (*privilegeRequestEnvelopeStub) SignedRelease() []byte            { return []byte(`{}`) }
func (*privilegeRequestEnvelopeStub) SignedRuntimeCatalog() []byte     { return []byte(`{}`) }
func (*privilegeRequestEnvelopeStub) CanonicalPlan() []byte            { return []byte(`{}`) }
func (*privilegeRequestEnvelopeStub) RuntimeCatalogResourceID() string { return "catalog" }
func (*privilegeRequestEnvelopeStub) HelperResourceID() string         { return "helper" }

type privilegeRequestDecoderStub struct {
	envelope PrivilegeRequestEnvelope
	err      error
	calls    int
}

func (s *privilegeRequestDecoderStub) DecodePrivilegeRequest([]byte) (PrivilegeRequestEnvelope, error) {
	s.calls++
	return s.envelope, s.err
}

type privilegeAuthorityVerifierStub struct {
	authority runtimeport.LinuxAuthority
	helper    runtimeinstall.Hash
	err       error
	calls     int
}

func (s *privilegeAuthorityVerifierStub) VerifyPrivilegeAuthority(
	context.Context,
	PrivilegeRequestEnvelope,
) (PrivilegeAuthorityEvidence, error) {
	s.calls++
	if s.err != nil {
		return PrivilegeAuthorityEvidence{}, s.err
	}
	return NewPrivilegeAuthorityEvidence(s.authority, s.helper, runtimeinstall.Sum([]byte("release")))
}

type privilegeArtifactTransactionStub struct{ root string }

func (s privilegeArtifactTransactionStub) Root() string                            { return s.root }
func (privilegeArtifactTransactionStub) Artifacts() []PrivilegeTransactionArtifact { return nil }
func (privilegeArtifactTransactionStub) PackagePaths() []string                    { return []string{"/root/package.deb"} }
func (privilegeArtifactTransactionStub) Artifact(string) (PrivilegeTransactionArtifact, bool) {
	return PrivilegeTransactionArtifact{}, false
}

type privilegeArtifactPreparerStub struct {
	transaction PrivilegeArtifactSet
	err         error
}

func (s *privilegeArtifactPreparerStub) PreparePrivilegeArtifacts(
	context.Context,
	runtimeport.PrivilegeRequest,
	[]PrivilegeArtifactBinding,
) (PrivilegeArtifactSet, error) {
	return s.transaction, s.err
}

type privilegeOperationExecutorStub struct {
	observation PrivilegeOperationObservationInput
	transaction PrivilegeArtifactSet
	err         error
	calls       int
}

func (s *privilegeOperationExecutorStub) ExecutePrivilegeOperation(
	_ context.Context,
	_ runtimeport.PrivilegeRequest,
	transaction PrivilegeArtifactSet,
	_ PrivilegeAuthorityEvidence,
) (PrivilegeOperationObservationInput, error) {
	s.calls++
	s.transaction = transaction
	return s.observation, s.err
}

type privilegeHelperClockStub struct{ now time.Time }

func (s *privilegeHelperClockStub) Now() time.Time { return s.now }

type privilegeHelperReplayStub struct {
	cached        runtimeport.PrivilegeReceipt
	completed     bool
	beginError    error
	completeError error
	beginCalls    int
	completeCalls int
}

func (s *privilegeHelperReplayStub) BeginPrivilegeRequest(
	context.Context,
	runtimeport.PrivilegeRequest,
) (runtimeport.PrivilegeReceipt, bool, error) {
	s.beginCalls++
	return s.cached, s.completed, s.beginError
}

func (s *privilegeHelperReplayStub) CompletePrivilegeRequest(
	context.Context,
	runtimeport.PrivilegeRequest,
	runtimeport.PrivilegeReceipt,
) error {
	s.completeCalls++
	return s.completeError
}

type privilegeReceiptSignerStub struct {
	receipt runtimeport.PrivilegeReceipt
	err     error
}

func (s *privilegeReceiptSignerStub) SignPrivilegeReceipt(
	context.Context,
	runtimeport.PrivilegeReceiptInput,
) (runtimeport.PrivilegeReceipt, error) {
	return s.receipt, s.err
}

type privilegeReceiptEncoderStub struct {
	raw []byte
	err error
}

func (s *privilegeReceiptEncoderStub) EncodePrivilegeReceipt(runtimeport.PrivilegeReceipt) ([]byte, error) {
	return append([]byte(nil), s.raw...), s.err
}
