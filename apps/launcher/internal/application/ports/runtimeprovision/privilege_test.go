package runtimeprovision

import (
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPrivilegeRequestAndReceiptBindNonceExpiryPrincipalMachineAndExactState(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, err := NewLinuxAuthority(testAuthorityInput(plan))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	nonce := Nonce{1, 2, 3}
	expected, _ := ExpectedPrivilegeState(authority, PrivilegeInstallPackages)
	request, err := NewPrivilegeRequest(PrivilegeRequestInput{
		OperationID: "operation-1", Attempt: 2, Operation: PrivilegeInstallPackages,
		Authority: authority, Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	packages, _ := ExpectedPackageStateDigest(authority)
	repository, _ := ExpectedRepositoryStateDigest(authority)
	receipt, err := NewPrivilegeReceipt(PrivilegeReceiptInput{
		RequestDigest: request.Digest(), OperationKey: request.OperationKey(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), Operation: request.Operation(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), Nonce: nonce, ExpiresAt: request.ExpiresAt(),
		Result: PrivilegeResultCompleted, ObservedState: expected, PackageStateDigest: packages,
		RepositoryDigest: repository, HelperDigest: runtimeinstall.Sum([]byte("signed-helper")),
		Signature: make([]byte, 64),
	})
	if err != nil || !receipt.Matches(request, now.Add(time.Second)) {
		t.Fatalf("receipt did not match exact request: %v", err)
	}
	if receipt.Matches(request, request.ExpiresAt()) {
		t.Fatal("receipt remained valid at its exclusive expiry")
	}
	if receipt.Matches(request, request.IssuedAt().Add(-time.Microsecond)) {
		t.Fatal("receipt was accepted before its request issue time")
	}

	mutations := []func(*PrivilegeReceiptInput){
		func(input *PrivilegeReceiptInput) { input.Nonce[0] ^= 1 },
		func(input *PrivilegeReceiptInput) { input.PlanDigest = runtimeinstall.Sum([]byte("other-plan")) },
		func(input *PrivilegeReceiptInput) { input.PrincipalID = "linux:uid:1001" },
		func(input *PrivilegeReceiptInput) { input.MachineDigest = runtimeinstall.Sum([]byte("other-machine")) },
		func(input *PrivilegeReceiptInput) {
			input.PackageStateDigest = runtimeinstall.Sum([]byte("other-packages"))
		},
		func(input *PrivilegeReceiptInput) { input.RepositoryDigest = runtimeinstall.Sum([]byte("other-repo")) },
	}
	for index, mutate := range mutations {
		input := PrivilegeReceiptInput{
			RequestDigest: request.Digest(), OperationKey: request.OperationKey(), PlanDigest: authority.PlanDigest(),
			AuthorityDigest: authority.Digest(), Operation: request.Operation(), PrincipalID: authority.PrincipalID(),
			MachineDigest: authority.MachineDigest(), Nonce: nonce, ExpiresAt: request.ExpiresAt(),
			Result: PrivilegeResultCompleted, ObservedState: expected, PackageStateDigest: packages,
			RepositoryDigest: repository, HelperDigest: runtimeinstall.Sum([]byte("signed-helper")),
			Signature: make([]byte, 64),
		}
		mutate(&input)
		candidate, candidateError := NewPrivilegeReceipt(input)
		if candidateError == nil && candidate.Matches(request, now.Add(time.Second)) {
			t.Fatalf("mutation %d retained receipt authority", index)
		}
	}
}

func TestPrivilegeRequestRejectsReplayFriendlyOrUnboundedInputs(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, _ := NewLinuxAuthority(testAuthorityInput(plan))
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	expected, _ := ExpectedPrivilegeState(authority, PrivilegeConfigureRepository)
	base := PrivilegeRequestInput{
		OperationID: "operation-1", Attempt: 1, Operation: PrivilegeConfigureRepository,
		Authority: authority, Nonce: Nonce{1}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
	}
	tests := []struct {
		name   string
		mutate func(*PrivilegeRequestInput)
	}{
		{name: "zero nonce", mutate: func(input *PrivilegeRequestInput) { input.Nonce = Nonce{} }},
		{name: "six minute lifetime", mutate: func(input *PrivilegeRequestInput) { input.ExpiresAt = now.Add(6 * time.Minute) }},
		{name: "non UTC", mutate: func(input *PrivilegeRequestInput) { input.IssuedAt = now.In(time.FixedZone("offset", 3600)) }},
		{name: "unsafe operation ID", mutate: func(input *PrivilegeRequestInput) { input.OperationID = "op;rm" }},
		{name: "unknown operation", mutate: func(input *PrivilegeRequestInput) { input.Operation = "run_command" }},
		{name: "missing state", mutate: func(input *PrivilegeRequestInput) { input.ExpectedState = runtimeinstall.Hash{} }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := base
			test.mutate(&candidate)
			if _, err := NewPrivilegeRequest(candidate); err == nil {
				t.Fatalf("NewPrivilegeRequest(%s) succeeded", test.name)
			}
		})
	}
}

func TestPrivilegeContractsProjectOnlyBoundNonSecretEvidence(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, _ := NewLinuxAuthority(testAuthorityInput(plan))
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	expected, _ := ExpectedPrivilegeState(authority, PrivilegeVerifyManagedState)
	request, err := NewPrivilegeRequest(PrivilegeRequestInput{
		OperationID: "operation-2", Attempt: 3, Operation: PrivilegeVerifyManagedState,
		Authority: authority, Nonce: Nonce{9}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.OperationID() != "operation-2" || request.Attempt() != 3 || !request.IssuedAt().Equal(now) ||
		request.OperationKey().IsZero() || request.Digest().IsZero() {
		t.Fatal("privilege request projection was incomplete")
	}
	packages, _ := ExpectedPackageStateDigest(authority)
	repository, _ := ExpectedRepositoryStateDigest(authority)
	helper := runtimeinstall.Sum([]byte("helper"))
	subordinateState := runtimeinstall.Sum([]byte("subordinate-state"))
	receipt, err := NewPrivilegeReceipt(PrivilegeReceiptInput{
		RequestDigest: request.Digest(), OperationKey: request.OperationKey(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), Operation: request.Operation(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), Nonce: request.Nonce(), ExpiresAt: request.ExpiresAt(),
		Result: PrivilegeResultAlreadyApplied, ObservedState: expected, PackageStateDigest: packages,
		RepositoryDigest: repository, ServiceUnitDigest: authority.ServiceUnitDigest(),
		ServiceEnabled: true, ServiceActive: true, UserLingerEnabled: true,
		SubordinateIDs: authority.SubordinateIDCount(), SubordinateUIDStart: 100000,
		SubordinateGIDStart: 200000, SubordinateStateDigest: subordinateState,
		HelperDigest: helper, Signature: make([]byte, 64),
	})
	if err != nil || !receipt.Matches(request, now) || receipt.HelperDigest() != helper ||
		receipt.PackageStateDigest() != packages || receipt.RepositoryDigest() != repository ||
		receipt.ServiceUnitDigest() != authority.ServiceUnitDigest() ||
		!receipt.ServiceEnabled() || !receipt.ServiceActive() || !receipt.UserLingerEnabled() ||
		receipt.SubordinateIDs() != authority.SubordinateIDCount() || receipt.SubordinateUIDStart() != 100000 ||
		receipt.SubordinateGIDStart() != 200000 || receipt.SubordinateStateDigest() != subordinateState ||
		len(receipt.Signature()) != 64 {
		t.Fatalf("privilege receipt projection failed: %v", err)
	}
	signature := receipt.Signature()
	signature[0] = 1
	if receipt.Signature()[0] != 0 {
		t.Fatal("receipt signature projection was mutable")
	}
}

func TestEveryPrivilegeOperationRequiresItsExactReceiptShape(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, err := NewLinuxAuthority(testAuthorityInput(plan))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	packages, _ := ExpectedPackageStateDigest(authority)
	repository, _ := ExpectedRepositoryStateDigest(authority)
	operations := []PrivilegeOperation{
		PrivilegeConfigureRepository,
		PrivilegeInstallPackages,
		PrivilegeConfigureSubordinateIDs,
		PrivilegeEnableUserService,
		PrivilegeVerifyManagedState,
	}
	nonces := []Nonce{{1}, {2}, {3}, {4}, {5}}
	for index, operation := range operations {
		operation := operation
		index := index
		t.Run(string(operation), func(t *testing.T) {
			t.Parallel()
			expected, stateError := ExpectedPrivilegeState(authority, operation)
			if stateError != nil {
				t.Fatal(stateError)
			}
			request, requestError := NewPrivilegeRequest(PrivilegeRequestInput{
				OperationID: "operation-all", Attempt: 1, Operation: operation, Authority: authority,
				Nonce: nonces[index], IssuedAt: now, ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
			})
			if requestError != nil {
				t.Fatal(requestError)
			}
			input := PrivilegeReceiptInput{
				RequestDigest: request.Digest(), OperationKey: request.OperationKey(), PlanDigest: authority.PlanDigest(),
				AuthorityDigest: authority.Digest(), Operation: operation, PrincipalID: authority.PrincipalID(),
				MachineDigest: authority.MachineDigest(), Nonce: request.Nonce(), ExpiresAt: request.ExpiresAt(),
				Result: PrivilegeResultCompleted, ObservedState: expected,
				HelperDigest: runtimeinstall.Sum([]byte("helper")), Signature: make([]byte, 64),
			}
			switch operation {
			case PrivilegeConfigureRepository:
				input.RepositoryDigest = repository
			case PrivilegeInstallPackages:
				input.RepositoryDigest, input.PackageStateDigest = repository, packages
			case PrivilegeConfigureSubordinateIDs:
				input.SubordinateIDs = authority.SubordinateIDCount()
				input.SubordinateUIDStart, input.SubordinateGIDStart = 100000, 200000
				input.SubordinateStateDigest = runtimeinstall.Sum([]byte("subordinate-state"))
			case PrivilegeEnableUserService:
				input.ServiceUnitDigest = authority.ServiceUnitDigest()
				input.ServiceEnabled, input.ServiceActive, input.UserLingerEnabled = true, true, true
			case PrivilegeVerifyManagedState:
				input.RepositoryDigest, input.PackageStateDigest = repository, packages
				input.ServiceUnitDigest, input.SubordinateIDs = authority.ServiceUnitDigest(), authority.SubordinateIDCount()
				input.ServiceEnabled, input.ServiceActive, input.UserLingerEnabled = true, true, true
				input.SubordinateUIDStart, input.SubordinateGIDStart = 100000, 200000
				input.SubordinateStateDigest = runtimeinstall.Sum([]byte("subordinate-state"))
			}
			receipt, receiptError := NewPrivilegeReceipt(input)
			if receiptError != nil || receipt.Digest().IsZero() || !receipt.Matches(request, now) {
				t.Fatalf("receipt for %s = digest:%s match:%t error:%v", operation, receipt.Digest(), receipt.Matches(request, now), receiptError)
			}
			input.RepositoryDigest = runtimeinstall.Sum([]byte("unexpected-repository"))
			bad, badError := NewPrivilegeReceipt(input)
			if badError == nil && bad.Matches(request, now) {
				t.Fatalf("receipt for %s accepted an operation-inconsistent field", operation)
			}
		})
	}
	if _, err := ExpectedPrivilegeState(LinuxAuthority{}, PrivilegeConfigureRepository); err == nil {
		t.Fatal("zero authority produced privilege state")
	}
}
