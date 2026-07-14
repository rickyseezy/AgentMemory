package runtimeprovision

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestDesktopAuthorityProjectsImmutableExactExecutionContract(t *testing.T) {
	t.Parallel()
	plan := desktopTestPlan(t, runtimeinstall.PlatformWindows, runtimeinstall.ArchitectureAMD64)
	authority, err := NewDesktopAuthority(desktopAuthorityInput(plan, runtimeinstall.PlatformWindows))
	if err != nil {
		t.Fatal(err)
	}
	publisher := authority.Publisher()
	terms := authority.Terms()
	if publisher.Kind() != DesktopPublisherAuthenticode || publisher.Identity() == "" ||
		publisher.SigningKeyIdentity() == "" || publisher.PackageIdentity() != "com.docker.docker" ||
		!publisher.valid(runtimeinstall.PlatformWindows) || terms.ID() == "" || terms.Version() == "" || terms.URL() == "" || !terms.valid() {
		t.Fatalf("publisher/terms projection was incomplete: %#v %#v", publisher, terms)
	}
	if authority.PlanDigest() != plan.Digest() || authority.CatalogDigest() != plan.CatalogDigest() ||
		authority.Platform() != runtimeinstall.PlatformWindows || authority.Architecture() != runtimeinstall.ArchitectureAMD64 ||
		authority.PrincipalID() == "" || authority.UserName() == "" || authority.MachineDigest().IsZero() ||
		authority.HomeDirectory() == "" || authority.OSProduct() != "windows-11" ||
		authority.MinimumOSVersion() == "" || authority.MaximumOSVersion() == "" ||
		authority.MinimumBuild() == 0 || authority.MaximumBuild() == 0 || authority.MinimumCPUs() == 0 ||
		authority.MinimumTotalMemory() == 0 || authority.MinimumAvailableMemory() == 0 || authority.MinimumFreeDisk() == 0 ||
		authority.RuntimeVersion() == "" || authority.EngineVersion() == "" || authority.ComposeVersion() == "" ||
		authority.Endpoint() == "" || authority.ArtifactPath() == "" || authority.ArtifactSHA256().IsZero() ||
		authority.ArtifactBytes() == 0 || authority.ArtifactSourceURL() == "" || authority.ApplicationPath() == "" ||
		authority.ApplicationExecutable() == "" || authority.DockerCLIPath() == "" || authority.ComposePluginPath() == "" ||
		authority.ProbeImage() == "" || authority.ProbeImageDigest().IsZero() || authority.ProbeContractVersion() != "1" ||
		authority.CapabilityPolicyDigest().IsZero() || authority.MinimumWSLVersion() != "2.1.5" ||
		authority.VendorUIMandatory() {
		t.Fatal("desktop authority omitted an execution-relevant field")
	}
	reboots := authority.RebootExitCodes()
	features := authority.WindowsFeatures()
	reboots[0] = 0
	features[0] = "attacker"
	if authority.RebootExitCodes()[0] == 0 || authority.WindowsFeatures()[0] == "attacker" {
		t.Fatal("desktop authority returned mutable collections")
	}
}

func TestDesktopHostEvidenceSupportsOnlyExactSecureHost(t *testing.T) {
	t.Parallel()
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		platform := platform
		t.Run(platform.String(), func(t *testing.T) {
			t.Parallel()
			authority := desktopContractAuthority(t, platform)
			input := desktopHostInput(authority)
			evidence, err := NewDesktopHostEvidence(input)
			if err != nil || evidence.Digest().IsZero() || evidence.Supports(authority) != nil || !evidence.PrerequisitesReady(authority) {
				t.Fatalf("valid host evidence = %#v, %v", evidence, err)
			}
			input.EnabledWindowsFeatures = append(input.EnabledWindowsFeatures, "attacker")
			if len(evidence.input.EnabledWindowsFeatures) > 0 && evidence.input.EnabledWindowsFeatures[len(evidence.input.EnabledWindowsFeatures)-1] == "attacker" {
				t.Fatal("host evidence retained a caller-owned slice")
			}
		})
	}
}

func TestDesktopHostEvidenceRejectsMalformedAndInsufficientObservations(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformWindows)
	valid := desktopHostInput(authority)
	invalid := []struct {
		name   string
		mutate func(*DesktopHostEvidenceInput)
	}{
		{name: "unknown architecture", mutate: func(v *DesktopHostEvidenceInput) { v.Architecture = runtimeinstall.ArchitectureUnknown }},
		{name: "unsafe product", mutate: func(v *DesktopHostEvidenceInput) { v.OSProduct = "windows\n11" }},
		{name: "zero build", mutate: func(v *DesktopHostEvidenceInput) { v.Build = 0 }},
		{name: "unsafe principal", mutate: func(v *DesktopHostEvidenceInput) { v.PrincipalID = "bad\nprincipal" }},
		{name: "zero machine", mutate: func(v *DesktopHostEvidenceInput) { v.MachineDigest = runtimeinstall.Hash{} }},
		{name: "zero CPUs", mutate: func(v *DesktopHostEvidenceInput) { v.CPUs = 0 }},
		{name: "available exceeds total", mutate: func(v *DesktopHostEvidenceInput) { v.AvailableMemory = v.TotalMemory + 1 }},
		{name: "zero disk", mutate: func(v *DesktopHostEvidenceInput) { v.FreeDisk = 0 }},
		{name: "unknown feature", mutate: func(v *DesktopHostEvidenceInput) { v.EnabledWindowsFeatures = []string{"TelnetClient"} }},
		{name: "duplicate feature", mutate: func(v *DesktopHostEvidenceInput) {
			v.EnabledWindowsFeatures = []string{"Microsoft-Windows-Subsystem-Linux", "Microsoft-Windows-Subsystem-Linux"}
		}},
		{name: "reordered features", mutate: func(v *DesktopHostEvidenceInput) {
			v.EnabledWindowsFeatures = []string{"VirtualMachinePlatform", "Microsoft-Windows-Subsystem-Linux"}
		}},
		{name: "too many features", mutate: func(v *DesktopHostEvidenceInput) {
			v.EnabledWindowsFeatures = []string{"Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "TelnetClient"}
		}},
		{name: "unsafe WSL", mutate: func(v *DesktopHostEvidenceInput) { v.WSLVersion = "latest" }},
	}
	for _, test := range invalid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			candidate.EnabledWindowsFeatures = slices.Clone(valid.EnabledWindowsFeatures)
			test.mutate(&candidate)
			if _, err := NewDesktopHostEvidence(candidate); err == nil {
				t.Fatalf("malformed host %q was accepted", test.name)
			}
		})
	}

	for _, mutate := range []func(*DesktopHostEvidenceInput){
		func(v *DesktopHostEvidenceInput) { v.OSVersion = "9.0.0" },
		func(v *DesktopHostEvidenceInput) { v.Build = authority.MinimumBuild() - 1 },
		func(v *DesktopHostEvidenceInput) { v.CPUs = authority.MinimumCPUs() - 1 },
		func(v *DesktopHostEvidenceInput) { v.Virtualization = false },
		func(v *DesktopHostEvidenceInput) { v.LocalFilesystem = false },
		func(v *DesktopHostEvidenceInput) { v.AtRestEncryption = false },
		func(v *DesktopHostEvidenceInput) { v.WSLVersion = "2.0.0" },
	} {
		candidate := valid
		candidate.EnabledWindowsFeatures = slices.Clone(valid.EnabledWindowsFeatures)
		mutate(&candidate)
		evidence, err := NewDesktopHostEvidence(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Supports(authority) == nil || evidence.PrerequisitesReady(authority) {
			t.Fatal("insufficient host evidence supported signed authority")
		}
	}

	mac := desktopContractAuthority(t, runtimeinstall.PlatformDarwin)
	macInput := desktopHostInput(mac)
	macInput.WSLVersion = "2.1.5"
	if _, err := NewDesktopHostEvidence(macInput); err == nil {
		t.Fatal("macOS observation accepted ambient Windows evidence")
	}
}

func TestDesktopRuntimeEvidenceDistinguishesAbsentCompatibleAndUnsafeState(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformDarwin)
	absent, err := NewDesktopRuntimeEvidence(DesktopRuntimeEvidenceInput{Condition: runtimeinstall.RuntimeConditionAbsent})
	if err != nil || absent.Condition() != runtimeinstall.RuntimeConditionAbsent || absent.Compatible(authority) ||
		absent.Ownership() != runtimeinstall.OwnershipUnknown || absent.Workloads() != 0 || absent.Digest().IsZero() {
		t.Fatalf("absent evidence = %#v, %v", absent, err)
	}
	compatibleInput := desktopRuntimeInput(authority)
	compatible, err := NewDesktopRuntimeEvidence(compatibleInput)
	if err != nil || !compatible.Compatible(authority) || compatible.Workloads() != authority.UnrelatedWorkloads() {
		t.Fatalf("compatible evidence = %#v, %v", compatible, err)
	}
	for _, mutate := range []func(*DesktopRuntimeEvidenceInput){
		func(v *DesktopRuntimeEvidenceInput) { v.CloudOffload = true },
		func(v *DesktopRuntimeEvidenceInput) { v.TCPListener = true },
		func(v *DesktopRuntimeEvidenceInput) { v.Endpoint = "tcp://127.0.0.1:2375" },
		func(v *DesktopRuntimeEvidenceInput) { v.PublisherVerified = false },
		func(v *DesktopRuntimeEvidenceInput) { v.RuntimeVersion = "4.69.0" },
	} {
		candidate := compatibleInput
		mutate(&candidate)
		evidence, candidateErr := NewDesktopRuntimeEvidence(candidate)
		if candidateErr == nil && evidence.Compatible(authority) {
			t.Fatal("unsafe runtime evidence was compatible")
		}
	}
	invalid := []DesktopRuntimeEvidenceInput{
		{},
		{Condition: runtimeinstall.RuntimeConditionAbsent, Product: "docker_desktop"},
		{Condition: runtimeinstall.RuntimeConditionRunning, Product: "docker_desktop"},
	}
	for _, input := range invalid {
		if _, candidateErr := NewDesktopRuntimeEvidence(input); candidateErr == nil {
			t.Fatalf("malformed runtime evidence was accepted: %#v", input)
		}
	}
}

func TestDesktopArtifactEvidenceRequiresExactAcquisitionAndNativePublisherProof(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformWindows)
	publisher := authority.Publisher()
	input := DesktopArtifactEvidenceInput{
		AuthorityDigest: authority.Digest(), Path: authority.ArtifactPath(), SHA256: authority.ArtifactSHA256(),
		Bytes: authority.ArtifactBytes(), SourceURL: authority.ArtifactSourceURL(), TLSVerified: true,
		PublisherKind: publisher.Kind(), PublisherIdentity: publisher.Identity(),
		CertificateSHA256: publisher.CertificateSHA256(), NativeVerified: true,
	}
	evidence, err := NewDesktopArtifactEvidence(input)
	if err != nil || !evidence.AcquiredFor(authority) || !evidence.VerifiedFor(authority) || evidence.Digest().IsZero() {
		t.Fatalf("verified artifact = %#v, %v", evidence, err)
	}
	acquiredInput := input
	acquiredInput.PublisherKind = ""
	acquiredInput.PublisherIdentity = ""
	acquiredInput.CertificateSHA256 = runtimeinstall.Hash{}
	acquiredInput.NativeVerified = false
	acquired, err := NewDesktopArtifactEvidence(acquiredInput)
	if err != nil || !acquired.AcquiredFor(authority) || acquired.VerifiedFor(authority) {
		t.Fatalf("acquired artifact = %#v, %v", acquired, err)
	}
	for _, mutate := range []func(*DesktopArtifactEvidenceInput){
		func(v *DesktopArtifactEvidenceInput) { v.AuthorityDigest = runtimeinstall.Hash{} },
		func(v *DesktopArtifactEvidenceInput) { v.Path = "" },
		func(v *DesktopArtifactEvidenceInput) { v.SHA256 = runtimeinstall.Hash{} },
		func(v *DesktopArtifactEvidenceInput) { v.Bytes = 0 },
		func(v *DesktopArtifactEvidenceInput) { v.SourceURL = "" },
		func(v *DesktopArtifactEvidenceInput) { v.TLSVerified = false },
		func(v *DesktopArtifactEvidenceInput) { v.PublisherIdentity = "" },
	} {
		candidate := input
		mutate(&candidate)
		candidateEvidence, candidateErr := NewDesktopArtifactEvidence(candidate)
		if candidateErr == nil && (candidateEvidence.AcquiredFor(authority) || candidateEvidence.VerifiedFor(authority)) {
			t.Fatal("invalid artifact evidence matched authority")
		}
	}
}

func TestDesktopInstalledApplicationEvidenceRequiresSignedVersionAndPublisher(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformDarwin)
	absent, err := NewDesktopInstalledApplicationEvidence(DesktopInstalledApplicationEvidenceInput{
		AuthorityDigest: authority.Digest(),
	})
	if err != nil || absent.Present() || absent.RuntimeVersion() != "" || !absent.VerifiedFor(authority) || absent.Digest().IsZero() {
		t.Fatalf("absent installed application = %#v, %v", absent, err)
	}
	publisher := authority.Publisher()
	present, err := NewDesktopInstalledApplicationEvidence(DesktopInstalledApplicationEvidenceInput{
		AuthorityDigest: authority.Digest(), Present: true, RuntimeVersion: authority.RuntimeVersion(),
		PublisherKind: publisher.Kind(), PublisherIdentity: publisher.Identity(),
		CertificateSHA256: publisher.CertificateSHA256(), NativeVerified: true,
	})
	if err != nil || !present.Present() || present.RuntimeVersion() != authority.RuntimeVersion() || !present.VerifiedFor(authority) {
		t.Fatalf("present installed application = %#v, %v", present, err)
	}
	for _, mutate := range []func(*DesktopInstalledApplicationEvidenceInput){
		func(v *DesktopInstalledApplicationEvidenceInput) { v.AuthorityDigest = runtimeinstall.Hash{} },
		func(v *DesktopInstalledApplicationEvidenceInput) { v.RuntimeVersion = "latest" },
		func(v *DesktopInstalledApplicationEvidenceInput) { v.PublisherKind = "" },
		func(v *DesktopInstalledApplicationEvidenceInput) { v.PublisherIdentity = "" },
		func(v *DesktopInstalledApplicationEvidenceInput) { v.CertificateSHA256 = runtimeinstall.Hash{} },
		func(v *DesktopInstalledApplicationEvidenceInput) { v.NativeVerified = false },
	} {
		input := DesktopInstalledApplicationEvidenceInput{
			AuthorityDigest: authority.Digest(), Present: true, RuntimeVersion: authority.RuntimeVersion(),
			PublisherKind: publisher.Kind(), PublisherIdentity: publisher.Identity(),
			CertificateSHA256: publisher.CertificateSHA256(), NativeVerified: true,
		}
		mutate(&input)
		if _, candidateErr := NewDesktopInstalledApplicationEvidence(input); candidateErr == nil {
			t.Fatal("invalid installed application evidence was accepted")
		}
	}
	if _, err := NewDesktopInstalledApplicationEvidence(DesktopInstalledApplicationEvidenceInput{
		AuthorityDigest: authority.Digest(), RuntimeVersion: authority.RuntimeVersion(),
	}); err == nil {
		t.Fatal("absent application accepted product metadata")
	}
}

func TestDesktopConsentIsExplicitAuthenticatedImmutableAndTimeBound(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformDarwin)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	nonce := Nonce{1, 2, 3}
	request, err := NewDesktopConsentRequest("desktop-consent-1", 2, authority, nonce, now, now.Add(5*time.Minute))
	if err != nil || request.OperationID() == "" || request.Attempt() != 2 || request.Authority().Digest() != authority.Digest() ||
		request.Nonce() != nonce || request.IssuedAt() != now || request.ExpiresAt() != now.Add(5*time.Minute) || request.Digest().IsZero() {
		t.Fatalf("consent request = %#v, %v", request, err)
	}
	receipt := desktopConsentReceipt(t, request, now.Add(time.Minute), now.Add(24*time.Hour))
	if !receipt.Matches(request, now.Add(2*time.Minute)) || !receipt.Authorizes(authority, now.Add(2*time.Minute)) || receipt.Digest().IsZero() {
		t.Fatal("valid explicit consent did not authorize the exact request")
	}
	signature := receipt.Signature()
	signature[0] ^= 0xff
	if bytes.Equal(signature, receipt.Signature()) {
		t.Fatal("consent receipt exposed its signature storage")
	}
	if receipt.Matches(request, now.Add(-time.Second)) || receipt.Matches(request, now.Add(25*time.Hour)) ||
		receipt.Authorizes(authority, now.Add(25*time.Hour)) {
		t.Fatal("consent was valid outside its decision lifetime")
	}
	otherRequest, _ := NewDesktopConsentRequest("desktop-consent-1", 2, authority, Nonce{9}, now, now.Add(5*time.Minute))
	if receipt.Matches(otherRequest, now.Add(2*time.Minute)) {
		t.Fatal("consent authorized another nonce")
	}
}

func TestDesktopConsentRejectsMalformedRequestsAndReceipts(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformDarwin)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	for _, input := range []struct {
		operation string
		attempt   uint32
		nonce     Nonce
		issued    time.Time
		expires   time.Time
	}{
		{operation: "bad id", attempt: 1, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operation: "desktop-1", attempt: 0, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operation: "desktop-1", attempt: 1, nonce: Nonce{}, issued: now, expires: now.Add(time.Minute)},
		{operation: "desktop-1", attempt: 1, nonce: Nonce{1}, issued: now.Local(), expires: now.Add(time.Minute)},
		{operation: "desktop-1", attempt: 1, nonce: Nonce{1}, issued: now, expires: now.Add(11 * time.Minute)},
	} {
		if _, err := NewDesktopConsentRequest(input.operation, input.attempt, authority, input.nonce, input.issued, input.expires); err == nil {
			t.Fatalf("invalid consent request was accepted: %#v", input)
		}
	}
	request, _ := NewDesktopConsentRequest("desktop-1", 1, authority, Nonce{1}, now, now.Add(time.Minute))
	signature := bytes.Repeat([]byte{7}, 64)
	valid := DesktopConsentReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: authority.Digest(), PlanDigest: authority.PlanDigest(),
		TermsDigest: authority.Terms().Digest(), PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: request.Nonce(), ExplicitlyAccepted: true, AuthorityAndEntitlement: true,
		NonPreselectedConfirmation: true, AcceptedAt: now, ExpiresAt: now.Add(time.Hour),
		Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	}
	for _, mutate := range []func(*DesktopConsentReceiptInput){
		func(v *DesktopConsentReceiptInput) { v.RequestDigest = runtimeinstall.Hash{} },
		func(v *DesktopConsentReceiptInput) { v.ExplicitlyAccepted = false },
		func(v *DesktopConsentReceiptInput) { v.AuthorityAndEntitlement = false },
		func(v *DesktopConsentReceiptInput) { v.NonPreselectedConfirmation = false },
		func(v *DesktopConsentReceiptInput) { v.AcceptedAt = now.Local() },
		func(v *DesktopConsentReceiptInput) { v.ExpiresAt = now.Add(31 * 24 * time.Hour) },
		func(v *DesktopConsentReceiptInput) { v.Signature = []byte("short") },
		func(v *DesktopConsentReceiptInput) { v.SignatureDigest = runtimeinstall.Sum([]byte("forged")) },
	} {
		candidate := valid
		candidate.Signature = slices.Clone(valid.Signature)
		mutate(&candidate)
		if _, err := NewDesktopConsentReceipt(candidate); err == nil {
			t.Fatal("invalid consent receipt was accepted")
		}
	}
}

func TestDesktopMutationRequestAndReceiptBindExactStateAndRebootSemantics(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformWindows)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	consent := runtimeinstall.Sum([]byte("consent"))
	artifact := runtimeinstall.Sum([]byte("artifact-evidence"))
	for _, operation := range []DesktopMutationOperation{DesktopMutationInstallPrerequisites, DesktopMutationInstallRuntime} {
		operation := operation
		t.Run(string(operation), func(t *testing.T) {
			t.Parallel()
			artifactForOperation := artifact
			if operation == DesktopMutationInstallPrerequisites {
				artifactForOperation = runtimeinstall.Hash{}
			}
			request, err := NewDesktopMutationRequest(
				"desktop-mutation-1", 3, operation, authority, consent, artifactForOperation,
				Nonce{4, 5, 6}, now, now.Add(5*time.Minute),
			)
			if err != nil || request.OperationID() == "" || request.Attempt() != 3 || request.Operation() != operation ||
				request.Authority().Digest() != authority.Digest() || request.ConsentDigest() != consent ||
				request.ArtifactDigest() != artifactForOperation || request.Nonce().IsZero() || request.IssuedAt() != now ||
				request.ExpiresAt() != now.Add(5*time.Minute) || request.ExpectedState().IsZero() || request.Digest().IsZero() ||
				len(request.CanonicalBytes()) == 0 {
				t.Fatalf("mutation request = %#v, %v", request, err)
			}
			receipt := desktopMutationReceipt(t, request, 0, runtimeinstall.Hash{}, now.Add(time.Minute))
			if !receipt.Matches(request, now.Add(2*time.Minute)) || receipt.Digest().IsZero() || !receipt.RebootReceipt().IsZero() {
				t.Fatal("successful mutation receipt did not match")
			}
			signature := receipt.Signature()
			signature[0] ^= 0xff
			if bytes.Equal(signature, receipt.Signature()) {
				t.Fatal("mutation receipt exposed its signature storage")
			}
			decoded, decodeErr := DecodeDesktopMutationReceiptV1(receipt.CanonicalBytes())
			if decodeErr != nil || decoded.Digest() != receipt.Digest() || !decoded.Matches(request, now.Add(2*time.Minute)) {
				t.Fatalf("decoded receipt = %#v, %v", decoded, decodeErr)
			}
			if operation == DesktopMutationInstallRuntime {
				rebootDigest := runtimeinstall.Sum([]byte("reboot"))
				reboot := desktopMutationReceipt(t, request, 3010, rebootDigest, now.Add(time.Minute))
				if !reboot.Matches(request, now.Add(2*time.Minute)) || reboot.RebootReceipt() != rebootDigest {
					t.Fatal("signed Windows reboot receipt did not match")
				}
				badReboot := desktopMutationReceipt(t, request, 7, rebootDigest, now.Add(time.Minute))
				if badReboot.Matches(request, now.Add(2*time.Minute)) {
					t.Fatal("unlisted exit code authorized a reboot")
				}
			}
		})
	}
}

func TestDesktopMutationRejectsBroadenedRequestsReceiptsAndJSON(t *testing.T) {
	t.Parallel()
	windows := desktopContractAuthority(t, runtimeinstall.PlatformWindows)
	darwin := desktopContractAuthority(t, runtimeinstall.PlatformDarwin)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	consent := runtimeinstall.Sum([]byte("consent"))
	artifact := runtimeinstall.Sum([]byte("artifact"))
	for _, candidate := range []struct {
		operationID string
		attempt     uint32
		operation   DesktopMutationOperation
		authority   DesktopAuthority
		consent     runtimeinstall.Hash
		artifact    runtimeinstall.Hash
		nonce       Nonce
		issued      time.Time
		expires     time.Time
	}{
		{operationID: "bad id", attempt: 1, operation: DesktopMutationInstallRuntime, authority: windows, consent: consent, artifact: artifact, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operationID: "desktop-1", attempt: 0, operation: DesktopMutationInstallRuntime, authority: windows, consent: consent, artifact: artifact, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operationID: "desktop-1", attempt: 1, operation: "shell", authority: windows, consent: consent, artifact: artifact, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operationID: "desktop-1", attempt: 1, operation: DesktopMutationInstallPrerequisites, authority: darwin, consent: consent, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operationID: "desktop-1", attempt: 1, operation: DesktopMutationInstallRuntime, authority: windows, consent: runtimeinstall.Hash{}, artifact: artifact, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operationID: "desktop-1", attempt: 1, operation: DesktopMutationInstallRuntime, authority: windows, consent: consent, artifact: runtimeinstall.Hash{}, nonce: Nonce{1}, issued: now, expires: now.Add(time.Minute)},
		{operationID: "desktop-1", attempt: 1, operation: DesktopMutationInstallRuntime, authority: windows, consent: consent, artifact: artifact, nonce: Nonce{}, issued: now, expires: now.Add(time.Minute)},
		{operationID: "desktop-1", attempt: 1, operation: DesktopMutationInstallRuntime, authority: windows, consent: consent, artifact: artifact, nonce: Nonce{1}, issued: now, expires: now.Add(11 * time.Minute)},
	} {
		if _, err := NewDesktopMutationRequest(candidate.operationID, candidate.attempt, candidate.operation, candidate.authority,
			candidate.consent, candidate.artifact, candidate.nonce, candidate.issued, candidate.expires); err == nil {
			t.Fatal("broadened mutation request was accepted")
		}
	}
	request, _ := NewDesktopMutationRequest("desktop-1", 1, DesktopMutationInstallRuntime, windows,
		consent, artifact, Nonce{1}, now, now.Add(time.Minute))
	validReceipt := desktopMutationReceiptInput(request, 0, runtimeinstall.Hash{}, now.Add(30*time.Second))
	for _, mutate := range []func(*DesktopMutationReceiptInput){
		func(v *DesktopMutationReceiptInput) { v.RequestDigest = runtimeinstall.Hash{} },
		func(v *DesktopMutationReceiptInput) { v.AuthorityDigest = runtimeinstall.Hash{} },
		func(v *DesktopMutationReceiptInput) { v.Nonce = Nonce{} },
		func(v *DesktopMutationReceiptInput) { v.PostState = runtimeinstall.Hash{} },
		func(v *DesktopMutationReceiptInput) { v.CompletedAt = now.Local() },
		func(v *DesktopMutationReceiptInput) { v.ExpiresAt = now.Add(11 * time.Minute) },
		func(v *DesktopMutationReceiptInput) { v.Signature = nil },
		func(v *DesktopMutationReceiptInput) { v.SignatureDigest = runtimeinstall.Hash{} },
	} {
		candidate := validReceipt
		candidate.Signature = slices.Clone(validReceipt.Signature)
		mutate(&candidate)
		if _, err := NewDesktopMutationReceipt(candidate); err == nil {
			t.Fatal("malformed mutation receipt was accepted")
		}
	}
	receipt, _ := NewDesktopMutationReceipt(validReceipt)
	canonical := receipt.CanonicalBytes()
	var document map[string]any
	if err := json.Unmarshal(canonical, &document); err != nil {
		t.Fatal(err)
	}
	document["ambient_command"] = "powershell"
	unknown, _ := json.Marshal(document)
	duplicate := bytes.Replace(canonical, []byte(`{"authority_digest":`), []byte(`{"exit_code":0,"authority_digest":`), 1)
	for _, raw := range [][]byte{
		nil,
		bytes.Repeat([]byte("x"), 64*1024+1),
		unknown,
		append(slices.Clone(canonical), []byte(" {}")...),
		duplicate,
	} {
		if _, err := DecodeDesktopMutationReceiptV1(raw); err == nil {
			t.Fatal("non-canonical or forged receipt JSON was accepted")
		}
	}
	forgedRaw := bytes.Replace(slices.Clone(canonical), []byte(request.Digest().String()), []byte(runtimeinstall.Sum([]byte("forged")).String()), 1)
	forged, err := DecodeDesktopMutationReceiptV1(forgedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if forged.Matches(request, now.Add(time.Minute)) {
		t.Fatal("receipt with another request digest matched the mutation")
	}
	zeroRequest := DesktopMutationRequest{}
	if zeroRequest.CanonicalBytes() != nil {
		t.Fatal("zero request emitted a helper document")
	}
	if (DesktopMutationReceipt{}).CanonicalBytes() != nil {
		t.Fatal("zero receipt emitted a helper document")
	}
}

func TestDesktopHelperAuthorityIsExactHostPlanAndReleaseBound(t *testing.T) {
	t.Parallel()
	for _, platform := range []runtimeinstall.Platform{runtimeinstall.PlatformDarwin, runtimeinstall.PlatformWindows} {
		platform := platform
		t.Run(platform.String(), func(t *testing.T) {
			t.Parallel()
			desktop := desktopContractAuthority(t, platform)
			input := desktopHelperInput(desktop)
			helper, err := NewDesktopHelperAuthority(input)
			if err != nil || !helper.Valid() || !helper.ValidFor(desktop) || helper.Digest().IsZero() ||
				helper.Platform() != desktop.Platform() || helper.Architecture() != desktop.Architecture() ||
				helper.PlanDigest() != desktop.PlanDigest() || helper.PrincipalID() != desktop.PrincipalID() ||
				helper.MachineDigest() != desktop.MachineDigest() || helper.CanonicalPath() == "" || helper.SHA256().IsZero() ||
				helper.PublisherIdentity() == "" || helper.PublisherCertificate().IsZero() ||
				helper.ReleaseManifestDigest().IsZero() || helper.ExchangeDirectory() == "" {
				t.Fatalf("helper authority = %#v, %v", helper, err)
			}
			for _, mutate := range []func(*DesktopHelperAuthorityInput){
				func(v *DesktopHelperAuthorityInput) { v.PlanDigest = runtimeinstall.Hash{} },
				func(v *DesktopHelperAuthorityInput) { v.PrincipalID = "attacker" },
				func(v *DesktopHelperAuthorityInput) { v.MachineDigest = runtimeinstall.Hash{} },
				func(v *DesktopHelperAuthorityInput) { v.CanonicalPath += ".attacker" },
				func(v *DesktopHelperAuthorityInput) { v.SHA256 = runtimeinstall.Hash{} },
				func(v *DesktopHelperAuthorityInput) { v.PublisherIdentity = "bad\npublisher" },
				func(v *DesktopHelperAuthorityInput) { v.PublisherCertificate = runtimeinstall.Hash{} },
				func(v *DesktopHelperAuthorityInput) { v.ReleaseManifestDigest = runtimeinstall.Hash{} },
				func(v *DesktopHelperAuthorityInput) { v.ExchangeDirectory = "/tmp/native" },
			} {
				candidate := input
				mutate(&candidate)
				if _, candidateErr := NewDesktopHelperAuthority(candidate); candidateErr == nil {
					t.Fatal("broadened helper authority was accepted")
				}
			}
		})
	}
}

func desktopContractAuthority(t testing.TB, platform runtimeinstall.Platform) DesktopAuthority {
	t.Helper()
	architecture := runtimeinstall.ArchitectureARM64
	if platform == runtimeinstall.PlatformWindows {
		architecture = runtimeinstall.ArchitectureAMD64
	}
	plan := desktopTestPlan(t, platform, architecture)
	authority, err := NewDesktopAuthority(desktopAuthorityInput(plan, platform))
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func desktopHostInput(authority DesktopAuthority) DesktopHostEvidenceInput {
	input := DesktopHostEvidenceInput{
		Platform: authority.Platform(), Architecture: authority.Architecture(), OSProduct: authority.OSProduct(),
		OSVersion: authority.MinimumOSVersion(), Build: authority.MinimumBuild(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), CPUs: authority.MinimumCPUs(), TotalMemory: authority.MinimumTotalMemory(),
		AvailableMemory: authority.MinimumAvailableMemory(), FreeDisk: authority.MinimumFreeDisk(),
		Virtualization: true, LocalFilesystem: true, AtRestEncryption: true,
	}
	if authority.Platform() == runtimeinstall.PlatformWindows {
		input.EnabledWindowsFeatures = authority.WindowsFeatures()
		input.WSLVersion = authority.MinimumWSLVersion()
	}
	return input
}

func desktopRuntimeInput(authority DesktopAuthority) DesktopRuntimeEvidenceInput {
	return DesktopRuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Ownership: runtimeinstall.OwnershipReusedExternal,
		Product: "docker_desktop", RuntimeVersion: authority.RuntimeVersion(), EngineVersion: authority.EngineVersion(),
		ComposeVersion: authority.ComposeVersion(), Endpoint: authority.Endpoint(), ApplicationPresent: true,
		ApplicationRunning: true, PublisherVerified: true, LocalEndpoint: true, LinuxContainers: true,
		UnrelatedWorkloads: authority.UnrelatedWorkloads(),
	}
}

func desktopConsentReceipt(
	t testing.TB,
	request DesktopConsentRequest,
	acceptedAt time.Time,
	expiresAt time.Time,
) DesktopConsentReceipt {
	t.Helper()
	signature := bytes.Repeat([]byte{0xa5}, 64)
	authority := request.Authority()
	receipt, err := NewDesktopConsentReceipt(DesktopConsentReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: authority.Digest(), PlanDigest: authority.PlanDigest(),
		TermsDigest: authority.Terms().Digest(), PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		Nonce: request.Nonce(), ExplicitlyAccepted: true, AuthorityAndEntitlement: true,
		NonPreselectedConfirmation: true, AcceptedAt: acceptedAt, ExpiresAt: expiresAt,
		Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func desktopMutationReceiptInput(
	request DesktopMutationRequest,
	exitCode uint32,
	reboot runtimeinstall.Hash,
	completedAt time.Time,
) DesktopMutationReceiptInput {
	signature := bytes.Repeat([]byte{0x5a}, 64)
	return DesktopMutationReceiptInput{
		RequestDigest: request.Digest(), AuthorityDigest: request.Authority().Digest(), Nonce: request.Nonce(),
		ExitCode: exitCode, PostState: request.ExpectedState(), RebootReceipt: reboot,
		CompletedAt: completedAt, ExpiresAt: completedAt.Add(5 * time.Minute),
		Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	}
}

func desktopMutationReceipt(
	t testing.TB,
	request DesktopMutationRequest,
	exitCode uint32,
	reboot runtimeinstall.Hash,
	completedAt time.Time,
) DesktopMutationReceipt {
	t.Helper()
	receipt, err := NewDesktopMutationReceipt(desktopMutationReceiptInput(request, exitCode, reboot, completedAt))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func desktopHelperInput(desktop DesktopAuthority) DesktopHelperAuthorityInput {
	input := DesktopHelperAuthorityInput{
		Platform: desktop.Platform(), Architecture: desktop.Architecture(), PlanDigest: desktop.PlanDigest(),
		PrincipalID: desktop.PrincipalID(), MachineDigest: desktop.MachineDigest(),
		SHA256: runtimeinstall.Sum([]byte("native-helper")), PublisherIdentity: "agentmemory-runtime-helper-2026",
		PublisherCertificate:  runtimeinstall.Sum([]byte("native-helper-certificate")),
		ReleaseManifestDigest: runtimeinstall.Sum([]byte("signed-release-manifest")),
	}
	if desktop.Platform() == runtimeinstall.PlatformDarwin {
		input.CanonicalPath = "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper"
		input.ExchangeDirectory = "/Users/agentmemory/Library/Application Support/AgentMemory/bootstrap/operation-1/native"
	} else {
		input.CanonicalPath = `C:\Program Files\AgentMemory\bin\agentmemory-runtime-helper.exe`
		input.ExchangeDirectory = `C:\Users\Agent User\AppData\Local\AgentMemory\bootstrap\operation-1\native`
	}
	return input
}

func TestDesktopMutationDocumentContainsNoAmbientCommandSurface(t *testing.T) {
	t.Parallel()
	authority := desktopContractAuthority(t, runtimeinstall.PlatformWindows)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	request, err := NewDesktopMutationRequest("desktop-closed-1", 1, DesktopMutationInstallRuntime, authority,
		runtimeinstall.Sum([]byte("consent")), runtimeinstall.Sum([]byte("artifact")), Nonce{1}, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	document := string(request.CanonicalBytes())
	for _, forbidden := range []string{"argv", "command", "environment", "powershell", "cmd.exe", "shell"} {
		if strings.Contains(strings.ToLower(document), forbidden) {
			t.Fatalf("helper request exposed ambient %q capability: %s", forbidden, document)
		}
	}
}
