package runtimeinstall

import (
	"strings"
	"testing"
)

func TestPF001RuntimeClosedVocabularyAndSafeGetters(t *testing.T) {
	t.Parallel()

	platforms := map[Platform]string{
		PlatformUnknown: "unknown", PlatformDarwin: "darwin", PlatformLinux: "linux", PlatformWindows: "windows", Platform(255): "unknown",
	}
	for value, want := range platforms {
		if value.String() != want {
			t.Fatalf("Platform(%d).String() = %q, want %q", value, value.String(), want)
		}
	}
	architectures := map[Architecture]string{
		ArchitectureUnknown: "unknown", ArchitectureAMD64: "amd64", ArchitectureARM64: "arm64", Architecture(255): "unknown",
	}
	for value, want := range architectures {
		if value.String() != want {
			t.Fatalf("Architecture(%d).String() = %q, want %q", value, value.String(), want)
		}
	}
	states := map[OperationState]string{
		OperationStateUnknown: "Unknown", OperationStateRunning: "Running",
		OperationStateRebootPending: "RebootPending", OperationStateReady: "Ready",
		OperationStateCancelled: "Cancelled", OperationStatePausedForAdministrator: "PausedForAdministrator",
		OperationStateUnsupportedHost: "UnsupportedHost", OperationStateRuntimeConflict: "RuntimeConflict",
		OperationStateFailedRecoverable: "FailedRecoverable", OperationState(255): "Unknown",
	}
	for value, want := range states {
		if value.String() != want {
			t.Fatalf("OperationState(%d).String() = %q, want %q", value, value.String(), want)
		}
	}
	actions := map[PlanAction]string{
		PlanActionUnknown: "unknown", PlanActionAdoptCompatible: "adopt_compatible",
		PlanActionStartCompatible: "start_compatible", PlanActionInstallCertified: "install_certified",
		PlanActionRepairManaged: "repair_managed", PlanActionBlock: "block", PlanAction(255): "unknown",
	}
	for value, want := range actions {
		if value.String() != want {
			t.Fatalf("PlanAction(%d).String() = %q, want %q", value, value.String(), want)
		}
	}
	codes := map[DecisionCode]string{
		DecisionOK: "ok", DecisionUnsupportedPlatform: "unsupported_platform",
		DecisionVirtualizationUnavailable: "virtualization_unavailable", DecisionNonLocalFilesystem: "nonlocal_filesystem",
		DecisionEncryptionUnattested: "encryption_unattested", DecisionInsufficientCPU: "insufficient_cpu",
		DecisionInsufficientMemory: "insufficient_memory", DecisionInsufficientDisk: "insufficient_disk",
		DecisionRuntimeRemote: "runtime_remote", DecisionRuntimeUntrusted: "runtime_untrusted",
		DecisionRuntimeConflict: "runtime_conflict", DecisionCatalogMismatch: "catalog_mismatch", DecisionCode(255): "unknown",
	}
	for value, want := range codes {
		if value.String() != want {
			t.Fatalf("DecisionCode(%d).String() = %q, want %q", value, value.String(), want)
		}
	}

	host := supportedHost(t)
	if host.Platform() != PlatformDarwin || host.Architecture() != ArchitectureARM64 || host.OSVersion() != "26.0" {
		t.Fatalf("host getter projection is inconsistent: %#v", host)
	}
	operation := newRuntimeOperationForTest(t)
	if operation.ID() == "" || len(mustHash(t, "printable").String()) != 64 {
		t.Fatal("safe identifiers or hash formatting are incomplete")
	}
}

func TestPF001RuntimeValueConstructorsRejectEveryIncompleteInvariant(t *testing.T) {
	t.Parallel()

	validHost := func(platform Platform, architecture Architecture, version string, cpus uint16, total, available uint64) error {
		_, err := NewHostCapabilities(platform, architecture, version, true, true, true, true, cpus, total, available, minimumFreeDisk)
		return err
	}
	for name, run := range map[string]func() error{
		"platform": func() error {
			return validHost(PlatformUnknown, ArchitectureARM64, "26", 4, minimumTotalMemory, minimumAvailableMemory)
		},
		"architecture": func() error {
			return validHost(PlatformDarwin, ArchitectureUnknown, "26", 4, minimumTotalMemory, minimumAvailableMemory)
		},
		"empty version": func() error {
			return validHost(PlatformDarwin, ArchitectureARM64, "", 4, minimumTotalMemory, minimumAvailableMemory)
		},
		"padded version": func() error {
			return validHost(PlatformDarwin, ArchitectureARM64, " 26 ", 4, minimumTotalMemory, minimumAvailableMemory)
		},
		"long version": func() error {
			return validHost(PlatformDarwin, ArchitectureARM64, strings.Repeat("x", 129), 4, minimumTotalMemory, minimumAvailableMemory)
		},
		"zero cpu": func() error {
			return validHost(PlatformDarwin, ArchitectureARM64, "26", 0, minimumTotalMemory, minimumAvailableMemory)
		},
		"zero memory":             func() error { return validHost(PlatformDarwin, ArchitectureARM64, "26", 4, 0, 0) },
		"available exceeds total": func() error { return validHost(PlatformDarwin, ArchitectureARM64, "26", 4, 1, 2) },
	} {
		if err := run(); err == nil {
			t.Fatalf("NewHostCapabilities() accepted %s", name)
		}
	}

	validDiscovery := func(condition RuntimeCondition, product, version, endpoint string, ownership OwnershipDisposition) error {
		_, err := NewRuntimeDiscovery(condition, product, version, endpoint, true, true, true, ownership, 0)
		return err
	}
	for name, run := range map[string]func() error{
		"unknown condition": func() error {
			return validDiscovery(RuntimeConditionUnknown, "docker", "1", "unix://local", OwnershipReusedExternal)
		},
		"absent concrete condition": func() error {
			return validDiscovery(RuntimeConditionAbsent, "docker", "1", "unix://local", OwnershipReusedExternal)
		},
		"empty product": func() error {
			return validDiscovery(RuntimeConditionRunning, "", "1", "unix://local", OwnershipReusedExternal)
		},
		"empty version": func() error {
			return validDiscovery(RuntimeConditionRunning, "docker", " ", "unix://local", OwnershipReusedExternal)
		},
		"empty endpoint": func() error {
			return validDiscovery(RuntimeConditionRunning, "docker", "1", "", OwnershipReusedExternal)
		},
		"long product": func() error {
			return validDiscovery(RuntimeConditionRunning, strings.Repeat("x", 129), "1", "unix://local", OwnershipReusedExternal)
		},
		"long version": func() error {
			return validDiscovery(RuntimeConditionRunning, "docker", strings.Repeat("x", 129), "unix://local", OwnershipReusedExternal)
		},
		"long endpoint": func() error {
			return validDiscovery(RuntimeConditionRunning, "docker", "1", strings.Repeat("x", 2049), OwnershipReusedExternal)
		},
		"unknown ownership": func() error {
			return validDiscovery(RuntimeConditionRunning, "docker", "1", "unix://local", OwnershipUnknown)
		},
	} {
		if err := run(); err == nil {
			t.Fatalf("NewRuntimeDiscovery() accepted %s", name)
		}
	}

	validCatalog := func(platform Platform, architecture Architecture, product, version, channel string, sequence uint64, catalog, terms Hash, download, expanded uint64) error {
		_, err := NewCertifiedRuntime(platform, architecture, product, version, channel, sequence, catalog, terms, download, expanded)
		return err
	}
	goodCatalog, goodTerms := mustHash(t, "catalog"), mustHash(t, "terms")
	for name, run := range map[string]func() error{
		"platform": func() error {
			return validCatalog(PlatformUnknown, ArchitectureARM64, "docker", "1", "stable", 1, goodCatalog, goodTerms, 1, 1)
		},
		"architecture": func() error {
			return validCatalog(PlatformDarwin, ArchitectureUnknown, "docker", "1", "stable", 1, goodCatalog, goodTerms, 1, 1)
		},
		"product": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "", "1", "stable", 1, goodCatalog, goodTerms, 1, 1)
		},
		"version": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "docker", " ", "stable", 1, goodCatalog, goodTerms, 1, 1)
		},
		"channel": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "docker", "1", "beta", 1, goodCatalog, goodTerms, 1, 1)
		},
		"sequence": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "docker", "1", "stable", 0, goodCatalog, goodTerms, 1, 1)
		},
		"catalog digest": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "docker", "1", "stable", 1, Hash{}, goodTerms, 1, 1)
		},
		"terms digest": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "docker", "1", "stable", 1, goodCatalog, Hash{}, 1, 1)
		},
		"download size": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "docker", "1", "stable", 1, goodCatalog, goodTerms, 0, 1)
		},
		"expanded size": func() error {
			return validCatalog(PlatformDarwin, ArchitectureARM64, "docker", "1", "stable", 1, goodCatalog, goodTerms, 2, 1)
		},
	} {
		if err := run(); err == nil {
			t.Fatalf("NewCertifiedRuntime() accepted %s", name)
		}
	}
}

func TestPF001RuntimeOperationPauseResumeAndConstructionMatrix(t *testing.T) {
	t.Parallel()

	for name, operationID := range map[string]string{
		"empty": "", "padded": " operation", "control": "operation\n", "path": "operation/private",
		"unicode": "opération", "long": strings.Repeat("x", 129),
	} {
		if _, err := NewOperation(operationID, mustHash(t, "plan")); err == nil {
			t.Fatalf("NewOperation() accepted %s identifier", name)
		}
	}
	if _, err := NewOperation("operation", Hash{}); err == nil {
		t.Fatal("NewOperation() accepted a zero plan")
	}

	resumable := []OperationState{OperationStateFailedRecoverable, OperationStatePausedForAdministrator}
	for _, state := range resumable {
		operation := newRuntimeOperationForTest(t)
		if err := operation.Pause(state); err != nil || operation.State() != state {
			t.Fatalf("Pause(%s) error/state = %v/%s", state, err, operation.State())
		}
		if err := operation.Resume(); err != nil || operation.State() != OperationStateRunning || operation.Attempt() != 2 {
			t.Fatalf("Resume(%s) error/state/attempt = %v/%s/%d", state, err, operation.State(), operation.Attempt())
		}
	}
	for _, state := range []OperationState{
		OperationStateCancelled, OperationStateUnsupportedHost, OperationStateRuntimeConflict,
	} {
		operation := newRuntimeOperationForTest(t)
		if err := operation.Pause(state); err != nil || operation.State() != state {
			t.Fatalf("Pause(%s) error/state = %v/%s", state, err, operation.State())
		}
		if err := operation.Resume(); err == nil {
			t.Fatalf("terminal state %s resumed", state)
		}
	}
	for _, state := range []OperationState{
		OperationStateUnknown, OperationStateRunning, OperationStateRebootPending, OperationStateReady,
	} {
		operation := newRuntimeOperationForTest(t)
		if err := operation.Pause(state); err == nil {
			t.Fatalf("Pause(%s) succeeded", state)
		}
	}
	operation := newRuntimeOperationForTest(t)
	if err := operation.Resume(); err == nil {
		t.Fatal("running operation resumed")
	}
	if err := operation.Pause(OperationStateCancelled); err != nil {
		t.Fatal(err)
	}
	if err := operation.Pause(OperationStateFailedRecoverable); err == nil {
		t.Fatal("already paused operation paused again")
	}
}

func TestPF001RuntimeTransitionEvidenceRejectsIncompleteFields(t *testing.T) {
	t.Parallel()

	plan, input, output, artifact := mustHash(t, "plan"), mustHash(t, "input"), mustHash(t, "output"), mustHash(t, "artifact")
	for name, run := range map[string]func() error{
		"phase": func() error {
			_, err := NewTransitionEvidence(PhaseUnknown, 1, plan, input, output, Hash{}, OwnershipUnknown)
			return err
		},
		"attempt": func() error {
			_, err := NewTransitionEvidence(PhaseDetectHost, 0, plan, input, output, Hash{}, OwnershipUnknown)
			return err
		},
		"plan": func() error {
			_, err := NewTransitionEvidence(PhaseDetectHost, 1, Hash{}, input, output, Hash{}, OwnershipUnknown)
			return err
		},
		"input": func() error {
			_, err := NewTransitionEvidence(PhaseDetectHost, 1, plan, Hash{}, output, Hash{}, OwnershipUnknown)
			return err
		},
		"output": func() error {
			_, err := NewTransitionEvidence(PhaseDetectHost, 1, plan, input, Hash{}, Hash{}, OwnershipUnknown)
			return err
		},
		"artifact": func() error {
			_, err := NewTransitionEvidence(PhaseVerifyRuntimeArtifact, 1, plan, input, output, Hash{}, OwnershipUnknown)
			return err
		},
		"ownership": func() error {
			_, err := NewTransitionEvidence(PhaseVerifyRuntimeCapabilities, 1, plan, input, output, artifact, OwnershipUnknown)
			return err
		},
	} {
		if err := run(); err == nil {
			t.Fatalf("NewTransitionEvidence() accepted missing %s", name)
		}
	}
}

func TestPF001RuntimeRestoreAcceptsEveryStateAndRejectsTamperingMatrix(t *testing.T) {
	t.Parallel()

	validSnapshots := make([]OperationSnapshot, 0, 8)
	validSnapshots = append(validSnapshots, newRuntimeOperationForTest(t).Snapshot())
	for _, state := range []OperationState{
		OperationStateCancelled, OperationStatePausedForAdministrator, OperationStateUnsupportedHost,
		OperationStateRuntimeConflict, OperationStateFailedRecoverable,
	} {
		operation := newRuntimeOperationForTest(t)
		if err := operation.Pause(state); err != nil {
			t.Fatal(err)
		}
		validSnapshots = append(validSnapshots, operation.Snapshot())
	}
	reboot := newRuntimeOperationForTest(t)
	completeUntil(t, reboot, PhaseInstallRuntime)
	if err := reboot.RequireReboot(mustHash(t, "reboot")); err != nil {
		t.Fatal(err)
	}
	validSnapshots = append(validSnapshots, reboot.Snapshot())
	ready := newRuntimeOperationForTest(t)
	completeUntil(t, ready, PhaseUnknown)
	validSnapshots = append(validSnapshots, ready.Snapshot())
	for _, snapshot := range validSnapshots {
		restored, err := RestoreOperation(snapshot)
		if err != nil || restored.State() != snapshot.State || restored.CurrentPhase() != snapshot.CurrentPhase ||
			restored.Version() != snapshot.Version || restored.Attempt() != snapshot.Attempt {
			t.Fatalf("RestoreOperation(%s) = %#v, %v", snapshot.State, restored, err)
		}
	}

	base := newRuntimeOperationForTest(t).Snapshot()
	partialOperation := newRuntimeOperationForTest(t)
	completeUntil(t, partialOperation, PhaseAcquireRuntime)
	partial := partialOperation.Snapshot()
	tests := map[string]OperationSnapshot{
		"schema":                 base,
		"running receipt":        base,
		"unknown state":          base,
		"reboot receipt":         partial,
		"reboot phase":           base,
		"ready incomplete":       partial,
		"paused after ready":     ready.Snapshot(),
		"version below evidence": partial,
		"zero attempt":           base,
		"cursor mismatch":        partial,
	}
	tampered := tests["schema"]
	tampered.SchemaVersion++
	tests["schema"] = tampered
	tampered = tests["running receipt"]
	tampered.RebootReceipt = mustHash(t, "unexpected")
	tests["running receipt"] = tampered
	tampered = tests["unknown state"]
	tampered.State = OperationStateUnknown
	tests["unknown state"] = tampered
	tampered = tests["reboot receipt"]
	tampered.State = OperationStateRebootPending
	tampered.RebootReceipt = Hash{}
	tampered.Version++
	tests["reboot receipt"] = tampered
	tampered = tests["reboot phase"]
	tampered.State = OperationStateRebootPending
	tampered.RebootReceipt = mustHash(t, "unexpected")
	tampered.Version++
	tests["reboot phase"] = tampered
	tampered = tests["ready incomplete"]
	tampered.State = OperationStateReady
	tests["ready incomplete"] = tampered
	tampered = tests["paused after ready"]
	tampered.State = OperationStateCancelled
	tampered.Version++
	tests["paused after ready"] = tampered
	tampered = tests["version below evidence"]
	tampered.Version = 0
	tests["version below evidence"] = tampered
	tampered = tests["zero attempt"]
	tampered.Attempt = 0
	tests["zero attempt"] = tampered
	tampered = tests["cursor mismatch"]
	tampered.CurrentPhase = PhaseVerifyRuntimeCapabilities
	tests["cursor mismatch"] = tampered
	for name, snapshot := range tests {
		if _, err := RestoreOperation(snapshot); err == nil {
			t.Fatalf("RestoreOperation() accepted %s tampering", name)
		}
	}
}
