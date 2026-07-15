package runtimeprovision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestRPMKeysPackageVerifierUsesIsolatedKeyDBAndStrongPolicy(t *testing.T) {
	trust := signedDNFTrustInput(t, "detached")
	packageBytes := bytes.Repeat([]byte{0x52}, 25)
	artifact := rpmTestArtifact(t, packageBytes)
	runner := &rpmKeysRunnerStub{authority: rpmKeysAuthority(t), expectedKey: trust.SigningKey, expectedPackage: packageBytes}
	verifier, err := NewRPMKeysPackageVerifier(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifier.VerifyRPMPackage(
		context.Background(), trust.SigningKey, trust.Repository.SigningKeyFingerprint,
		artifact, bytes.NewReader(packageBytes),
	); err != nil {
		t.Fatalf("VerifyRPMPackage() error = %v", err)
	}
	if runner.calls != 2 || !runner.importChecked || !runner.packageChecked || runner.databasePath == "" {
		t.Fatalf("rpmkeys calls=%d import=%t package=%t db=%q", runner.calls, runner.importChecked, runner.packageChecked, runner.databasePath)
	}
}

func TestRPMKeysPackageVerifierRejectsKeyPackageAndProcessFailures(t *testing.T) {
	trust := signedDNFTrustInput(t, "detached")
	packageBytes := bytes.Repeat([]byte{0x52}, 25)
	artifact := rpmTestArtifact(t, packageBytes)
	tests := []struct {
		name        string
		fingerprint string
		content     []byte
		runError    error
		exitCode    int
		truncated   bool
	}{
		{name: "wrong fingerprint", fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", content: packageBytes},
		{name: "short package", fingerprint: trust.Repository.SigningKeyFingerprint, content: packageBytes[:24]},
		{name: "rpmkeys failure", fingerprint: trust.Repository.SigningKeyFingerprint, content: packageBytes, runError: errors.New("failed")},
		{name: "rpmkeys exit", fingerprint: trust.Repository.SigningKeyFingerprint, content: packageBytes, exitCode: 1},
		{name: "rpmkeys truncated", fingerprint: trust.Repository.SigningKeyFingerprint, content: packageBytes, truncated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &rpmKeysRunnerStub{
				authority: rpmKeysAuthority(t), expectedKey: trust.SigningKey,
				expectedPackage: packageBytes, runError: test.runError,
				exitCode: test.exitCode, truncated: test.truncated,
			}
			verifier, err := NewRPMKeysPackageVerifier(runner)
			if err != nil {
				t.Fatal(err)
			}
			if err = verifier.VerifyRPMPackage(
				context.Background(), trust.SigningKey, test.fingerprint, artifact, bytes.NewReader(test.content),
			); err == nil {
				t.Fatal("invalid RPM verification was accepted")
			}
		})
	}
	if _, err := NewRPMKeysPackageVerifier(nil); err == nil {
		t.Fatal("nil rpmkeys runner was accepted")
	}
	verifier, err := NewRPMKeysPackageVerifier(&rpmKeysRunnerStub{authority: rpmKeysAuthority(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err = verifier.VerifyRPMPackage(hostileNilContext(), trust.SigningKey, trust.Repository.SigningKeyFingerprint, artifact, bytes.NewReader(packageBytes)); err == nil {
		t.Fatal("nil context was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = verifier.VerifyRPMPackage(cancelled, trust.SigningKey, trust.Repository.SigningKeyFingerprint, artifact, bytes.NewReader(packageBytes)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verification error = %v", err)
	}
	if err = writePrivateRPMVerificationFile("unused", bytes.NewReader(nil), 0); err == nil {
		t.Fatal("zero-sized verification file was accepted")
	}
}

type rpmKeysRunnerStub struct {
	authority       argvprocess.ExecutableAuthority
	expectedKey     []byte
	expectedPackage []byte
	runError        error
	exitCode        int
	truncated       bool
	calls           int
	importChecked   bool
	packageChecked  bool
	databasePath    string
}

func (r *rpmKeysRunnerStub) ExecutableAuthority() argvprocess.ExecutableAuthority { return r.authority }

func (r *rpmKeysRunnerStub) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.calls++
	if r.runError != nil {
		return argvprocess.Result{}, r.runError
	}
	if r.exitCode != 0 || r.truncated {
		return argvprocess.Result{ExitCode: r.exitCode, OutputTruncated: r.truncated}, nil
	}
	arguments := invocation.Arguments()
	if len(arguments) == 4 && arguments[0] == "--dbpath" && arguments[2] == "--import" {
		value, err := os.ReadFile(arguments[3]) // #nosec G304 -- path is created by the verifier under its private directory.
		if err != nil {
			return argvprocess.Result{}, err
		}
		if !bytes.Equal(value, r.expectedKey) {
			return argvprocess.Result{ExitCode: 1}, nil
		}
		r.databasePath = arguments[1]
		r.importChecked = true
		return argvprocess.Result{}, nil
	}
	if len(arguments) == 6 && arguments[0] == "--dbpath" && arguments[1] == r.databasePath &&
		arguments[2] == "--define" && arguments[3] == "%_pkgverify_level all" && arguments[4] == "--checksig" {
		value, err := os.ReadFile(arguments[5]) // #nosec G304 -- path is created by the verifier under its private directory.
		if err != nil {
			return argvprocess.Result{}, err
		}
		if !bytes.Equal(value, r.expectedPackage) {
			return argvprocess.Result{ExitCode: 1}, nil
		}
		r.packageChecked = true
		return argvprocess.Result{}, nil
	}
	return argvprocess.Result{ExitCode: 1}, nil
}

func rpmKeysAuthority(t testing.TB) argvprocess.ExecutableAuthority {
	t.Helper()
	authority, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "rpmkeys", CanonicalPath: "/usr/bin/rpmkeys", SHA256: sha256.Sum256([]byte("rpmkeys")),
		OwnerIdentity: "root", PublisherIdentity: "fedora-project", PublisherPolicyID: "fedora-rpm-policy",
		PublisherTrustDigest: sha256.Sum256([]byte("fedora-rpm-trust")),
		Platform:             "linux", Architecture: "amd64", ReleaseManifestDigest: sha256.Sum256([]byte("release")),
		RuntimePlanDigest: sha256.Sum256([]byte("runtime")), Role: argvprocess.ExecutableRoleRPMKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func rpmTestArtifact(t testing.TB, value []byte) artifactacquisition.Artifact {
	t.Helper()
	digest := releaseinventory.Digest(sha256.Sum256(value))
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.Digest(sha256.Sum256([]byte("plan"))),
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "docker-ce", Digest: digest, Size: uint64(len(value)), Sources: []string{"https://example.test/docker-ce.rpm"},
			Chunks: []artifactacquisition.ChunkInput{{Offset: 0, Size: uint64(len(value)), Digest: digest}},
		}},
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: uint64(len(value)), RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1,
			RequiredBytes: uint64(len(value)) + 2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan.Artifacts()[0]
}
