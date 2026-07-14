package runtimeprovision

import (
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxArtifactEvidenceRequiresExactAuthorityRepositoryAndPackageBindings(t *testing.T) {
	t.Parallel()
	plan := testPlan(t)
	authority, err := NewLinuxAuthority(testAuthorityInput(plan))
	if err != nil {
		t.Fatal(err)
	}
	repository, _ := ExpectedRepositoryStateDigest(authority)
	packages, _ := ExpectedPackageStateDigest(authority)
	valid := LinuxArtifactEvidenceInput{
		AuthorityDigest: authority.Digest(), ArtifactDigest: authority.ArtifactDigest(),
		RepositoryStateDigest: repository, PackageStateDigest: packages,
		RetainedSetDigest: runtimeinstall.Sum([]byte("retained-set")), EveryPackageAcquired: true,
		RepositoryAuthenticated: true, PackagesAuthenticated: true,
	}
	evidence, err := NewLinuxArtifactEvidence(valid)
	if err != nil || !evidence.AcquiredFor(authority) || !evidence.VerifiedFor(authority) || evidence.Digest().IsZero() {
		t.Fatalf("verified evidence = acquired:%t verified:%t digest:%s error:%v",
			evidence.AcquiredFor(authority), evidence.VerifiedFor(authority), evidence.Digest(), err)
	}

	for _, mutate := range []func(*LinuxArtifactEvidenceInput){
		func(input *LinuxArtifactEvidenceInput) { input.AuthorityDigest = runtimeinstall.Hash{} },
		func(input *LinuxArtifactEvidenceInput) { input.ArtifactDigest = runtimeinstall.Sum([]byte("other")) },
		func(input *LinuxArtifactEvidenceInput) {
			input.RepositoryStateDigest = runtimeinstall.Sum([]byte("other"))
		},
		func(input *LinuxArtifactEvidenceInput) {
			input.PackageStateDigest = runtimeinstall.Sum([]byte("other"))
		},
		func(input *LinuxArtifactEvidenceInput) { input.RetainedSetDigest = runtimeinstall.Hash{} },
		func(input *LinuxArtifactEvidenceInput) { input.EveryPackageAcquired = false },
		func(input *LinuxArtifactEvidenceInput) {
			input.RepositoryAuthenticated, input.PackagesAuthenticated = false, true
		},
	} {
		candidate := valid
		mutate(&candidate)
		candidateEvidence, candidateErr := NewLinuxArtifactEvidence(candidate)
		if candidateErr == nil && candidateEvidence.AcquiredFor(authority) && candidateEvidence.VerifiedFor(authority) {
			t.Fatal("substituted or incomplete Linux package evidence was accepted")
		}
	}

	acquired := valid
	acquired.RepositoryAuthenticated, acquired.PackagesAuthenticated = false, false
	acquiredEvidence, err := NewLinuxArtifactEvidence(acquired)
	if err != nil || !acquiredEvidence.AcquiredFor(authority) || acquiredEvidence.VerifiedFor(authority) {
		t.Fatalf("acquisition-only evidence = acquired:%t verified:%t error:%v",
			acquiredEvidence.AcquiredFor(authority), acquiredEvidence.VerifiedFor(authority), err)
	}
}
