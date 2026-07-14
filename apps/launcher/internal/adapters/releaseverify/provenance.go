package releaseverifyadapter

import (
	"context"
	"errors"
	"strings"
	"time"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	inTotoStatementV1 = "https://in-toto.io/Statement/v1"
	slsaProvenanceV1  = "https://slsa.dev/provenance/v1"
)

// ProvenanceBuildIdentity is one indivisible approved builder/build/source/
// workflow tuple. Tuple policy prevents separate allowlist privileges from
// being combined into an identity that was never reviewed.
type ProvenanceBuildIdentity struct {
	BuilderID        string
	BuildType        string
	SourceRepository string
	WorkflowPath     string
}

// ProvenanceTrustPolicyInput is the launcher-owned allowlist independent of a
// self-asserted provenance statement. Every tuple and digest is copied.
type ProvenanceTrustPolicyInput struct {
	BuildIdentities []ProvenanceBuildIdentity
	RecipeDigests   []releaseinventory.Digest
}

// ProvenanceTrustPolicy is an immutable approved build-plane policy.
type ProvenanceTrustPolicy struct {
	buildIdentities map[string]struct{}
	recipeDigests   map[releaseinventory.Digest]struct{}
}

// NewProvenanceTrustPolicy rejects empty, duplicate, or unsafe allowlists.
func NewProvenanceTrustPolicy(input ProvenanceTrustPolicyInput) (ProvenanceTrustPolicy, error) {
	if len(input.BuildIdentities) == 0 || len(input.BuildIdentities) > 64 {
		return ProvenanceTrustPolicy{}, errors.New("approved provenance build identities are required")
	}
	identities := make(map[string]struct{}, len(input.BuildIdentities))
	for _, identity := range input.BuildIdentities {
		if !validSafeEvidenceText(identity.BuilderID, 2048) ||
			!validSafeEvidenceText(identity.BuildType, 2048) ||
			!validSafeEvidenceText(identity.SourceRepository, 2048) ||
			!validSafeEvidenceText(identity.WorkflowPath, 512) {
			return ProvenanceTrustPolicy{}, errors.New("approved provenance build identity is invalid")
		}
		key := provenanceIdentityKey(
			identity.BuilderID,
			identity.BuildType,
			identity.SourceRepository,
			identity.WorkflowPath,
		)
		if _, duplicate := identities[key]; duplicate {
			return ProvenanceTrustPolicy{}, errors.New("approved provenance build identity is duplicated")
		}
		identities[key] = struct{}{}
	}
	if len(input.RecipeDigests) == 0 || len(input.RecipeDigests) > 64 {
		return ProvenanceTrustPolicy{}, errors.New("approved provenance recipes are required")
	}
	recipes := make(map[releaseinventory.Digest]struct{}, len(input.RecipeDigests))
	for _, digest := range input.RecipeDigests {
		if digest.IsZero() {
			return ProvenanceTrustPolicy{}, errors.New("approved provenance recipe is invalid")
		}
		if _, duplicate := recipes[digest]; duplicate {
			return ProvenanceTrustPolicy{}, errors.New("approved provenance recipe is duplicated")
		}
		recipes[digest] = struct{}{}
	}
	return ProvenanceTrustPolicy{buildIdentities: identities, recipeDigests: recipes}, nil
}

// SLSAProvenanceVerifier verifies the closed AgentMemory SLSA v1 profile from
// immutable local bytes against an independently injected build policy.
type SLSAProvenanceVerifier struct {
	source ResourceContentSource
	policy ProvenanceTrustPolicy
}

var _ application.ProvenanceVerifier = (*SLSAProvenanceVerifier)(nil)

// NewSLSAProvenanceVerifier requires both local bytes and a nonempty policy.
func NewSLSAProvenanceVerifier(
	source ResourceContentSource,
	policy ProvenanceTrustPolicy,
) (*SLSAProvenanceVerifier, error) {
	if adapterNil(source) || !policy.valid() {
		return nil, errors.New("release provenance source and trust policy are required")
	}
	return &SLSAProvenanceVerifier{source: source, policy: policy}, nil
}

// VerifyProvenance binds the in-toto subject and all SLSA build claims to the
// signed release manifest and the launcher's independent trust policy.
func (v *SLSAProvenanceVerifier) VerifyProvenance(
	ctx context.Context,
	manifest releaseinventory.Manifest,
	subject releaseinventory.Resource,
	evidence releaseinventory.Resource,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	if manifest.SchemaVersion() != releaseinventory.SupportedManifestSchemaMajor ||
		manifest.Digest().IsZero() || subject.Kind().IsEvidence() ||
		evidence.Kind() != releaseinventory.ResourceKindProvenance ||
		evidence.SubjectResourceID() != subject.ID() ||
		!evidence.SubjectDigest().Equal(subject.Digest()) {
		return application.ErrProvenanceInvalid
	}
	raw, err := readEvidence(ctx, v.source, evidence)
	if err != nil {
		return evidencePortError(application.ErrProvenanceInvalid, err)
	}
	var statement slsaStatement
	if err := decodeCanonicalJSON(raw, &statement); err != nil {
		return evidencePortError(application.ErrProvenanceInvalid, err)
	}
	if !v.statementValid(statement, manifest, subject) {
		return application.ErrProvenanceInvalid
	}
	return nil
}

func (p ProvenanceTrustPolicy) valid() bool {
	return len(p.buildIdentities) > 0 && len(p.recipeDigests) > 0
}

type slsaStatement struct {
	Type          string        `json:"_type"`
	Predicate     slsaPredicate `json:"predicate"`
	PredicateType string        `json:"predicateType"`
	Subject       []slsaSubject `json:"subject"`
}

type slsaSubject struct {
	Digest map[string]string `json:"digest"`
	Name   string            `json:"name"`
}

type slsaPredicate struct {
	BuildDefinition slsaBuildDefinition `json:"buildDefinition"`
	RunDetails      slsaRunDetails      `json:"runDetails"`
}

type slsaBuildDefinition struct {
	BuildType            string                 `json:"buildType"`
	ExternalParameters   slsaExternalParameters `json:"externalParameters"`
	InternalParameters   slsaInternalParameters `json:"internalParameters"`
	ResolvedDependencies []slsaDependency       `json:"resolvedDependencies"`
}

type slsaExternalParameters struct {
	RecipeDigest string       `json:"recipeDigest"`
	Source       slsaSource   `json:"source"`
	Workflow     slsaWorkflow `json:"workflow"`
}

type slsaSource struct {
	Digest     map[string]string `json:"digest"`
	Repository string            `json:"repository"`
}

type slsaWorkflow struct {
	Path string `json:"path"`
	Ref  string `json:"ref"`
}

type slsaInternalParameters struct {
	Hermetic     bool `json:"hermetic"`
	Reproducible bool `json:"reproducible"`
}

type slsaDependency struct {
	Digest map[string]string `json:"digest"`
	URI    string            `json:"uri"`
}

type slsaRunDetails struct {
	Builder  slsaBuilder  `json:"builder"`
	Metadata slsaMetadata `json:"metadata"`
}

type slsaBuilder struct {
	ID string `json:"id"`
}

type slsaMetadata struct {
	FinishedOn   string `json:"finishedOn"`
	InvocationID string `json:"invocationId"`
	StartedOn    string `json:"startedOn"`
}

func (v *SLSAProvenanceVerifier) statementValid(
	statement slsaStatement,
	manifest releaseinventory.Manifest,
	subject releaseinventory.Resource,
) bool {
	if statement.Type != inTotoStatementV1 || statement.PredicateType != slsaProvenanceV1 ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != subject.ID() ||
		!exactDigestMap(statement.Subject[0].Digest, "sha256", subject.Digest().Hex()) {
		return false
	}
	definition := statement.Predicate.BuildDefinition
	parameters := definition.ExternalParameters
	recipeDigest, err := releaseinventory.ParseDigest(parameters.RecipeDigest)
	if err != nil {
		return false
	}
	if _, approved := v.policy.recipeDigests[recipeDigest]; !approved {
		return false
	}
	commitAlgorithm := "sha1"
	if len(manifest.SourceCommit()) == 64 {
		commitAlgorithm = "sha256"
	}
	if !exactDigestMap(parameters.Source.Digest, commitAlgorithm, manifest.SourceCommit()) ||
		parameters.Workflow.Ref != manifest.SourceCommit() {
		return false
	}
	if !definition.InternalParameters.Hermetic || !definition.InternalParameters.Reproducible ||
		!validLockedDependencies(definition.ResolvedDependencies) {
		return false
	}
	run := statement.Predicate.RunDetails
	identityKey := provenanceIdentityKey(
		run.Builder.ID,
		definition.BuildType,
		parameters.Source.Repository,
		parameters.Workflow.Path,
	)
	if _, approved := v.policy.buildIdentities[identityKey]; !approved {
		return false
	}
	if run.Metadata.InvocationID != manifest.BuildID() {
		return false
	}
	started, startError := time.Parse(time.RFC3339Nano, run.Metadata.StartedOn)
	finished, finishError := time.Parse(time.RFC3339Nano, run.Metadata.FinishedOn)
	return startError == nil && finishError == nil && started.Location() == time.UTC &&
		finished.Location() == time.UTC && !started.After(finished) &&
		finished.Equal(manifest.BuildTimestamp()) &&
		started.Format(time.RFC3339Nano) == run.Metadata.StartedOn &&
		finished.Format(time.RFC3339Nano) == run.Metadata.FinishedOn
}

func provenanceIdentityKey(builderID string, buildType string, repository string, workflow string) string {
	return builderID + "\x00" + buildType + "\x00" + repository + "\x00" + workflow
}

func exactDigestMap(values map[string]string, algorithm string, expected string) bool {
	return len(values) == 1 && values[algorithm] == expected
}

func validLockedDependencies(dependencies []slsaDependency) bool {
	if len(dependencies) == 0 || len(dependencies) > 4096 {
		return false
	}
	previous := ""
	for index, dependency := range dependencies {
		if !validSafeEvidenceText(dependency.URI, 2048) ||
			len(dependency.Digest) != 1 {
			return false
		}
		digest, exists := dependency.Digest["sha256"]
		if !exists || !validHexDigest(digest) || !strings.HasSuffix(dependency.URI, "@sha256:"+digest) {
			return false
		}
		if index > 0 && dependency.URI <= previous {
			return false
		}
		previous = dependency.URI
	}
	return true
}
