package runtimeprovision

import (
	"context"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

const maximumRuntimePublisherPolicies = 64

// RuntimePublisherPolicyInput is release-generated public policy. It is kept
// outside runtime catalog manifests so a signed catalog cannot authorize its
// own native publisher identity.
type RuntimePublisherPolicyInput struct {
	Verification       runtimecatalog.NativeVerification `json:"verification"`
	Identity           string                            `json:"identity"`
	SigningKeyIdentity string                            `json:"signingKeyIdentity"`
	PackageIdentity    string                            `json:"packageIdentity"`
}

type runtimePublisherIdentity struct {
	verification       runtimecatalog.NativeVerification
	identity           string
	signingKeyIdentity string
	packageIdentity    string
}

// RuntimePublisherPolicyVerifier authorizes exact, independently embedded
// native verification/publisher/key/package tuples.
type RuntimePublisherPolicyVerifier struct {
	policies map[runtimePublisherIdentity]struct{}
}

// NewRuntimePublisherPolicyVerifier validates, de-duplicates, and closes the allowlist.
func NewRuntimePublisherPolicyVerifier(
	input []RuntimePublisherPolicyInput,
) (*RuntimePublisherPolicyVerifier, error) {
	if len(input) == 0 || len(input) > maximumRuntimePublisherPolicies {
		return nil, runtimecatalogapp.ErrNativePublisherInvalid
	}
	policies := make(map[runtimePublisherIdentity]struct{}, len(input))
	for _, candidate := range input {
		identity := runtimePublisherIdentity{
			verification: candidate.Verification, identity: candidate.Identity,
			signingKeyIdentity: candidate.SigningKeyIdentity, packageIdentity: candidate.PackageIdentity,
		}
		if !validRuntimePublisherIdentity(identity) {
			return nil, runtimecatalogapp.ErrNativePublisherInvalid
		}
		if _, duplicate := policies[identity]; duplicate {
			return nil, runtimecatalogapp.ErrNativePublisherInvalid
		}
		policies[identity] = struct{}{}
	}
	return &RuntimePublisherPolicyVerifier{policies: policies}, nil
}

// VerifyNativePublisherPolicy allows only one exact embedded tuple. Actual
// artifact bytes must subsequently pass the declared platform-native verifier.
func (v *RuntimePublisherPolicyVerifier) VerifyNativePublisherPolicy(
	ctx context.Context,
	policy runtimecatalog.PublisherPolicy,
) error {
	if v == nil || ctx == nil || len(v.policies) == 0 {
		return runtimecatalogapp.ErrNativePublisherInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	identity := runtimePublisherIdentity{
		verification: policy.Verification(), identity: policy.Identity(),
		signingKeyIdentity: policy.SigningKeyIdentity(), packageIdentity: policy.PackageIdentity(),
	}
	if !validRuntimePublisherIdentity(identity) {
		return runtimecatalogapp.ErrNativePublisherInvalid
	}
	if _, authorized := v.policies[identity]; !authorized {
		return runtimecatalogapp.ErrNativePublisherInvalid
	}
	return nil
}

func validRuntimePublisherIdentity(value runtimePublisherIdentity) bool {
	switch value.verification {
	case runtimecatalog.NativeVerificationAppleNotarized,
		runtimecatalog.NativeVerificationAuthenticode,
		runtimecatalog.NativeVerificationPackageSignature:
	default:
		return false
	}
	return validRuntimePublisherIdentifier(value.identity) &&
		validRuntimePublisherIdentifier(value.signingKeyIdentity) &&
		validRuntimePublisherIdentifier(value.packageIdentity)
}

func validRuntimePublisherIdentifier(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:+-/@", character) {
			continue
		}
		return false
	}
	return true
}

var _ runtimecatalogapp.NativePublisherVerifier = (*RuntimePublisherPolicyVerifier)(nil)
