package releaseverifyadapter

import (
	"context"
	"sort"
	"strings"

	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const maximumNativePublisherPolicies = 64

// NativePublisherPolicyInput is public release-generated policy. Each policy
// ID maps to the complete set of native publisher identities it authorizes.
// It is independent from the manifest so a signed manifest cannot authorize
// its own publisher allowlist.
type NativePublisherPolicyInput map[string][]string

// NativePublisherPolicyVerifier verifies the independently embedded policy
// binding. Native signature validation still occurs against the opened
// executable in the platform process adapter before execution.
type NativePublisherPolicyVerifier struct{ policies map[string][]string }

// NewNativePublisherPolicyVerifier copies and closes the embedded allowlist.
func NewNativePublisherPolicyVerifier(
	input NativePublisherPolicyInput,
) (*NativePublisherPolicyVerifier, error) {
	if len(input) == 0 || len(input) > maximumNativePublisherPolicies {
		return nil, appreleaseverify.ErrNativePublisherInvalid
	}
	policies := make(map[string][]string, len(input))
	for policyID, identities := range input {
		if !validNativePublisherIdentifier(policyID) || len(identities) == 0 ||
			len(identities) > maximumNativePublisherPolicies {
			return nil, appreleaseverify.ErrNativePublisherInvalid
		}
		copied := append([]string(nil), identities...)
		sort.Strings(copied)
		for index, identity := range copied {
			if !validNativePublisherIdentifier(identity) || (index > 0 && copied[index-1] == identity) {
				return nil, appreleaseverify.ErrNativePublisherInvalid
			}
		}
		policies[policyID] = copied
	}
	return &NativePublisherPolicyVerifier{policies: policies}, nil
}

// VerifyNativePublisher authorizes only native executable resources carrying
// an exact independently embedded policy/identity pair.
func (v *NativePublisherPolicyVerifier) VerifyNativePublisher(
	ctx context.Context,
	resource releaseinventory.Resource,
) error {
	if v == nil || ctx == nil || len(v.policies) == 0 || resource.Platform().IsAny() {
		return appreleaseverify.ErrNativePublisherInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	//nolint:exhaustive // Every non-native resource kind is deliberately rejected.
	switch resource.Kind() {
	case releaseinventory.ResourceKindLauncher,
		releaseinventory.ResourceKindHelper,
		releaseinventory.ResourceKindVerifier:
	default:
		return appreleaseverify.ErrNativePublisherInvalid
	}
	identities, present := v.policies[resource.NativePublisherPolicyID()]
	if !present {
		return appreleaseverify.ErrNativePublisherInvalid
	}
	identity := resource.NativePublisherIdentity()
	index := sort.SearchStrings(identities, identity)
	if index >= len(identities) || identities[index] != identity {
		return appreleaseverify.ErrNativePublisherInvalid
	}
	return nil
}

func validNativePublisherIdentifier(value string) bool {
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

var _ appreleaseverify.NativePublisherVerifier = (*NativePublisherPolicyVerifier)(nil)
