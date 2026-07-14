package agentconfig

import "bytes"

// MergeAction is the closed mutation vocabulary for one host configuration.
type MergeAction uint8

const (
	// MergeActionUnknown is the invalid zero value.
	MergeActionUnknown MergeAction = iota
	// MergeActionAdd adds an absent owned server entry.
	MergeActionAdd
	// MergeActionNoChange reports an exact managed entry already present.
	MergeActionNoChange
	// MergeActionReplaceManaged replaces only an entry bound to a protected
	// previous managed-entry digest.
	MergeActionReplaceManaged
)

// String returns the stable journal-safe action name.
func (a MergeAction) String() string {
	switch a {
	case MergeActionUnknown:
		return "unknown"
	case MergeActionAdd:
		return "add"
	case MergeActionNoChange:
		return "no_change"
	case MergeActionReplaceManaged:
		return "replace_managed"
	default:
		return "unknown"
	}
}

// MergePlan binds an exact observed configuration to one validated result.
type MergePlan struct {
	action             MergeAction
	originalExisted    bool
	before             []byte
	after              []byte
	beforeDigest       Digest
	afterDigest        Digest
	managedEntryDigest Digest
	target             Target
}

// PlanMerge returns a side-effect-free, copy-owned merge plan.
func PlanMerge(
	original []byte,
	originalExisted bool,
	target Target,
	expectedManagedEntryDigest Digest,
) (MergePlan, error) {
	if target.Command() == "" || target.LauncherDigest().IsZero() {
		return MergePlan{}, ErrInvalidTarget
	}
	if target.Host() == AgentHostCodex {
		return MergePlan{}, ErrInvalidTarget
	}
	if !target.Host().Valid() {
		return MergePlan{}, ErrInvalidTarget
	}
	contents := original
	if !originalExisted {
		if len(original) != 0 {
			return MergePlan{}, ErrInvalidDocument
		}
		contents = []byte("{}")
	}
	parsed, err := parseDocument(contents)
	if err != nil {
		return MergePlan{}, err
	}
	for serverName, encoded := range parsed.servers {
		if serverName != managedServerName && claimsAgentMemoryOwnership(encoded) {
			return MergePlan{}, ErrAmbiguousOwnership
		}
	}
	desired, desiredDigest, err := desiredEntry(target)
	if err != nil {
		return MergePlan{}, err
	}

	action := MergeActionAdd
	if current, found := parsed.servers[managedServerName]; found {
		ownership, currentDigest, inspectErr := inspectManagedEntry(current)
		if inspectErr != nil || ownership.InstallationID != target.InstallationID() || ownership.EntryID != target.EntryID() {
			return MergePlan{}, ErrAmbiguousOwnership
		}
		if currentDigest.Equal(desiredDigest) {
			return newMergePlan(
				MergeActionNoChange,
				originalExisted,
				original,
				original,
				desiredDigest,
				target,
			), nil
		}
		if expectedManagedEntryDigest.IsZero() || !currentDigest.Equal(expectedManagedEntryDigest) {
			return MergePlan{}, ErrManagedEntryConflict
		}
		action = MergeActionReplaceManaged
	}
	after, err := parsed.withManagedEntry(desired)
	if err != nil {
		return MergePlan{}, err
	}
	return newMergePlan(action, originalExisted, original, after, desiredDigest, target), nil
}

func newMergePlan(
	action MergeAction,
	originalExisted bool,
	before []byte,
	after []byte,
	managedEntryDigest Digest,
	target Target,
) MergePlan {
	beforeDigest := Digest{}
	if originalExisted {
		beforeDigest = DigestBytes(before)
	}
	return MergePlan{
		action:             action,
		originalExisted:    originalExisted,
		before:             append([]byte(nil), before...),
		after:              append([]byte(nil), after...),
		beforeDigest:       beforeDigest,
		afterDigest:        DigestBytes(after),
		managedEntryDigest: managedEntryDigest,
		target:             target,
	}
}

// NewMergePlan constructs an immutable result for a syntax adapter after it
// has validated both documents and the exact managed entry. It keeps format
// libraries outside the domain while retaining all plan invariants here.
func NewMergePlan(
	action MergeAction,
	originalExisted bool,
	before []byte,
	after []byte,
	managedEntryDigest Digest,
	target Target,
) (MergePlan, error) {
	if (action != MergeActionAdd && action != MergeActionNoChange && action != MergeActionReplaceManaged) ||
		!target.Host().Valid() || target.Command() == "" || target.LauncherDigest().IsZero() ||
		len(after) == 0 || len(after) > MaxDocumentBytes || managedEntryDigest.IsZero() ||
		(!originalExisted && len(before) != 0) ||
		(action == MergeActionNoChange && !bytes.Equal(before, after)) ||
		(action != MergeActionNoChange && bytes.Equal(before, after)) {
		return MergePlan{}, ErrInvalidDocument
	}
	return newMergePlan(action, originalExisted, before, after, managedEntryDigest, target), nil
}

// VerifyManagedEntry proves that the one named entry exactly matches target.
func VerifyManagedEntry(contents []byte, target Target) error {
	if target.Host() == AgentHostCodex {
		return ErrInvalidTarget
	}
	if !target.Host().Valid() {
		return ErrInvalidTarget
	}
	parsed, err := parseDocument(contents)
	if err != nil {
		return err
	}
	current, found := parsed.servers[managedServerName]
	if !found {
		return ErrManagedEntryConflict
	}
	ownership, currentDigest, err := inspectManagedEntry(current)
	if err != nil || ownership.InstallationID != target.InstallationID() || ownership.EntryID != target.EntryID() {
		return ErrAmbiguousOwnership
	}
	_, desiredDigest, err := desiredEntry(target)
	if err != nil {
		return err
	}
	if !currentDigest.Equal(desiredDigest) {
		return ErrManagedEntryConflict
	}
	return nil
}

// Action returns the planned mutation.
func (p MergePlan) Action() MergeAction { return p.action }

// Changed reports whether an atomic filesystem mutation is required.
func (p MergePlan) Changed() bool {
	return p.action == MergeActionAdd || p.action == MergeActionReplaceManaged
}

// OriginalExisted reports whether the target existed at planning time.
func (p MergePlan) OriginalExisted() bool { return p.originalExisted }

// BeforeContent returns a caller-owned exact snapshot for backup.
func (p MergePlan) BeforeContent() []byte { return append([]byte(nil), p.before...) }

// AfterContent returns a caller-owned validated replacement document.
func (p MergePlan) AfterContent() []byte { return append([]byte(nil), p.after...) }

// BeforeDigest returns the exact original configuration hash, or zero when absent.
func (p MergePlan) BeforeDigest() Digest { return p.beforeDigest }

// AfterDigest returns the exact replacement configuration hash.
func (p MergePlan) AfterDigest() Digest { return p.afterDigest }

// ManagedEntryDigest returns the canonical owned-entry hash for future updates.
func (p MergePlan) ManagedEntryDigest() Digest { return p.managedEntryDigest }

// Target returns the immutable managed-entry target.
func (p MergePlan) Target() Target { return p.target }
