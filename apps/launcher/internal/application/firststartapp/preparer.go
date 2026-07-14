package firststartapp

import (
	"context"
	"errors"
	"reflect"

	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// ErrPreparationNotFound means no durable pristine-start intent exists yet.
var ErrPreparationNotFound = errors.New("first-start preparation not found")

// Template identifies one exact, already verified packaged installation-plan
// template. The source must retain every template addressable by a durable
// Preparation until that preparation is explicitly retired.
type Template struct {
	canonical []byte
	digest    install.PlanDigest
}

// NewTemplate creates an immutable exact-template authority.
func NewTemplate(canonical []byte) (Template, error) {
	digest, err := install.BindPlan(canonical)
	if err != nil {
		return Template{}, ErrIntegrity
	}
	return Template{canonical: append([]byte(nil), canonical...), digest: digest}, nil
}

// Canonical returns caller-owned exact template bytes.
func (t Template) Canonical() []byte { return append([]byte(nil), t.canonical...) }

// Digest returns the exact template byte binding.
func (t Template) Digest() install.PlanDigest { return t.digest }

// Valid reauthenticates the immutable template binding.
func (t Template) Valid() bool {
	digest, err := install.BindPlan(t.canonical)
	return err == nil && digest.Equal(t.digest)
}

// Preparation is the rollback-protected intent selected before any canonical
// plan or operation is published. Every identifier remains stable across
// process death and launcher upgrades.
type Preparation struct {
	host            agentconfigdomain.AgentHost
	templateDigest  install.PlanDigest
	operationID     install.OperationID
	installationID  string
	generationID    string
	brainID         string
	ownerPrincipal  string
	ownerGrant      string
	agentEntryID    string
	securityEpoch   uint64
	confirmedDigest install.PlanDigest
}

// NewPreparation validates the complete unconfirmed durable intent.
func NewPreparation(
	host agentconfigdomain.AgentHost,
	templateDigest install.PlanDigest,
	operationID install.OperationID,
	identifiers []string,
	securityEpoch uint64,
) (Preparation, error) {
	if !host.Valid() || templateDigest.IsZero() || operationID.IsZero() ||
		len(identifiers) != 6 || securityEpoch == 0 {
		return Preparation{}, ErrIntegrity
	}
	for _, identifier := range identifiers {
		if identifier == "" {
			return Preparation{}, ErrIntegrity
		}
	}
	return Preparation{
		host: host, templateDigest: templateDigest, operationID: operationID,
		installationID: identifiers[0], generationID: identifiers[1], brainID: identifiers[2],
		ownerPrincipal: identifiers[3], ownerGrant: identifiers[4], agentEntryID: identifiers[5],
		securityEpoch: securityEpoch,
	}, nil
}

// Host returns the selected agent-host adapter.
func (p Preparation) Host() agentconfigdomain.AgentHost { return p.host }

// TemplateDigest returns the exact verified packaged template binding.
func (p Preparation) TemplateDigest() install.PlanDigest { return p.templateDigest }

// OperationID returns the stable install operation identity.
func (p Preparation) OperationID() install.OperationID { return p.operationID }

// InstallationID returns the stable local installation identity.
func (p Preparation) InstallationID() string { return p.installationID }

// GenerationID returns the stable initial release-generation identity.
func (p Preparation) GenerationID() string { return p.generationID }

// BrainID returns the stable initial Brain identity.
func (p Preparation) BrainID() string { return p.brainID }

// OwnerPrincipalID returns the stable initial owner principal identity.
func (p Preparation) OwnerPrincipalID() string { return p.ownerPrincipal }

// OwnerGrantID returns the stable initial owner grant identity.
func (p Preparation) OwnerGrantID() string { return p.ownerGrant }

// AgentEntryID returns the stable managed agent-configuration entry identity.
func (p Preparation) AgentEntryID() string { return p.agentEntryID }

// SecurityEpoch returns the monotonic initial activation security epoch.
func (p Preparation) SecurityEpoch() uint64 { return p.securityEpoch }

// ConfirmedPlanDigest returns the exact derived plan binding, when confirmed.
func (p Preparation) ConfirmedPlanDigest() install.PlanDigest { return p.confirmedDigest }

// Confirmed reports whether the derived plan was durably bound.
func (p Preparation) Confirmed() bool { return !p.confirmedDigest.IsZero() }

// Valid validates the complete durable identifier and template selection.
func (p Preparation) Valid() bool {
	return p.host.Valid() && !p.templateDigest.IsZero() && !p.operationID.IsZero() &&
		p.installationID != "" && p.generationID != "" && p.brainID != "" &&
		p.ownerPrincipal != "" && p.ownerGrant != "" && p.agentEntryID != "" && p.securityEpoch != 0
}

// WithConfirmedPlan returns the only legal state successor.
func (p Preparation) WithConfirmedPlan(digest install.PlanDigest) (Preparation, error) {
	if !p.Valid() || digest.IsZero() || (p.Confirmed() && !p.confirmedDigest.Equal(digest)) {
		return Preparation{}, ErrConflict
	}
	p.confirmedDigest = digest
	return p, nil
}

// VerifiedTemplateSource exposes only cryptographically verified packaged
// templates. Exact must not fall forward to a newer release.
type VerifiedTemplateSource interface {
	Current(context.Context) (Template, error)
	Exact(context.Context, install.PlanDigest) (Template, error)
}

// IdentifierGenerator generates RFC 9562 UUIDv7 identities from protected
// entropy. It is deliberately the same narrow shape as the bootstrap port.
type IdentifierGenerator interface {
	NewOperationID(context.Context) (install.OperationID, error)
}

// PreparationRepository atomically acquires one intent per host and confirms
// its exact derived plan before any caller can publish that plan.
type PreparationRepository interface {
	Load(context.Context, agentconfigdomain.AgentHost) (Preparation, error)
	Acquire(context.Context, Preparation) (Preparation, error)
	ConfirmPlan(context.Context, Preparation, install.PlanDigest) (Preparation, error)
}

// PreparationBinder deterministically binds host facts to an exact template.
type PreparationBinder interface {
	Bind(context.Context, Template, Preparation) (PreparedInstallation, error)
}

// PreparerDependencies are all mandatory; no identifier or path is accepted
// from MCP input.
type PreparerDependencies struct {
	Templates   VerifiedTemplateSource
	Identifiers IdentifierGenerator
	Repository  PreparationRepository
	Binder      PreparationBinder
}

// Preparer implements the crash-safe first-start authority selection use case.
type Preparer struct{ dependencies PreparerDependencies }

// NewPreparer creates the crash-safe first-start preparation use case.
func NewPreparer(dependencies PreparerDependencies) (*Preparer, error) {
	for _, capability := range []any{
		dependencies.Templates, dependencies.Identifiers, dependencies.Repository, dependencies.Binder,
	} {
		if nilPreparationCapability(capability) {
			return nil, ErrIntegrity
		}
	}
	return &Preparer{dependencies: dependencies}, nil
}

// Prepare either replays the exact confirmed intent or durably selects it
// before deriving and confirming the canonical plan.
func (p *Preparer) Prepare(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (PreparedInstallation, error) {
	if p == nil || ctx == nil || !host.Valid() {
		return PreparedInstallation{}, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return PreparedInstallation{}, err
	}
	preparation, err := p.dependencies.Repository.Load(ctx, host)
	if errors.Is(err, ErrPreparationNotFound) {
		preparation, err = p.acquire(ctx, host)
	}
	if err != nil || !preparation.Valid() || preparation.Host() != host {
		return PreparedInstallation{}, mapPreparationBoundary(err)
	}
	template, err := p.dependencies.Templates.Exact(ctx, preparation.TemplateDigest())
	if err != nil || !template.Valid() || !template.Digest().Equal(preparation.TemplateDigest()) {
		return PreparedInstallation{}, mapPreparationBoundary(err)
	}
	prepared, err := p.dependencies.Binder.Bind(ctx, template, preparation)
	if err != nil || !prepared.Valid() || prepared.Host() != host ||
		prepared.OperationID() != preparation.OperationID() ||
		prepared.InstallationID() != preparation.InstallationID() {
		return PreparedInstallation{}, mapPreparationBoundary(err)
	}
	if preparation.Confirmed() {
		if !preparation.ConfirmedPlanDigest().Equal(prepared.PlanDigest()) {
			return PreparedInstallation{}, ErrConflict
		}
		return prepared, nil
	}
	confirmed, err := p.dependencies.Repository.ConfirmPlan(ctx, preparation, prepared.PlanDigest())
	if err != nil || !confirmed.Valid() || !confirmed.Confirmed() ||
		!confirmed.ConfirmedPlanDigest().Equal(prepared.PlanDigest()) {
		return PreparedInstallation{}, mapPreparationBoundary(err)
	}
	return prepared, nil
}

func (p *Preparer) acquire(ctx context.Context, host agentconfigdomain.AgentHost) (Preparation, error) {
	template, err := p.dependencies.Templates.Current(ctx)
	if err != nil || !template.Valid() {
		return Preparation{}, mapPreparationBoundary(err)
	}
	identities := make([]install.OperationID, 7)
	for index := range identities {
		identities[index], err = p.dependencies.Identifiers.NewOperationID(ctx)
		if err != nil || identities[index].IsZero() {
			return Preparation{}, mapPreparationBoundary(err)
		}
	}
	strings := make([]string, 6)
	for index := range strings {
		strings[index] = identities[index+1].String()
	}
	candidate, err := NewPreparation(host, template.Digest(), identities[0], strings, 1)
	if err != nil {
		return Preparation{}, err
	}
	return p.dependencies.Repository.Acquire(ctx, candidate)
}

func mapPreparationBoundary(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrIntegrity) {
		return ErrIntegrity
	}
	if errors.Is(err, ErrConflict) {
		return ErrConflict
	}
	return ErrUnavailable
}

func nilPreparationCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid capability.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ AuthorityPreparer = (*Preparer)(nil)
