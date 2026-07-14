package firststartapp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001PreparerDurablySelectsBeforeBindingAndReplaysExactAuthority(t *testing.T) {
	t.Parallel()
	order := make([]string, 0, 12)
	template, _ := NewTemplate([]byte("verified-template"))
	fixture := preparationFixtureForTest(t, template, &order)
	preparer, err := NewPreparer(fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	first, err := preparer.Prepare(context.Background(), agentconfigdomain.AgentHostCodex)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"load", "current", "id", "id", "id", "id", "id", "id", "id", "acquire", "exact", "bind", "confirm"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("order=%q want=%q", order, want)
	}
	if !fixture.repository.state.Confirmed() ||
		!fixture.repository.state.ConfirmedPlanDigest().Equal(first.PlanDigest()) {
		t.Fatal("plan authority was not confirmed before publication")
	}
	order = order[:0]
	second, err := preparer.Prepare(context.Background(), agentconfigdomain.AgentHostCodex)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(order) != fmt.Sprint([]string{"load", "exact", "bind"}) ||
		!second.PlanDigest().Equal(first.PlanDigest()) || fixture.identifiers.calls != 7 {
		t.Fatalf("replay order=%q identities=%d", order, fixture.identifiers.calls)
	}
}

func TestPF001PreparerRejectsTemplateAndDerivedPlanSubstitution(t *testing.T) {
	t.Parallel()
	template, _ := NewTemplate([]byte("verified-template"))
	for name, mutate := range map[string]func(*preparationFixture){
		"load host": func(f *preparationFixture) {
			state := preparationStateForTest(t, template, agentconfigdomain.AgentHostClaude)
			f.repository.state = state
		},
		"exact template": func(f *preparationFixture) {
			foreign, _ := NewTemplate([]byte("foreign-template"))
			f.templates.exact = foreign
		},
		"binder operation":    func(f *preparationFixture) { f.binder.foreignOperation = true },
		"binder installation": func(f *preparationFixture) { f.binder.foreignInstallation = true },
		"binder host":         func(f *preparationFixture) { f.binder.foreignHost = true },
		"confirmed digest": func(f *preparationFixture) {
			state := preparationStateForTest(t, template, agentconfigdomain.AgentHostCodex)
			state, _ = state.WithConfirmedPlan(preparationPlanDigest(t, "foreign"))
			f.repository.state = state
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			order := []string{}
			fixture := preparationFixtureForTest(t, template, &order)
			mutate(&fixture)
			preparer, _ := NewPreparer(fixture.dependencies())
			if _, err := preparer.Prepare(context.Background(), agentconfigdomain.AgentHostCodex); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
}

func TestPF001PreparerMapsEveryDurableBoundaryAndRejectsPartialComposition(t *testing.T) {
	t.Parallel()
	template, _ := NewTemplate([]byte("verified-template"))
	order := []string{}
	base := preparationFixtureForTest(t, template, &order)
	var typedNil *preparationTemplateSource
	for name, dependencies := range map[string]PreparerDependencies{
		"empty": {},
		"typed nil": {Templates: typedNil, Identifiers: base.identifiers,
			Repository: base.repository, Binder: base.binder},
	} {
		if value, err := NewPreparer(dependencies); value != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s NewPreparer()=%v,%v", name, value, err)
		}
	}
	preparer, _ := NewPreparer(base.dependencies())
	//lint:ignore SA1012 Deliberate nil-context contract test.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := preparer.Prepare(nil, agentconfigdomain.AgentHostCodex); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("nil context=%v", err)
	}
	if _, err := preparer.Prepare(context.Background(), agentconfigdomain.AgentHost("foreign")); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("foreign host=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := preparer.Prepare(cancelled, agentconfigdomain.AgentHostCodex); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled=%v", err)
	}

	for name, configure := range map[string]func(*preparationFixture){
		"load":       func(f *preparationFixture) { f.repository.loadErr = errors.New("private") },
		"current":    func(f *preparationFixture) { f.templates.currentErr = errors.New("private") },
		"identifier": func(f *preparationFixture) { f.identifiers.err = errors.New("private") },
		"acquire":    func(f *preparationFixture) { f.repository.acquireErr = ErrConflict },
		"exact":      func(f *preparationFixture) { f.templates.exactErr = errors.New("private") },
		"bind":       func(f *preparationFixture) { f.binder.err = errors.New("private") },
		"confirm":    func(f *preparationFixture) { f.repository.confirmErr = errors.New("private") },
	} {
		name, configure := name, configure
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			localOrder := []string{}
			fixture := preparationFixtureForTest(t, template, &localOrder)
			configure(&fixture)
			preparer, _ := NewPreparer(fixture.dependencies())
			_, err := preparer.Prepare(context.Background(), agentconfigdomain.AgentHostCodex)
			if err == nil {
				t.Fatal("failed boundary accepted")
			}
		})
	}
}

func TestPF001PreparationValueObjectsAreImmutableAndClosed(t *testing.T) {
	t.Parallel()
	raw := []byte("template")
	template, err := NewTemplate(raw)
	if err != nil || !template.Valid() {
		t.Fatalf("template=%+v,%v", template, err)
	}
	raw[0] = 'X'
	canonicalCopy := template.Canonical()
	canonicalCopy[0] = 'Y'
	if string(template.Canonical()) != "template" {
		t.Fatal("template exposed mutable bytes")
	}
	if _, err := NewTemplate(nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("empty template=%v", err)
	}
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	identifiers := []string{"installation", "generation", "brain", "principal", "grant", "entry"}
	for name, build := range map[string]func() (Preparation, error){
		"host": func() (Preparation, error) {
			return NewPreparation("bad", template.Digest(), operation, identifiers, 1)
		},
		"template": func() (Preparation, error) {
			return NewPreparation(agentconfigdomain.AgentHostCodex, install.PlanDigest{}, operation, identifiers, 1)
		},
		"operation": func() (Preparation, error) {
			return NewPreparation(agentconfigdomain.AgentHostCodex, template.Digest(), install.OperationID{}, identifiers, 1)
		},
		"identifiers": func() (Preparation, error) {
			return NewPreparation(agentconfigdomain.AgentHostCodex, template.Digest(), operation, identifiers[:5], 1)
		},
		"epoch": func() (Preparation, error) {
			return NewPreparation(agentconfigdomain.AgentHostCodex, template.Digest(), operation, identifiers, 0)
		},
	} {
		if value, err := build(); value.Valid() || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s preparation=%+v,%v", name, value, err)
		}
	}
	valid, _ := NewPreparation(agentconfigdomain.AgentHostCodex, template.Digest(), operation, identifiers, 1)
	if valid.GenerationID() != "generation" || valid.BrainID() != "brain" ||
		valid.OwnerPrincipalID() != "principal" || valid.OwnerGrantID() != "grant" ||
		valid.AgentEntryID() != "entry" || valid.SecurityEpoch() != 1 {
		t.Fatalf("preparation accessors lost authority: %+v", valid)
	}
	confirmed, err := valid.WithConfirmedPlan(preparationPlanDigest(t, "plan"))
	if err != nil || !confirmed.Confirmed() || valid.Confirmed() {
		t.Fatalf("confirmed=%+v,%v", confirmed, err)
	}
	if _, err := confirmed.WithConfirmedPlan(preparationPlanDigest(t, "other")); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting confirmation=%v", err)
	}
}

func TestPF001PreparationBoundaryKeepsOnlyClosedPublicErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input error
		want  error
	}{
		{input: nil, want: ErrUnavailable},
		{input: context.Canceled, want: context.Canceled},
		{input: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{input: ErrIntegrity, want: ErrIntegrity},
		{input: ErrConflict, want: ErrConflict},
		{input: errors.New("private"), want: ErrUnavailable},
	} {
		if actual := mapPreparationBoundary(test.input); !errors.Is(actual, test.want) {
			t.Fatalf("mapPreparationBoundary(%v) = %v, want %v", test.input, actual, test.want)
		}
	}
}

func preparationPlanDigest(t testing.TB, value string) install.PlanDigest {
	t.Helper()
	digest, err := install.BindPlan([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type preparationFixture struct {
	templates   *preparationTemplateSource
	identifiers *preparationIdentifiers
	repository  *preparationRepository
	binder      *preparationBinder
}

func preparationFixtureForTest(t testing.TB, template Template, order *[]string) preparationFixture {
	t.Helper()
	return preparationFixture{
		templates:   &preparationTemplateSource{current: template, exact: template, order: order},
		identifiers: &preparationIdentifiers{order: order},
		repository:  &preparationRepository{order: order},
		binder:      &preparationBinder{order: order},
	}
}

func (f preparationFixture) dependencies() PreparerDependencies {
	return PreparerDependencies{Templates: f.templates, Identifiers: f.identifiers, Repository: f.repository, Binder: f.binder}
}

func preparationStateForTest(t testing.TB, template Template, host agentconfigdomain.AgentHost) Preparation {
	t.Helper()
	operation, _ := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	state, err := NewPreparation(host, template.Digest(), operation, []string{
		"019f5f20-0000-7abc-8123-0123456789ab", "019f5f21-0000-7abc-8123-0123456789ab",
		"019f5f22-0000-7abc-8123-0123456789ab", "019f5f23-0000-7abc-8123-0123456789ab",
		"019f5f24-0000-7abc-8123-0123456789ab", "019f5f25-0000-7abc-8123-0123456789ab",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

type preparationTemplateSource struct {
	current, exact       Template
	currentErr, exactErr error
	order                *[]string
}

func (s *preparationTemplateSource) Current(context.Context) (Template, error) {
	*s.order = append(*s.order, "current")
	return s.current, s.currentErr
}
func (s *preparationTemplateSource) Exact(context.Context, install.PlanDigest) (Template, error) {
	*s.order = append(*s.order, "exact")
	return s.exact, s.exactErr
}

type preparationIdentifiers struct {
	calls int
	err   error
	order *[]string
}

func (g *preparationIdentifiers) NewOperationID(context.Context) (install.OperationID, error) {
	*g.order = append(*g.order, "id")
	if g.err != nil {
		return install.OperationID{}, g.err
	}
	g.calls++
	return install.NewOperationID(fmt.Sprintf("019f5f%02x-0000-7abc-8123-%012x", g.calls, g.calls))
}

type preparationRepository struct {
	state                           Preparation
	loadErr, acquireErr, confirmErr error
	order                           *[]string
}

func (r *preparationRepository) Load(context.Context, agentconfigdomain.AgentHost) (Preparation, error) {
	*r.order = append(*r.order, "load")
	if r.loadErr != nil {
		return Preparation{}, r.loadErr
	}
	if !r.state.Valid() {
		return Preparation{}, ErrPreparationNotFound
	}
	return r.state, nil
}
func (r *preparationRepository) Acquire(_ context.Context, candidate Preparation) (Preparation, error) {
	*r.order = append(*r.order, "acquire")
	if r.acquireErr != nil {
		return Preparation{}, r.acquireErr
	}
	r.state = candidate
	return r.state, nil
}
func (r *preparationRepository) ConfirmPlan(_ context.Context, expected Preparation, digest install.PlanDigest) (Preparation, error) {
	*r.order = append(*r.order, "confirm")
	if r.confirmErr != nil {
		return Preparation{}, r.confirmErr
	}
	if r.state != expected {
		return Preparation{}, ErrConflict
	}
	r.state, _ = r.state.WithConfirmedPlan(digest)
	return r.state, nil
}

type preparationBinder struct {
	order                                              *[]string
	err                                                error
	foreignOperation, foreignInstallation, foreignHost bool
}

func (b *preparationBinder) Bind(_ context.Context, template Template, state Preparation) (PreparedInstallation, error) {
	*b.order = append(*b.order, "bind")
	if b.err != nil {
		return PreparedInstallation{}, b.err
	}
	operation := state.OperationID()
	installation, host := state.InstallationID(), state.Host()
	if b.foreignOperation {
		operation, _ = install.NewOperationID("019f5fff-0000-7abc-8123-0123456789ab")
	}
	if b.foreignInstallation {
		installation = "foreign"
	}
	if b.foreignHost {
		host = agentconfigdomain.AgentHostClaude
	}
	canonical := append(template.Canonical(), []byte(state.OperationID().String())...)
	return NewPreparedInstallation(canonical, operation, installation, host)
}
