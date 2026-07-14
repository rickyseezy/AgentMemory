package firststart

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

type binderProjectionSource struct {
	projection HostProjection
	err        error
}

func (s *binderProjectionSource) Project(context.Context, agentconfigdomain.AgentHost) (HostProjection, error) {
	return s.projection, s.err
}

func TestPF001PlanBinderRejectsIncompleteCompositionAndInput(t *testing.T) {
	t.Parallel()
	var typedNil *binderProjectionSource
	for _, source := range []HostProjectionSource{nil, typedNil} {
		if binder, err := NewPlanBinder(source); binder != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
			t.Fatalf("expected closed constructor rejection, got %#v, %v", binder, err)
		}
	}
	source := &binderProjectionSource{}
	binder, err := NewPlanBinder(source)
	if err != nil {
		t.Fatal(err)
	}
	template, _ := firststartapp.NewTemplate([]byte("authenticated but invalid plan"))
	preparation := binderPreparation(t, template)
	for _, test := range []struct {
		name        string
		receiver    *PlanBinder
		ctx         context.Context
		template    firststartapp.Template
		preparation firststartapp.Preparation
		expected    error
	}{
		{name: "nil receiver", ctx: context.Background(), template: template, preparation: preparation, expected: firststartapp.ErrIntegrity},
		{name: "nil context", receiver: binder, template: template, preparation: preparation, expected: firststartapp.ErrIntegrity},
		{name: "invalid template", receiver: binder, ctx: context.Background(), preparation: preparation, expected: firststartapp.ErrIntegrity},
		{name: "invalid preparation", receiver: binder, ctx: context.Background(), template: template, expected: firststartapp.ErrIntegrity},
		{name: "invalid canonical plan", receiver: binder, ctx: context.Background(), template: template, preparation: preparation, expected: firststartapp.ErrIntegrity},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, got := test.receiver.Bind(test.ctx, test.template, test.preparation)
			if !errors.Is(got, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, got)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := binder.Bind(canceled, template, preparation); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if source, err := NewNativeHostProjectionSource(nil, nil); source != nil || !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("expected production constructor to fail closed, got %#v, %v", source, err)
	}
}

func TestPF001BinderHostProjectionValidationIsPlatformClosed(t *testing.T) {
	t.Parallel()
	launcher := agentconfigdomain.DigestBytes([]byte("launcher"))
	owner := install.DigestBytes([]byte("owner"))
	validUnix := HostProjection{
		StorageRoot: "/home/user/.agentmemory", RuntimeEndpoint: "unix:///run/user/1000/docker.sock",
		ConfigurationPath: "/home/user/.codex/config.toml", LauncherPath: "/opt/agentmemory/launcher",
		LauncherDigest: launcher, OwnerSubjectDigest: owner,
	}
	validWindows := HostProjection{
		StorageRoot: `C:\Users\User\.agentmemory`, RuntimeEndpoint: "npipe:////./pipe/docker_engine",
		ConfigurationPath: `C:\Users\User\.codex\config.toml`, LauncherPath: `C:\Program Files\AgentMemory\launcher.exe`,
		LauncherDigest: launcher, OwnerSubjectDigest: owner,
	}
	if !validHostProjection(validUnix) || !validHostProjection(validWindows) {
		t.Fatal("expected certified Unix and Windows projections to be accepted")
	}
	invalid := []HostProjection{
		{},
		{StorageRoot: "relative", RuntimeEndpoint: validUnix.RuntimeEndpoint, ConfigurationPath: validUnix.ConfigurationPath, LauncherPath: validUnix.LauncherPath, LauncherDigest: launcher, OwnerSubjectDigest: owner},
		{StorageRoot: `c:\Users\User`, RuntimeEndpoint: validWindows.RuntimeEndpoint, ConfigurationPath: validWindows.ConfigurationPath, LauncherPath: validWindows.LauncherPath, LauncherDigest: launcher, OwnerSubjectDigest: owner},
		{StorageRoot: `C:\Users\User\`, RuntimeEndpoint: validWindows.RuntimeEndpoint, ConfigurationPath: validWindows.ConfigurationPath, LauncherPath: validWindows.LauncherPath, LauncherDigest: launcher, OwnerSubjectDigest: owner},
	}
	for index, projection := range invalid {
		if validHostProjection(projection) {
			t.Fatalf("invalid projection %d was accepted", index)
		}
	}
	if got := joinHostPath("/home/user/.agentmemory/", "/releases/", "generation"); got != "/home/user/.agentmemory/releases/generation" {
		t.Fatalf("unexpected Unix path %q", got)
	}
	if got := joinHostPath(`C:\Users\User\.agentmemory`, `\releases\`, "generation"); got != `C:\Users\User\.agentmemory\releases\generation` {
		t.Fatalf("unexpected Windows path %q", got)
	}
}

func TestPF001BinderMapsPrivateFailuresAndBindsHostDirectories(t *testing.T) {
	t.Parallel()
	private := errors.New("private")
	for _, test := range []struct {
		input, expected error
	}{
		{context.Canceled, context.Canceled},
		{context.DeadlineExceeded, context.DeadlineExceeded},
		{firststartapp.ErrIntegrity, firststartapp.ErrIntegrity},
		{private, firststartapp.ErrUnavailable},
	} {
		if got := mapBinderError(test.input); !errors.Is(got, test.expected) {
			t.Fatalf("expected %v, got %v", test.expected, got)
		}
	}
	template, _ := firststartapp.NewTemplate([]byte("template"))
	preparation := binderPreparation(t, template)
	product, err := bindProduct(installplan.Plan{}, preparation, "/home/user/.agentmemory")
	if err != nil {
		t.Fatal(err)
	}
	if product.ReleaseDirectory != "/home/user/.agentmemory/releases/019f5f21-0000-7abc-8123-0123456789ab" ||
		product.ConfigurationDirectory != "/home/user/.agentmemory/config" ||
		product.CoreEndpoint != nativeCoreEndpoint || product.InitialBrainID != preparation.BrainID() ||
		product.OwnerPrincipalID != preparation.OwnerPrincipalID() || product.OwnerGrantID != preparation.OwnerGrantID() {
		t.Fatalf("unexpected bound product: %#v", product)
	}
}

func binderPreparation(t testing.TB, template firststartapp.Template) firststartapp.Preparation {
	t.Helper()
	operation, err := install.NewOperationID("019f5f1f-0000-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := firststartapp.NewPreparation(agentconfigdomain.AgentHostCodex, template.Digest(), operation, []string{
		"019f5f20-0000-7abc-8123-0123456789ab", "019f5f21-0000-7abc-8123-0123456789ab",
		"019f5f22-0000-7abc-8123-0123456789ab", "019f5f23-0000-7abc-8123-0123456789ab",
		"019f5f24-0000-7abc-8123-0123456789ab", "019f5f25-0000-7abc-8123-0123456789ab",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return preparation
}
