package setuphttp

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPF001SetupControllerMintsFreshAuthorityAndClosesPredecessor(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	dependencies := setupDependencies(t, now)
	controller, err := NewController(owner, Config{RequestTimeout: time.Second}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.OpenSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := controller.current
	firstURL := openedURL(dependencies.BrowserOpener.(*openerStub))
	if first == nil || firstURL == "" {
		t.Fatal("first setup authority was not opened")
	}
	dependencies.Clock.(*clockStub).advance(time.Second)
	if err := controller.OpenSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := controller.current
	secondURL := openedURL(dependencies.BrowserOpener.(*openerStub))
	if second == nil || second == first || secondURL == firstURL {
		t.Fatalf("authority was reused: first=%p second=%p URLs equal=%t", first, second, firstURL == secondURL)
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("predecessor authority remained open")
	}
	if err := controller.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.Done():
	default:
		t.Fatal("current authority remained open")
	}
	if err := controller.OpenSetup(context.Background()); err == nil {
		t.Fatal("closed controller reopened")
	}
	if err := controller.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
}

func TestPF001SetupControllerRejectsInvalidLifecycleAndSanitizesOpenFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)
	valid := setupDependencies(t, now)
	cancelledOwner, cancelOwner := context.WithCancel(context.Background())
	cancelOwner()
	zeroClock := setupDependencies(t, now)
	zeroClock.Clock.(*clockStub).now = time.Time{}
	nilClock := valid
	nilClock.Clock = nil
	for _, input := range []struct {
		owner  context.Context
		config Config
		deps   Dependencies
	}{
		{owner: nil, deps: valid},
		{owner: cancelledOwner, deps: valid},
		{owner: context.Background(), config: Config{ExpiresAt: now.Add(time.Hour)}, deps: valid},
		{owner: context.Background(), deps: nilClock},
		{owner: context.Background(), deps: zeroClock},
	} {
		if controller, err := NewController(input.owner, input.config, input.deps); controller != nil || err == nil {
			t.Fatalf("invalid controller = %#v, %v", controller, err)
		}
	}

	owner, stopOwner := context.WithCancel(context.Background())
	controller, err := NewController(owner, Config{}, valid)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: lifecycle boundary fixture; owner=security expiry=2027-07-14.
	if err := controller.OpenSetup(nil); err == nil {
		t.Fatal("nil OpenSetup context accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.OpenSetup(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled OpenSetup error = %v", err)
	}
	stopOwner()
	if err := controller.OpenSetup(context.Background()); err == nil {
		t.Fatal("cancelled owner opened setup")
	}

	failing := setupDependencies(t, now)
	failing.BrowserOpener.(*openerStub).err = errors.New("raw browser detail")
	failingController, err := NewController(context.Background(), Config{}, failing)
	if err != nil {
		t.Fatal(err)
	}
	if err := failingController.OpenSetup(context.Background()); err == nil ||
		err.Error() != "setup authority could not be opened" {
		t.Fatalf("browser failure = %v", err)
	}

	clockFailure := setupDependencies(t, now)
	clockController, _ := NewController(context.Background(), Config{}, clockFailure)
	clockFailure.Clock.(*clockStub).now = time.Time{}
	if err := clockController.OpenSetup(context.Background()); err == nil {
		t.Fatal("zero authority clock accepted")
	}
	if err := clockController.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: lifecycle boundary fixture; owner=security expiry=2027-07-14.
	if err := clockController.Close(nil); err == nil {
		t.Fatal("nil Close context accepted")
	}
	var nilController *Controller
	if err := nilController.Close(context.Background()); err == nil {
		t.Fatal("nil controller Close accepted")
	}
}

func openedURL(opener *openerStub) string {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.url
}
