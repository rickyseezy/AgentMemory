//go:build darwin && cgo

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestPF001DarwinNativeOwnerBindingIntegration(t *testing.T) {
	t.Parallel()
	source, err := NewDarwinOwnerBindingSource()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if owner.IsZero() {
		t.Fatal("native macOS owner binding is zero")
	}
}

func TestPF001DarwinNativeCapabilityBoundaryValidation(t *testing.T) {
	t.Parallel()
	if _, err := newDarwinKeychainCapability(""); err == nil {
		t.Fatal("empty native Keychain service was accepted")
	}
	capability, err := newDarwinKeychainCapability("io.agentmemory.native-boundary-test")
	if err != nil {
		t.Fatal(err)
	}
	keychain, ok := capability.(*darwinNativeKeychain)
	if !ok {
		t.Fatal("native Keychain capability has an unexpected implementation")
	}
	if _, err := NewDarwinKeychainOperationKeySource(darwinOwnerSourceStub{}); err != nil {
		t.Fatalf("compose native Keychain source: %v", err)
	}
	if err := keychain.Add(context.Background(), "", nil); err == nil {
		t.Fatal("empty native Keychain add was accepted")
	}
	if _, err := keychain.Get(context.Background(), ""); err == nil {
		t.Fatal("empty native Keychain get was accepted")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	identity := darwinNativeIdentity{}
	if _, err := identity.PlatformUUID(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled platform UUID lookup error = %v", err)
	}
	if _, err := identity.UserUUID(cancelled, 501); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled user UUID lookup error = %v", err)
	}
	if _, err := identity.UserUUID(context.Background(), -1); err == nil {
		t.Fatal("negative native UID was accepted")
	}
	if err := keychain.Add(cancelled, "account", []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Keychain add error = %v", err)
	}
	if _, err := keychain.Get(cancelled, "account"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Keychain get error = %v", err)
	}
	if err := keychain.delete(cancelled, "account"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Keychain delete error = %v", err)
	}
	if got := cStringFromBuffer([]byte{'a', 0, 'b'}); got != "a" {
		t.Fatalf("terminated C buffer = %q", got)
	}
	if got := cStringFromBuffer([]byte{'a', 'b'}); got != "ab" {
		t.Fatalf("unterminated C buffer = %q", got)
	}

	if err := mapDarwinKeychainStatusCode("test", darwinKeychainStatusSuccess); err != nil {
		t.Fatalf("success status = %v", err)
	}
	if err := mapDarwinKeychainStatusCode("test", darwinKeychainStatusDuplicate); !errors.Is(err, errDarwinKeychainDuplicate) {
		t.Fatalf("duplicate status = %v", err)
	}
	if err := mapDarwinKeychainStatusCode("test", darwinKeychainStatusNotFound); !errors.Is(err, errDarwinKeychainNotFound) {
		t.Fatalf("not-found status = %v", err)
	}
	if err := mapDarwinKeychainStatusCode("test", -1); err == nil {
		t.Fatal("unexpected native Keychain status was accepted")
	}
}

func TestPF001DarwinNativeKeychainIntegration(t *testing.T) {
	if os.Getenv("AGENTMEMORY_KEYCHAIN_INTEGRATION") != "1" {
		t.Skip("requires a signed test host with the production application identifier/keychain-access-group entitlement and an unlocked user Data Protection Keychain")
	}
	service := fmt.Sprintf("io.agentmemory.bootstrap-hmac.integration.%d.%d", os.Getpid(), time.Now().UnixNano())
	capability, err := newDarwinKeychainCapability(service)
	if err != nil {
		t.Fatal(err)
	}
	keychain, ok := capability.(*darwinNativeKeychain)
	if !ok {
		t.Fatal("native Keychain capability has an unexpected implementation")
	}
	account := "sha256-84e6ef42a43dc5b7d2ffbcf9a910b7e143af5bbaff24da81207bb242a571f6a8"
	record := bytes.Repeat([]byte{0xa7}, darwinKeyRecordSize)
	t.Cleanup(func() {
		deleteError := keychain.delete(context.Background(), account)
		if deleteError != nil && !errors.Is(deleteError, errDarwinKeychainNotFound) {
			t.Errorf("remove Keychain integration fixture: %v", deleteError)
		}
	})
	if err := keychain.Add(context.Background(), account, record); err != nil {
		t.Fatalf("add prompt-free Data Protection Keychain record: %v", err)
	}
	loaded, err := keychain.Get(context.Background(), account)
	if err != nil {
		t.Fatalf("read prompt-free Data Protection Keychain record: %v", err)
	}
	defer clear(loaded)
	if !bytes.Equal(loaded, record) {
		t.Fatal("native Keychain changed the integration record")
	}
}
