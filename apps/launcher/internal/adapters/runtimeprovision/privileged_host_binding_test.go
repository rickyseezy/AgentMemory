package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006PrivilegedLinuxHostBindingReconstructsOnlyProtectedOriginalPrincipal(t *testing.T) {
	t.Parallel()
	identity := &privilegedLinuxIdentitySourceStub{identity: privilegedLinuxIdentity{
		uid: 1000, gid: 1000, account: "agentmemory", home: "/home/agentmemory",
	}}
	machine := &privilegedLinuxMachineSourceStub{
		version: "24.04", digest: runtimeinstall.Sum([]byte("machine")),
	}
	provider, err := newPrivilegedLinuxHostBindingProvider(identity, machine)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := provider.CurrentLinuxHostBinding(t.Context())
	if err != nil || binding.InvokingUID() != 1000 || binding.InvokingGID() != 1000 ||
		binding.AccountName() != "agentmemory" || binding.PrincipalID() != "linux:uid:1000" ||
		binding.HomeDirectory() != "/home/agentmemory" || binding.RuntimeDirectory() != "/run/user/1000" ||
		binding.Endpoint() != "unix:///run/user/1000/docker.sock" || identity.calls != 1 || machine.calls != 1 {
		t.Fatalf("binding=%+v error=%v identity=%d machine=%d", binding, err, identity.calls, machine.calls)
	}
}

func TestPF006PrivilegedLinuxHostBindingFailsClosedAtEachProtectedFact(t *testing.T) {
	t.Parallel()
	for name, configure := range map[string]func(*privilegedLinuxIdentitySourceStub, *privilegedLinuxMachineSourceStub){
		"identity error": func(identity *privilegedLinuxIdentitySourceStub, _ *privilegedLinuxMachineSourceStub) {
			identity.err = errors.New("identity failed")
		},
		"machine error": func(_ *privilegedLinuxIdentitySourceStub, machine *privilegedLinuxMachineSourceStub) {
			machine.err = errors.New("machine failed")
		},
		"root uid": func(identity *privilegedLinuxIdentitySourceStub, _ *privilegedLinuxMachineSourceStub) {
			identity.identity.uid = 0
		},
		"zero gid": func(identity *privilegedLinuxIdentitySourceStub, _ *privilegedLinuxMachineSourceStub) {
			identity.identity.gid = 0
		},
		"unsafe account": func(identity *privilegedLinuxIdentitySourceStub, _ *privilegedLinuxMachineSourceStub) {
			identity.identity.account = "unsafe account"
		},
		"relative home": func(identity *privilegedLinuxIdentitySourceStub, _ *privilegedLinuxMachineSourceStub) {
			identity.identity.home = "relative"
		},
		"missing version": func(_ *privilegedLinuxIdentitySourceStub, machine *privilegedLinuxMachineSourceStub) {
			machine.version = ""
		},
		"missing machine": func(_ *privilegedLinuxIdentitySourceStub, machine *privilegedLinuxMachineSourceStub) {
			machine.digest = runtimeinstall.Hash{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			identity := &privilegedLinuxIdentitySourceStub{identity: privilegedLinuxIdentity{
				uid: 1000, gid: 1000, account: "agentmemory", home: "/home/agentmemory",
			}}
			machine := &privilegedLinuxMachineSourceStub{
				version: "24.04", digest: runtimeinstall.Sum([]byte("machine")),
			}
			configure(identity, machine)
			provider, err := newPrivilegedLinuxHostBindingProvider(identity, machine)
			if err != nil {
				t.Fatal(err)
			}
			if binding, bindingError := provider.CurrentLinuxHostBinding(t.Context()); !errors.Is(bindingError, ErrUnsupportedHost) || binding.InvokingUID() != 0 {
				t.Fatalf("binding=%+v error=%v", binding, bindingError)
			}
		})
	}
	if provider, err := newPrivilegedLinuxHostBindingProvider(nil, &privilegedLinuxMachineSourceStub{}); provider != nil || err == nil {
		t.Fatal("missing identity source accepted")
	}
	if provider, err := newPrivilegedLinuxHostBindingProvider(&privilegedLinuxIdentitySourceStub{}, nil); provider != nil || err == nil {
		t.Fatal("missing machine source accepted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	provider, _ := newPrivilegedLinuxHostBindingProvider(
		&privilegedLinuxIdentitySourceStub{}, &privilegedLinuxMachineSourceStub{},
	)
	if _, err := provider.CurrentLinuxHostBinding(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

type privilegedLinuxIdentitySourceStub struct {
	identity privilegedLinuxIdentity
	err      error
	calls    int
}

func (s *privilegedLinuxIdentitySourceStub) CurrentPrivilegedLinuxIdentity(
	context.Context,
) (privilegedLinuxIdentity, error) {
	s.calls++
	return s.identity, s.err
}

type privilegedLinuxMachineSourceStub struct {
	version string
	digest  runtimeinstall.Hash
	err     error
	calls   int
}

func (s *privilegedLinuxMachineSourceStub) CurrentPrivilegedLinuxMachine(
	context.Context,
) (string, runtimeinstall.Hash, error) {
	s.calls++
	return s.version, s.digest, s.err
}
