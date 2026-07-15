package runtimeprovision

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestPF006RootPrivilegeArtifactStoreMaterializesClosedTransaction(t *testing.T) {
	t.Parallel()
	_, authority, request, _ := privilegeCodecFixture(t)
	bindings := privilegeCodecArtifactStager(authority).bindings
	copier := &privilegeArtifactCopierStub{}
	store, err := newRootPrivilegeArtifactStore(copier)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := store.PreparePrivilegeArtifacts(t.Context(), request, bindings)
	wantRoot := filepath.Join(linuxPrivilegeTransactionRoot, request.Digest().String())
	paths := transaction.PackagePaths()
	if err != nil || transaction.Root() != wantRoot || len(transaction.Artifacts()) != len(bindings) ||
		len(paths) != len(authority.Packages()) || !slices.IsSorted(paths) || copier.calls != 1 ||
		copier.root != wantRoot || copier.uid != authority.InvokingUID() || copier.gid != authority.InvokingGID() {
		t.Fatalf(
			"root=%t artifacts=%d/%d packages=%d/%d sorted=%t calls=%d copy-root=%t uid=%d/%d gid=%d/%d error=%v",
			transaction.Root() == wantRoot, len(transaction.Artifacts()), len(bindings),
			len(paths), len(authority.Packages()), slices.IsSorted(paths), copier.calls, copier.root == wantRoot,
			copier.uid, authority.InvokingUID(), copier.gid, authority.InvokingGID(), err,
		)
	}
	first := transaction.Artifacts()[0]
	if first.ArtifactID() != bindings[0].ArtifactID() || first.SourcePath() != bindings[0].Path() ||
		first.TargetPath() != filepath.Join(
			wantRoot, bindings[0].ArtifactID()+"-"+bindings[0].SHA256().String()+".deb",
		) || first.SHA256() != bindings[0].SHA256() || first.Size() != bindings[0].Size() {
		t.Fatalf("first transaction artifact=%+v", first)
	}
	copyOf := transaction.Artifacts()
	copyOf[0] = PrivilegeTransactionArtifact{}
	if transaction.Artifacts()[0].ArtifactID() == "" {
		t.Fatal("transaction artifacts exposed mutable storage")
	}
}

func TestPF006RootPrivilegeArtifactStoreRejectsSubstitutionAndCopyFailure(t *testing.T) {
	t.Parallel()
	_, authority, request, _ := privilegeCodecFixture(t)
	bindings := privilegeCodecArtifactStager(authority).bindings
	copyFailure := errors.New("descriptor copy failed")
	for name, test := range map[string]struct {
		copier   privilegeArtifactCopier
		request  runtimeport.PrivilegeRequest
		bindings []PrivilegeArtifactBinding
		want     error
	}{
		"invalid request":   {copier: &privilegeArtifactCopierStub{}, bindings: bindings, want: runtimeport.ErrLinuxArtifactIntegrity},
		"missing artifacts": {copier: &privilegeArtifactCopierStub{}, request: request, want: runtimeport.ErrLinuxArtifactIntegrity},
		"copy failure":      {copier: &privilegeArtifactCopierStub{err: copyFailure}, request: request, bindings: bindings, want: runtimeport.ErrLinuxArtifactIntegrity},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := newRootPrivilegeArtifactStore(test.copier)
			if err != nil {
				t.Fatal(err)
			}
			if transaction, prepareError := store.PreparePrivilegeArtifacts(
				t.Context(), test.request, test.bindings,
			); !errors.Is(prepareError, test.want) || transaction.Root() != "" {
				t.Fatalf("transaction=%+v error=%v", transaction, prepareError)
			}
		})
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	store, _ := newRootPrivilegeArtifactStore(&privilegeArtifactCopierStub{})
	if _, err := store.PreparePrivilegeArtifacts(cancelled, request, bindings); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	if _, err := store.PreparePrivilegeArtifacts(hostileNilContext(), request, bindings); !errors.Is(err, runtimeport.ErrLinuxArtifactIntegrity) {
		t.Fatalf("nil context error=%v", err)
	}
	if candidate, err := newRootPrivilegeArtifactStore(nil); candidate != nil || err == nil {
		t.Fatal("nil copier accepted")
	}
}

type privilegeArtifactCopierStub struct {
	root  string
	uid   uint32
	gid   uint32
	calls int
	err   error
}

func (s *privilegeArtifactCopierStub) CopyPrivilegeArtifacts(
	_ context.Context,
	root string,
	uid uint32,
	gid uint32,
	_ []PrivilegeTransactionArtifact,
) error {
	s.calls++
	s.root, s.uid, s.gid = root, uid, gid
	return s.err
}
