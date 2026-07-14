package releaseverifyadapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestSHA256ResourceDigestVerifierChecksBytesAndDeclaredLength(t *testing.T) {
	t.Parallel()

	content := []byte("verified release bytes")
	resource := digestResource(t, content)
	tests := []struct {
		name    string
		content []byte
		wantErr error
	}{
		{name: "exact", content: content},
		{name: "same length tamper", content: []byte("tampered release bytes"), wantErr: application.ErrResourceDigestMismatch},
		{name: "short", content: content[:len(content)-1], wantErr: application.ErrResourceDigestMismatch},
		{name: "long", content: append(append([]byte(nil), content...), '!'), wantErr: application.ErrResourceDigestMismatch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := NewSHA256ResourceDigestVerifier(contentSourceStub{content: test.content})
			if err != nil {
				t.Fatalf("NewSHA256ResourceDigestVerifier() error = %v", err)
			}
			err = verifier.VerifyResourceDigest(context.Background(), resource)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("VerifyResourceDigest() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestSHA256ResourceDigestVerifierMapsSourceReadCloseAndContextFailures(t *testing.T) {
	t.Parallel()

	resource := digestResource(t, []byte("content"))
	tests := []struct {
		name   string
		source ResourceContentSource
		ctx    func() context.Context
		want   error
	}{
		{name: "source", source: contentSourceStub{openError: errors.New("private source")}, ctx: context.Background, want: application.ErrResourceUnavailable},
		{name: "typed nil reader", source: contentSourceStub{reader: (*failingReadCloser)(nil)}, ctx: context.Background, want: application.ErrResourceUnavailable},
		{name: "read", source: contentSourceStub{reader: &failingReadCloser{readError: errors.New("private read")}}, ctx: context.Background, want: application.ErrResourceUnavailable},
		{name: "no read progress", source: contentSourceStub{reader: noProgressReadCloser{}}, ctx: context.Background, want: application.ErrResourceUnavailable},
		{name: "close", source: contentSourceStub{reader: &failingReadCloser{content: []byte("content"), closeError: errors.New("private close")}}, ctx: context.Background, want: application.ErrResourceUnavailable},
		{
			name:   "cancelled",
			source: contentSourceStub{content: []byte("content")},
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			want: context.Canceled,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := NewSHA256ResourceDigestVerifier(test.source)
			if err != nil {
				t.Fatalf("NewSHA256ResourceDigestVerifier() error = %v", err)
			}
			if err := verifier.VerifyResourceDigest(test.ctx(), resource); !errors.Is(err, test.want) {
				t.Fatalf("VerifyResourceDigest() error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := NewSHA256ResourceDigestVerifier(nil); err == nil {
		t.Fatal("NewSHA256ResourceDigestVerifier() accepted nil source")
	}
	ctx, cancel := context.WithCancel(context.Background())
	verifier, err := NewSHA256ResourceDigestVerifier(contentSourceStub{
		reader: &cancelOnReadCloser{cancel: cancel},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyResourceDigest(ctx, resource); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-stream cancellation error = %v, want context.Canceled", err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves release digest verification fails closed.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := verifier.VerifyResourceDigest(nil, resource); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("nil context error = %v, want ErrDependencyUnavailable", err)
	}
}

type contentSourceStub struct {
	content   []byte
	reader    io.ReadCloser
	openError error
}

func (s contentSourceStub) OpenResource(
	context.Context,
	releaseinventory.Resource,
) (io.ReadCloser, error) {
	if s.openError != nil {
		return nil, s.openError
	}
	if s.reader != nil {
		return s.reader, nil
	}
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

type failingReadCloser struct {
	content    []byte
	read       bool
	readError  error
	closeError error
}

func (r *failingReadCloser) Read(target []byte) (int, error) {
	if r.readError != nil {
		return 0, r.readError
	}
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	return copy(target, r.content), nil
}

func (r *failingReadCloser) Close() error { return r.closeError }

type noProgressReadCloser struct{}

func (noProgressReadCloser) Read([]byte) (int, error) { return 0, nil }

func (noProgressReadCloser) Close() error { return nil }

type cancelOnReadCloser struct {
	cancel context.CancelFunc
}

func (r *cancelOnReadCloser) Read([]byte) (int, error) {
	r.cancel()
	return 0, nil
}

func (*cancelOnReadCloser) Close() error { return nil }

func digestResource(t *testing.T, content []byte) releaseinventory.Resource {
	t.Helper()
	resource, err := releaseinventory.NewResource(releaseinventory.ResourceInput{
		ID: "cyclonedx", Kind: releaseinventory.ResourceKindCycloneDXSBOM,
		Purpose:   releaseinventory.ResourcePurposeCycloneDXSBOM,
		MediaType: releaseinventory.MediaTypeCycloneDX,
		Digest:    releaseinventory.DigestBytes(content), Size: uint64(len(content)),
		SourceRef: "bundle://cyclonedx", SourceAllowlist: []string{"bundle://cyclonedx"},
		SubjectResourceID: "launcher", SubjectDigest: releaseinventory.DigestBytes([]byte("launcher")),
	})
	if err != nil {
		t.Fatalf("NewResource() error = %v", err)
	}
	return resource
}
