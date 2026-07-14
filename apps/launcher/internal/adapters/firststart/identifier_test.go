package firststart

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
)

func TestPF001NativeIdentifierGeneratorCreatesExactRFC9562UUIDv7(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 12, 34, 56, 789_000_000, time.UTC)
	entropy := byte(0)
	generator, err := newNativeIdentifierGenerator(identifierDependencies{
		now: func() time.Time { return now },
		read: func(value []byte) (int, error) {
			for index := range value {
				value[index] = entropy + byte(index)
			}
			entropy++
			return len(value), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := generator.NewOperationID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := generator.NewOperationID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first.String()[14] != '7' || strings.IndexByte("89ab", first.String()[19]) < 0 {
		t.Fatalf("identifiers=%s,%s", first, second)
	}
	wantPrefix := uint64(now.UnixMilli())
	if parsedUUIDv7Milliseconds(t, first.String()) != wantPrefix {
		t.Fatalf("timestamp=%d want=%d", parsedUUIDv7Milliseconds(t, first.String()), wantPrefix)
	}
}

func TestPF001NativeIdentifierGeneratorFailsClosedAtEveryAuthorityBoundary(t *testing.T) {
	t.Parallel()
	for _, dependencies := range []identifierDependencies{
		{},
		{now: time.Now},
		{read: func(value []byte) (int, error) { return len(value), nil }},
	} {
		if generator, err := newNativeIdentifierGenerator(dependencies); generator != nil ||
			!errors.Is(err, firststartapp.ErrIntegrity) {
			t.Fatalf("generator=%v error=%v", generator, err)
		}
	}
	var absent *NativeIdentifierGenerator
	if _, err := absent.NewOperationID(t.Context()); !errors.Is(err, firststartapp.ErrIntegrity) {
		t.Fatalf("nil generator error=%v", err)
	}
	generator := NewNativeIdentifierGenerator()
	//lint:ignore SA1012 Deliberate absent-context boundary test.
	if _, err := generator.NewOperationID(nil); !errors.Is(err, firststartapp.ErrIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := generator.NewOperationID(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	for _, test := range []struct {
		name string
		deps identifierDependencies
	}{
		{name: "pre epoch", deps: identifierDependencies{now: func() time.Time { return time.Unix(-1, 0) }, read: fullEntropy}},
		{name: "timestamp overflow", deps: identifierDependencies{now: func() time.Time { return time.UnixMilli(1 << 48) }, read: fullEntropy}},
		{name: "entropy error", deps: identifierDependencies{now: time.Now, read: func([]byte) (int, error) { return 0, errors.New("private") }}},
		{name: "short entropy", deps: identifierDependencies{now: time.Now, read: func([]byte) (int, error) { return 15, nil }}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := newNativeIdentifierGenerator(test.deps)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = candidate.NewOperationID(t.Context()); !errors.Is(err, firststartapp.ErrUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func fullEntropy(value []byte) (int, error) {
	for index := range value {
		value[index] = byte(index)
	}
	return len(value), nil
}

func parsedUUIDv7Milliseconds(t *testing.T, value string) uint64 {
	t.Helper()
	var milliseconds uint64
	if _, err := fmt.Sscanf(strings.ReplaceAll(value[:13], "-", ""), "%x", &milliseconds); err != nil {
		t.Fatal(err)
	}
	return milliseconds
}
