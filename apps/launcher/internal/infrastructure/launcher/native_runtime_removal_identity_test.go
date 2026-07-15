package launcher

import (
	"strings"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001ManagedRuntimeRemovalIdentityIsDistinctDeterministicRFC9562UUIDv7(t *testing.T) {
	t.Parallel()
	source, _ := install.NewOperationID("019f60a0-1111-7abc-8123-0123456789ab")
	first, err := deriveManagedRuntimeRemovalOperationID(source)
	if err != nil || first.IsZero() || first == source {
		t.Fatalf("derive()=%s,%v", first.String(), err)
	}
	second, err := deriveManagedRuntimeRemovalOperationID(source)
	if err != nil || second != first {
		t.Fatalf("replay=%s,%v first=%s", second.String(), err, first.String())
	}
	value := first.String()
	if len(value) != 36 || value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) ||
		value[:13] != source.String()[:13] {
		t.Fatalf("derived identity is not timestamp-bound UUIDv7: %q", value)
	}
	foreign, _ := install.NewOperationID("019f60a0-1111-7abc-8123-0123456789ac")
	other, err := deriveManagedRuntimeRemovalOperationID(foreign)
	if err != nil || other == first {
		t.Fatalf("foreign derive()=%s,%v first=%s", other.String(), err, first.String())
	}
}

func TestPF001ManagedRuntimeRemovalIdentityRejectsNonUUIDv7Sources(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"opaque", "019f60a0-1111-6abc-8123-0123456789ab", "019f60a0-1111-7abc-7123-0123456789ab"} {
		source, _ := install.NewOperationID(value)
		if result, err := deriveManagedRuntimeRemovalOperationID(source); !result.IsZero() || err == nil {
			t.Fatalf("derive(%q)=%s,%v", value, result.String(), err)
		}
	}
	if result, err := deriveManagedRuntimeRemovalOperationID(install.OperationID{}); !result.IsZero() || err == nil {
		t.Fatalf("zero derive()=%s,%v", result.String(), err)
	}
}
