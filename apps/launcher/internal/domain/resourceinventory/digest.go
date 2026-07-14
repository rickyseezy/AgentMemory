package resourceinventory

import (
	"encoding/binary"
	"sort"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// Digest returns a deterministic complete binding for activation and runtime
// agreement. It includes pending intents; only the caller decides whether the
// inventory is complete enough for its phase.
func (i *Inventory) Digest() (install.Digest, error) {
	if i == nil {
		return install.Digest{}, ErrInventoryIntegrity
	}
	return DigestSnapshot(i.Snapshot())
}

// DigestSnapshot validates and hashes the canonical aggregate projection.
func DigestSnapshot(snapshot Snapshot) (install.Digest, error) {
	inventory, err := Restore(snapshot)
	if err != nil {
		return install.Digest{}, ErrInventoryIntegrity
	}
	verified := inventory.Snapshot()
	canonical := resourceAppendField(nil, "agentmemory.resource-inventory.v1")
	canonical = resourceAppendField(canonical, verified.InstallationID)
	canonical = resourceAppendUint64(canonical, verified.Version)
	canonical = resourceAppendUint64(canonical, uint64(len(verified.Entries)))
	for _, entry := range verified.Entries {
		canonical = resourceAppendField(canonical, entry.Kind)
		canonical = resourceAppendField(canonical, entry.Purpose)
		canonical = resourceAppendField(canonical, entry.Name)
		canonical = resourceAppendField(canonical, entry.CreationOperation)
		canonical = resourceAppendField(canonical, entry.State)
		canonical = resourceAppendField(canonical, entry.ObjectID)
		keys := make([]string, 0, len(entry.Labels))
		for key := range entry.Labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		canonical = resourceAppendUint64(canonical, uint64(len(keys)))
		for _, key := range keys {
			canonical = resourceAppendField(canonical, key)
			canonical = resourceAppendField(canonical, entry.Labels[key])
		}
	}
	return install.DigestBytes(canonical), nil
}

func resourceAppendField(output []byte, value string) []byte {
	output = resourceAppendUint64(output, uint64(len(value)))
	return append(output, value...)
}

func resourceAppendUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}
