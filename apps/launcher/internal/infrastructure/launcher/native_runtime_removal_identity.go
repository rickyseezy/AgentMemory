package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const managedRuntimeRemovalIdentityDomain = "agentmemory.managed-runtime-removal-operation.v1\x00"

// deriveManagedRuntimeRemovalOperationID provides a restart-stable distinct
// UUIDv7 namespace for the child destructive saga. It retains only the
// authenticated source operation timestamp; all random fields are replaced
// by a purpose-separated SHA-256 derivation and the RFC 9562 version/variant.
func deriveManagedRuntimeRemovalOperationID(source install.OperationID) (install.OperationID, error) {
	value := source.String()
	if source.IsZero() || len(value) != 36 || value != strings.ToLower(value) ||
		value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return install.OperationID{}, errors.New("managed runtime removal source identity is invalid")
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(raw) != 16 || raw[6]>>4 != 7 || raw[8]>>6 != 2 {
		return install.OperationID{}, errors.New("managed runtime removal source identity is not UUIDv7")
	}
	digest := sha256.Sum256([]byte(managedRuntimeRemovalIdentityDomain + value))
	copy(raw[6:], digest[:10])
	raw[6] = (raw[6] & 0x0f) | 0x70
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	derived := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:]
	operationID, err := install.NewOperationID(derived)
	if err != nil || operationID == source {
		return install.OperationID{}, errors.New("managed runtime removal identity derivation failed")
	}
	return operationID, nil
}
