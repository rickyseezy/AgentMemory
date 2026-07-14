package firststart

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const maximumUUIDv7UnixMilliseconds = uint64(1<<48 - 1)

type identifierDependencies struct {
	now  func() time.Time
	read func([]byte) (int, error)
}

// NativeIdentifierGenerator creates cryptographically random RFC 9562 UUIDv7
// identities. The first-start preparation journal makes the generated values
// durable before any plan or operation can be published.
type NativeIdentifierGenerator struct{ dependencies identifierDependencies }

// NewNativeIdentifierGenerator binds the production wall clock and operating
// system CSPRNG. No identifier input is accepted from MCP or the environment.
func NewNativeIdentifierGenerator() *NativeIdentifierGenerator {
	return &NativeIdentifierGenerator{identifierDependencies{now: time.Now, read: rand.Read}}
}

func newNativeIdentifierGenerator(dependencies identifierDependencies) (*NativeIdentifierGenerator, error) {
	if dependencies.now == nil || dependencies.read == nil {
		return nil, firststartapp.ErrIntegrity
	}
	return &NativeIdentifierGenerator{dependencies: dependencies}, nil
}

// NewOperationID returns one UUIDv7 with a 48-bit Unix-millisecond timestamp,
// the version-7 nibble, RFC 4122 variant bits, and 74 CSPRNG-provided bits.
func (g *NativeIdentifierGenerator) NewOperationID(ctx context.Context) (install.OperationID, error) {
	if g == nil || ctx == nil || g.dependencies.now == nil || g.dependencies.read == nil {
		return install.OperationID{}, firststartapp.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return install.OperationID{}, err
	}
	now := g.dependencies.now().UTC()
	if now.Before(time.Unix(0, 0)) {
		return install.OperationID{}, firststartapp.ErrUnavailable
	}
	milliseconds := uint64(now.UnixMilli())
	if milliseconds > maximumUUIDv7UnixMilliseconds {
		return install.OperationID{}, firststartapp.ErrUnavailable
	}
	var value [16]byte
	if count, err := g.dependencies.read(value[:]); err != nil || count != len(value) {
		return install.OperationID{}, firststartapp.ErrUnavailable
	}
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], milliseconds)
	copy(value[0:6], timestamp[2:])
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	encoded := fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(value[0:4]),
		binary.BigEndian.Uint16(value[4:6]),
		binary.BigEndian.Uint16(value[6:8]),
		binary.BigEndian.Uint16(value[8:10]),
		value[10:16],
	)
	identifier, err := install.NewOperationID(encoded)
	if err != nil {
		return install.OperationID{}, errors.Join(firststartapp.ErrIntegrity, err)
	}
	return identifier, nil
}

var _ firststartapp.IdentifierGenerator = (*NativeIdentifierGenerator)(nil)
