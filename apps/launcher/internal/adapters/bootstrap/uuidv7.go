package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"

	bootstrapport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/installbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const maxUUIDv7Timestamp = uint64(1<<48 - 1)

// UUIDv7Clock supplies UTC wall time without ambient time in tests.
type UUIDv7Clock interface {
	Now() time.Time
}

// UUIDv7Generator creates RFC 9562 UUIDv7 identities and keeps the 12-bit
// rand_a field monotonic within one observed millisecond.
type UUIDv7Generator struct {
	clock       UUIDv7Clock
	entropy     io.Reader
	mu          sync.Mutex
	initialized bool
	lastMillis  uint64
	random      [10]byte
}

var _ bootstrapport.OperationIDGenerator = (*UUIDv7Generator)(nil)

// NewUUIDv7Generator creates a production generator backed by crypto/rand.
func NewUUIDv7Generator(clock UUIDv7Clock) (*UUIDv7Generator, error) {
	return NewUUIDv7GeneratorWithEntropy(clock, rand.Reader)
}

// NewUUIDv7GeneratorWithEntropy creates an injectable generator for tests.
func NewUUIDv7GeneratorWithEntropy(clock UUIDv7Clock, entropy io.Reader) (*UUIDv7Generator, error) {
	if nilDependency(clock) {
		return nil, errors.New("UUIDv7 clock is required")
	}
	if nilDependency(entropy) {
		return nil, errors.New("UUIDv7 entropy source is required")
	}
	return &UUIDv7Generator{clock: clock, entropy: entropy}, nil
}

// NewOperationID creates one canonical lower-case UUIDv7 operation ID.
func (g *UUIDv7Generator) NewOperationID(ctx context.Context) (install.OperationID, error) {
	if err := ctx.Err(); err != nil {
		return install.OperationID{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	nowMillis := g.clock.Now().UTC().UnixMilli()
	if nowMillis < 0 || uint64(nowMillis) > maxUUIDv7Timestamp {
		return install.OperationID{}, errors.New("UUIDv7 clock is outside its 48-bit range")
	}
	milliseconds := uint64(nowMillis)
	switch {
	case !g.initialized || milliseconds > g.lastMillis:
		if _, err := io.ReadFull(g.entropy, g.random[:]); err != nil {
			return install.OperationID{}, errors.New("read UUIDv7 entropy")
		}
		g.initialized = true
		g.lastMillis = milliseconds
		g.random[0] &= 0x0f
		g.random[2] &= 0x3f
	default:
		milliseconds = g.lastMillis
		if !incrementUUIDv7Random(&g.random) {
			return install.OperationID{}, errors.New("UUIDv7 same-millisecond random space exhausted")
		}
	}

	var encoded [16]byte
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], milliseconds)
	copy(encoded[:6], timestamp[2:])
	encoded[6] = 0x70 | g.random[0]
	encoded[7] = g.random[1]
	encoded[8] = 0x80 | g.random[2]
	copy(encoded[9:], g.random[3:])

	hexadecimal := hex.EncodeToString(encoded[:])
	value := hexadecimal[0:8] + "-" + hexadecimal[8:12] + "-" + hexadecimal[12:16] + "-" +
		hexadecimal[16:20] + "-" + hexadecimal[20:32]
	return install.NewOperationID(value)
}

// NewSessionID reuses the same cryptographic, monotonic RFC 9562 generator for PF-005 sessions.
func (g *UUIDv7Generator) NewSessionID(ctx context.Context) (string, error) {
	operationID, err := g.NewOperationID(ctx)
	if err != nil {
		return "", err
	}
	return operationID.String(), nil
}

func incrementUUIDv7Random(random *[10]byte) bool {
	for index := len(random) - 1; index >= 0; index-- {
		maximum := byte(0xff)
		switch index {
		case 0:
			maximum = 0x0f
		case 2:
			maximum = 0x3f
		}
		if random[index] < maximum {
			random[index]++
			return true
		}
		random[index] = 0
	}
	return false
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32,
		reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.String, reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return false
}
