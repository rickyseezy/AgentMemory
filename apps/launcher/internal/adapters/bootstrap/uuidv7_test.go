package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"regexp"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestPF001UUIDv7GeneratorProducesCanonicalTimeOrderedIdentifiers(t *testing.T) {
	t.Parallel()
	instant := time.Date(2026, time.July, 13, 10, 11, 12, 345_000_000, time.UTC)
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x21}, 40))
	generator, err := NewUUIDv7GeneratorWithEntropy(fixedGeneratorClock{now: instant}, entropy)
	if err != nil {
		t.Fatal(err)
	}
	first, err := generator.NewOperationID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := generator.NewOperationID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(first.String()) || !pattern.MatchString(second.String()) || first.String() >= second.String() {
		t.Fatalf("UUIDv7 ordering/canonical form = %q, %q", first.String(), second.String())
	}
	timestampHex := first.String()[0:8] + first.String()[9:13]
	decoded, decodeError := hex.DecodeString(timestampHex)
	if decodeError != nil {
		t.Fatal(decodeError)
	}
	var timestamp uint64
	for _, value := range decoded {
		timestamp = timestamp<<8 | uint64(value)
	}
	if timestamp != uint64(instant.UnixMilli()) {
		t.Fatalf("UUID timestamp = %d, want %d", timestamp, instant.UnixMilli())
	}
}

func TestPF001UUIDv7GeneratorIsUniqueUnderConcurrencyAndClockRollback(t *testing.T) {
	t.Parallel()
	clock := &mutableGeneratorClock{now: time.Date(2026, time.July, 13, 0, 0, 0, 0, time.UTC)}
	generator, err := NewUUIDv7Generator(clock)
	if err != nil {
		t.Fatal(err)
	}
	const count = 256
	results := make(chan string, count)
	var waitGroup sync.WaitGroup
	for index := 0; index < count; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			operationID, generateError := generator.NewOperationID(context.Background())
			if generateError != nil {
				results <- "error:" + generateError.Error()
				return
			}
			results <- operationID.String()
		}()
	}
	waitGroup.Wait()
	close(results)
	identities := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for identity := range results {
		if stringsHasPrefix(identity, "error:") {
			t.Fatal(identity)
		}
		if _, exists := seen[identity]; exists {
			t.Fatalf("duplicate operation identity %s", identity)
		}
		seen[identity] = struct{}{}
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	clock.Set(clock.Now().Add(-time.Hour))
	afterRollback, err := generator.NewOperationID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if afterRollback.String() <= identities[len(identities)-1] {
		t.Fatal("wall-clock rollback moved UUIDv7 identity backward")
	}
}

func TestPF001UUIDv7GeneratorRejectsInvalidDependenciesAndExhaustion(t *testing.T) {
	t.Parallel()
	if _, err := NewUUIDv7GeneratorWithEntropy(nil, bytes.NewReader(make([]byte, 32))); err == nil {
		t.Fatal("nil clock was accepted")
	}
	clock := fixedGeneratorClock{now: time.UnixMilli(1)}
	if _, err := NewUUIDv7GeneratorWithEntropy(clock, nil); err == nil {
		t.Fatal("nil entropy was accepted")
	}
	exhaustedRandom := bytes.Repeat([]byte{0xff}, 10)
	exhaustedRandom[0] = 0x0f
	exhaustedRandom[2] = 0x3f
	entropy := bytes.NewReader(exhaustedRandom)
	generator, err := NewUUIDv7GeneratorWithEntropy(clock, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generator.NewOperationID(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := generator.NewOperationID(context.Background()); err == nil {
		t.Fatal("same-millisecond UUIDv7 random-space exhaustion was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := generator.NewOperationID(cancelled); err == nil {
		t.Fatal("cancelled generation was accepted")
	}
}

func TestPF001UUIDv7GeneratorRejectsInvalidClockAndEntropyFailure(t *testing.T) {
	t.Parallel()
	negativeClock := fixedGeneratorClock{now: time.UnixMilli(-1)}
	generator, err := NewUUIDv7GeneratorWithEntropy(negativeClock, bytes.NewReader(make([]byte, 10)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generator.NewOperationID(context.Background()); err == nil {
		t.Fatal("negative UUIDv7 timestamp was accepted")
	}
	shortEntropy, _ := NewUUIDv7GeneratorWithEntropy(
		fixedGeneratorClock{now: time.UnixMilli(1)},
		bytes.NewReader([]byte{1}),
	)
	if _, err := shortEntropy.NewOperationID(context.Background()); err == nil {
		t.Fatal("short UUIDv7 entropy was accepted")
	}
}

type fixedGeneratorClock struct{ now time.Time }

func (c fixedGeneratorClock) Now() time.Time { return c.now }

type mutableGeneratorClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableGeneratorClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableGeneratorClock) Set(value time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = value
}

func stringsHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
