package installplanfs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/activereleaseapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/readinessapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

const (
	readinessEnvelopeSchema = uint16(1)
	readinessKeyBytes       = 32
	maximumReadinessBytes   = 128 * 1024
)

var errReadinessRepositoryIntegrity = errors.New("readiness receipt repository integrity violation")

// ReadinessKeySource reads the purpose-separated installation root key from a
// protected native file. Implementations return caller-owned bytes.
type ReadinessKeySource interface {
	ReadCredential(context.Context, string) ([]byte, error)
}

// ReadinessRepository stores authenticated immutable receipt envelopes in an
// owner-only descriptor/handle-rooted directory.
type ReadinessRepository struct {
	mu      sync.RWMutex
	store   platformStore
	keyPath string
	keys    ReadinessKeySource
}

// NewReadinessRepository opens one explicit owner-only receipt root and binds
// it to the exact protected installation root-key reference.
func NewReadinessRepository(
	ctx context.Context,
	root string,
	keyPath string,
	keys ReadinessKeySource,
) (*ReadinessRepository, error) {
	if ctx == nil || strings.TrimSpace(root) == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		strings.IndexByte(root, 0) >= 0 || strings.TrimSpace(keyPath) == "" ||
		strings.IndexByte(keyPath, 0) >= 0 || nilReadinessCapability(keys) {
		return nil, errReadinessRepositoryIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := openPlatformStore(ctx, root)
	if err != nil {
		return nil, errReadinessRepositoryIntegrity
	}
	return &ReadinessRepository{store: store, keyPath: keyPath, keys: keys}, nil
}

// SaveReadinessReceipt authenticates and durably publishes one receipt. Exact
// replay is idempotent; contradictory immutable content is a conflict.
func (r *ReadinessRepository) SaveReadinessReceipt(ctx context.Context, receipt readiness.Receipt) error {
	if r == nil || ctx == nil || receipt.IsZero() {
		return errReadinessRepositoryIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical, err := r.encode(ctx, receipt)
	if err != nil {
		return errReadinessRepositoryIntegrity
	}
	defer clear(canonical)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.store == nil {
		return errReadinessRepositoryIntegrity
	}
	if err := r.store.save(ctx, readinessFilename(receipt.Digest()), canonical); err != nil {
		if errors.Is(err, errImmutableConflict) {
			return readinessapp.ErrReceiptConflict
		}
		return errReadinessRepositoryIntegrity
	}
	return nil
}

// LoadReadinessReceipt verifies native file shape, canonical envelope bytes,
// HMAC, domain receipt digest, and requested filename binding.
func (r *ReadinessRepository) LoadReadinessReceipt(
	ctx context.Context,
	digest install.Digest,
) (readiness.Receipt, error) {
	if r == nil || ctx == nil || digest.IsZero() {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	if err := ctx.Err(); err != nil {
		return readiness.Receipt{}, err
	}
	r.mu.RLock()
	if r.store == nil {
		r.mu.RUnlock()
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	raw, err := r.store.load(ctx, readinessFilename(digest))
	r.mu.RUnlock()
	if err != nil {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	defer clear(raw)
	receipt, err := r.decode(ctx, raw)
	if err != nil || !receipt.Digest().Equal(digest) {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	return receipt, nil
}

// Close releases retained native directory handles idempotently.
func (r *ReadinessRepository) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store == nil {
		return nil
	}
	err := r.store.close()
	r.store = nil
	return err
}

type readinessEnvelope struct {
	SchemaVersion     uint16                 `json:"schema_version"`
	Receipt           canonicalReceiptRecord `json:"receipt"`
	AuthenticationTag string                 `json:"authentication_tag"`
}

type canonicalReceiptRecord struct {
	SchemaVersion  uint16                  `json:"schema_version"`
	OperationID    string                  `json:"operation_id"`
	PlanDigest     string                  `json:"plan_digest"`
	ReleaseID      string                  `json:"release_id"`
	GenerationID   string                  `json:"generation_id"`
	ManifestDigest string                  `json:"manifest_digest"`
	ComposeDigest  string                  `json:"compose_digest"`
	EvaluatedAt    string                  `json:"evaluated_at"`
	Results        []canonicalResultRecord `json:"results"`
	ReceiptDigest  string                  `json:"receipt_digest"`
}

type canonicalResultRecord struct {
	Probe          string `json:"probe"`
	Status         string `json:"status"`
	OperationID    string `json:"operation_id"`
	PlanDigest     string `json:"plan_digest"`
	ReleaseID      string `json:"release_id"`
	GenerationID   string `json:"generation_id"`
	ManifestDigest string `json:"manifest_digest"`
	ComposeDigest  string `json:"compose_digest"`
	EvidenceDigest string `json:"evidence_digest"`
	ObservedAt     string `json:"observed_at"`
}

func (r *ReadinessRepository) encode(ctx context.Context, receipt readiness.Receipt) ([]byte, error) {
	record := canonicalReadinessRecord(receipt.Record())
	canonicalRecord, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	key, err := r.readKey(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonicalRecord)
	envelope := readinessEnvelope{
		SchemaVersion: readinessEnvelopeSchema, Receipt: record,
		AuthenticationTag: hex.EncodeToString(mac.Sum(nil)),
	}
	clear(canonicalRecord)
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumReadinessBytes {
		clear(encoded)
		return nil, errReadinessRepositoryIntegrity
	}
	return encoded, nil
}

func (r *ReadinessRepository) decode(ctx context.Context, raw []byte) (readiness.Receipt, error) {
	if len(raw) == 0 || len(raw) > maximumReadinessBytes {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope readinessEnvelope
	if err := decoder.Decode(&envelope); err != nil || envelope.SchemaVersion != readinessEnvelopeSchema {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonicalEnvelope, raw) {
		clear(canonicalEnvelope)
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	clear(canonicalEnvelope)
	tag, err := hex.DecodeString(envelope.AuthenticationTag)
	if err != nil || len(tag) != sha256.Size {
		clear(tag)
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	defer clear(tag)
	recordBytes, err := json.Marshal(envelope.Receipt)
	if err != nil {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	defer clear(recordBytes)
	key, err := r.readKey(ctx)
	if err != nil {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(recordBytes)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	receipt, err := readiness.RestoreReceipt(domainReadinessRecord(envelope.Receipt))
	if err != nil {
		return readiness.Receipt{}, errReadinessRepositoryIntegrity
	}
	return receipt, nil
}

func (r *ReadinessRepository) readKey(ctx context.Context) ([]byte, error) {
	if r == nil || nilReadinessCapability(r.keys) {
		return nil, errReadinessRepositoryIntegrity
	}
	key, err := r.keys.ReadCredential(ctx, r.keyPath)
	if err != nil || len(key) != readinessKeyBytes {
		clear(key)
		return nil, errReadinessRepositoryIntegrity
	}
	return key, nil
}

func canonicalReadinessRecord(record readiness.ReceiptRecord) canonicalReceiptRecord {
	results := make([]canonicalResultRecord, 0, len(record.Results))
	for _, result := range record.Results {
		results = append(results, canonicalResultRecord{
			Probe: result.Probe, Status: result.Status, OperationID: result.OperationID,
			PlanDigest: result.PlanDigest, ReleaseID: result.ReleaseID, GenerationID: result.GenerationID,
			ManifestDigest: result.ManifestDigest, ComposeDigest: result.ComposeDigest,
			EvidenceDigest: result.EvidenceDigest, ObservedAt: result.ObservedAt,
		})
	}
	return canonicalReceiptRecord{
		SchemaVersion: record.SchemaVersion, OperationID: record.OperationID, PlanDigest: record.PlanDigest,
		ReleaseID: record.ReleaseID, GenerationID: record.GenerationID,
		ManifestDigest: record.ManifestDigest, ComposeDigest: record.ComposeDigest,
		EvaluatedAt: record.EvaluatedAt, Results: results, ReceiptDigest: record.ReceiptDigest,
	}
}

func domainReadinessRecord(record canonicalReceiptRecord) readiness.ReceiptRecord {
	results := make([]readiness.ResultRecord, 0, len(record.Results))
	for _, result := range record.Results {
		results = append(results, readiness.ResultRecord{
			Probe: result.Probe, Status: result.Status, OperationID: result.OperationID,
			PlanDigest: result.PlanDigest, ReleaseID: result.ReleaseID, GenerationID: result.GenerationID,
			ManifestDigest: result.ManifestDigest, ComposeDigest: result.ComposeDigest,
			EvidenceDigest: result.EvidenceDigest, ObservedAt: result.ObservedAt,
		})
	}
	return readiness.ReceiptRecord{
		SchemaVersion: record.SchemaVersion, OperationID: record.OperationID, PlanDigest: record.PlanDigest,
		ReleaseID: record.ReleaseID, GenerationID: record.GenerationID,
		ManifestDigest: record.ManifestDigest, ComposeDigest: record.ComposeDigest,
		EvaluatedAt: record.EvaluatedAt, Results: results, ReceiptDigest: record.ReceiptDigest,
	}
}

func readinessFilename(digest install.Digest) string {
	return "readiness-sha256-" + digest.String() + ".json"
}

func nilReadinessCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface {
		return reflected.IsNil()
	}
	return false
}

var (
	_ readinessapp.ReceiptRepository              = (*ReadinessRepository)(nil)
	_ installplanapp.ReadinessReceiptRepository   = (*ReadinessRepository)(nil)
	_ activereleaseapp.ReadinessReceiptRepository = (*ReadinessRepository)(nil)
)
