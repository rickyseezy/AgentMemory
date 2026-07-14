package capacityhelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

// MetadataState is the closed durable state stored inside one capacity volume.
type MetadataState string

// Durable helper metadata states.
const (
	MetadataReservePending MetadataState = "reserve-pending"
	MetadataReserved       MetadataState = "reserved"
	MetadataTransferred    MetadataState = "transferred"
)

// Metadata is the owner-only canonical file stored with the physical
// reservation. All identity fields are supplied by the signed request.
type Metadata struct {
	Bytes         uint64 `json:"bytes"`
	LeaseID       string `json:"lease_id"`
	Owner         string `json:"owner"`
	PlanDigest    string `json:"plan_digest"`
	PoolID        string `json:"pool_id"`
	PoolKind      string `json:"pool_kind"`
	ReceiptToken  string `json:"receipt_token"`
	SchemaVersion uint16 `json:"schema_version"`
	State         string `json:"state"`
}

// NewMetadata creates exact durable metadata for one request and owner.
func NewMetadata(request Request, owner string, state MetadataState) (Metadata, error) {
	if !request.Valid() || !validIdentifier(owner) ||
		(state != MetadataReservePending && state != MetadataReserved && state != MetadataTransferred) {
		return Metadata{}, errors.New("capacity helper metadata is invalid")
	}
	if state == MetadataReservePending || state == MetadataReserved {
		if owner != request.Owner() {
			return Metadata{}, errors.New("capacity helper reservation owner is invalid")
		}
	}
	if state == MetadataTransferred && owner != request.NewOwner() && owner != request.AlternateOwner() {
		return Metadata{}, errors.New("capacity helper transfer owner is invalid")
	}
	return Metadata{
		Bytes: request.Bytes(), LeaseID: request.LeaseID(), Owner: owner,
		PlanDigest: request.PlanDigest(), PoolID: request.PoolID(), PoolKind: request.PoolKind(),
		ReceiptToken: request.ReceiptToken(), SchemaVersion: ProtocolVersion, State: string(state),
	}, nil
}

// MatchesImmutable reports exact agreement with every non-owner, non-state
// request field.
func (m Metadata) MatchesImmutable(request Request) bool {
	return request.Valid() && m.SchemaVersion == ProtocolVersion && m.Bytes == request.Bytes() &&
		m.LeaseID == request.LeaseID() && m.PlanDigest == request.PlanDigest() &&
		m.PoolID == request.PoolID() && m.PoolKind == request.PoolKind() &&
		m.ReceiptToken == request.ReceiptToken()
}

// CanonicalMetadata encodes the exact bounded owner-only file contents.
func CanonicalMetadata(metadata Metadata) ([]byte, error) {
	if !validMetadata(metadata) {
		return nil, errors.New("capacity helper metadata fields are invalid")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || len(encoded) > 4096 {
		return nil, errors.New("capacity helper metadata exceeds its bound")
	}
	return encoded, nil
}

// ParseMetadata strictly decodes an exact canonical metadata file.
func ParseMetadata(data []byte) (Metadata, error) {
	if len(data) == 0 || len(data) > 4096 || bytes.IndexByte(data, '\n') >= 0 {
		return Metadata{}, errors.New("capacity helper metadata size is invalid")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&metadata); err != nil {
		return Metadata{}, errors.New("capacity helper metadata JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Metadata{}, errors.New("capacity helper metadata has trailing data")
	}
	canonical, err := CanonicalMetadata(metadata)
	if err != nil || !bytes.Equal(canonical, data) {
		return Metadata{}, errors.New("capacity helper metadata is not canonical")
	}
	return metadata, nil
}

// MetadataDigest returns the lowercase SHA-256 digest of canonical metadata.
func MetadataDigest(metadata Metadata) (string, error) {
	canonical, err := CanonicalMetadata(metadata)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// Observation is a storage adapter's measured result. File size and allocated
// block bytes are independent so sparse files cannot masquerade as capacity.
type Observation struct {
	AllocatedBlockBytes uint64
	AvailableBytes      uint64
	FileSizeBytes       uint64
	Metadata            Metadata
	Owner               string
	State               string
}

// Store is the fixed volume-local physical allocation boundary. Its
// production implementation has no caller-supplied path.
type Store interface {
	Reserve(context.Context, Request) (Observation, error)
	Inspect(context.Context, Request) (Observation, error)
	Transfer(context.Context, Request) (Observation, error)
	ActivateProjection(context.Context, Request) (Observation, error)
	DeleteProof(context.Context, Request) (Observation, error)
}

// Service parses the closed command and emits one canonical stdout line.
type Service struct {
	store Store
}

// NewService rejects an absent or typed-nil physical store.
func NewService(store Store) (*Service, error) {
	if nilStore(store) {
		return nil, errors.New("capacity helper store is required")
	}
	return &Service{store: store}, nil
}

// Execute validates argv before invoking exactly one closed store operation.
func (s *Service) Execute(ctx context.Context, arguments []string) ([]byte, error) {
	if ctx == nil || s == nil || nilStore(s.store) {
		return nil, errors.New("capacity helper execution is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(errors.New("capacity helper execution cancelled"), err)
	}
	request, err := ParseArguments(arguments)
	if err != nil {
		return nil, err
	}
	var observation Observation
	switch request.Operation() {
	case OperationReserve:
		observation, err = s.store.Reserve(ctx, request)
	case OperationInspect:
		observation, err = s.store.Inspect(ctx, request)
	case OperationTransfer:
		observation, err = s.store.Transfer(ctx, request)
	case OperationActivateProjection:
		observation, err = s.store.ActivateProjection(ctx, request)
	case OperationDeleteProof:
		observation, err = s.store.DeleteProof(ctx, request)
	}
	if err != nil {
		return nil, errors.New("capacity helper storage operation failed")
	}
	if err := validateObservation(request, observation); err != nil {
		return nil, err
	}
	metadataDigest, err := MetadataDigest(observation.Metadata)
	if err != nil {
		return nil, err
	}
	return CanonicalResponseLine(Response{
		AllocatedBlockBytes: observation.AllocatedBlockBytes,
		AvailableBytes:      observation.AvailableBytes,
		Bytes:               request.Bytes(),
		FileSizeBytes:       observation.FileSizeBytes,
		LeaseID:             request.LeaseID(),
		MetadataDigest:      metadataDigest,
		Operation:           string(request.Operation()),
		Owner:               observation.Owner,
		PlanDigest:          request.PlanDigest(),
		PoolID:              request.PoolID(),
		PoolKind:            request.PoolKind(),
		Present:             request.Operation() != OperationActivateProjection,
		ReceiptToken:        request.ReceiptToken(),
		SchemaVersion:       ProtocolVersion,
		State:               observation.State,
	})
}

func validateObservation(request Request, observation Observation) error {
	if !observation.Metadata.MatchesImmutable(request) || observation.Owner != observation.Metadata.Owner ||
		observation.State == "" || observation.State != observation.Metadata.State &&
		request.Operation() != OperationDeleteProof && request.Operation() != OperationActivateProjection ||
		observation.AvailableBytes > maximumSafeBytes ||
		observation.FileSizeBytes > request.Bytes() || observation.AllocatedBlockBytes < observation.FileSizeBytes ||
		observation.AllocatedBlockBytes > maximumSafeBytes {
		return errors.New("capacity helper storage proof is invalid")
	}
	switch request.Operation() {
	case OperationReserve, OperationInspect:
		if observation.Owner != request.Owner() || observation.State != string(MetadataReserved) ||
			observation.FileSizeBytes != request.Bytes() || observation.AllocatedBlockBytes < request.Bytes() {
			return errors.New("capacity helper reservation proof is invalid")
		}
	case OperationTransfer:
		if observation.Owner != request.NewOwner() || observation.State != string(MetadataTransferred) ||
			observation.FileSizeBytes != request.Bytes() || observation.AllocatedBlockBytes < request.Bytes() {
			return errors.New("capacity helper transfer proof is invalid")
		}
	case OperationActivateProjection:
		if observation.Owner != request.NewOwner() || observation.State != "projection-ready" ||
			observation.Metadata.State != string(MetadataTransferred) || observation.FileSizeBytes != 0 ||
			observation.AllocatedBlockBytes != 0 {
			return errors.New("capacity helper projection activation proof is invalid")
		}
	case OperationDeleteProof:
		ownerAllowed := observation.Owner == request.Owner() ||
			request.AlternateOwner() != "" && observation.Owner == request.AlternateOwner()
		if !ownerAllowed || observation.State != "delete-approved" {
			return errors.New("capacity helper delete proof is invalid")
		}
	default:
		return errors.New("capacity helper operation is invalid")
	}
	return nil
}

func validMetadata(metadata Metadata) bool {
	if metadata.SchemaVersion != ProtocolVersion || metadata.Bytes == 0 || metadata.Bytes > maximumSafeBytes ||
		!validDigestID(metadata.LeaseID, "l-") || !validIdentifier(metadata.Owner) ||
		!validDigest(metadata.PlanDigest) || !validDigestID(metadata.PoolID, "d-") ||
		metadata.PoolKind != "docker-engine" || !validDigestID(metadata.ReceiptToken, "r-") {
		return false
	}
	state := MetadataState(metadata.State)
	return state == MetadataReservePending || state == MetadataReserved || state == MetadataTransferred
}

func nilStore(store Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid non-nil interface implementation.
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
