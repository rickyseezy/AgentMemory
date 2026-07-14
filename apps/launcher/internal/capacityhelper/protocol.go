// Package capacityhelper defines the closed protocol used by the signed
// AgentMemory capacity-helper container. The protocol contains no path,
// command, environment, or secret field.
package capacityhelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// ProtocolVersion is the only helper protocol understood by this launcher.
	ProtocolVersion uint16 = 1
	// MountTarget is the fixed writable Docker volume mount inside the helper.
	MountTarget = "/capacity"
	// Entrypoint is the fixed executable path in the signed helper image.
	Entrypoint = "/agentmemory-capacity-helper"
	// MaximumResponseBytes bounds the helper's complete canonical stdout line.
	MaximumResponseBytes = 16 * 1024
	maximumSafeBytes     = uint64(1<<53 - 1)
	noneArgument         = "~"
)

// Operation is the closed helper command vocabulary.
type Operation string

// Supported helper operations.
const (
	OperationReserve            Operation = "reserve"
	OperationInspect            Operation = "inspect"
	OperationTransfer           Operation = "transfer"
	OperationActivateProjection Operation = "activate-projection"
	OperationDeleteProof        Operation = "delete-proof"
)

// PriorState is the authenticated aggregate state that authorized a delete
// proof. It is data, not an instruction to infer or widen ownership.
type PriorState string

// Prior states that can describe an adapter-owned reservation volume.
const (
	PriorReservePending  PriorState = "reserve-pending"
	PriorReserved        PriorState = "reserved"
	PriorTransferPending PriorState = "transfer-pending"
	PriorTransferred     PriorState = "transferred"
)

// RequestInput contains only immutable signed-plan projections and an exact
// aggregate-minted lifecycle state.
type RequestInput struct {
	Operation      Operation
	LeaseID        string
	PlanDigest     string
	PoolID         string
	PoolKind       string
	Bytes          uint64
	Owner          string
	NewOwner       string
	AlternateOwner string
	PriorState     PriorState
}

// Request is a validated immutable helper invocation.
type Request struct {
	operation      Operation
	leaseID        string
	planDigest     string
	poolID         string
	poolKind       string
	bytes          uint64
	owner          string
	newOwner       string
	alternateOwner string
	priorState     PriorState
	receiptToken   string
}

// NewRequest validates and closes one helper request.
func NewRequest(input RequestInput) (Request, error) {
	if !validOperation(input.Operation) || !validDigestID(input.LeaseID, "l-") ||
		!validDigest(input.PlanDigest) || !validDigestID(input.PoolID, "d-") ||
		input.PoolKind != "docker-engine" || input.Bytes == 0 || input.Bytes > maximumSafeBytes ||
		!validIdentifier(input.Owner) {
		return Request{}, errors.New("capacity helper request is invalid")
	}
	switch input.Operation {
	case OperationReserve, OperationInspect:
		if input.NewOwner != "" || input.AlternateOwner != "" || input.PriorState != "" {
			return Request{}, errors.New("capacity helper request carries forbidden lifecycle fields")
		}
	case OperationTransfer, OperationActivateProjection:
		if !validIdentifier(input.NewOwner) || input.NewOwner == input.Owner ||
			input.AlternateOwner != "" || input.PriorState != "" {
			return Request{}, errors.New("capacity helper transfer is invalid")
		}
	case OperationDeleteProof:
		if !validPriorState(input.PriorState) || input.NewOwner != "" ||
			(input.AlternateOwner != "" && (!validIdentifier(input.AlternateOwner) || input.AlternateOwner == input.Owner)) {
			return Request{}, errors.New("capacity helper delete proof is invalid")
		}
	}
	request := Request{
		operation: input.Operation, leaseID: input.LeaseID, planDigest: input.PlanDigest,
		poolID: input.PoolID, poolKind: input.PoolKind, bytes: input.Bytes,
		owner: input.Owner, newOwner: input.NewOwner, alternateOwner: input.AlternateOwner,
		priorState: input.PriorState,
	}
	request.receiptToken = deriveReceiptToken(request)
	return request, nil
}

// ParseArguments accepts only the exact positional flag sequence emitted by
// Arguments. Generic flags, reordered fields, duplicates, and extras fail.
func ParseArguments(arguments []string) (Request, error) {
	if len(arguments) < 13 {
		return Request{}, errors.New("capacity helper argument count is invalid")
	}
	operation := Operation(arguments[0])
	if !validOperation(operation) {
		return Request{}, errors.New("capacity helper operation is invalid")
	}
	baseLabels := []string{"--lease-id", "--plan-digest", "--pool-id", "--pool-kind", "--bytes", "--owner"}
	for index, label := range baseLabels {
		if arguments[index*2+1] != label {
			return Request{}, errors.New("capacity helper arguments are not canonical")
		}
	}
	bytesValue, err := strconv.ParseUint(arguments[10], 10, 64)
	if err != nil || strconv.FormatUint(bytesValue, 10) != arguments[10] {
		return Request{}, errors.New("capacity helper byte count is invalid")
	}
	input := RequestInput{
		Operation: operation, LeaseID: arguments[2], PlanDigest: arguments[4],
		PoolID: arguments[6], PoolKind: arguments[8], Bytes: bytesValue, Owner: arguments[12],
	}
	switch operation {
	case OperationReserve, OperationInspect:
		if len(arguments) != 13 {
			return Request{}, errors.New("capacity helper argument count is invalid")
		}
	case OperationTransfer, OperationActivateProjection:
		if len(arguments) != 15 || arguments[13] != "--new-owner" {
			return Request{}, errors.New("capacity helper transfer arguments are invalid")
		}
		input.NewOwner = arguments[14]
	case OperationDeleteProof:
		if len(arguments) != 17 || arguments[13] != "--prior-state" || arguments[15] != "--alternate-owner" {
			return Request{}, errors.New("capacity helper delete arguments are invalid")
		}
		input.PriorState = PriorState(arguments[14])
		if arguments[16] != noneArgument {
			input.AlternateOwner = arguments[16]
		}
	}
	return NewRequest(input)
}

// Arguments returns the exact closed argv following the signed image name.
func (r Request) Arguments() []string {
	if !r.Valid() {
		return nil
	}
	arguments := []string{
		string(r.operation), "--lease-id", r.leaseID, "--plan-digest", r.planDigest,
		"--pool-id", r.poolID, "--pool-kind", r.poolKind, "--bytes", strconv.FormatUint(r.bytes, 10),
		"--owner", r.owner,
	}
	switch r.operation {
	case OperationTransfer, OperationActivateProjection:
		arguments = append(arguments, "--new-owner", r.newOwner)
	case OperationDeleteProof:
		alternate := r.alternateOwner
		if alternate == "" {
			alternate = noneArgument
		}
		arguments = append(arguments, "--prior-state", string(r.priorState), "--alternate-owner", alternate)
	case OperationReserve, OperationInspect:
	}
	return arguments
}

// Valid reports whether the request was produced by the closed constructor.
func (r Request) Valid() bool {
	rebuilt, err := NewRequest(RequestInput{
		Operation: r.operation, LeaseID: r.leaseID, PlanDigest: r.planDigest,
		PoolID: r.poolID, PoolKind: r.poolKind, Bytes: r.bytes, Owner: r.owner,
		NewOwner: r.newOwner, AlternateOwner: r.alternateOwner, PriorState: r.priorState,
	})
	return err == nil && rebuilt == r
}

// Operation returns the closed requested action.
func (r Request) Operation() Operation { return r.operation }

// LeaseID returns the deterministic aggregate lease identity.
func (r Request) LeaseID() string { return r.leaseID }

// PlanDigest returns the signed artifact-plan digest.
func (r Request) PlanDigest() string { return r.planDigest }

// PoolID returns the attested Docker backing-pool identity.
func (r Request) PoolID() string { return r.poolID }

// PoolKind returns the closed Docker allocation-pool kind.
func (r Request) PoolKind() string { return r.poolKind }

// Bytes returns the exact requested file length.
func (r Request) Bytes() uint64 { return r.bytes }

// Owner returns the exact current owner expected by the caller.
func (r Request) Owner() string { return r.owner }

// NewOwner returns the exact transfer target when present.
func (r Request) NewOwner() string { return r.newOwner }

// AlternateOwner returns the second owner allowed only for an interrupted transfer.
func (r Request) AlternateOwner() string { return r.alternateOwner }

// PriorState returns the aggregate state authorizing a delete proof.
func (r Request) PriorState() PriorState { return r.priorState }

// ReceiptToken returns the replay-stable receipt identity derived from every
// immutable reservation field.
func (r Request) ReceiptToken() string { return r.receiptToken }

// Response is the helper's bounded canonical stdout document.
type Response struct {
	AllocatedBlockBytes uint64 `json:"allocated_block_bytes"`
	AvailableBytes      uint64 `json:"available_bytes"`
	Bytes               uint64 `json:"bytes"`
	FileSizeBytes       uint64 `json:"file_size_bytes"`
	LeaseID             string `json:"lease_id"`
	MetadataDigest      string `json:"metadata_digest"`
	Operation           string `json:"operation"`
	Owner               string `json:"owner"`
	PlanDigest          string `json:"plan_digest"`
	PoolID              string `json:"pool_id"`
	PoolKind            string `json:"pool_kind"`
	Present             bool   `json:"present"`
	ReceiptToken        string `json:"receipt_token"`
	SchemaVersion       uint16 `json:"schema_version"`
	State               string `json:"state"`
}

// CanonicalResponseLine encodes exactly one canonical JSON line.
func CanonicalResponseLine(response Response) ([]byte, error) {
	if err := validateResponseShape(response); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded)+1 > MaximumResponseBytes {
		return nil, errors.New("capacity helper response exceeds its bound")
	}
	return append(encoded, '\n'), nil
}

// ParseResponseLine strictly decodes one canonical response line and rejects
// duplicate, unknown, trailing, noncanonical, or oversized JSON.
func ParseResponseLine(data []byte) (Response, error) {
	var response Response
	if len(data) < 3 || len(data) > MaximumResponseBytes || data[len(data)-1] != '\n' ||
		bytes.IndexByte(data[:len(data)-1], '\n') >= 0 {
		return response, errors.New("capacity helper response line is invalid")
	}
	body := data[:len(data)-1]
	if err := rejectDuplicateKeys(body); err != nil {
		return response, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return Response{}, errors.New("capacity helper response JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Response{}, errors.New("capacity helper response has trailing data")
	}
	canonical, err := CanonicalResponseLine(response)
	if err != nil || !bytes.Equal(canonical, data) {
		return Response{}, errors.New("capacity helper response is not canonical")
	}
	return response, nil
}

func deriveReceiptToken(request Request) string {
	material := strings.Join([]string{
		"agentmemory-capacity-receipt-v1", request.leaseID, request.planDigest,
		request.poolID, request.poolKind, strconv.FormatUint(request.bytes, 10), request.owner,
	}, "\x00")
	digest := sha256.Sum256([]byte(material))
	return "r-" + hex.EncodeToString(digest[:])
}

func validOperation(value Operation) bool {
	return value == OperationReserve || value == OperationInspect || value == OperationTransfer ||
		value == OperationActivateProjection || value == OperationDeleteProof
}

func validPriorState(value PriorState) bool {
	return value == PriorReservePending || value == PriorReserved || value == PriorTransferPending || value == PriorTransferred
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value == strings.Repeat("0", sha256.Size*2) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validDigestID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && validDigest(strings.TrimPrefix(value, prefix))
}

func validateResponseShape(response Response) error {
	if response.SchemaVersion != ProtocolVersion || !validOperation(Operation(response.Operation)) ||
		!validDigestID(response.LeaseID, "l-") || !validDigest(response.PlanDigest) ||
		!validDigestID(response.PoolID, "d-") || response.PoolKind != "docker-engine" ||
		response.Bytes == 0 || response.Bytes > maximumSafeBytes || !validIdentifier(response.Owner) ||
		!validDigestID(response.ReceiptToken, "r-") || !validDigest(response.MetadataDigest) ||
		response.AllocatedBlockBytes > maximumSafeBytes ||
		response.AvailableBytes > maximumSafeBytes || response.FileSizeBytes > response.Bytes {
		return errors.New("capacity helper response fields are invalid")
	}
	switch response.Operation {
	case string(OperationReserve), string(OperationInspect):
		if !response.Present || response.State != "reserved" || response.FileSizeBytes != response.Bytes ||
			response.AllocatedBlockBytes < response.Bytes {
			return errors.New("capacity helper reservation proof is incomplete")
		}
	case string(OperationTransfer):
		if !response.Present || response.State != "transferred" || response.FileSizeBytes != response.Bytes ||
			response.AllocatedBlockBytes < response.Bytes {
			return errors.New("capacity helper transfer proof is incomplete")
		}
	case string(OperationActivateProjection):
		if response.Present || response.State != "projection-ready" || response.FileSizeBytes != 0 ||
			response.AllocatedBlockBytes != 0 {
			return errors.New("capacity helper projection activation proof is incomplete")
		}
	case string(OperationDeleteProof):
		if !response.Present || response.State != "delete-approved" || response.AllocatedBlockBytes < response.FileSizeBytes {
			return errors.New("capacity helper delete proof is incomplete")
		}
	default:
		return fmt.Errorf("unsupported capacity helper operation %q", response.Operation)
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0, new(uint32)); err != nil {
		return errors.New("capacity helper response JSON is ambiguous")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("capacity helper response JSON has trailing data")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth uint32, values *uint32) error {
	if depth > 16 || *values >= 256 {
		return errors.New("capacity helper JSON bound exceeded")
	}
	*values++
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			key, ok := keyToken.(string)
			if keyError != nil || !ok || len(key) == 0 || len(key) > 64 {
				return errors.New("invalid capacity helper object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate capacity helper object key")
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1, values); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return errors.New("invalid capacity helper object close")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1, values); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return errors.New("invalid capacity helper array close")
		}
	default:
		return errors.New("invalid capacity helper JSON delimiter")
	}
	return nil
}
