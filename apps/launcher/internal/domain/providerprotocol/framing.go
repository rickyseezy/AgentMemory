// Package providerprotocol implements the bounded language-neutral PRO-002 wire contract.
package providerprotocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"slices"
)

const (
	// FramePrefixBytes is the unsigned big-endian frame length width.
	FramePrefixBytes = 4
	// MaxFrameBytes is the hard request and response payload ceiling.
	MaxFrameBytes = 8 * 1024 * 1024
	maximumItems  = 1000
)

var (
	// ErrInvalidFrame is returned for malformed, ambiguous, or unbounded wire data.
	ErrInvalidFrame = errors.New("custom provider protocol frame is invalid")
	// ErrInvalidRequest is returned when a request cannot satisfy the closed contract.
	ErrInvalidRequest = errors.New("custom provider protocol request is invalid")
	// ErrInvalidResponse is returned when a response cannot satisfy the closed contract.
	ErrInvalidResponse         = errors.New("custom provider protocol response is invalid")
	tokenPattern               = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	uuid7Pattern               = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tracePattern               = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$`)
	sensitiveDiagnosticPattern = regexp.MustCompile(`(?i)(api[_-]?key|authorization|bearer|password|secret|token)`)
)

// Method is the closed language-neutral provider operation vocabulary.
type Method string

const (
	// MethodGetManifest reads the signed runtime manifest.
	MethodGetManifest Method = "get_manifest"
	// MethodValidateConfiguration validates profile configuration.
	MethodValidateConfiguration Method = "validate_configuration"
	// MethodProbe returns live output-contract evidence.
	MethodProbe Method = "probe"
	// MethodHealth checks liveness and readiness.
	MethodHealth Method = "health"
	// MethodListModels enumerates immutable model identities.
	MethodListModels Method = "list_models"
	// MethodEmbedDocuments embeds document-purpose input.
	MethodEmbedDocuments Method = "embed_documents"
	// MethodEmbedQueries embeds query-purpose input.
	MethodEmbedQueries Method = "embed_queries"
	// MethodRerank scores ordered candidates.
	MethodRerank Method = "rerank"
	// MethodEstimateCost estimates usage without provider execution.
	MethodEstimateCost Method = "estimate_cost"
	// MethodCancel cancels an in-flight operation.
	MethodCancel Method = "cancel"
	// MethodShutdown requests a graceful stop.
	MethodShutdown Method = "shutdown"
)

var methods = map[Method]struct{}{
	MethodGetManifest: {}, MethodValidateConfiguration: {}, MethodProbe: {}, MethodHealth: {},
	MethodListModels: {}, MethodEmbedDocuments: {}, MethodEmbedQueries: {}, MethodRerank: {},
	MethodEstimateCost: {}, MethodCancel: {}, MethodShutdown: {},
}

// Purpose declares the semantic use of provider input.
type Purpose string

const (
	// PurposeRetrievalQuery labels recall queries.
	PurposeRetrievalQuery Purpose = "retrieval_query"
	// PurposeRetrievalDocument labels recall corpus content.
	PurposeRetrievalDocument Purpose = "retrieval_document"
	// PurposeCodeQuery labels code-search queries.
	PurposeCodeQuery Purpose = "code_query"
	// PurposeCodeDocument labels indexed source code.
	PurposeCodeDocument Purpose = "code_document"
	// PurposeSemanticSimilarity labels general similarity work.
	PurposeSemanticSimilarity Purpose = "semantic_similarity"
	// PurposeClassification labels classification work.
	PurposeClassification Purpose = "classification"
	// PurposeClustering labels clustering work.
	PurposeClustering Purpose = "clustering"
)

var purposes = map[Purpose]struct{}{
	PurposeRetrievalQuery: {}, PurposeRetrievalDocument: {}, PurposeCodeQuery: {},
	PurposeCodeDocument: {}, PurposeSemanticSimilarity: {}, PurposeClassification: {},
	PurposeClustering: {},
}

// Classification is the closed privacy classification vocabulary.
type Classification string

const (
	// ClassificationPublic allows public input policy.
	ClassificationPublic Classification = "public"
	// ClassificationInternal marks local non-public input.
	ClassificationInternal Classification = "internal"
	// ClassificationConfidential requires confidential-input policy.
	ClassificationConfidential Classification = "confidential"
	// ClassificationRestricted requires the strongest input policy.
	ClassificationRestricted Classification = "restricted"
)

var classifications = map[Classification]struct{}{
	ClassificationPublic: {}, ClassificationInternal: {},
	ClassificationConfidential: {}, ClassificationRestricted: {},
}

// RequestParameters contains every mandatory operation identity and policy field.
type RequestParameters struct {
	ProtocolVersion    uint16          `json:"protocol_version"`
	OperationID        string          `json:"operation_id"`
	ProfileID          string          `json:"profile_id"`
	Purpose            Purpose         `json:"purpose"`
	ContentIDs         []string        `json:"content_ids"`
	Classification     Classification  `json:"classification"`
	DeadlineUnixMicros int64           `json:"deadline_unix_micros"`
	IdempotencyKey     string          `json:"idempotency_key"`
	TraceParent        string          `json:"traceparent"`
	Payload            json.RawMessage `json:"payload"`
}

// Request is one strict JSON-RPC 2.0 provider request.
type Request struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      string            `json:"id"`
	Method  Method            `json:"method"`
	Params  RequestParameters `json:"params"`
}

// EncodeRequest validates and length-prefixes one request.
func EncodeRequest(request Request) ([]byte, error) {
	if !request.valid() {
		return nil, ErrInvalidRequest
	}
	payload, err := marshalRequest(request)
	if err != nil || len(payload) == 0 || len(payload) > MaxFrameBytes {
		return nil, ErrInvalidRequest
	}
	result := make([]byte, FramePrefixBytes+len(payload))
	binary.BigEndian.PutUint32(result[:FramePrefixBytes], uint32(len(payload))) //nolint:gosec // G115: payload is bounded by MaxFrameBytes above.
	copy(result[FramePrefixBytes:], payload)
	return result, nil
}

func marshalRequest(request Request) ([]byte, error) { return json.Marshal(request) }

// DecodeRequest accepts exactly one complete framed request and rejects trailing data.
func DecodeRequest(reader io.Reader) (Request, error) {
	payload, err := readFrame(reader)
	if err != nil {
		return Request{}, err
	}
	one := make([]byte, 1)
	if count, readErr := reader.Read(one); count != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return Request{}, ErrInvalidFrame
	}
	return decodeRequestPayload(payload)
}

// Decoder reads consecutive frames from a persistent stdio connection.
type Decoder struct{ reader io.Reader }

// NewDecoder creates a bounded streaming decoder.
func NewDecoder(reader io.Reader) *Decoder { return &Decoder{reader: reader} }

// NextRequest reads exactly one request while leaving the next frame unread.
func (d *Decoder) NextRequest() (Request, error) {
	if d == nil {
		return Request{}, ErrInvalidFrame
	}
	payload, err := readFrame(d.reader)
	if err != nil {
		return Request{}, err
	}
	return decodeRequestPayload(payload)
}

func readFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, ErrInvalidFrame
	}
	prefix := make([]byte, FramePrefixBytes)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, ErrInvalidFrame
	}
	length := binary.BigEndian.Uint32(prefix)
	if length == 0 || length > MaxFrameBytes {
		return nil, ErrInvalidFrame
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, ErrInvalidFrame
	}
	return payload, nil
}

func decodeRequestPayload(payload []byte) (Request, error) {
	if err := rejectDuplicateNames(payload); err != nil {
		return Request{}, ErrInvalidFrame
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !request.valid() {
		return Request{}, ErrInvalidFrame
	}
	request.Params.ContentIDs = append([]string(nil), request.Params.ContentIDs...)
	request.Params.Payload = append(json.RawMessage(nil), request.Params.Payload...)
	return request, nil
}

// ErrorCode is the closed adapter failure taxonomy.
type ErrorCode string

const (
	// ErrorInvalidRequest reports safe request validation failure.
	ErrorInvalidRequest ErrorCode = "invalid_request"
	// ErrorUnauthorized reports authentication or policy denial.
	ErrorUnauthorized ErrorCode = "unauthorized"
	// ErrorUnsupported reports a valid but unsupported operation.
	ErrorUnsupported ErrorCode = "unsupported"
	// ErrorDeadlineExceeded reports bounded deadline expiry.
	ErrorDeadlineExceeded ErrorCode = "deadline_exceeded"
	// ErrorCancelled reports successful cancellation.
	ErrorCancelled ErrorCode = "cancelled"
	// ErrorRateLimited reports retryable provider throttling.
	ErrorRateLimited ErrorCode = "rate_limited"
	// ErrorUnavailable reports retryable dependency failure.
	ErrorUnavailable ErrorCode = "unavailable"
	// ErrorInternal reports a redacted non-retryable adapter failure.
	ErrorInternal ErrorCode = "internal"
)

var errorCodes = map[ErrorCode]struct{}{
	ErrorInvalidRequest: {}, ErrorUnauthorized: {}, ErrorUnsupported: {},
	ErrorDeadlineExceeded: {}, ErrorCancelled: {}, ErrorRateLimited: {},
	ErrorUnavailable: {}, ErrorInternal: {},
}

var errorNumbers = map[ErrorCode]int32{
	ErrorInvalidRequest:   -32602,
	ErrorUnauthorized:     -32001,
	ErrorUnsupported:      -32601,
	ErrorDeadlineExceeded: -32002,
	ErrorCancelled:        -32003,
	ErrorRateLimited:      -32004,
	ErrorUnavailable:      -32005,
	ErrorInternal:         -32603,
}

// Usage reports nonnegative provider accounting without credential-bearing diagnostics.
type Usage struct {
	InputTokens   uint64 `json:"input_tokens"`
	OutputTokens  uint64 `json:"output_tokens"`
	BillableUnits uint64 `json:"billable_units"`
}

// ItemResult is one ordered result bound to its input content identifier.
type ItemResult struct {
	ContentID string    `json:"content_id"`
	Vector    []float32 `json:"vector,omitempty"`
	Score     *float64  `json:"score,omitempty"`
}

// ResponseResult is the strict successful response envelope.
type ResponseResult struct {
	OperationID   string       `json:"operation_id"`
	ContentIDs    []string     `json:"content_ids"`
	Items         []ItemResult `json:"items"`
	Dimensions    uint32       `json:"dimensions"`
	Usage         Usage        `json:"usage"`
	ModelRevision string       `json:"model_revision"`
}

// RPCErrorData carries the closed safe failure category and retry hint.
type RPCErrorData struct {
	Kind      ErrorCode `json:"kind"`
	Retryable bool      `json:"retryable"`
}

// RPCError is the JSON-RPC 2.0 numeric error object; raw diagnostics are forbidden.
type RPCError struct {
	Code    int32        `json:"code"`
	Message string       `json:"message"`
	Data    RPCErrorData `json:"data"`
}

// Response is a JSON-RPC response containing exactly one result or error.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  *ResponseResult `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// EncodeResponse validates and frames one response.
func EncodeResponse(response Response) ([]byte, error) {
	if !response.valid() {
		return nil, ErrInvalidResponse
	}
	payload, err := json.Marshal(response)
	if err != nil || len(payload) == 0 || len(payload) > MaxFrameBytes {
		return nil, ErrInvalidResponse
	}
	framed := make([]byte, FramePrefixBytes+len(payload))
	binary.BigEndian.PutUint32(framed[:FramePrefixBytes], uint32(len(payload))) //nolint:gosec // G115: payload is bounded by MaxFrameBytes above.
	copy(framed[FramePrefixBytes:], payload)
	return framed, nil
}

// DecodeResponse reads a single complete response body.
func DecodeResponse(reader io.Reader) (Response, error) {
	payload, err := readFrame(reader)
	if err != nil {
		return Response{}, err
	}
	one := make([]byte, 1)
	if count, readErr := reader.Read(one); count != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return Response{}, ErrInvalidFrame
	}
	return decodeResponsePayload(payload)
}

// NextResponse reads one response from a persistent framed stream.
func (d *Decoder) NextResponse() (Response, error) {
	if d == nil {
		return Response{}, ErrInvalidFrame
	}
	payload, err := readFrame(d.reader)
	if err != nil {
		return Response{}, err
	}
	return decodeResponsePayload(payload)
}

func decodeResponsePayload(payload []byte) (Response, error) {
	if rejectDuplicateNames(payload) != nil {
		return Response{}, ErrInvalidFrame
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var response Response
	if decoder.Decode(&response) != nil || decoder.Decode(&struct{}{}) != io.EOF || !response.valid() {
		return Response{}, ErrInvalidFrame
	}
	if response.Result != nil {
		result := *response.Result
		result.ContentIDs = append([]string(nil), result.ContentIDs...)
		result.Items = append([]ItemResult(nil), result.Items...)
		for index := range result.Items {
			result.Items[index].Vector = append([]float32(nil), result.Items[index].Vector...)
		}
		response.Result = &result
	}
	return response, nil
}

func (response Response) valid() bool {
	if response.JSONRPC != "2.0" || !tokenPattern.MatchString(response.ID) || (response.Result == nil) == (response.Error == nil) {
		return false
	}
	if response.Error != nil {
		_, known := errorCodes[response.Error.Data.Kind]
		return known && response.Error.Code == errorNumbers[response.Error.Data.Kind] &&
			len(response.Error.Message) > 0 && len(response.Error.Message) <= 256 &&
			!sensitiveDiagnosticPattern.MatchString(response.Error.Message)
	}
	r := response.Result
	if r.OperationID != response.ID || !tokenPattern.MatchString(r.OperationID) || !tokenPattern.MatchString(r.ModelRevision) ||
		len(r.ContentIDs) != len(r.Items) || len(r.ContentIDs) > maximumItems {
		return false
	}
	for index, id := range r.ContentIDs {
		item := r.Items[index]
		if !tokenPattern.MatchString(id) || item.ContentID != id {
			return false
		}
		if len(item.Vector) > 0 && (r.Dimensions == 0 || len(item.Vector) != int(r.Dimensions)) {
			return false
		}
		for _, value := range item.Vector {
			if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
				return false
			}
		}
		if item.Score != nil && (math.IsNaN(*item.Score) || math.IsInf(*item.Score, 0)) {
			return false
		}
	}
	return true
}

// ValidateResponseFor binds a valid response to its exact request and method semantics.
func ValidateResponseFor(request Request, response Response) error {
	if !request.valid() || !response.valid() || response.ID != request.ID {
		return ErrInvalidResponse
	}
	if response.Error != nil {
		return nil
	}
	result := response.Result
	if result == nil || !slices.Equal(result.ContentIDs, request.Params.ContentIDs) {
		return ErrInvalidResponse
	}
	for _, item := range result.Items {
		switch request.Method {
		case MethodEmbedDocuments, MethodEmbedQueries, MethodProbe:
			if result.Dimensions == 0 || len(item.Vector) != int(result.Dimensions) || item.Score != nil {
				return ErrInvalidResponse
			}
		case MethodRerank:
			if item.Score == nil || len(item.Vector) != 0 || result.Dimensions != 0 {
				return ErrInvalidResponse
			}
		case MethodGetManifest, MethodValidateConfiguration, MethodHealth, MethodListModels,
			MethodEstimateCost, MethodCancel, MethodShutdown:
			if len(item.Vector) != 0 || item.Score != nil || result.Dimensions != 0 {
				return ErrInvalidResponse
			}
		}
	}
	return nil
}

func (request Request) valid() bool {
	if request.JSONRPC != "2.0" || !tokenPattern.MatchString(request.ID) {
		return false
	}
	if _, valid := methods[request.Method]; !valid {
		return false
	}
	params := request.Params
	if params.ProtocolVersion != 1 || !tokenPattern.MatchString(params.OperationID) ||
		params.OperationID != request.ID || !uuid7Pattern.MatchString(params.ProfileID) ||
		params.DeadlineUnixMicros <= 0 || !tokenPattern.MatchString(params.IdempotencyKey) ||
		!tracePattern.MatchString(params.TraceParent) || len(params.ContentIDs) == 0 ||
		len(params.ContentIDs) > maximumItems || len(params.Payload) == 0 || !json.Valid(params.Payload) {
		return false
	}
	if _, valid := purposes[params.Purpose]; !valid {
		return false
	}
	if _, valid := classifications[params.Classification]; !valid {
		return false
	}
	seen := make(map[string]struct{}, len(params.ContentIDs))
	for _, contentID := range params.ContentIDs {
		if !tokenPattern.MatchString(contentID) {
			return false
		}
		if _, duplicate := seen[contentID]; duplicate {
			return false
		}
		seen[contentID] = struct{}{}
	}
	return true
}

func rejectDuplicateNames(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidFrame
	}
	return nil
}

func consumeValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidFrame
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			name, valid := nameToken.(string)
			if err != nil || !valid {
				return ErrInvalidFrame
			}
			if _, duplicate := seen[name]; duplicate {
				return ErrInvalidFrame
			}
			seen[name] = struct{}{}
			if err := consumeValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidFrame
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(map[json.Delim]rune{'{': '}', '[': ']'}[delimiter]) {
		return ErrInvalidFrame
	}
	return nil
}
