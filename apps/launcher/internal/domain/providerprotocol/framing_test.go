package providerprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestPRO002FrameRoundTripPreservesStrictJSONRPCRequest(t *testing.T) {
	t.Parallel()
	request := validRequest()
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if binary.BigEndian.Uint32(encoded[:FramePrefixBytes]) != uint32(len(encoded)-FramePrefixBytes) { //nolint:gosec // G115: encoded frame is bounded by MaxFrameBytes.
		t.Fatal("frame prefix does not bind the exact JSON byte length")
	}
	decoded, err := DecodeRequest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.JSONRPC != "2.0" || decoded.ID != request.ID || decoded.Method != request.Method ||
		decoded.Params.OperationID != request.Params.OperationID ||
		!bytes.Equal(decoded.Params.Payload, request.Params.Payload) {
		t.Fatalf("round trip changed request: %#v", decoded)
	}
	decoded.Params.ContentIDs[0] = "changed"
	if request.Params.ContentIDs[0] == "changed" {
		t.Fatal("codec retained caller-owned content IDs")
	}
}

func TestPRO002FrameRejectsMalformedAmbiguousOrUnboundedInput(t *testing.T) {
	t.Parallel()
	valid, err := EncodeRequest(validRequest())
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	tests := []struct {
		name  string
		frame []byte
	}{
		{"empty", nil},
		{"short prefix", []byte{0, 0, 1}},
		{"zero length", []byte{0, 0, 0, 0}},
		{"oversized", prefix(MaxFrameBytes + 1)},
		{"truncated", append(prefix(20), []byte("{}")...)},
		{"trailing frame bytes", append(append([]byte(nil), valid...), 0)},
		{"duplicate top level", jsonFrame(`{"jsonrpc":"2.0","jsonrpc":"2.0","id":"op","method":"health","params":{}}`)},
		{"duplicate nested", jsonFrame(`{"jsonrpc":"2.0","id":"op","method":"health","params":{"protocol_version":1,"protocol_version":1}}`)},
		{"unknown field", jsonFrame(validJSONWith(`,"compose":{}`))},
		{"batch", jsonFrame(`[]`)},
		{"notification", jsonFrame(validJSONWithout(`,"id":"operation-1"`))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeRequest(bytes.NewReader(test.frame)); !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("unsafe frame accepted or leaked error: %v", err)
			}
		})
	}
}

func TestPRO002RequestRejectsMissingIdentityDeadlineAndClosedVocabularyViolations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{"jsonrpc", func(value *Request) { value.JSONRPC = "1.0" }},
		{"request id", func(value *Request) { value.ID = "" }},
		{"method", func(value *Request) { value.Method = "exec" }},
		{"protocol", func(value *Request) { value.Params.ProtocolVersion = 2 }},
		{"operation", func(value *Request) { value.Params.OperationID = "bad operation" }},
		{"profile", func(value *Request) { value.Params.ProfileID = "bad" }},
		{"purpose", func(value *Request) { value.Params.Purpose = "admin" }},
		{"classification", func(value *Request) { value.Params.Classification = "secret" }},
		{"deadline", func(value *Request) { value.Params.DeadlineUnixMicros = 0 }},
		{"idempotency", func(value *Request) { value.Params.IdempotencyKey = "" }},
		{"trace", func(value *Request) { value.Params.TraceParent = "invalid" }},
		{"content", func(value *Request) { value.Params.ContentIDs = nil }},
		{"duplicate content", func(value *Request) { value.Params.ContentIDs = []string{"content-1", "content-1"} }},
		{"empty payload", func(value *Request) { value.Params.Payload = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validRequest()
			test.mutate(&request)
			if _, err := EncodeRequest(request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid request accepted: %v", err)
			}
		})
	}
}

func FuzzPRO002DecodeFrameNeverPanicsOrAllocatesBeyondBound(f *testing.F) {
	valid, _ := EncodeRequest(validRequest())
	f.Add(valid)
	f.Add([]byte{0, 0, 0, 0})
	f.Add(jsonFrame(`{"jsonrpc":"2.0"}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		if len(input) > MaxFrameBytes+FramePrefixBytes+1 {
			input = input[:MaxFrameBytes+FramePrefixBytes+1]
		}
		_, _ = DecodeRequest(bytes.NewReader(input))
	})
}

func TestPRO002StreamingDecoderPreservesConsecutiveFrameBoundaries(t *testing.T) {
	t.Parallel()
	first := validRequest()
	second := validRequest()
	second.ID = "operation-2"
	second.Params.OperationID = second.ID
	firstFrame, _ := EncodeRequest(first)
	secondFrame, _ := EncodeRequest(second)
	decoder := NewDecoder(bytes.NewReader(append(firstFrame, secondFrame...)))
	gotFirst, firstErr := decoder.NextRequest()
	gotSecond, secondErr := decoder.NextRequest()
	if firstErr != nil || secondErr != nil || gotFirst.ID != first.ID || gotSecond.ID != second.ID {
		t.Fatalf("stream frames = %#v/%v %#v/%v", gotFirst, firstErr, gotSecond, secondErr)
	}
}

func TestPRO002ResponseRoundTripEnforcesOrderDimensionsAndSafeErrors(t *testing.T) {
	t.Parallel()
	response := Response{JSONRPC: "2.0", ID: "operation-1", Result: &ResponseResult{
		OperationID: "operation-1", ContentIDs: []string{"content-1", "content-2"}, Dimensions: 2,
		Items:         []ItemResult{{ContentID: "content-1", Vector: []float32{1, 2}}, {ContentID: "content-2", Vector: []float32{3, 4}}},
		ModelRevision: "model-revision-1",
	}}
	framed, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeResponse(bytes.NewReader(framed))
	if err != nil || decoded.Result == nil || decoded.Result.Items[1].ContentID != "content-2" {
		t.Fatalf("decode = %#v %v", decoded, err)
	}
	if err := ValidateResponseFor(validRequest(), decoded); err != nil {
		t.Fatalf("response binding: %v", err)
	}
	reordered := decoded
	reordered.Result.ContentIDs = []string{"content-2", "content-1"}
	if err := ValidateResponseFor(validRequest(), reordered); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("reordered response accepted: %v", err)
	}

	tests := []Response{
		{JSONRPC: "2.0", ID: "operation-1"},
		{JSONRPC: "2.0", ID: "operation-1", Result: response.Result, Error: &RPCError{Code: -32603, Message: "safe", Data: RPCErrorData{Kind: ErrorInternal, Retryable: true}}},
		{JSONRPC: "2.0", ID: "operation-1", Result: &ResponseResult{OperationID: "wrong", ModelRevision: "revision"}},
		{JSONRPC: "2.0", ID: "operation-1", Result: &ResponseResult{OperationID: "operation-1", ContentIDs: []string{"a"}, Items: []ItemResult{{ContentID: "b"}}, ModelRevision: "revision"}},
		{JSONRPC: "2.0", ID: "operation-1", Error: &RPCError{Code: -32603, Message: "authorization bearer token leaked", Data: RPCErrorData{Kind: ErrorInternal}}},
		{JSONRPC: "2.0", ID: "operation-1", Error: &RPCError{Code: -32001, Message: "safe", Data: RPCErrorData{Kind: ErrorInternal}}},
	}
	for _, invalid := range tests {
		if _, err := EncodeResponse(invalid); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("invalid response accepted: %#v %v", invalid, err)
		}
	}
}

func validRequest() Request {
	return Request{
		JSONRPC: "2.0", ID: "operation-1", Method: MethodEmbedDocuments,
		Params: RequestParameters{
			ProtocolVersion: 1, OperationID: "operation-1",
			ProfileID: "018f0000-0000-7000-8000-000000000711",
			Purpose:   PurposeRetrievalDocument, ContentIDs: []string{"content-1", "content-2"},
			Classification: ClassificationInternal, DeadlineUnixMicros: 1784707230000000,
			IdempotencyKey: "operation-1", TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			Payload: []byte(`{"texts":["alpha","beta"]}`),
		},
	}
}

func prefix(length uint32) []byte {
	result := make([]byte, FramePrefixBytes)
	binary.BigEndian.PutUint32(result, length)
	return result
}

func jsonFrame(value string) []byte {
	return append(prefix(uint32(len(value))), []byte(value)...) //nolint:gosec // G115: static test fixtures are far below MaxFrameBytes.
}

func validJSONWith(suffix string) string {
	value := string(mustJSON(validRequest()))
	return value[:len(value)-1] + suffix + "}"
}

func validJSONWithout(fragment string) string {
	return string(bytes.ReplaceAll(mustJSON(validRequest()), []byte(fragment), nil))
}

func mustJSON(value Request) []byte {
	result, err := marshalRequest(value)
	if err != nil {
		panic(err)
	}
	return result
}
