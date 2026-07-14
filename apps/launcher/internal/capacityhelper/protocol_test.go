package capacityhelper

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPF001CapacityHelperArgumentsAreClosedAndCanonical(t *testing.T) {
	t.Parallel()
	for _, input := range []RequestInput{
		helperRequestInput(OperationReserve),
		helperRequestInput(OperationInspect),
		withTransfer(helperRequestInput(OperationTransfer)),
		withTransfer(helperRequestInput(OperationActivateProjection)),
		withDelete(helperRequestInput(OperationDeleteProof), PriorReservePending, ""),
		withDelete(helperRequestInput(OperationDeleteProof), PriorTransferPending, "generation-1"),
	} {
		request, err := NewRequest(input)
		if err != nil || !request.Valid() || request.ReceiptToken() == "" {
			t.Fatalf("NewRequest(%s)=%+v,%v", input.Operation, request, err)
		}
		parsed, err := ParseArguments(request.Arguments())
		if err != nil || parsed != request {
			t.Fatalf("ParseArguments(%s)=%+v,%v", input.Operation, parsed, err)
		}
		arguments := request.Arguments()
		arguments[1], arguments[3] = arguments[3], arguments[1]
		if _, err := ParseArguments(arguments); err == nil {
			t.Fatalf("reordered %s request accepted", input.Operation)
		}
	}
}

func TestPF001CapacityHelperRejectsGenericOrMalformedRequests(t *testing.T) {
	t.Parallel()
	valid := helperRequestInput(OperationReserve)
	tests := []struct {
		name   string
		mutate func(*RequestInput)
	}{
		{name: "unknown operation", mutate: func(v *RequestInput) { v.Operation = "shell" }},
		{name: "generic path", mutate: func(v *RequestInput) { v.Owner = "/host/path" }},
		{name: "foreign lease", mutate: func(v *RequestInput) { v.LeaseID = "foreign" }},
		{name: "uppercase digest", mutate: func(v *RequestInput) { v.PlanDigest = strings.ToUpper(v.PlanDigest) }},
		{name: "zero digest", mutate: func(v *RequestInput) { v.PlanDigest = strings.Repeat("0", 64) }},
		{name: "foreign pool", mutate: func(v *RequestInput) { v.PoolKind = "host-cas" }},
		{name: "zero bytes", mutate: func(v *RequestInput) { v.Bytes = 0 }},
		{name: "unsafe bytes", mutate: func(v *RequestInput) { v.Bytes = maximumSafeBytes + 1 }},
		{name: "reserve transfer owner", mutate: func(v *RequestInput) { v.NewOwner = "generation" }},
		{name: "reserve prior state", mutate: func(v *RequestInput) { v.PriorState = PriorReserved }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if _, err := NewRequest(input); err == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}

	transfer := withTransfer(helperRequestInput(OperationTransfer))
	transfer.NewOwner = transfer.Owner
	if _, err := NewRequest(transfer); err == nil {
		t.Fatal("no-op owner transfer accepted")
	}
	deleteInput := withDelete(helperRequestInput(OperationDeleteProof), "unknown", "")
	if _, err := NewRequest(deleteInput); err == nil {
		t.Fatal("unknown delete predecessor accepted")
	}
	deleteInput = withDelete(helperRequestInput(OperationDeleteProof), PriorTransferPending, valid.Owner)
	if _, err := NewRequest(deleteInput); err == nil {
		t.Fatal("duplicate alternate owner accepted")
	}
	if _, err := ParseArguments([]string{"reserve", "--path", "/host"}); err == nil {
		t.Fatal("generic path arguments accepted")
	}
}

func TestPF001CapacityHelperResponseAndMetadataRejectAmbiguousJSON(t *testing.T) {
	t.Parallel()
	request := mustHelperRequest(t, helperRequestInput(OperationReserve))
	metadata, err := NewMetadata(request, request.Owner(), MetadataReserved)
	if err != nil || !metadata.MatchesImmutable(request) {
		t.Fatalf("NewMetadata()=%+v,%v", metadata, err)
	}
	canonicalMetadata, err := CanonicalMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	parsedMetadata, err := ParseMetadata(canonicalMetadata)
	if err != nil || parsedMetadata != metadata {
		t.Fatalf("ParseMetadata()=%+v,%v", parsedMetadata, err)
	}
	metadataDigest, err := MetadataDigest(metadata)
	if err != nil {
		t.Fatal(err)
	}
	response := helperResponse(request, metadataDigest, request.Owner(), string(MetadataReserved), string(OperationReserve))
	line, err := CanonicalResponseLine(response)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseResponseLine(line)
	if err != nil || parsed != response {
		t.Fatalf("ParseResponseLine()=%+v,%v", parsed, err)
	}

	duplicate := bytes.Replace(line, []byte(`"bytes":4096`), []byte(`"bytes":4096,"bytes":4096`), 1)
	unknown := bytes.Replace(line, []byte(`"state":"reserved"`), []byte(`"state":"reserved","unknown":true`), 1)
	noncanonical := append([]byte(" "), line...)
	trailing := append(append([]byte(nil), line...), []byte("{}\n")...)
	for name, value := range map[string][]byte{
		"duplicate": duplicate, "unknown": unknown, "noncanonical": noncanonical, "trailing": trailing,
		"no newline": bytes.TrimSuffix(line, []byte("\n")), "oversized": bytes.Repeat([]byte("x"), MaximumResponseBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResponseLine(value); err == nil {
				t.Fatal("ambiguous response accepted")
			}
		})
	}

	metadataDuplicate := bytes.Replace(canonicalMetadata, []byte(`"bytes":4096`), []byte(`"bytes":4096,"bytes":4096`), 1)
	metadataUnknown := append([]byte(nil), canonicalMetadata[:len(canonicalMetadata)-1]...)
	metadataUnknown = append(metadataUnknown, []byte(`,"unknown":true}`)...)
	metadataWhitespace := append([]byte(" "), canonicalMetadata...)
	for _, value := range [][]byte{metadataDuplicate, metadataUnknown, metadataWhitespace, nil, bytes.Repeat([]byte("x"), 4097)} {
		if _, err := ParseMetadata(value); err == nil {
			t.Fatal("ambiguous metadata accepted")
		}
	}
}

func TestPF001CapacityHelperResponseRejectsEveryIncompletePhysicalProof(t *testing.T) {
	t.Parallel()
	request := mustHelperRequest(t, helperRequestInput(OperationReserve))
	metadata, _ := NewMetadata(request, request.Owner(), MetadataReserved)
	digest, _ := MetadataDigest(metadata)
	valid := helperResponse(request, digest, request.Owner(), string(MetadataReserved), string(OperationReserve))
	tests := []struct {
		name   string
		mutate func(*Response)
	}{
		{name: "schema", mutate: func(v *Response) { v.SchemaVersion = 0 }},
		{name: "operation", mutate: func(v *Response) { v.Operation = "shell" }},
		{name: "lease", mutate: func(v *Response) { v.LeaseID = "foreign" }},
		{name: "plan", mutate: func(v *Response) { v.PlanDigest = strings.Repeat("0", 64) }},
		{name: "pool", mutate: func(v *Response) { v.PoolID = "foreign" }},
		{name: "pool kind", mutate: func(v *Response) { v.PoolKind = "remote" }},
		{name: "bytes", mutate: func(v *Response) { v.Bytes = 0 }},
		{name: "owner", mutate: func(v *Response) { v.Owner = "/path" }},
		{name: "receipt", mutate: func(v *Response) { v.ReceiptToken = "foreign" }},
		{name: "metadata", mutate: func(v *Response) { v.MetadataDigest = "foreign" }},
		{name: "absent", mutate: func(v *Response) { v.Present = false }},
		{name: "oversized file", mutate: func(v *Response) { v.FileSizeBytes++ }},
		{name: "sparse", mutate: func(v *Response) { v.AllocatedBlockBytes = v.Bytes - 1 }},
		{name: "state", mutate: func(v *Response) { v.State = "transferred" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := valid
			test.mutate(&response)
			if _, err := CanonicalResponseLine(response); err == nil {
				t.Fatal("incomplete physical proof accepted")
			}
		})
	}
	transfer := valid
	transfer.Operation, transfer.State = string(OperationTransfer), "reserved"
	if _, err := CanonicalResponseLine(transfer); err == nil {
		t.Fatal("uncommitted transfer proof accepted")
	}
	deletion := valid
	deletion.Operation, deletion.State = string(OperationDeleteProof), "delete-approved"
	deletion.AllocatedBlockBytes = deletion.FileSizeBytes - 1
	if _, err := CanonicalResponseLine(deletion); err == nil {
		t.Fatal("sparse delete proof accepted")
	}
	if _, err := NewMetadata(request, "foreign", MetadataReserved); err == nil {
		t.Fatal("foreign reservation metadata owner accepted")
	}
	if _, err := NewMetadata(request, request.Owner(), "unknown"); err == nil {
		t.Fatal("unknown metadata state accepted")
	}
}

func TestPF001CapacityHelperServiceRoutesOnlyClosedOperations(t *testing.T) {
	t.Parallel()
	store := &recordingHelperStore{}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []RequestInput{
		helperRequestInput(OperationReserve),
		helperRequestInput(OperationInspect),
		withTransfer(helperRequestInput(OperationTransfer)),
		withTransfer(helperRequestInput(OperationActivateProjection)),
		withDelete(helperRequestInput(OperationDeleteProof), PriorTransferPending, "generation-1"),
	}
	for _, input := range inputs {
		request := mustHelperRequest(t, input)
		line, err := service.Execute(context.Background(), request.Arguments())
		if err != nil {
			t.Fatalf("Execute(%s)=%v", input.Operation, err)
		}
		response, err := ParseResponseLine(line)
		if err != nil || response.Operation != string(input.Operation) || response.ReceiptToken != request.ReceiptToken() {
			t.Fatalf("response(%s)=%+v,%v", input.Operation, response, err)
		}
	}
	if store.reserveCalls != 1 || store.inspectCalls != 1 || store.transferCalls != 1 ||
		store.activateCalls != 1 || store.deleteCalls != 1 {
		t.Fatalf("store calls=%+v", store)
	}
}

func TestPF001CapacityHelperServiceFailsWithoutACompleteProof(t *testing.T) {
	t.Parallel()
	var typedNil *recordingHelperStore
	if _, err := NewService(nil); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewService(typedNil); err == nil {
		t.Fatal("typed-nil store accepted")
	}
	request := mustHelperRequest(t, helperRequestInput(OperationReserve))
	store := &recordingHelperStore{fail: true}
	service, _ := NewService(store)
	if output, err := service.Execute(context.Background(), request.Arguments()); err == nil || len(output) != 0 {
		t.Fatalf("storage failure output=%q error=%v", output, err)
	}
	store.fail = false
	store.invalid = true
	if output, err := service.Execute(context.Background(), request.Arguments()); err == nil || len(output) != 0 {
		t.Fatalf("invalid proof output=%q error=%v", output, err)
	}
	//lint:ignore SA1012 Deliberate nil-context attack proves the helper fails before storage.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := service.Execute(nil, request.Arguments()); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Execute(ctx, request.Arguments()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	var absent *Service
	if _, err := absent.Execute(context.Background(), request.Arguments()); err == nil {
		t.Fatal("nil service accepted")
	}
}

func FuzzPF001CapacityHelperStrictParsers(f *testing.F) {
	request, _ := NewRequest(helperRequestInput(OperationReserve))
	metadata, _ := NewMetadata(request, request.Owner(), MetadataReserved)
	metadataBytes, _ := CanonicalMetadata(metadata)
	metadataDigest, _ := MetadataDigest(metadata)
	line, _ := CanonicalResponseLine(helperResponse(
		request, metadataDigest, request.Owner(), string(MetadataReserved), string(OperationReserve),
	))
	f.Add(line)
	f.Add(metadataBytes)
	f.Add([]byte(`{"bytes":1,"bytes":2}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) > MaximumResponseBytes+1 {
			data = data[:MaximumResponseBytes+1]
		}
		_, _ = ParseResponseLine(data)
		_, _ = ParseMetadata(data)
	})
}

type recordingHelperStore struct {
	reserveCalls  int
	inspectCalls  int
	transferCalls int
	activateCalls int
	deleteCalls   int
	fail          bool
	invalid       bool
}

func (s *recordingHelperStore) Reserve(_ context.Context, request Request) (Observation, error) {
	s.reserveCalls++
	return s.result(request, MetadataReserved)
}

func (s *recordingHelperStore) Inspect(_ context.Context, request Request) (Observation, error) {
	s.inspectCalls++
	return s.result(request, MetadataReserved)
}

func (s *recordingHelperStore) Transfer(_ context.Context, request Request) (Observation, error) {
	s.transferCalls++
	return s.result(request, MetadataTransferred)
}

func (s *recordingHelperStore) ActivateProjection(_ context.Context, request Request) (Observation, error) {
	s.activateCalls++
	metadata, err := NewMetadata(request, request.NewOwner(), MetadataTransferred)
	if err != nil || s.fail {
		return Observation{}, errors.New("store failed")
	}
	return Observation{
		AvailableBytes: 8192, Metadata: metadata, Owner: request.NewOwner(), State: "projection-ready",
	}, nil
}

func (s *recordingHelperStore) DeleteProof(_ context.Context, request Request) (Observation, error) {
	s.deleteCalls++
	state := MetadataReserved
	owner := request.Owner()
	if request.PriorState() == PriorTransferPending || request.PriorState() == PriorTransferred {
		state, owner = MetadataTransferred, request.AlternateOwner()
	}
	metadata, err := NewMetadata(request, owner, state)
	if err != nil {
		return Observation{}, err
	}
	if s.fail {
		return Observation{}, errors.New("store failed")
	}
	return Observation{
		AllocatedBlockBytes: request.Bytes(), AvailableBytes: 8192, FileSizeBytes: request.Bytes(),
		Metadata: metadata, Owner: owner, State: "delete-approved",
	}, nil
}

func (s *recordingHelperStore) result(request Request, state MetadataState) (Observation, error) {
	if s.fail {
		return Observation{}, errors.New("store failed")
	}
	owner := request.Owner()
	if state == MetadataTransferred {
		owner = request.NewOwner()
	}
	metadata, err := NewMetadata(request, owner, state)
	if err != nil {
		return Observation{}, err
	}
	result := Observation{
		AllocatedBlockBytes: request.Bytes(), AvailableBytes: 8192, FileSizeBytes: request.Bytes(),
		Metadata: metadata, Owner: owner, State: string(state),
	}
	if s.invalid {
		result.FileSizeBytes--
	}
	return result, nil
}

func helperRequestInput(operation Operation) RequestInput {
	return RequestInput{
		Operation: operation, LeaseID: "l-" + strings.Repeat("a", 64),
		PlanDigest: strings.Repeat("b", 64), PoolID: "d-" + strings.Repeat("c", 64),
		PoolKind: "docker-engine", Bytes: 4096, Owner: "install-owner",
	}
}

func withTransfer(input RequestInput) RequestInput {
	input.NewOwner = "generation-1"
	return input
}

func withDelete(input RequestInput, prior PriorState, alternate string) RequestInput {
	input.PriorState, input.AlternateOwner = prior, alternate
	return input
}

func mustHelperRequest(t *testing.T, input RequestInput) Request {
	t.Helper()
	request, err := NewRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func helperResponse(request Request, metadataDigest, owner, state, operation string) Response {
	return Response{
		AllocatedBlockBytes: request.Bytes(), AvailableBytes: 8192, Bytes: request.Bytes(),
		FileSizeBytes: request.Bytes(), LeaseID: request.LeaseID(), MetadataDigest: metadataDigest,
		Operation: operation, Owner: owner, PlanDigest: request.PlanDigest(), PoolID: request.PoolID(),
		PoolKind: request.PoolKind(), Present: true, ReceiptToken: request.ReceiptToken(),
		SchemaVersion: ProtocolVersion, State: state,
	}
}
