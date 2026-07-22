package hostverify

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const testVolumeID = `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\`

func TestPF001BitLockerQueryTargetsOneEscapedVolumeIdentity(t *testing.T) {
	t.Parallel()
	query, err := exactBitLockerQuery(testVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	want := `SELECT * FROM Win32_EncryptableVolume WHERE DeviceID = '\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\'`
	if query != want {
		t.Fatalf("query = %q, want %q", query, want)
	}
	if got := escapeWQLString(`a\b'c"d`); got != `a\\b\'c\"d` {
		t.Fatalf("escaped WQL value = %q", got)
	}
	for _, invalid := range []string{
		"", `C:\`, `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}`,
		`\\?\Volume{01234567-89ab-cdef-0123-456789abcdeg}\`,
		`\\?\Volume{01234567_89ab-cdef-0123-456789abcdef}\`,
		`\\?\volume{01234567-89ab-cdef-0123-456789abcdef}\`,
		`\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\' OR 1=1`,
	} {
		if _, err := exactBitLockerQuery(invalid); !errors.Is(err, errBitLockerEvidence) {
			t.Fatalf("exactBitLockerQuery(%q) error = %v", invalid, err)
		}
	}
}

func TestPF001WMIBitLockerSessionRequiresExactLiveMethodEvidence(t *testing.T) {
	t.Parallel()
	fixture := newBitLockerWMIFixture()
	session := &wmiBitLockerSession{service: fixture.service}
	snapshot, err := session.snapshot(context.Background(), testVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.compliantWith(testVolumeID) {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if len(fixture.service.queries) != 1 || fixture.service.queries[0] != mustBitLockerQuery(t, testVolumeID) {
		t.Fatalf("queries = %#v", fixture.service.queries)
	}
	wantMethods := []string{"GetConversionStatus", "GetProtectionStatus"}
	if !equalStrings(fixture.record.invocations, wantMethods) {
		t.Fatalf("method calls = %#v", fixture.record.invocations)
	}
	if len(fixture.record.inputs) != 2 || len(fixture.record.inputs[0]) != 1 ||
		fixture.record.inputs[0][0] != (bitLockerInput{name: "PrecisionFactor", value: bitLockerI4(0)}) ||
		len(fixture.record.inputs[1]) != 0 {
		t.Fatalf("method inputs = %#v", fixture.record.inputs)
	}
	if fixture.record.propertyCalls != 2 {
		t.Fatalf("DeviceID property calls = %d", fixture.record.propertyCalls)
	}
	if !fixture.result.closed || !fixture.record.closed || !fixture.conversion.closed || !fixture.protection.closed {
		t.Fatal("WMI automation objects were not released deterministically")
	}
	session.close()
	if !fixture.service.closed {
		t.Fatal("WMI service was not closed")
	}
}

func TestPF001WMIBitLockerSessionRejectsMalformedOrAmbiguousEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*bitLockerWMIFixture)
		ctx    func() context.Context
	}{
		{name: "query failure", mutate: func(f *bitLockerWMIFixture) { f.service.queryErr = errors.New("provider unavailable") }},
		{name: "nil query result", mutate: func(f *bitLockerWMIFixture) { f.service.nilResult = true }},
		{name: "count failure", mutate: func(f *bitLockerWMIFixture) { f.result.countErr = errors.New("count") }},
		{name: "count type drift", mutate: func(f *bitLockerWMIFixture) {
			f.result.countValue = bitLockerValue{kind: bitLockerValueBSTR, text: "1"}
		}},
		{name: "zero records", mutate: func(f *bitLockerWMIFixture) { f.result.countValue = bitLockerI4(0) }},
		{name: "duplicate records", mutate: func(f *bitLockerWMIFixture) { f.result.countValue = bitLockerI4(2) }},
		{name: "negative count", mutate: func(f *bitLockerWMIFixture) { f.result.countValue = bitLockerI4(-1) }},
		{name: "item failure", mutate: func(f *bitLockerWMIFixture) { f.result.itemErr = errors.New("item") }},
		{name: "device type drift", mutate: func(f *bitLockerWMIFixture) { f.record.deviceIDs = []bitLockerValue{bitLockerI4(1)} }},
		{name: "wrong device", mutate: func(f *bitLockerWMIFixture) {
			f.record.deviceIDs = []bitLockerValue{bitLockerBSTR(`\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\`)}
		}},
		{name: "conversion invocation failure", mutate: func(f *bitLockerWMIFixture) { f.record.invokeErrAt = 1 }},
		{name: "conversion return type drift", mutate: func(f *bitLockerWMIFixture) { f.conversion.properties["ReturnValue"] = bitLockerBSTR("0") }},
		{name: "conversion provider failure", mutate: func(f *bitLockerWMIFixture) { f.conversion.properties["ReturnValue"] = bitLockerI4(1) }},
		{name: "conversion status type drift", mutate: func(f *bitLockerWMIFixture) { f.conversion.properties["ConversionStatus"] = bitLockerBSTR("1") }},
		{name: "percentage type drift", mutate: func(f *bitLockerWMIFixture) { f.conversion.properties["EncryptionPercentage"] = bitLockerBSTR("100") }},
		{name: "protection invocation failure", mutate: func(f *bitLockerWMIFixture) { f.record.invokeErrAt = 2 }},
		{name: "protection return type drift", mutate: func(f *bitLockerWMIFixture) { f.protection.properties["ReturnValue"] = bitLockerBSTR("0") }},
		{name: "protection provider failure", mutate: func(f *bitLockerWMIFixture) { f.protection.properties["ReturnValue"] = bitLockerI4(1) }},
		{name: "protection status type drift", mutate: func(f *bitLockerWMIFixture) { f.protection.properties["ProtectionStatus"] = bitLockerBSTR("1") }},
		{name: "post-call device substitution", mutate: func(f *bitLockerWMIFixture) {
			f.record.deviceIDs = []bitLockerValue{
				bitLockerBSTR(testVolumeID),
				bitLockerBSTR(`\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\`),
			}
		}},
		{name: "cancelled", ctx: cancelledContext},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBitLockerWMIFixture()
			if test.mutate != nil {
				test.mutate(fixture)
			}
			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx()
			}
			_, err := (&wmiBitLockerSession{service: fixture.service}).snapshot(ctx, testVolumeID)
			if err == nil {
				t.Fatal("malformed evidence was accepted")
			}
		})
	}
	if _, err := (&wmiBitLockerSession{}).snapshot(context.Background(), testVolumeID); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("uninitialized session error = %v", err)
	}
	fixture := newBitLockerWMIFixture()
	if _, err := (&wmiBitLockerSession{service: fixture.service}).snapshot(context.Background(), "invalid"); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("invalid volume identity error = %v", err)
	}
	if _, err := (*wmiBitLockerSession)(nil).snapshot(context.Background(), testVolumeID); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("nil session error = %v", err)
	}
	var absent context.Context
	if _, err := (&wmiBitLockerSession{service: fixture.service}).snapshot(absent, testVolumeID); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestPF001BitLockerBackendRebindsExactVolumeAndRejectsNoncompliance(t *testing.T) {
	t.Parallel()
	compliant := bitLockerSnapshot{volumeID: testVolumeID, conversionStatus: 1, encryptionPercentage: 100, protectionStatus: 1}
	tests := []struct {
		name      string
		resolver  *fakeBitLockerResolver
		session   *fakeBitLockerStatusSession
		want      bool
		cancelled bool
	}{
		{name: "compliant", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID, testVolumeID}}, session: &fakeBitLockerStatusSession{snapshotValue: compliant}, want: true},
		{name: "first resolve failure", resolver: &fakeBitLockerResolver{errAt: 1}, session: &fakeBitLockerStatusSession{snapshotValue: compliant}},
		{name: "provider failure", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID}}, session: &fakeBitLockerStatusSession{err: errors.New("provider")}},
		{name: "path rebound", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID, `\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\`}}, session: &fakeBitLockerStatusSession{snapshotValue: compliant}},
		{name: "reported identity mismatch", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID, testVolumeID}}, session: &fakeBitLockerStatusSession{snapshotValue: bitLockerSnapshot{volumeID: `\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\`, conversionStatus: 1, encryptionPercentage: 100, protectionStatus: 1}}},
		{name: "partially encrypted", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID, testVolumeID}}, session: &fakeBitLockerStatusSession{snapshotValue: bitLockerSnapshot{volumeID: testVolumeID, conversionStatus: 2, encryptionPercentage: 75, protectionStatus: 1}}},
		{name: "percentage incomplete", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID, testVolumeID}}, session: &fakeBitLockerStatusSession{snapshotValue: bitLockerSnapshot{volumeID: testVolumeID, conversionStatus: 1, encryptionPercentage: 99, protectionStatus: 1}}},
		{name: "protection suspended", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID, testVolumeID}}, session: &fakeBitLockerStatusSession{snapshotValue: bitLockerSnapshot{volumeID: testVolumeID, conversionStatus: 1, encryptionPercentage: 100, protectionStatus: 0}}},
		{name: "cancelled", resolver: &fakeBitLockerResolver{ids: []string{testVolumeID, testVolumeID}}, session: &fakeBitLockerStatusSession{snapshotValue: compliant}, cancelled: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			factory := &fakeBitLockerSessionFactory{session: test.session}
			backend := &bitLockerAttestationBackend{resolver: test.resolver, factory: factory}
			if err := backend.open(); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if test.cancelled {
				ctx = cancelledContext()
			}
			if got := backend.attest(ctx, `C:\Users\person\AgentMemory`); got != test.want {
				t.Fatalf("attest() = %v, want %v", got, test.want)
			}
			backend.close()
			if !test.session.closed {
				t.Fatal("session was not closed")
			}
		})
	}

	if err := (&bitLockerAttestationBackend{}).open(); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("uninitialized backend error = %v", err)
	}
	if (&bitLockerAttestationBackend{}).attest(context.Background(), `C:\target`) {
		t.Fatal("uninitialized backend attested a volume")
	}
	if (*bitLockerAttestationBackend)(nil).attest(context.Background(), `C:\target`) {
		t.Fatal("nil backend attested a volume")
	}
	openFailure := &bitLockerAttestationBackend{
		resolver: &fakeBitLockerResolver{},
		factory:  &fakeBitLockerSessionFactory{err: errors.New("namespace unavailable")},
	}
	if err := openFailure.open(); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("provider open error = %v", err)
	}
}

func TestPF001BitLockerWorkerSerializesRequestsAndShutsDown(t *testing.T) {
	backend := newBlockingBitLockerWorkerBackend()
	worker := newBitLockerWorker(backend)
	results := make(chan bool, 2)
	go func() { results <- worker.attest(context.Background(), `C:\first`) }()
	if !waitClosed(backend.opened) {
		t.Fatal("worker did not initialize")
	}
	if !waitClosed(backend.started) {
		t.Fatal("first request did not start")
	}
	go func() { results <- worker.attest(context.Background(), `C:\second`) }()
	time.Sleep(10 * time.Millisecond)
	backend.release <- struct{}{}
	backend.release <- struct{}{}
	for range 2 {
		if !<-results {
			t.Fatal("serialized request failed")
		}
	}
	if backend.maximumConcurrent() != 1 || backend.attestationCount() != 2 {
		t.Fatalf("concurrency = %d, calls = %d", backend.maximumConcurrent(), backend.attestationCount())
	}
	if err := worker.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !backend.wasClosed() {
		t.Fatal("worker backend was not closed")
	}
	if worker.attest(context.Background(), `C:\after-close`) {
		t.Fatal("closed worker accepted a request")
	}
	if err := worker.close(context.Background()); err != nil {
		t.Fatalf("idempotent close = %v", err)
	}
}

func TestPF001BitLockerWorkerHonorsCancellationWithoutUnboundedWork(t *testing.T) {
	backend := newBlockingBitLockerWorkerBackend()
	worker := newBitLockerWorker(backend)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- worker.attest(ctx, `C:\blocked`) }()
	if !waitClosed(backend.opened) {
		t.Fatal("worker did not initialize")
	}
	if !waitClosed(backend.started) {
		t.Fatal("blocked work did not start")
	}
	cancel()
	if <-result {
		t.Fatal("timed-out work succeeded")
	}
	if backend.attestationCount() != 1 || backend.maximumConcurrent() != 1 {
		t.Fatalf("calls = %d, concurrency = %d", backend.attestationCount(), backend.maximumConcurrent())
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer closeCancel()
	if err := worker.close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded close error = %v", err)
	}
	backend.release <- struct{}{}
	if err := worker.close(context.Background()); err != nil {
		t.Fatalf("eventual close = %v", err)
	}
	if worker.attest(cancelledContext(), `C:\cancelled`) {
		t.Fatal("cancelled request succeeded")
	}
	var absent context.Context
	if worker.attest(absent, `C:\nil`) {
		t.Fatal("nil-context request succeeded")
	}
}

func TestPF001BitLockerWorkerDoesNotInitializeCOMWhenClosedUnused(t *testing.T) {
	t.Parallel()
	backend := &fixedBitLockerWorkerBackend{}
	worker := newBitLockerWorker(backend)
	if err := worker.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.openCalls != 0 || !backend.closed {
		t.Fatalf("unused worker initialization/close = %d/%v", backend.openCalls, backend.closed)
	}
}

func TestPF001BitLockerWorkerFailsClosedWhenCOMInitializationFails(t *testing.T) {
	t.Parallel()
	backend := &fixedBitLockerWorkerBackend{openErr: errors.New("COM unavailable")}
	worker := newBitLockerWorker(backend)
	if worker.attest(context.Background(), `C:\target`) {
		t.Fatal("worker with failed COM initialization succeeded")
	}
	if err := worker.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !backend.closed {
		t.Fatal("failed backend was not closed")
	}
	if (*bitLockerWorker)(nil).attest(context.Background(), `C:\target`) {
		t.Fatal("nil worker succeeded")
	}
	if err := (*bitLockerWorker)(nil).close(context.Background()); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("nil worker close error = %v", err)
	}
	var nilContext context.Context
	if err := worker.close(nilContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context close error = %v", err)
	}

	nilBackendWorker := newBitLockerWorker(nil)
	if nilBackendWorker.attest(context.Background(), `C:\target`) {
		t.Fatal("nil-backend worker succeeded")
	}
	if nilBackendWorker.attest(context.Background(), "") {
		t.Fatal("empty-path worker request succeeded")
	}
	if err := nilBackendWorker.close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func mustBitLockerQuery(t *testing.T, volumeID string) string {
	t.Helper()
	query, err := exactBitLockerQuery(volumeID)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type bitLockerWMIFixture struct {
	service    *fakeBitLockerQueryService
	result     *fakeBitLockerSet
	record     *fakeBitLockerObject
	conversion *fakeBitLockerObject
	protection *fakeBitLockerObject
}

func newBitLockerWMIFixture() *bitLockerWMIFixture {
	conversion := &fakeBitLockerObject{properties: map[string]bitLockerValue{
		"ReturnValue": bitLockerI4(0), "ConversionStatus": bitLockerI4(1),
		"EncryptionPercentage": bitLockerI4(100),
	}}
	protection := &fakeBitLockerObject{properties: map[string]bitLockerValue{
		"ReturnValue": bitLockerI4(0), "ProtectionStatus": bitLockerI4(1),
	}}
	record := &fakeBitLockerObject{
		deviceIDs: []bitLockerValue{bitLockerBSTR(testVolumeID)},
		outputs:   []*fakeBitLockerObject{conversion, protection},
	}
	result := &fakeBitLockerSet{countValue: bitLockerI4(1), object: record}
	return &bitLockerWMIFixture{
		service: &fakeBitLockerQueryService{result: result}, result: result,
		record: record, conversion: conversion, protection: protection,
	}
}

type fakeBitLockerQueryService struct {
	queries   []string
	result    *fakeBitLockerSet
	queryErr  error
	nilResult bool
	closed    bool
}

func (s *fakeBitLockerQueryService) query(query string) (bitLockerAutomationSet, error) {
	s.queries = append(s.queries, query)
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	if s.nilResult {
		return nil, nil
	}
	return s.result, nil
}

func (s *fakeBitLockerQueryService) close() { s.closed = true }

type fakeBitLockerSet struct {
	countValue bitLockerValue
	countErr   error
	object     *fakeBitLockerObject
	itemErr    error
	closed     bool
}

func (s *fakeBitLockerSet) count() (bitLockerValue, error) { return s.countValue, s.countErr }
func (s *fakeBitLockerSet) item(uint32) (bitLockerAutomationObject, error) {
	if s.itemErr != nil {
		return nil, s.itemErr
	}
	return s.object, nil
}
func (s *fakeBitLockerSet) close() { s.closed = true }

type fakeBitLockerObject struct {
	properties    map[string]bitLockerValue
	deviceIDs     []bitLockerValue
	propertyCalls int
	outputs       []*fakeBitLockerObject
	invokeErrAt   int
	invocations   []string
	inputs        [][]bitLockerInput
	closed        bool
}

func (o *fakeBitLockerObject) property(name string) (bitLockerValue, error) {
	if name == "DeviceID" {
		index := o.propertyCalls
		o.propertyCalls++
		if len(o.deviceIDs) == 0 {
			return bitLockerValue{}, errors.New("missing DeviceID")
		}
		if index >= len(o.deviceIDs) {
			index = len(o.deviceIDs) - 1
		}
		return o.deviceIDs[index], nil
	}
	value, ok := o.properties[name]
	if !ok {
		return bitLockerValue{}, errors.New("missing property")
	}
	return value, nil
}

func (o *fakeBitLockerObject) invoke(method string, inputs []bitLockerInput) (bitLockerAutomationObject, error) {
	o.invocations = append(o.invocations, method)
	o.inputs = append(o.inputs, append([]bitLockerInput(nil), inputs...))
	if o.invokeErrAt == len(o.invocations) {
		return nil, errors.New("method unavailable")
	}
	index := len(o.invocations) - 1
	if index >= len(o.outputs) {
		return nil, errors.New("missing output")
	}
	return o.outputs[index], nil
}

func (o *fakeBitLockerObject) close() { o.closed = true }

type fakeBitLockerResolver struct {
	ids   []string
	errAt int
	calls int
}

func (r *fakeBitLockerResolver) resolve(ctx context.Context, _ string) (string, error) {
	r.calls++
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.errAt == r.calls || len(r.ids) == 0 {
		return "", errors.New("volume unavailable")
	}
	index := r.calls - 1
	if index >= len(r.ids) {
		index = len(r.ids) - 1
	}
	return r.ids[index], nil
}

type fakeBitLockerStatusSession struct {
	snapshotValue bitLockerSnapshot
	err           error
	closed        bool
}

func (s *fakeBitLockerStatusSession) snapshot(context.Context, string) (bitLockerSnapshot, error) {
	return s.snapshotValue, s.err
}
func (s *fakeBitLockerStatusSession) close() { s.closed = true }

type fakeBitLockerSessionFactory struct {
	session *fakeBitLockerStatusSession
	err     error
}

func (f *fakeBitLockerSessionFactory) open() (bitLockerStatusSession, error) {
	return f.session, f.err
}

type blockingBitLockerWorkerBackend struct {
	opened  chan struct{}
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	active  int
	maximum int
	calls   int
	closed  bool
}

func newBlockingBitLockerWorkerBackend() *blockingBitLockerWorkerBackend {
	return &blockingBitLockerWorkerBackend{
		opened: make(chan struct{}), started: make(chan struct{}), release: make(chan struct{}, 2),
	}
}

func (b *blockingBitLockerWorkerBackend) open() error {
	close(b.opened)
	return nil
}

func (b *blockingBitLockerWorkerBackend) attest(context.Context, string) bool {
	b.mu.Lock()
	b.calls++
	b.active++
	if b.active > b.maximum {
		b.maximum = b.active
	}
	b.once.Do(func() { close(b.started) })
	b.mu.Unlock()
	<-b.release
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
	return true
}

func (b *blockingBitLockerWorkerBackend) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
}

func (b *blockingBitLockerWorkerBackend) maximumConcurrent() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maximum
}

func (b *blockingBitLockerWorkerBackend) attestationCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *blockingBitLockerWorkerBackend) wasClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

type fixedBitLockerWorkerBackend struct {
	openErr   error
	openCalls int
	closed    bool
}

func (b *fixedBitLockerWorkerBackend) open() error {
	b.openCalls++
	return b.openErr
}
func (b *fixedBitLockerWorkerBackend) attest(context.Context, string) bool { return true }
func (b *fixedBitLockerWorkerBackend) close()                              { b.closed = true }

func waitClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	case <-time.After(time.Second):
		return false
	}
}
