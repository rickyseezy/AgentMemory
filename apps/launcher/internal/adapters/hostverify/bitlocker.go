package hostverify

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
)

const (
	bitLockerFullyEncrypted       = int32(1)
	bitLockerEncryptionComplete   = int32(100)
	bitLockerProtectionEnabled    = int32(1)
	bitLockerWorkerQueueCapacity  = 1
	bitLockerConversionMethod     = "GetConversionStatus"
	bitLockerProtectionMethod     = "GetProtectionStatus"
	bitLockerVolumeClass          = "Win32_EncryptableVolume"
	bitLockerDeviceIDProperty     = "DeviceID"
	bitLockerReturnValueProperty  = "ReturnValue"
	bitLockerConversionProperty   = "ConversionStatus"
	bitLockerPercentageProperty   = "EncryptionPercentage"
	bitLockerProtectionProperty   = "ProtectionStatus"
	bitLockerPrecisionFactorInput = "PrecisionFactor"
)

var errBitLockerEvidence = errors.New("bitlocker evidence is unavailable")

type bitLockerValueKind uint8

const (
	bitLockerValueI4 bitLockerValueKind = iota + 1
	bitLockerValueBSTR
)

// bitLockerValue retains the exact Automation type. WMI represents CIM
// uint32 as VT_I4; accepting converted strings or alternate VARIANT types
// would hide provider/schema drift.
type bitLockerValue struct {
	kind bitLockerValueKind
	i4   int32
	text string
}

func bitLockerI4(value int32) bitLockerValue {
	return bitLockerValue{kind: bitLockerValueI4, i4: value}
}

func bitLockerBSTR(value string) bitLockerValue {
	return bitLockerValue{kind: bitLockerValueBSTR, text: value}
}

type bitLockerInput struct {
	name  string
	value bitLockerValue
}

type bitLockerAutomationObject interface {
	property(string) (bitLockerValue, error)
	invoke(string, []bitLockerInput) (bitLockerAutomationObject, error)
	close()
}

type bitLockerAutomationSet interface {
	count() (bitLockerValue, error)
	item(uint32) (bitLockerAutomationObject, error)
	close()
}

type bitLockerQueryService interface {
	query(string) (bitLockerAutomationSet, error)
	close()
}

type bitLockerSnapshot struct {
	volumeID             string
	conversionStatus     int32
	encryptionPercentage int32
	protectionStatus     int32
}

func (s bitLockerSnapshot) compliantWith(volumeID string) bool {
	return validBitLockerVolumeID(volumeID) && s.volumeID == volumeID &&
		s.conversionStatus == bitLockerFullyEncrypted &&
		s.encryptionPercentage == bitLockerEncryptionComplete &&
		s.protectionStatus == bitLockerProtectionEnabled
}

type bitLockerStatusSession interface {
	snapshot(context.Context, string) (bitLockerSnapshot, error)
	close()
}

// wmiBitLockerSession owns only the fail-closed WMI decision protocol. The
// Windows adapter below it owns COM and translates VARIANTs without coercion.
type wmiBitLockerSession struct{ service bitLockerQueryService }

func (s *wmiBitLockerSession) snapshot(
	ctx context.Context,
	volumeID string,
) (bitLockerSnapshot, error) {
	if ctx == nil {
		return bitLockerSnapshot{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return bitLockerSnapshot{}, err
	}
	if s == nil || s.service == nil {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	query, err := exactBitLockerQuery(volumeID)
	if err != nil {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	result, err := s.service.query(query)
	if err != nil || result == nil {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	defer result.close()
	count, err := result.count()
	if err != nil || count.kind != bitLockerValueI4 || count.i4 != 1 {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	record, err := result.item(0)
	if err != nil || record == nil {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	defer record.close()
	if !exactBitLockerDevice(record, volumeID) {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}

	conversion, err := record.invoke(bitLockerConversionMethod, []bitLockerInput{{
		name: bitLockerPrecisionFactorInput, value: bitLockerI4(0),
	}})
	if err != nil || conversion == nil {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	defer conversion.close()
	conversionReturn, ok := exactBitLockerI4(conversion, bitLockerReturnValueProperty)
	if !ok || conversionReturn != 0 {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	conversionStatus, ok := exactBitLockerI4(conversion, bitLockerConversionProperty)
	if !ok {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	encryptionPercentage, ok := exactBitLockerI4(conversion, bitLockerPercentageProperty)
	if !ok {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	if err := ctx.Err(); err != nil {
		return bitLockerSnapshot{}, err
	}

	protection, err := record.invoke(bitLockerProtectionMethod, nil)
	if err != nil || protection == nil {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	defer protection.close()
	protectionReturn, ok := exactBitLockerI4(protection, bitLockerReturnValueProperty)
	if !ok || protectionReturn != 0 {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	protectionStatus, ok := exactBitLockerI4(protection, bitLockerProtectionProperty)
	if !ok || !exactBitLockerDevice(record, volumeID) {
		return bitLockerSnapshot{}, errBitLockerEvidence
	}
	if err := ctx.Err(); err != nil {
		return bitLockerSnapshot{}, err
	}
	return bitLockerSnapshot{
		volumeID: volumeID, conversionStatus: conversionStatus,
		encryptionPercentage: encryptionPercentage, protectionStatus: protectionStatus,
	}, nil
}

func (s *wmiBitLockerSession) close() {
	if s != nil && s.service != nil {
		s.service.close()
	}
}

func exactBitLockerI4(object bitLockerAutomationObject, property string) (int32, bool) {
	value, err := object.property(property)
	return value.i4, err == nil && value.kind == bitLockerValueI4
}

func exactBitLockerDevice(object bitLockerAutomationObject, volumeID string) bool {
	value, err := object.property(bitLockerDeviceIDProperty)
	return err == nil && value.kind == bitLockerValueBSTR && value.text == volumeID
}

func exactBitLockerQuery(volumeID string) (string, error) {
	if !validBitLockerVolumeID(volumeID) {
		return "", errBitLockerEvidence
	}
	return "SELECT * FROM " + bitLockerVolumeClass + " WHERE " +
		bitLockerDeviceIDProperty + " = '" + escapeWQLString(volumeID) + "'", nil
}

// escapeWQLString follows WQL's backslash escaping rules for backslashes and
// both quote characters. Volume IDs are validated before this is used, making
// the exact equality query non-extensible by input data.
func escapeWQLString(value string) string {
	var escaped strings.Builder
	escaped.Grow(len(value) * 2)
	for _, character := range value {
		switch character {
		case '\\', '\'', '"':
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(character)
	}
	return escaped.String()
}

func validBitLockerVolumeID(value string) bool {
	const (
		prefix = `\\?\Volume{`
		suffix = `}\`
	)
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) ||
		len(value) != len(prefix)+36+len(suffix) {
		return false
	}
	identifier := value[len(prefix) : len(prefix)+36]
	for index, character := range identifier {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'f') &&
				(character < 'A' || character > 'F') {
				return false
			}
		}
	}
	return true
}

type bitLockerVolumeResolver interface {
	resolve(context.Context, string) (string, error)
}

type bitLockerSessionFactory interface {
	open() (bitLockerStatusSession, error)
}

type bitLockerAttestationBackend struct {
	resolver bitLockerVolumeResolver
	factory  bitLockerSessionFactory
	session  bitLockerStatusSession
}

func (b *bitLockerAttestationBackend) open() error {
	if b == nil || b.resolver == nil || b.factory == nil || b.session != nil {
		return errBitLockerEvidence
	}
	session, err := b.factory.open()
	if err != nil || session == nil {
		return errBitLockerEvidence
	}
	b.session = session
	return nil
}

func (b *bitLockerAttestationBackend) attest(ctx context.Context, path string) bool {
	if ctx == nil || b == nil || b.resolver == nil || b.session == nil || path == "" {
		return false
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	boundVolume, err := b.resolver.resolve(ctx, path)
	if err != nil || !validBitLockerVolumeID(boundVolume) {
		return false
	}
	snapshot, err := b.session.snapshot(ctx, boundVolume)
	if err != nil || ctx.Err() != nil {
		return false
	}
	reboundVolume, err := b.resolver.resolve(ctx, path)
	if err != nil || ctx.Err() != nil || reboundVolume != boundVolume {
		return false
	}
	return snapshot.compliantWith(boundVolume)
}

func (b *bitLockerAttestationBackend) close() {
	if b != nil && b.session != nil {
		b.session.close()
		b.session = nil
	}
}

type bitLockerWorkerBackend interface {
	open() error
	attest(context.Context, string) bool
	close()
}

type bitLockerRequest struct {
	ctx    context.Context
	path   string
	result chan bool
}

// bitLockerWorker bounds all potentially blocking COM work to one request
// queue and one locked OS-thread goroutine. A caller's deadline never creates
// a replacement goroutine; if WMI stalls, future requests remain bounded by
// the same worker and fail when their contexts expire.
type bitLockerWorker struct {
	backend     bitLockerWorkerBackend
	requests    chan bitLockerRequest
	ready       chan struct{}
	stop        chan struct{}
	stopped     chan struct{}
	closeOne    sync.Once
	initialized bool
	opened      bool
}

func newBitLockerWorker(backend bitLockerWorkerBackend) *bitLockerWorker {
	worker := &bitLockerWorker{
		backend: backend, requests: make(chan bitLockerRequest, bitLockerWorkerQueueCapacity),
		ready: make(chan struct{}), stop: make(chan struct{}), stopped: make(chan struct{}),
	}
	go worker.run()
	return worker
}

func (w *bitLockerWorker) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(w.stopped)
	if w.backend == nil {
		close(w.ready)
		<-w.stop
		return
	}
	defer w.backend.close()
	close(w.ready)
	for {
		select {
		case <-w.stop:
			return
		default:
		}
		select {
		case <-w.stop:
			return
		case request := <-w.requests:
			if !w.initialized {
				w.opened = w.backend.open() == nil
				w.initialized = true
			}
			accepted := w.opened && request.ctx.Err() == nil && w.backend.attest(request.ctx, request.path)
			accepted = accepted && request.ctx.Err() == nil
			request.result <- accepted
		}
	}
}

func (w *bitLockerWorker) attest(ctx context.Context, path string) bool {
	if ctx == nil || w == nil || w.backend == nil || path == "" {
		return false
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-w.stop:
		return false
	case <-w.ready:
	}
	select {
	case <-w.stop:
		return false
	default:
	}
	request := bitLockerRequest{ctx: ctx, path: path, result: make(chan bool, 1)}
	select {
	case <-ctx.Done():
		return false
	case <-w.stop:
		return false
	case w.requests <- request:
	}
	select {
	case <-ctx.Done():
		return false
	case <-w.stop:
		return false
	case <-w.stopped:
		return false
	case accepted := <-request.result:
		return accepted
	}
}

func (w *bitLockerWorker) close(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if w == nil {
		return errBitLockerEvidence
	}
	w.closeOne.Do(func() { close(w.stop) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.stopped:
		return nil
	}
}
