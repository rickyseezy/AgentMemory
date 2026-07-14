package install

// CancellationStatus is the authenticated aggregate-owned lifecycle of one
// cancellation request.
type CancellationStatus uint8

const (
	// CancellationUnknown is invalid or absent.
	CancellationUnknown CancellationStatus = iota
	// CancellationRequested requires the installer to stop and settle.
	CancellationRequested
	// CancellationAcknowledged proves terminal cancellation cleanup completed.
	CancellationAcknowledged
)

// CancellationRestoreInput is the persistence-neutral representation of the
// two monotonic aggregate versions in the cancellation lifecycle.
type CancellationRestoreInput struct {
	RequestedAtVersion    uint64
	AcknowledgedAtVersion uint64
}

// CancellationSnapshot is immutable aggregate evidence.
type CancellationSnapshot struct {
	requestedAtVersion    uint64
	acknowledgedAtVersion uint64
}

// Status returns the closed cancellation lifecycle value.
func (s CancellationSnapshot) Status() CancellationStatus {
	if s.requestedAtVersion == 0 {
		return CancellationUnknown
	}
	if s.acknowledgedAtVersion == 0 {
		return CancellationRequested
	}
	return CancellationAcknowledged
}

// RequestedAtVersion returns the aggregate CAS version that accepted intent.
func (s CancellationSnapshot) RequestedAtVersion() uint64 { return s.requestedAtVersion }

// AcknowledgedAtVersion returns zero until terminal settlement is durable.
func (s CancellationSnapshot) AcknowledgedAtVersion() uint64 { return s.acknowledgedAtVersion }

func restoreCancellation(
	input *CancellationRestoreInput,
	aggregateVersion uint64,
	state State,
) (*CancellationSnapshot, error) {
	if input == nil {
		return nil, nil
	}
	if input.RequestedAtVersion == 0 || input.RequestedAtVersion > aggregateVersion {
		return nil, newIntegrityError("cancellation request version is invalid")
	}
	if input.AcknowledgedAtVersion != 0 {
		if input.AcknowledgedAtVersion <= input.RequestedAtVersion ||
			input.AcknowledgedAtVersion > aggregateVersion || state != StateCancelled {
			return nil, newIntegrityError("cancellation acknowledgement is impossible")
		}
	}
	if state.Terminal() && state != StateCancelled {
		return nil, newIntegrityError("terminal non-cancelled state retains cancellation intent")
	}
	return &CancellationSnapshot{
		requestedAtVersion:    input.RequestedAtVersion,
		acknowledgedAtVersion: input.AcknowledgedAtVersion,
	}, nil
}
