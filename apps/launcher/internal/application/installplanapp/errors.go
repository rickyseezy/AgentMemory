// Package installplanapp resolves immutable PF-001 phase projections from one
// canonical installation-plan repository.
package installplanapp

import "errors"

var (
	// ErrPlanNotFound means no canonical plan exists for the requested digest.
	ErrPlanNotFound = errors.New("canonical installation plan not found")
	// ErrPlanConflict means immutable content already exists under a contradictory binding.
	ErrPlanConflict = errors.New("canonical installation plan conflict")
	// ErrPlanIntegrity means durable bytes, digest, or projection bindings are invalid.
	ErrPlanIntegrity = errors.New("canonical installation plan integrity violation")
	// ErrRuntimePlanNotFound means no immutable nested runtime authority exists yet.
	ErrRuntimePlanNotFound = errors.New("operation runtime plan authority not found")
	// ErrRuntimePlanConflict means immutable runtime authority already exists but differs.
	ErrRuntimePlanConflict = errors.New("operation runtime plan authority conflict")
	// ErrRuntimePlanIntegrity means nested plan or evidence bindings are invalid.
	ErrRuntimePlanIntegrity = errors.New("operation runtime plan authority integrity violation")
	// ErrRuntimeEvidenceUnavailable means verified host, discovery, or catalog evidence could not be resolved.
	ErrRuntimeEvidenceUnavailable = errors.New("verified runtime plan evidence is unavailable")
	// ErrActivationEvidenceUnavailable means the completed operation, readiness
	// receipt, or exact resource inventory needed for activation is unavailable.
	ErrActivationEvidenceUnavailable = errors.New("authenticated activation evidence is unavailable")
)
