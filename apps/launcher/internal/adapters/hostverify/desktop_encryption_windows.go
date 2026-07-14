//go:build windows

package hostverify

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

// DesktopEncryptionAttestor reuses the packet-privacy WMI BitLocker worker for
// Docker Desktop host certification.
type DesktopEncryptionAttestor struct{ worker *bitLockerWorker }

// NewDesktopEncryptionAttestor creates a production native BitLocker attestor.
func NewDesktopEncryptionAttestor() (*DesktopEncryptionAttestor, error) {
	worker := newBitLockerWorker(newWindowsBitLockerBackend())
	if worker == nil {
		return nil, errBitLockerEvidence
	}
	return &DesktopEncryptionAttestor{worker: worker}, nil
}

// AttestWindowsVolumeEncryption requires conversion complete and protection on.
func (a *DesktopEncryptionAttestor) AttestWindowsVolumeEncryption(ctx context.Context, path string) error {
	if a == nil || a.worker == nil || ctx == nil {
		return errBitLockerEvidence
	}
	if !a.worker.attest(ctx, path) {
		return errBitLockerEvidence
	}
	return nil
}

// Close settles the dedicated COM worker.
func (a *DesktopEncryptionAttestor) Close(ctx context.Context) error {
	if a == nil || a.worker == nil {
		return errBitLockerEvidence
	}
	return a.worker.close(ctx)
}

var (
	_ runtimeport.DesktopWindowsEncryptionAttestor = (*DesktopEncryptionAttestor)(nil)
)
