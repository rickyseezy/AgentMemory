//go:build darwin && !cgo

package hostverify

// Disk Arbitration is required to prove the exact target's active encryption.
// A no-cgo Darwin build therefore rejects certification rather than guessing.
func darwinEncryptionAttested(string) bool { return false }
