//go:build darwin

package filesystem

import "context"

func ensureOperationStateFenceDirectory(
	ctx context.Context,
	configRoot string,
	operationDirectory string,
) error {
	return ensureDarwinOperationDirectory(ctx, configRoot, operationDirectory)
}
