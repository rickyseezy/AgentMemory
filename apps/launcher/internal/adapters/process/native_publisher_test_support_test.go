package process

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

type packageReceiptStub struct{}

func (packageReceiptStub) VerifyLinuxPackageReceipt(
	context.Context,
	argvprocess.ExecutableAuthority,
	ExecutableEvidence,
) error {
	return nil
}

type windowsSignerStub struct{}

func (windowsSignerStub) VerifyWindowsSignerIdentity(
	context.Context,
	argvprocess.ExecutableAuthority,
	ExecutableEvidence,
) error {
	return nil
}
