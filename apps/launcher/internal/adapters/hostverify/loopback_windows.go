//go:build windows

package hostverify

import (
	"context"
	"net"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"golang.org/x/sys/windows"
)

const windowsExclusiveAddressUse = 0x4

func listenExclusiveLoopback(ctx context.Context, endpoint hostverification.LoopbackEndpoint) (net.Listener, error) {
	network, address, err := loopbackAddress(endpoint)
	if err != nil {
		return nil, err
	}
	configuration := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var controlError error
		if err := raw.Control(func(descriptor uintptr) {
			controlError = windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windowsExclusiveAddressUse, 1)
			if controlError == nil && endpoint.Family == hostverification.LoopbackIPv6 {
				controlError = windows.SetsockoptInt(windows.Handle(descriptor), windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 1)
			}
		}); err != nil {
			return err
		}
		return controlError
	}}
	return configuration.Listen(ctx, network, address)
}
