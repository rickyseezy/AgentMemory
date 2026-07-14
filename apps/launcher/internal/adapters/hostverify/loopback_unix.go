//go:build darwin || linux

package hostverify

import (
	"context"
	"net"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"golang.org/x/sys/unix"
)

func listenExclusiveLoopback(ctx context.Context, endpoint hostverification.LoopbackEndpoint) (net.Listener, error) {
	network, address, err := loopbackAddress(endpoint)
	if err != nil {
		return nil, err
	}
	configuration := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var controlError error
		if err := raw.Control(func(descriptor uintptr) {
			controlError = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_REUSEADDR, 0)
			if controlError == nil && endpoint.Family == hostverification.LoopbackIPv6 {
				controlError = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
			}
		}); err != nil {
			return err
		}
		return controlError
	}}
	return configuration.Listen(ctx, network, address)
}
