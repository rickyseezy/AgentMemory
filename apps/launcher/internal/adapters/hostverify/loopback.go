package hostverify

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
)

func attestLoopback(ctx context.Context, endpoints []hostverification.LoopbackEndpoint) bool {
	listeners := make([]net.Listener, 0, len(endpoints))
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return false
		}
		listener, err := listenExclusiveLoopback(ctx, endpoint)
		if err != nil {
			return false
		}
		listeners = append(listeners, listener)
	}
	return true
}

func loopbackAddress(endpoint hostverification.LoopbackEndpoint) (string, string, error) {
	switch endpoint.Family {
	case hostverification.LoopbackIPv4:
		return "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(endpoint.Port))), nil
	case hostverification.LoopbackIPv6:
		return "tcp6", net.JoinHostPort("::1", strconv.Itoa(int(endpoint.Port))), nil
	default:
		return "", "", errors.New("unsupported loopback family")
	}
}
