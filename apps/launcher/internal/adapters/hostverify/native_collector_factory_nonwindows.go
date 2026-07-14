//go:build !windows

package hostverify

func newNativeCollector() collector { return nativeCollector{} }
