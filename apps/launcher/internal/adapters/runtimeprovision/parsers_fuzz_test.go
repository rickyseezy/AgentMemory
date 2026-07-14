package runtimeprovision

import "testing"

func FuzzStrictLinuxParsers(f *testing.F) {
	f.Add([]byte("ID=ubuntu\nVERSION_ID=24.04\n"))
	f.Add([]byte("alice:100000:65536\n"))
	f.Add([]byte("Name:\tdockerd\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n"))
	f.Add([]byte("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _, _ = parseOSRelease(raw)
		_, _ = parseSubordinateRanges(raw)
		_, _, _ = parseProcStatus(raw)
		_, _ = parseListeningTCPInodes(raw)
		_, _ = parseMemAvailable(raw)
		_, _ = parseContainerIDs(raw)
		_, _ = dockerGroupAbsent(raw, "agentmemory", map[uint32]struct{}{1000: {}})
	})
}
