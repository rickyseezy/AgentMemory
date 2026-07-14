package setuphost

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPF001SetupURLAcceptsOnlyExactOneUseIPv4LoopbackAuthority(t *testing.T) {
	t.Parallel()

	capability := base64.RawURLEncoding.EncodeToString(bytesOf(7, setupCapabilityBytes))
	valid := "http://127.0.0.1:49152/#capability=" + capability
	if err := validateSetupURL(valid); err != nil {
		t.Fatalf("validateSetupURL(valid) error = %v", err)
	}
	tests := map[string]string{
		"empty":                "",
		"https":                strings.Replace(valid, "http://", "https://", 1),
		"localhost alias":      strings.Replace(valid, "127.0.0.1", "localhost", 1),
		"IPv6":                 strings.Replace(valid, "127.0.0.1", "[::1]", 1),
		"remote":               strings.Replace(valid, "127.0.0.1", "192.0.2.1", 1),
		"userinfo":             strings.Replace(valid, "127.0.0.1", "user@127.0.0.1", 1),
		"zero port":            strings.Replace(valid, ":49152", ":0", 1),
		"missing port":         strings.Replace(valid, ":49152", "", 1),
		"overflow port":        strings.Replace(valid, ":49152", ":65536", 1),
		"path":                 strings.Replace(valid, "/#", "/setup/#", 1),
		"query":                strings.Replace(valid, "/#", "/?x=1#", 1),
		"empty query":          strings.Replace(valid, "/#", "/?#", 1),
		"wrong fragment key":   strings.Replace(valid, "capability=", "token=", 1),
		"duplicate capability": valid + "&capability=" + capability,
		"additional fragment":  valid + "&next=1",
		"padded capability":    valid + "=",
		"short capability":     strings.TrimSuffix(valid, capability) + capability[:42],
		"escaped capability":   strings.TrimSuffix(valid, capability) + "%5F" + capability[1:],
		"newline":              valid + "\n",
	}
	for name, candidate := range tests {
		candidate := candidate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateSetupURL(candidate); !errors.Is(err, ErrInvalidSetupURL) {
				t.Fatalf("validateSetupURL(%q) error = %v", candidate, err)
			}
		})
	}
}

func TestPF001SetupClockAlwaysReturnsUTC(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	observed := (Clock{}).Now()
	after := time.Now().UTC()
	if observed.Location() != time.UTC || observed.Before(before) || observed.After(after) {
		t.Fatalf("Clock.Now() = %v outside [%v, %v] UTC", observed, before, after)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
