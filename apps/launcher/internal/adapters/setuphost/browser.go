package setuphost

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	setupCapabilityKey   = "capability"
	setupCapabilityBytes = 32
)

var (
	// ErrInvalidSetupURL rejects any authority outside the exact one-use IPv4
	// loopback setup URL minted by setuphttp.Server.
	ErrInvalidSetupURL = errors.New("setup browser URL is invalid")
	// ErrBrowserUnavailable reports a missing or unsafe native browser-launch
	// boundary without exposing host paths or process diagnostics.
	ErrBrowserUnavailable = errors.New("setup browser launch is unavailable")
)

func validateSetupURL(value string) error {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return ErrInvalidSetupURL
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" ||
		parsed.Path != "/" || parsed.RawPath != "" || parsed.RawFragment != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.User != nil || parsed.Opaque != "" {
		return ErrInvalidSetupURL
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 || net.ParseIP(parsed.Hostname()) == nil {
		return ErrInvalidSetupURL
	}
	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil || len(fragment) != 1 || len(fragment[setupCapabilityKey]) != 1 {
		return ErrInvalidSetupURL
	}
	capability := fragment.Get(setupCapabilityKey)
	if parsed.Fragment != setupCapabilityKey+"="+capability {
		return ErrInvalidSetupURL
	}
	decoded, err := base64.RawURLEncoding.DecodeString(capability)
	if err != nil || len(decoded) != setupCapabilityBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != capability {
		return ErrInvalidSetupURL
	}
	return nil
}
