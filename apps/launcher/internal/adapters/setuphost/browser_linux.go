//go:build linux

package setuphost

const nativeBrowserExecutable = "/usr/bin/xdg-open"

func nativeBrowserEnvironmentKeys() map[string]struct{} {
	return map[string]struct{}{
		"DBUS_SESSION_BUS_ADDRESS": {},
		"DISPLAY":                  {},
		"HOME":                     {},
		"LANG":                     {},
		"LC_ALL":                   {},
		"LOGNAME":                  {},
		"USER":                     {},
		"WAYLAND_DISPLAY":          {},
		"XDG_CURRENT_DESKTOP":      {},
		"XDG_RUNTIME_DIR":          {},
	}
}
