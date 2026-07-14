//go:build darwin

package setuphost

const nativeBrowserExecutable = "/usr/bin/open"

func nativeBrowserEnvironmentKeys() map[string]struct{} {
	return map[string]struct{}{
		"HOME":    {},
		"LANG":    {},
		"LC_ALL":  {},
		"LOGNAME": {},
		"TMPDIR":  {},
		"USER":    {},
	}
}
