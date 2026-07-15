package nativepackage

import (
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

var errPackageFormat = errors.New("native package format is unsupported")

func packageFormatFor(
	operatingSystem string,
	osRelease []byte,
) (releasepublication.Format, error) {
	switch operatingSystem {
	case "darwin":
		return releasepublication.FormatPKG, nil
	case "windows":
		return releasepublication.FormatMSI, nil
	case "linux":
		values, err := parseOSRelease(osRelease)
		if err != nil {
			return "", errPackageFormat
		}
		family := make(map[string]bool)
		for _, token := range append([]string{values["ID"]}, strings.Fields(values["ID_LIKE"])...) {
			family[strings.ToLower(token)] = true
		}
		deb := family["debian"] || family["ubuntu"]
		rpm := family["fedora"] || family["rhel"] || family["centos"]
		if deb == rpm {
			return "", errPackageFormat
		}
		if deb {
			return releasepublication.FormatDEB, nil
		}
		return releasepublication.FormatRPM, nil
	default:
		return "", errPackageFormat
	}
}

func parseOSRelease(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 64*1024 || strings.ContainsRune(string(raw), 0) {
		return nil, errPackageFormat
	}
	result := make(map[string]string, 2)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || strings.TrimSpace(key) != key {
			return nil, errPackageFormat
		}
		if key != "ID" && key != "ID_LIKE" {
			continue
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errPackageFormat
		}
		decoded, err := decodeOSReleaseValue(value)
		if err != nil || decoded == "" {
			return nil, errPackageFormat
		}
		result[key] = decoded
	}
	if result["ID"] == "" {
		return nil, errPackageFormat
	}
	return result, nil
}

func decodeOSReleaseValue(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", errPackageFormat
	}
	if value[0] == '\'' || value[0] == '"' {
		if len(value) < 2 || value[len(value)-1] != value[0] {
			return "", errPackageFormat
		}
		value = value[1 : len(value)-1]
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._- ", character) {
			continue
		}
		return "", errPackageFormat
	}
	return value, nil
}
