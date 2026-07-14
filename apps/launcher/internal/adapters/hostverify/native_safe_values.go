//go:build !windows

package hostverify

import "strings"

func safeProduct(value string) bool {
	if value == "" || len(value) > 128 || value != strings.ToLower(value) {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func safeVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.EqualFold(value, "latest") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._+-~", character) {
			continue
		}
		return false
	}
	return true
}
