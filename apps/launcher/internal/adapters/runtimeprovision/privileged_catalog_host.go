package runtimeprovision

import (
	"errors"
	"strconv"
	"strings"
)

func normalizedPrivilegeCatalogVersion(value string) (string, error) {
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return "", errors.New("linux version is invalid")
	}
	normalized := make([]string, 3)
	for index := range normalized {
		if index >= len(parts) {
			normalized[index] = "0"
			continue
		}
		if parts[index] == "" {
			return "", errors.New("linux version is invalid")
		}
		parsed, err := strconv.ParseUint(parts[index], 10, 32)
		if err != nil {
			return "", errors.New("linux version is invalid")
		}
		normalized[index] = strconv.FormatUint(parsed, 10)
	}
	return strings.Join(normalized, "."), nil
}

func normalizedPrivilegeCatalogBuild(value string) (uint64, error) {
	parts := strings.FieldsFunc(value, func(character rune) bool {
		return character < '0' || character > '9'
	})
	if len(parts) < 2 {
		return 0, errors.New("linux kernel build is invalid")
	}
	values := [3]uint64{}
	for index := range values {
		if index >= len(parts) {
			break
		}
		parsed, err := strconv.ParseUint(parts[index], 10, 16)
		if err != nil || parsed > 99 {
			return 0, errors.New("linux kernel build is invalid")
		}
		values[index] = parsed
	}
	build := values[0]*10_000 + values[1]*100 + values[2]
	if build == 0 {
		return 0, errors.New("linux kernel build is invalid")
	}
	return build, nil
}

func privilegedLinuxVirtualizationFlags(raw []byte) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		name, values, present := strings.Cut(line, ":")
		if !present || strings.TrimSpace(strings.ToLower(name)) != "flags" {
			continue
		}
		for _, flag := range strings.Fields(values) {
			if flag == "vmx" || flag == "svm" {
				return true
			}
		}
	}
	return false
}
