package runtimeprovision

import (
	"bufio"
	"bytes"
	"math"
	"slices"
	"strconv"
	"strings"
)

const (
	maximumOSReleaseBytes = 64 * 1024
	maximumIDMapBytes     = 4 * 1024 * 1024
	maximumIDMapEntries   = 131072
)

func parseOSRelease(raw []byte) (string, string, error) {
	if len(raw) == 0 || len(raw) > maximumOSReleaseBytes || bytes.IndexByte(raw, 0) >= 0 {
		return "", "", ErrProbeFailed
	}
	values := make(map[string]string, 2)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), maximumOSReleaseBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, present := strings.Cut(line, "=")
		if !present || key != "ID" && key != "VERSION_ID" {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return "", "", ErrProbeFailed
		}
		decoded, ok := decodeOSReleaseValue(value)
		if !ok {
			return "", "", ErrProbeFailed
		}
		values[key] = decoded
	}
	if scanner.Err() != nil {
		return "", "", ErrProbeFailed
	}
	distribution, distributionOK := values["ID"]
	version, versionOK := values["VERSION_ID"]
	if !distributionOK || !versionOK || !validOSReleaseToken(distribution) || !validOSReleaseToken(version) {
		return "", "", ErrProbeFailed
	}
	return distribution, version, nil
}

func decodeOSReleaseValue(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		if len(value) < 2 || value[len(value)-1] != quote {
			return "", false
		}
		value = value[1 : len(value)-1]
	}
	if !validOSReleaseToken(value) {
		return "", false
	}
	return value, true
}

func validOSReleaseToken(value string) bool {
	if value == "" || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._+~-", character) {
			continue
		}
		return false
	}
	return true
}

func validKernel(value string) bool {
	return validOSReleaseToken(value) && len(numericKernelPrefix(value)) != 0
}

func compareKernel(left, right string) int {
	leftParts := numericKernelPrefix(left)
	rightParts := numericKernelPrefix(right)
	for index := 0; index < len(leftParts) || index < len(rightParts); index++ {
		var leftValue, rightValue uint64
		if index < len(leftParts) {
			leftValue = leftParts[index]
		}
		if index < len(rightParts) {
			rightValue = rightParts[index]
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}

func numericKernelPrefix(value string) []uint64 {
	prefix := value
	if index := strings.IndexFunc(prefix, func(character rune) bool {
		return character != '.' && (character < '0' || character > '9')
	}); index >= 0 {
		prefix = prefix[:index]
	}
	parts := strings.Split(strings.TrimSuffix(prefix, "."), ".")
	result := make([]uint64, 0, len(parts))
	for _, part := range parts {
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil
		}
		result = append(result, parsed)
	}
	return result
}

type subordinateRange struct {
	principal string
	start     uint32
	count     uint32
}

func parseSubordinateRanges(raw []byte) ([]subordinateRange, error) {
	if len(raw) > maximumIDMapBytes || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrProbeFailed
	}
	ranges := make([]subordinateRange, 0)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), maximumOSReleaseBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 || !validMapPrincipal(parts[0]) || len(ranges) >= maximumIDMapEntries {
			return nil, ErrProbeFailed
		}
		start, startError := strconv.ParseUint(parts[1], 10, 32)
		count, countError := strconv.ParseUint(parts[2], 10, 32)
		if startError != nil || countError != nil || start == 0 || count == 0 || start+count > math.MaxUint32+1 {
			return nil, ErrProbeFailed
		}
		ranges = append(ranges, subordinateRange{
			principal: parts[0], start: uint32(start), count: uint32(count),
		})
	}
	if scanner.Err() != nil || rangesOverlap(ranges) {
		return nil, ErrProbeFailed
	}
	return ranges, nil
}

func validMapPrincipal(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func dockerGroupAbsent(raw []byte, account string, activeGroups map[uint32]struct{}) (bool, error) {
	if len(raw) > maximumIDMapBytes || bytes.IndexByte(raw, 0) >= 0 || !validMapPrincipal(account) ||
		activeGroups == nil {
		return false, ErrProbeFailed
	}
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), maximumOSReleaseBytes)
	for scanner.Scan() {
		line := scanner.Text()
		name, _, hasFields := strings.Cut(line, ":")
		if !hasFields || name != "docker" {
			continue
		}
		if found {
			return false, ErrProbeFailed
		}
		found = true
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			return false, ErrProbeFailed
		}
		group, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || group == 0 {
			return false, ErrProbeFailed
		}
		if _, member := activeGroups[uint32(group)]; member {
			return false, nil
		}
		if fields[3] == "" {
			continue
		}
		seen := make(map[string]struct{})
		for _, member := range strings.Split(fields[3], ",") {
			if !validMapPrincipal(member) {
				return false, ErrProbeFailed
			}
			if _, duplicate := seen[member]; duplicate {
				return false, ErrProbeFailed
			}
			seen[member] = struct{}{}
			if member == account {
				return false, nil
			}
		}
	}
	if scanner.Err() != nil {
		return false, ErrProbeFailed
	}
	return true, nil
}

func rangesOverlap(ranges []subordinateRange) bool {
	ordered := slices.Clone(ranges)
	slices.SortFunc(ordered, func(left, right subordinateRange) int {
		if left.start < right.start {
			return -1
		}
		if left.start > right.start {
			return 1
		}
		return 0
	})
	for index := 1; index < len(ordered); index++ {
		previousEnd := uint64(ordered[index-1].start) + uint64(ordered[index-1].count)
		if uint64(ordered[index].start) < previousEnd {
			return true
		}
	}
	return false
}

func subordinateCount(ranges []subordinateRange, principal string) (uint32, error) {
	var total uint64
	for _, candidate := range ranges {
		if candidate.principal == principal {
			total += uint64(candidate.count)
			if total > math.MaxUint32 {
				return 0, ErrProbeFailed
			}
		}
	}
	return uint32(total), nil
}

func parsePositiveUint(raw []byte) (uint64, error) {
	value := strings.TrimSuffix(string(raw), "\n")
	if value == "" || strings.ContainsAny(value, " \t\r\n+") {
		return 0, ErrProbeFailed
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, ErrProbeFailed
	}
	return parsed, nil
}

func parseMemAvailable(raw []byte) (uint64, error) {
	if len(raw) == 0 || len(raw) > maximumOSReleaseBytes {
		return 0, ErrProbeFailed
	}
	var result uint64
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			if found {
				return 0, ErrProbeFailed
			}
			kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || kilobytes == 0 || kilobytes > math.MaxUint64/1024 {
				return 0, ErrProbeFailed
			}
			result, found = kilobytes*1024, true
		}
	}
	if scanner.Err() != nil || !found {
		return 0, ErrProbeFailed
	}
	return result, nil
}

func sanitizedContextError(ctx contextLike, fallback error) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return fallback
}

type contextLike interface{ Err() error }

func parseProcStatus(raw []byte) (uint32, uint32, error) {
	if len(raw) == 0 || len(raw) > maximumOSReleaseBytes || bytes.IndexByte(raw, 0) >= 0 {
		return 0, 0, ErrProbeFailed
	}
	var parent, uid uint64
	parentFound, uidFound := false, false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		switch {
		case len(fields) == 2 && fields[0] == "PPid:":
			if parentFound {
				return 0, 0, ErrProbeFailed
			}
			parsed, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return 0, 0, ErrProbeFailed
			}
			parent, parentFound = parsed, true
		case len(fields) == 5 && fields[0] == "Uid:":
			if uidFound || fields[1] != fields[2] || fields[1] != fields[3] || fields[1] != fields[4] {
				return 0, 0, ErrProbeFailed
			}
			parsed, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return 0, 0, ErrProbeFailed
			}
			uid, uidFound = parsed, true
		}
	}
	if scanner.Err() != nil || !parentFound || !uidFound {
		return 0, 0, ErrProbeFailed
	}
	return uint32(parent), uint32(uid), nil
}

func parseListeningTCPInodes(raw []byte) (map[uint64]struct{}, error) {
	if len(raw) > maximumIDMapBytes || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrProbeFailed
	}
	result := make(map[uint64]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), maximumOSReleaseBytes)
	first := true
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if first {
			first = false
			if len(fields) < 10 || fields[0] != "sl" {
				return nil, ErrProbeFailed
			}
			continue
		}
		if len(fields) < 10 {
			return nil, ErrProbeFailed
		}
		if fields[3] != "0A" {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			return nil, ErrProbeFailed
		}
		result[inode] = struct{}{}
	}
	if scanner.Err() != nil || first {
		return nil, ErrProbeFailed
	}
	return result, nil
}
