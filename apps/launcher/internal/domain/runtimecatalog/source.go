package runtimecatalog

import (
	"errors"
	"strings"
)

// OfficialSourceInput contains structured URL authority without granting URL parsing or network access.
type OfficialSourceInput struct {
	Scheme     string
	Host       string
	PathPrefix string
}

// SourceLocation is a validated official HTTPS source boundary.
type SourceLocation struct {
	scheme     string
	host       string
	pathPrefix string
}

// NewSourceLocation validates a lowercase host and absolute path without using ambient URL behavior.
func NewSourceLocation(input OfficialSourceInput) (SourceLocation, error) {
	if input.Scheme != "https" || !validHost(input.Host) || !validSourcePath(input.PathPrefix) {
		return SourceLocation{}, errors.New("official source is invalid")
	}
	return SourceLocation{scheme: input.Scheme, host: input.Host, pathPrefix: input.PathPrefix}, nil
}

// Scheme returns the required source scheme.
func (s SourceLocation) Scheme() string { return s.scheme }

// Host returns the exact lowercase official host.
func (s SourceLocation) Host() string { return s.host }

// PathPrefix returns the exact absolute official path prefix.
func (s SourceLocation) PathPrefix() string { return s.pathPrefix }

func (s SourceLocation) valid() bool {
	validated, err := NewSourceLocation(OfficialSourceInput{
		Scheme: s.scheme, Host: s.host, PathPrefix: s.pathPrefix,
	})
	return err == nil && validated == s
}

func (s SourceLocation) authorizes(requested SourceLocation) bool {
	return s.valid() && requested.valid() && s.scheme == requested.scheme && s.host == requested.host &&
		strings.HasPrefix(requested.pathPrefix, s.pathPrefix)
}

func validHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	lastDot := false
	for index, character := range value {
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			lastDot = false
		case character == '-' && index > 0 && value[index-1] != '.':
			lastDot = false
		case character == '.' && index > 0 && !lastDot && value[index-1] != '-':
			lastDot = true
		default:
			return false
		}
	}
	return !lastDot && value[len(value)-1] != '-'
}

func validSourcePath(value string) bool {
	if value == "" || len(value) > maximumPathLength || value[0] != '/' ||
		strings.Contains(value, "//") || strings.Contains(value, "/../") ||
		strings.HasSuffix(value, "/..") || strings.ContainsAny(value, "%?#\\<>'\"") {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
