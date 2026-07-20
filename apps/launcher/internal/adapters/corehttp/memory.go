package corehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const canonicalMemoryTime = "2006-01-02T15:04:05.000000Z"

// ExplainMemory returns the complete provenance and bitemporal explanation for
// one memory through the same authenticated literal-loopback boundary as Ready.
func (c *StatusClient) ExplainMemory(
	ctx context.Context,
	memoryID string,
	brainID string,
	actorID string,
	grantID string,
	validAt string,
	recordedAt string,
) (json.RawMessage, error) {
	if c == nil || ctx == nil || !validUUIDv7(memoryID) || !validUUIDv7(brainID) ||
		!validUUIDv7(actorID) || !validUUIDv7(grantID) || !validMemoryTime(validAt) ||
		!validMemoryTime(recordedAt) {
		return nil, errCoreStatusUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("brain_id", brainID)
	query.Set("actor_id", actorID)
	query.Set("grant_id", grantID)
	query.Set("valid_at", validAt)
	query.Set("recorded_at", recordedAt)
	body, statusCode, err := authenticatedGet(
		ctx,
		c.credentials,
		c.endpoint,
		c.credentialPath,
		"/memories/"+memoryID+"?"+query.Encode(),
	)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return nil, contextError
		}
		return nil, errCoreStatusUnavailable
	}
	defer clear(body)
	trimmed := bytes.TrimSpace(body)
	if statusCode != http.StatusOK || len(trimmed) < 2 || trimmed[0] != '{' ||
		trimmed[len(trimmed)-1] != '}' || rejectDuplicateJSONKeys(trimmed) != nil {
		return nil, errCoreStatusUnavailable
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &document); err != nil || document == nil {
		return nil, errCoreStatusUnavailable
	}
	return append(json.RawMessage(nil), trimmed...), nil
}

func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validMemoryTime(value string) bool {
	parsed, err := time.Parse(canonicalMemoryTime, value)
	return err == nil && parsed.UTC().Format(canonicalMemoryTime) == value
}

var _ interface {
	ExplainMemory(context.Context, string, string, string, string, string, string) (json.RawMessage, error)
} = (*StatusClient)(nil)
