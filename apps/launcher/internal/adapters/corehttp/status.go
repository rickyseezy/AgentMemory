package corehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var errCoreStatusUnavailable = errors.New("core status is unavailable")

// StatusClient proves that the authenticated Core still exposes the complete
// readiness receipt before a launcher product surface reports Ready.
type StatusClient struct {
	credentials    CredentialSource
	endpoint       string
	credentialPath string
}

// NewStatusClient binds status checks to one literal-loopback endpoint and
// one protected credential path.
func NewStatusClient(
	credentials CredentialSource,
	endpoint string,
	credentialPath string,
) (*StatusClient, error) {
	if nilCapability(credentials) || credentialPath == "" || credentialPath != strings.TrimSpace(credentialPath) ||
		len(credentialPath) > 4096 || strings.ContainsAny(credentialPath, "\x00\r\n") {
		return nil, errCoreStatusUnavailable
	}
	client, closeIdle, err := literalLoopbackClient(endpoint)
	if err != nil || client == nil || closeIdle == nil {
		return nil, errCoreStatusUnavailable
	}
	closeIdle()
	return &StatusClient{credentials: credentials, endpoint: endpoint, credentialPath: credentialPath}, nil
}

type statusResponse struct {
	Ready   bool            `json:"ready"`
	Receipt json.RawMessage `json:"receipt"`
}

// Ready returns true only for an exact authenticated Core status document
// carrying a non-null, unambiguous readiness receipt.
func (c *StatusClient) Ready(ctx context.Context) (bool, error) {
	if c == nil || ctx == nil {
		return false, errCoreStatusUnavailable
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	body, statusCode, err := authenticatedGet(
		ctx, c.credentials, c.endpoint, c.credentialPath, "/v1/status",
	)
	if err != nil || statusCode != http.StatusOK || rejectDuplicateJSONKeys(body) != nil {
		clear(body)
		return false, errCoreStatusUnavailable
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var response statusResponse
	if err := decoder.Decode(&response); err != nil || requireJSONEOF(decoder) != nil {
		return false, errCoreStatusUnavailable
	}
	receipt := bytes.TrimSpace(response.Receipt)
	if !response.Ready {
		if !bytes.Equal(receipt, []byte("null")) {
			return false, errCoreStatusUnavailable
		}
		return false, nil
	}
	if len(receipt) < 2 || receipt[0] != '{' || receipt[len(receipt)-1] != '}' ||
		rejectDuplicateJSONKeys(receipt) != nil {
		return false, errCoreStatusUnavailable
	}
	return true, nil
}

var _ interface {
	Ready(context.Context) (bool, error)
} = (*StatusClient)(nil)
