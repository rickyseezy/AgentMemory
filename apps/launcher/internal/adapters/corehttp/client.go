// Package corehttp implements the authenticated literal-loopback PF-001 Core
// bootstrap and readiness client. It never honors proxy, redirect, DNS, or
// ambient authentication configuration.
package corehttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/brainbootstrap"
)

const (
	protectedCredentialBytes = 32
	maximumCoreResponseBytes = 64 * 1024
	coreRequestTimeout       = 30 * time.Second
)

// CredentialSource reads one exact protected API credential through a native
// descriptor/handle security boundary. Implementations return caller-owned bytes.
type CredentialSource interface {
	ReadCredential(context.Context, string) ([]byte, error)
}

// Client is the strict authenticated local Core adapter.
type Client struct {
	credentials CredentialSource
}

// New requires a protected credential source.
func New(credentials CredentialSource) (*Client, error) {
	if nilCapability(credentials) {
		return nil, errors.New("core API credential source is required")
	}
	return &Client{credentials: credentials}, nil
}

type bootstrapRequest struct {
	CommandID          string `json:"command_id"`
	InstallationID     string `json:"installation_id"`
	OwnerPrincipalID   string `json:"owner_principal_id"`
	OwnerGrantID       string `json:"owner_grant_id"`
	OwnerSubjectDigest string `json:"owner_subject_digest"`
	BrainID            string `json:"brain_id"`
	BrainName          string `json:"brain_name"`
	ReleaseDigest      string `json:"release_digest"`
	GenerationID       string `json:"generation_id"`
}

type bootstrapResponse struct {
	InstallationID string `json:"installation_id"`
	BrainID        string `json:"brain_id"`
	Disposition    string `json:"disposition"`
}

// BootstrapLocalBrain posts the exact immutable owner/Brain command and
// accepts only an identity-equal idempotent response.
func (c *Client) BootstrapLocalBrain(
	ctx context.Context,
	authorization brainbootstrap.Authorization,
) (brainbootstrap.Receipt, error) {
	if c == nil || ctx == nil || !authorization.Valid() {
		return brainbootstrap.Receipt{}, brainbootstrap.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return brainbootstrap.Receipt{}, brainbootstrap.ErrUnavailable
	}
	body, err := json.Marshal(bootstrapRequest{
		CommandID: authorization.OperationID().String(), InstallationID: authorization.InstallationID(),
		OwnerPrincipalID: authorization.OwnerPrincipalID(), OwnerGrantID: authorization.OwnerGrantID(),
		OwnerSubjectDigest: authorization.OwnerSubjectDigest().String(), BrainID: authorization.BrainID(),
		BrainName: authorization.BrainName(), ReleaseDigest: authorization.ReleaseDigest().String(),
		GenerationID: authorization.GenerationID(),
	})
	if err != nil {
		return brainbootstrap.Receipt{}, brainbootstrap.ErrIntegrity
	}
	defer clear(body)
	responseBody, statusCode, err := authenticatedPost(
		ctx, c.credentials, authorization.CoreEndpoint(), authorization.APICredentialPath(),
		authorization.OperationID().String(), "/v1/bootstrap", body,
	)
	if err != nil {
		return brainbootstrap.Receipt{}, err
	}
	defer clear(responseBody)
	if (statusCode != http.StatusCreated && statusCode != http.StatusOK) ||
		rejectDuplicateJSONKeys(responseBody) != nil {
		return brainbootstrap.Receipt{}, brainbootstrap.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var result bootstrapResponse
	if err := decoder.Decode(&result); err != nil || requireJSONEOF(decoder) != nil ||
		result.InstallationID != authorization.InstallationID() || result.BrainID != authorization.BrainID() {
		return brainbootstrap.Receipt{}, brainbootstrap.ErrIntegrity
	}
	disposition := brainbootstrap.Disposition(result.Disposition)
	if statusCode == http.StatusCreated && disposition != brainbootstrap.DispositionCreated ||
		statusCode == http.StatusOK && disposition != brainbootstrap.DispositionAlreadyInitialized {
		return brainbootstrap.Receipt{}, brainbootstrap.ErrIntegrity
	}
	receipt, err := brainbootstrap.NewReceiptForAdapter(authorization, disposition)
	if err != nil {
		return brainbootstrap.Receipt{}, brainbootstrap.ErrIntegrity
	}
	return receipt, nil
}

func authenticatedPost(
	ctx context.Context,
	credentials CredentialSource,
	endpoint string,
	credentialPath string,
	idempotencyKey string,
	path string,
	body []byte,
) ([]byte, int, error) {
	credential, err := credentials.ReadCredential(ctx, credentialPath)
	if err != nil {
		return nil, 0, brainbootstrap.ErrUnavailable
	}
	defer clear(credential)
	if len(credential) != protectedCredentialBytes {
		return nil, 0, brainbootstrap.ErrIntegrity
	}
	requestContext, cancel := context.WithTimeout(ctx, coreRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, endpoint+path, bytes.NewReader(body),
	)
	if err != nil {
		return nil, 0, brainbootstrap.ErrIntegrity
	}
	authorizationHeader := make([]byte, len("Bearer ")+hex.EncodedLen(len(credential)))
	copy(authorizationHeader, "Bearer ")
	hex.Encode(authorizationHeader[len("Bearer "):], credential)
	request.Header.Set("Authorization", string(authorizationHeader))
	clear(authorizationHeader)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("X-Correlation-ID", idempotencyKey)
	client, closeIdle, err := literalLoopbackClient(endpoint)
	if err != nil {
		return nil, 0, brainbootstrap.ErrIntegrity
	}
	defer closeIdle()
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, brainbootstrap.ErrUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumCoreResponseBytes+1))
	if err != nil || len(responseBody) == 0 || len(responseBody) > maximumCoreResponseBytes {
		clear(responseBody)
		return nil, 0, brainbootstrap.ErrUnavailable
	}
	if response.Header.Get("Content-Type") != "application/json" {
		clear(responseBody)
		return nil, 0, brainbootstrap.ErrUnavailable
	}
	return responseBody, response.StatusCode, nil
}

func authenticatedGet(
	ctx context.Context,
	credentials CredentialSource,
	endpoint string,
	credentialPath string,
	path string,
) ([]byte, int, error) {
	credential, err := credentials.ReadCredential(ctx, credentialPath)
	if err != nil {
		return nil, 0, brainbootstrap.ErrUnavailable
	}
	defer clear(credential)
	if len(credential) != protectedCredentialBytes {
		return nil, 0, brainbootstrap.ErrIntegrity
	}
	requestContext, cancel := context.WithTimeout(ctx, coreRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint+path, nil)
	if err != nil {
		return nil, 0, brainbootstrap.ErrIntegrity
	}
	authorizationHeader := make([]byte, len("Bearer ")+hex.EncodedLen(len(credential)))
	copy(authorizationHeader, "Bearer ")
	hex.Encode(authorizationHeader[len("Bearer "):], credential)
	request.Header.Set("Authorization", string(authorizationHeader))
	clear(authorizationHeader)
	request.Header.Set("Accept", "application/json")
	client, closeIdle, err := literalLoopbackClient(endpoint)
	if err != nil {
		return nil, 0, brainbootstrap.ErrIntegrity
	}
	defer closeIdle()
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, brainbootstrap.ErrUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumCoreResponseBytes+1))
	if err != nil || len(responseBody) == 0 || len(responseBody) > maximumCoreResponseBytes ||
		response.Header.Get("Content-Type") != "application/json" {
		clear(responseBody)
		return nil, 0, brainbootstrap.ErrUnavailable
	}
	return responseBody, response.StatusCode, nil
}

func literalLoopbackClient(endpoint string) (*http.Client, func(), error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.Path != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.User != nil || parsed.Host == "" {
		return nil, nil, brainbootstrap.ErrIntegrity
	}
	hostname := parsed.Hostname()
	if hostname != "127.0.0.1" && hostname != "::1" {
		return nil, nil, brainbootstrap.ErrIntegrity
	}
	expectedAddress := parsed.Host
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != expectedAddress {
				return nil, errors.New("core dial target is not the authorized loopback endpoint")
			}
			return dialer.DialContext(ctx, "tcp", expectedAddress)
		},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("core redirects are forbidden")
		},
	}
	return client, transport.CloseIdleConnections, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			key, ok := keyToken.(string)
			if keyError != nil || !ok {
				return errors.New("core JSON object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("core JSON object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return errors.New("core JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return errors.New("core JSON array is incomplete")
		}
	default:
		return errors.New("core JSON delimiter is invalid")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("core JSON has trailing content")
}

func nilCapability(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface {
		return reflected.IsNil()
	}
	return false
}

var _ brainbootstrap.Bootstrapper = (*Client)(nil)
