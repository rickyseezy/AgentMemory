package setuphttp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	sessionPath  = "/setup/v1/session"
	commandsPath = "/setup/v1/commands"
	eventsPath   = "/setup/v1/events"

	contentSecurityPolicy = "default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'"
	permissionsPolicy     = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
)

// ServeHTTP rejects every request outside the exact static/API surface.
func (s *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response.Header())
	if s == nil || request == nil || !s.started.Load() || s.closed.Load() ||
		!s.validRequestTarget(request) || !s.allowedHost(request.Host) {
		reject(response, http.StatusNotFound)
		return
	}
	if !s.allowRate() {
		reject(response, http.StatusTooManyRequests)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		reject(response, http.StatusTooManyRequests)
		return
	}
	if asset, present := staticAssets[request.URL.Path]; present {
		s.serveAsset(response, request, asset)
		return
	}
	switch request.URL.Path {
	case sessionPath:
		s.exchangeSession(response, request)
	case commandsPath:
		s.applyCommand(response, request)
	case eventsPath:
		s.streamEvents(response, request)
	default:
		reject(response, http.StatusNotFound)
	}
}

func (s *Server) serveAsset(response http.ResponseWriter, request *http.Request, asset staticAsset) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 ||
		parseContentLengthValues(request.Header.Values("Content-Length"), request.ContentLength) != nil ||
		!s.validStaticMetadata(request, asset) {
		reject(response, http.StatusMethodNotAllowed)
		return
	}
	response.Header().Set("Content-Type", asset.contentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(asset.bytes)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(asset.bytes)
}

func (s *Server) exchangeSession(response http.ResponseWriter, request *http.Request) {
	if !s.validAPIRequest(request, http.MethodPost, "application/json", true) || request.URL.RawQuery != "" {
		reject(response, http.StatusBadRequest)
		return
	}
	var document sessionRequestDocument
	if err := readCanonicalBody(request, &document); err != nil || document.ContractVersion != setupprogressapp.ContractVersion {
		reject(response, http.StatusBadRequest)
		return
	}
	principal, ok := s.verifyCurrentPrincipal(request.Context())
	if !ok {
		reject(response, http.StatusForbidden)
		return
	}
	authorization, present := exactSingleHeader(request.Header, "Authorization")
	const scheme = "AgentMemorySetup "
	if !present || !strings.HasPrefix(authorization, scheme) || !validToken(strings.TrimPrefix(authorization, scheme)) {
		reject(response, http.StatusUnauthorized)
		return
	}
	capability := strings.TrimPrefix(authorization, scheme)
	now := s.clock.Now().UTC()
	s.stateMu.Lock()
	used := s.capabilityUsed
	expired := now.IsZero() || !now.Before(s.config.ExpiresAt.UTC())
	principalMatches := principal.Equal(s.boundPrincipal)
	capabilityDigest := tokenHash(capability)
	hashMatches := subtle.ConstantTimeCompare(capabilityDigest[:], s.capabilityHash[:]) == 1
	if !used && !expired && principalMatches && hashMatches {
		s.capabilityUsed = true
	}
	s.stateMu.Unlock()
	if used || expired {
		reject(response, http.StatusGone)
		return
	}
	if !principalMatches {
		reject(response, http.StatusForbidden)
		return
	}
	if !hashMatches {
		reject(response, http.StatusUnauthorized)
		return
	}
	operationContext, cancel := context.WithTimeout(request.Context(), s.config.RequestTimeout)
	snapshot, err := s.app.Current(operationContext)
	cancel()
	if err != nil {
		rejectApplicationError(response, err)
		return
	}
	sessionToken, sessionError := randomToken()
	csrfToken, csrfError := randomToken()
	if sessionError != nil || csrfError != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	expiresAt := now.Add(s.config.SessionLifetime)
	if expiresAt.After(s.config.ExpiresAt.UTC()) {
		expiresAt = s.config.ExpiresAt.UTC()
	}
	s.stateMu.Lock()
	s.session = &sessionState{
		tokenHash: tokenHash(sessionToken), csrfHash: tokenHash(csrfToken),
		principal: principal, binding: s.app.Binding(), expiresAt: expiresAt,
	}
	s.stateMu.Unlock()
	snapshotJSON, err := snapshot.CanonicalJSON()
	if err != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	// G117: these one-use credentials are intentionally returned once to the
	// authenticated same-origin browser and only their hashes are retained.
	encoded, err := json.Marshal(sessionDocument{ //nolint:gosec
		SessionToken: sessionToken, CSRFToken: csrfToken, Snapshot: snapshotJSON,
	})
	if err != nil || len(encoded) > maximumDynamicBytes {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	writeJSON(response, encoded)
	if snapshot.Terminal() {
		s.scheduleTerminalClose(request.Context())
	}
}

func (s *Server) applyCommand(response http.ResponseWriter, request *http.Request) {
	if !s.validAPIRequest(request, http.MethodPost, "application/json", true) || request.URL.RawQuery != "" {
		reject(response, http.StatusBadRequest)
		return
	}
	if status := s.authenticateSession(request); status != 0 {
		reject(response, status)
		return
	}
	var document commandDocument
	if err := readCanonicalBody(request, &document); err != nil ||
		document.ContractVersion != setupprogressapp.ContractVersion {
		reject(response, http.StatusBadRequest)
		return
	}
	operationContext, cancel := context.WithTimeout(request.Context(), s.config.RequestTimeout)
	snapshot, err := s.app.Decide(operationContext, setupprogressapp.DecisionInput{
		PlanDigest: document.PlanDigest, Decision: setupprogressapp.Decision(document.Decision),
		IdempotencyKey: document.IdempotencyKey,
	})
	cancel()
	if err != nil {
		rejectApplicationError(response, err)
		return
	}
	encoded, err := snapshot.CanonicalJSON()
	if err != nil {
		reject(response, http.StatusServiceUnavailable)
		return
	}
	writeJSON(response, encoded)
	if snapshot.Terminal() {
		s.scheduleTerminalClose(request.Context())
	}
}

func (s *Server) streamEvents(response http.ResponseWriter, request *http.Request) {
	if !s.validAPIRequest(request, http.MethodGet, "text/event-stream", false) || request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 {
		reject(response, http.StatusBadRequest)
		return
	}
	values := request.URL.Query()
	afterValues, afterPresent := values["after"]
	if len(values) != 1 || !afterPresent || len(afterValues) != 1 {
		reject(response, http.StatusBadRequest)
		return
	}
	after, err := parseAfter(afterValues[0])
	if err != nil {
		reject(response, http.StatusBadRequest)
		return
	}
	if status := s.authenticateSession(request); status != 0 {
		reject(response, status)
		return
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("X-Accel-Buffering", "no")
	response.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(response)
	if err := controller.Flush(); err != nil {
		return
	}
	lastSequence := after
	for request.Context().Err() == nil {
		currentPrincipal, ok := s.verifyCurrentPrincipal(request.Context())
		s.stateMu.Lock()
		principalMatches := ok && currentPrincipal.Equal(s.boundPrincipal) &&
			s.session != nil && currentPrincipal.Equal(s.session.principal)
		s.stateMu.Unlock()
		if !principalMatches {
			_, _ = response.Write([]byte(": closed\n\n"))
			_ = controller.Flush()
			return
		}
		waitContext, cancel := context.WithTimeout(request.Context(), s.config.HeartbeatInterval)
		snapshot, waitError := s.app.WaitAfter(waitContext, lastSequence)
		waitContextError := waitContext.Err()
		cancel()
		if waitError != nil {
			if request.Context().Err() != nil {
				return
			}
			if errors.Is(waitContextError, context.DeadlineExceeded) || setupprogressapp.IsDeadlineError(waitError) {
				if _, err := response.Write([]byte(": heartbeat\n\n")); err != nil || controller.Flush() != nil {
					return
				}
				continue
			}
			_, _ = response.Write([]byte(": closed\n\n"))
			_ = controller.Flush()
			return
		}
		encoded, encodeError := snapshot.CanonicalJSON()
		if encodeError != nil {
			return
		}
		event := []byte(fmt.Sprintf("id: %d\nevent: snapshot\nretry: 1000\ndata: %s\n\n", snapshot.Sequence(), encoded))
		if len(event) > maximumDynamicBytes {
			return
		}
		// G705: event contains only a validated canonical JSON DTO and fixed SSE
		// framing; CSP also forbids inline execution and remote content.
		if _, err := response.Write(event); err != nil || controller.Flush() != nil { //nolint:gosec
			return
		}
		lastSequence = snapshot.Sequence()
		if snapshot.Terminal() {
			s.scheduleTerminalClose(request.Context())
			return
		}
	}
}

func (s *Server) authenticateSession(request *http.Request) int {
	principal, ok := s.verifyCurrentPrincipal(request.Context())
	if !ok {
		return http.StatusForbidden
	}
	authorization, hasAuthorization := exactSingleHeader(request.Header, "Authorization")
	csrf, hasCSRF := exactSingleHeader(request.Header, "X-AgentMemory-CSRF")
	const scheme = "AgentMemorySession "
	if !hasAuthorization || !strings.HasPrefix(authorization, scheme) ||
		!validToken(strings.TrimPrefix(authorization, scheme)) || !hasCSRF || !validToken(csrf) {
		return http.StatusUnauthorized
	}
	now := s.clock.Now().UTC()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.session == nil || now.IsZero() || !now.Before(s.session.expiresAt) || !now.Before(s.config.ExpiresAt.UTC()) {
		return http.StatusGone
	}
	if !principal.Equal(s.boundPrincipal) || !principal.Equal(s.session.principal) {
		return http.StatusForbidden
	}
	binding := s.app.Binding()
	if s.session.binding.OperationID() != binding.OperationID() ||
		s.session.binding.PlanDigest() != binding.PlanDigest() {
		return http.StatusForbidden
	}
	tokenDigest := tokenHash(strings.TrimPrefix(authorization, scheme))
	csrfDigest := tokenHash(csrf)
	if subtle.ConstantTimeCompare(tokenDigest[:], s.session.tokenHash[:]) != 1 ||
		subtle.ConstantTimeCompare(csrfDigest[:], s.session.csrfHash[:]) != 1 {
		return http.StatusUnauthorized
	}
	return 0
}

func (s *Server) verifyCurrentPrincipal(parent context.Context) (install.Digest, bool) {
	if parent == nil {
		return install.Digest{}, false
	}
	ctx, cancel := context.WithTimeout(parent, s.config.RequestTimeout)
	defer cancel()
	principal, err := s.principal.CurrentPrincipal(ctx)
	return principal, err == nil && !principal.IsZero()
}

func (s *Server) validRequestTarget(request *http.Request) bool {
	return request.URL != nil && request.URL.Scheme == "" && request.URL.Host == "" &&
		request.URL.RawPath == "" && request.URL.EscapedPath() == request.URL.Path &&
		!strings.Contains(request.URL.Path, "\\") && !strings.ContainsRune(request.URL.Path, 0)
}

func (s *Server) allowedHost(host string) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	_, allowed := s.allowedHosts[host]
	return allowed
}

func (s *Server) allowedOrigin(origin string) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	_, allowed := s.allowedOrigins[origin]
	return allowed
}

func (s *Server) validAPIRequest(request *http.Request, method, accept string, mutation bool) bool {
	if request.Method != method || !headerAbsent(request.Header, "Cookie") ||
		!headerAbsent(request.Header, "Referer") || !headerAbsent(request.Header, "Sec-Fetch-User") ||
		len(request.TransferEncoding) != 0 || !headerAbsent(request.Header, "Transfer-Encoding") {
		return false
	}
	actualAccept, acceptPresent := exactSingleHeader(request.Header, "Accept")
	contentType, contentTypePresent := exactSingleHeader(request.Header, "Content-Type")
	origin, originPresent := exactSingleHeader(request.Header, "Origin")
	fetchSite, sitePresent := exactSingleHeader(request.Header, "Sec-Fetch-Site")
	fetchMode, modePresent := exactSingleHeader(request.Header, "Sec-Fetch-Mode")
	fetchDestination, destinationPresent := exactSingleHeader(request.Header, "Sec-Fetch-Dest")
	if !acceptPresent || actualAccept != accept || !contentTypePresent || contentType != "application/json" ||
		!sitePresent || fetchSite != "same-origin" || !modePresent || fetchMode != "cors" ||
		!destinationPresent || fetchDestination != "empty" || originPresent && !s.allowedOrigin(origin) ||
		mutation && (!originPresent || !s.allowedOrigin(origin)) {
		return false
	}
	if mutation {
		return parseContentLengthValues(request.Header.Values("Content-Length"), request.ContentLength) == nil
	}
	return request.ContentLength == 0 &&
		parseContentLengthValues(request.Header.Values("Content-Length"), request.ContentLength) == nil
}

func (s *Server) validStaticMetadata(request *http.Request, asset staticAsset) bool {
	accept, acceptPresent := exactSingleHeader(request.Header, "Accept")
	site, sitePresent := exactSingleHeader(request.Header, "Sec-Fetch-Site")
	mode, modePresent := exactSingleHeader(request.Header, "Sec-Fetch-Mode")
	destination, destinationPresent := exactSingleHeader(request.Header, "Sec-Fetch-Dest")
	origin, originPresent := exactSingleHeader(request.Header, "Origin")
	if !acceptPresent || !acceptsExactMediaRange(accept, asset.accept) || !sitePresent ||
		site != "same-origin" && (request.URL.Path != "/" || site != "none") ||
		!modePresent || mode != asset.mode || !destinationPresent || destination != asset.destination ||
		originPresent && !s.allowedOrigin(origin) || !headerAbsent(request.Header, "Cookie") ||
		!headerAbsent(request.Header, "Referer") {
		return false
	}
	if request.URL.Path == "/" {
		userValues := request.Header.Values("Sec-Fetch-User")
		if len(userValues) == 0 {
			return true
		}
		user, present := exactSingleHeader(request.Header, "Sec-Fetch-User")
		return present && user == "?1"
	}
	return headerAbsent(request.Header, "Sec-Fetch-User")
}

func acceptsExactMediaRange(value, expected string) bool {
	for mediaRange := range strings.SplitSeq(value, ",") {
		mediaType, _, _ := strings.Cut(strings.TrimSpace(mediaRange), ";")
		if strings.TrimSpace(mediaType) == expected {
			return true
		}
	}
	return false
}

func headerAbsent(header http.Header, name string) bool { return len(header.Values(name)) == 0 }

func (s *Server) allowRate() bool {
	now := s.clock.Now().UTC()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if now.IsZero() {
		return false
	}
	if s.rateWindow.IsZero() || now.Before(s.rateWindow) || now.Sub(s.rateWindow) >= time.Second {
		s.rateWindow, s.rateCount = now, 0
	}
	if s.rateCount >= s.config.RequestsPerSecond {
		return false
	}
	s.rateCount++
	return true
}

func writeJSON(response http.ResponseWriter, encoded []byte) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func rejectApplicationError(response http.ResponseWriter, err error) {
	switch {
	case setupprogressapp.IsInvalidArgument(err):
		reject(response, http.StatusBadRequest)
	case setupprogressapp.IsConflictError(err):
		reject(response, http.StatusConflict)
	case setupprogressapp.IsDeadlineError(err):
		reject(response, http.StatusGatewayTimeout)
	case setupprogressapp.IsIntegrityError(err):
		reject(response, http.StatusServiceUnavailable)
	default:
		reject(response, http.StatusServiceUnavailable)
	}
}

func reject(response http.ResponseWriter, status int) {
	response.Header().Del("Content-Type")
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(status)
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("Cross-Origin-Embedder-Policy", "require-corp")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", permissionsPolicy)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
}
