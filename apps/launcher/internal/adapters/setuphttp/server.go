package setuphttp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	defaultRequestTimeout    = 5 * time.Second
	defaultSessionLifetime   = 15 * time.Minute
	defaultHeartbeatInterval = 500 * time.Millisecond
	defaultConcurrentLimit   = 32
	defaultRequestsPerSecond = 128
	maximumDynamicBytes      = 64 * 1024
	maximumHeaderBytes       = 16 * 1024
	tokenBytes               = 32
)

// Config contains only bounded local setup transport policy.
type Config struct {
	ExpiresAt                 time.Time
	RequestTimeout            time.Duration
	SessionLifetime           time.Duration
	HeartbeatInterval         time.Duration
	MaximumConcurrentRequests int
	RequestsPerSecond         int
}

// Dependencies are mandatory clean-architecture and host capabilities.
type Dependencies struct {
	Application       *setupprogressapp.Application
	PrincipalVerifier PrincipalVerifier
	BrowserOpener     BrowserOpener
	Clock             Clock
}

// Launch contains non-secret loopback origins. The capability is never
// exposed here because it exists only in the browser URL fragment.
type Launch struct {
	ipv4Origin string
	ipv6Origin string
}

// IPv4Origin returns the random-port IPv4 loopback origin.
func (l Launch) IPv4Origin() string { return l.ipv4Origin }

// IPv6Origin returns the random-port IPv6 loopback origin.
func (l Launch) IPv6Origin() string { return l.ipv6Origin }

type sessionState struct {
	tokenHash [sha256.Size]byte
	csrfHash  [sha256.Size]byte
	principal install.Digest
	binding   setupprogressapp.Binding
	expiresAt time.Time
}

// Server owns the one-use capability, memory-only session hashes, loopback
// listeners, and exact transport policy for one application binding.
type Server struct {
	config    Config
	app       *setupprogressapp.Application
	principal PrincipalVerifier
	opener    BrowserOpener
	clock     Clock
	slots     chan struct{}

	startMu sync.Mutex
	started atomic.Bool
	closed  atomic.Bool

	stateMu        sync.Mutex
	boundPrincipal install.Digest
	capabilityHash [sha256.Size]byte
	capabilityUsed bool
	session        *sessionState
	allowedHosts   map[string]struct{}
	allowedOrigins map[string]struct{}
	rateWindow     time.Time
	rateCount      int

	runtimeContext context.Context
	runtimeCancel  context.CancelFunc
	listeners      []net.Listener
	httpServers    []*http.Server
	serveGroup     sync.WaitGroup
	done           chan struct{}
	doneOnce       sync.Once
	terminalOnce   sync.Once
}

// NewServer validates all production dependencies and bounded policy.
func NewServer(config Config, dependencies Dependencies) (*Server, error) {
	config = normalizeConfig(config)
	if config.ExpiresAt.IsZero() || config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute ||
		config.SessionLifetime <= 0 || config.SessionLifetime > time.Hour ||
		config.HeartbeatInterval <= 0 || config.HeartbeatInterval > time.Second ||
		config.MaximumConcurrentRequests < 1 || config.MaximumConcurrentRequests > 256 ||
		config.RequestsPerSecond < 1 || config.RequestsPerSecond > 4096 ||
		dependencies.Application == nil || !dependencies.Application.Binding().Valid() ||
		nilDependency(dependencies.PrincipalVerifier) || nilDependency(dependencies.BrowserOpener) ||
		nilDependency(dependencies.Clock) {
		return nil, errors.New("setup HTTP server configuration is invalid")
	}
	return &Server{
		config: config, app: dependencies.Application, principal: dependencies.PrincipalVerifier,
		opener: dependencies.BrowserOpener, clock: dependencies.Clock,
		slots: make(chan struct{}, config.MaximumConcurrentRequests), done: make(chan struct{}),
		allowedHosts: make(map[string]struct{}, 2), allowedOrigins: make(map[string]struct{}, 2),
	}, nil
}

func normalizeConfig(config Config) Config {
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}
	if config.SessionLifetime == 0 {
		config.SessionLifetime = defaultSessionLifetime
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = defaultHeartbeatInterval
	}
	if config.MaximumConcurrentRequests == 0 {
		config.MaximumConcurrentRequests = defaultConcurrentLimit
	}
	if config.RequestsPerSecond == 0 {
		config.RequestsPerSecond = defaultRequestsPerSecond
	}
	return config
}

// Start binds both loopback families on random ports, captures the current OS
// principal, mints one capability, and opens only an IPv4 fragment URL.
func (s *Server) Start(ctx context.Context) (Launch, error) {
	if s == nil || ctx == nil {
		return Launch{}, errors.New("setup HTTP server start is invalid")
	}
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.started.Load() || s.closed.Load() || ctx.Err() != nil {
		return Launch{}, errors.New("setup HTTP server cannot start")
	}
	now := s.clock.Now().UTC()
	if now.IsZero() || !now.Before(s.config.ExpiresAt.UTC()) {
		return Launch{}, errors.New("setup HTTP server authority expired")
	}
	principalContext, cancelPrincipal := context.WithTimeout(ctx, s.config.RequestTimeout)
	currentPrincipal, err := s.principal.CurrentPrincipal(principalContext)
	cancelPrincipal()
	if err != nil || currentPrincipal.IsZero() {
		return Launch{}, errors.New("setup HTTP principal is unavailable")
	}
	capability, err := randomToken()
	if err != nil {
		return Launch{}, errors.New("setup HTTP capability is unavailable")
	}
	listenerConfig := net.ListenConfig{}
	ipv4, err := listenerConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return Launch{}, errors.New("setup IPv4 loopback listener is unavailable")
	}
	ipv6, err := listenerConfig.Listen(ctx, "tcp6", "[::1]:0")
	if err != nil {
		_ = ipv4.Close()
		return Launch{}, errors.New("setup IPv6 loopback listener is unavailable")
	}
	ipv4Host, ipv6Host := ipv4.Addr().String(), ipv6.Addr().String()
	launch := Launch{ipv4Origin: "http://" + ipv4Host, ipv6Origin: "http://" + ipv6Host}
	runtimeContext, runtimeCancel := context.WithCancel(ctx)
	s.stateMu.Lock()
	s.boundPrincipal = currentPrincipal
	s.capabilityHash = tokenHash(capability)
	s.allowedHosts[ipv4Host] = struct{}{}
	s.allowedHosts[ipv6Host] = struct{}{}
	s.allowedOrigins[launch.ipv4Origin] = struct{}{}
	s.allowedOrigins[launch.ipv6Origin] = struct{}{}
	s.runtimeContext, s.runtimeCancel = runtimeContext, runtimeCancel
	s.listeners = []net.Listener{ipv4, ipv6}
	s.stateMu.Unlock()

	newHTTPServer := func() *http.Server {
		return &http.Server{
			Handler: s, ReadHeaderTimeout: s.config.RequestTimeout,
			ReadTimeout: s.config.RequestTimeout, IdleTimeout: 2 * s.config.HeartbeatInterval,
			MaxHeaderBytes: maximumHeaderBytes,
			BaseContext:    func(net.Listener) context.Context { return runtimeContext },
		}
	}
	s.httpServers = []*http.Server{newHTTPServer(), newHTTPServer()}
	s.serveGroup.Add(2)
	for index := range s.httpServers {
		server, listener := s.httpServers[index], s.listeners[index]
		go func() {
			defer s.serveGroup.Done()
			_ = server.Serve(listener)
		}()
	}
	go func() {
		s.serveGroup.Wait()
		s.doneOnce.Do(func() { close(s.done) })
	}()
	s.started.Store(true)
	go s.closeWhenOwnerStops(ctx)
	openContext, cancelOpen := context.WithTimeout(ctx, s.config.RequestTimeout)
	openError := s.opener.Open(openContext, launch.ipv4Origin+"/#capability="+capability)
	cancelOpen()
	if openError != nil {
		closeContext, closeCancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.RequestTimeout)
		defer closeCancel()
		s.closed.Store(true)
		_ = s.shutdown(closeContext, s.runtimeCancel, append([]*http.Server(nil), s.httpServers...))
		return Launch{}, errors.New("setup browser could not be opened")
	}
	return launch, nil
}

// Close idempotently stops both listeners and active authority streams.
func (s *Server) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("setup HTTP server close is invalid")
	}
	s.closed.Store(true)
	s.startMu.Lock()
	cancel := s.runtimeCancel
	servers := append([]*http.Server(nil), s.httpServers...)
	s.startMu.Unlock()
	return s.shutdown(ctx, cancel, servers)
}

func (s *Server) shutdown(ctx context.Context, cancel context.CancelFunc, servers []*http.Server) error {
	if cancel != nil {
		cancel()
	}
	var closeError error
	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			closeError = errors.Join(closeError, errors.New("setup HTTP shutdown failed"))
		}
	}
	if len(servers) == 0 {
		s.doneOnce.Do(func() { close(s.done) })
		return closeError
	}
	select {
	case <-s.done:
		return closeError
	case <-ctx.Done():
		return errors.Join(errors.New("setup HTTP shutdown deadline"), ctx.Err())
	}
}

func (s *Server) closeWhenOwnerStops(owner context.Context) {
	select {
	case <-owner.Done():
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(owner), s.config.RequestTimeout)
		defer cancel()
		_ = s.Close(closeContext)
	case <-s.done:
	}
}

// Done closes after both loopback listeners stop.
func (s *Server) Done() <-chan struct{} {
	if s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.done
}

func (s *Server) scheduleTerminalClose(parent context.Context) {
	s.terminalOnce.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.config.RequestTimeout)
			defer cancel()
			_ = s.Close(ctx)
		}()
	})
}

func randomToken() (string, error) {
	material := make([]byte, tokenBytes)
	if _, err := rand.Read(material); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(material), nil
}

func tokenHash(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }

func validToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == tokenBytes && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid non-nil dependency.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	case reflect.Invalid:
		return true
	default:
		return false
	}
}
