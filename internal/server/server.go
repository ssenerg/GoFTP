package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/helmet"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"go.uber.org/zap"

	"goftp/internal/auth"
	"goftp/internal/config"
)

// readBufferSize bounds the request line plus headers; percent-encoded
// non-ASCII paths are long. Idle connections release it (ReduceMemoryUsage).
const readBufferSize = 16 << 10

// contentSecurityPolicy lets pages run their own script, upload to this
// site and show its images, media and PDFs, and nothing else.
var contentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; media-src 'self'; frame-src 'self'; script-src " +
	scriptHash + "; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

const allowedMethods = "GET, HEAD, PUT, POST, DELETE"

type Server struct {
	cfg       *config.Config
	log       *zap.Logger
	auth      *auth.Service
	app       *fiber.App
	root      *os.Root
	rootPath  string
	limiter   *rateLimiter // failed password checks per client
	signIns   *rateLimiter // successful password checks per user
	errEscape error
	lockMu    sync.Mutex
	// trashMu orders restoring entries from the trash against removing
	// them for good.
	trashMu sync.Mutex
	// touched notes when links were last noted as used, by ID.
	touched sync.Map
	// homesChecked holds the IDs of users whose home was claimed (see
	// claimHome); homeMu orders the claims.
	homesChecked sync.Map
	homeMu       sync.Mutex
	// uses holds what homes hold, by name (see homeUse).
	uses sync.Map
	// davLocks holds the WebDAV locks by token; davMu guards it.
	davLocks map[string]*davLock
	davMu    sync.Mutex
	// fold is how rules compare paths (see checkNames), nil as spelled.
	fold func(string) string
	// proxyNoted is set once untrusted proxy headers have been logged.
	proxyNoted atomic.Bool

	shareGuesses *rateLimiter // password checks per share link
	// passkeyStarts are the passkey sign-ins started per client.
	passkeyStarts *rateLimiter
	thumbs        *thumbCache
	thumbing      chan struct{} // thumbnails being made
	thumbWait     time.Duration // for a turn to make one
}

func New(cfg *config.Config, log *zap.Logger, authSvc *auth.Service) (*Server, error) {
	rootPath, err := filepath.EvalSymlinks(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if filepath.Dir(rootPath) == rootPath {
		return nil, fmt.Errorf("refusing to serve the whole file system (%s): set dir to a folder", rootPath)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	// Spelled as the kernel spells the paths of what is in it.
	if f, err := root.Open("."); err == nil {
		if p, ok := fdPath(f); ok {
			rootPath = p
		}
		_ = f.Close()
	}
	s := &Server{
		cfg:       cfg,
		log:       log,
		auth:      authSvc,
		root:      root,
		rootPath:  rootPath,
		errEscape: escapeError(root),
		davLocks:  map[string]*davLock{},
	}
	fold, err := s.checkNames()
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	s.fold = fold
	authSvc.SetFold(fold)
	authSvc.SetHomes(cfg.Homes.Path)
	if err := s.checkHomes(); err != nil {
		_ = root.Close()
		return nil, err
	}
	s.warnOldHomes()

	s.app = fiber.New(fiber.Config{
		ErrorHandler:      s.handleError,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadBufferSize:    readBufferSize,
		ReduceMemoryUsage: true,
		Concurrency:       maxConns(),
		// Uploads are streamed to disk instead of buffered in memory.
		StreamRequestBody:            true,
		DisablePreParseMultipartForm: true,
		RequestMethods:               append(slices.Clone(fiber.DefaultMethods), davMethods...),
		CaseSensitive:                true,
		StrictRouting:                true,
		// Forwarded headers (the proxy header, X-Forwarded-Proto) are only
		// believed from these proxies.
		ProxyHeader:        cfg.Server.ProxyHeader,
		TrustProxy:         len(cfg.Server.TrustedProxies) > 0,
		TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: cfg.Server.TrustedProxies},
		EnableIPValidation: true,
	})

	panics := recover.Config{EnableStackTrace: true, StackTraceHandler: s.logPanic}
	// The outer recover guards the logger; the inner one turns handler
	// panics into logged 500s.
	s.app.Use(recover.New(panics))
	s.app.Use(s.logRequests)
	s.app.Use(recover.New(panics))
	s.app.Use(helmet.New(helmet.Config{
		XFrameOptions:         "DENY",
		ContentSecurityPolicy: contentSecurityPolicy,
		// Sent over HTTPS only, including from a trusted proxy.
		HSTSMaxAge:            365 * 24 * 60 * 60,
		HSTSExcludeSubdomains: true,
	}))
	if cfg.Limiter.MaxFailures > 0 {
		s.limiter = newRateLimiter(cfg.Limiter.MaxFailures, cfg.Limiter.Window)
	}
	s.signIns = newRateLimiter(signInsPerMinute, time.Minute)
	s.shareGuesses = newRateLimiter(shareGuessesPerMinute, time.Minute)
	s.passkeyStarts = newRateLimiter(passkeyStartsPerMinute, time.Minute)
	s.thumbs = newThumbCache(cfg.Cache.Dir, int64(cfg.Cache.MaxSize), log)
	s.thumbing, s.thumbWait = make(chan struct{}, thumbConcurrency()), 30*time.Second
	s.app.Use(s.noteProxyHeaders, s.checkOrigin, s.identify, s.requirePasswordChange)
	s.app.Get(loginPath, s.loginPage)
	s.app.Post(loginPath, s.login)
	s.app.Post(logoutPath, s.logout)
	s.app.Get(passwordPath, s.passwordPage)
	s.app.Post(passwordPath, s.changePassword)
	s.app.Get(twoFactorPath, s.twoFactorPage)
	s.app.Post(twoFactorPath, s.twoFactorAction)
	s.app.Post(passkeyLoginPath, s.passkeyLogin)
	s.app.Get(passkeysPath, s.passkeysPage)
	s.app.Post(passkeysPath, s.passkeysAction)
	s.app.Get(strings.TrimSuffix(adminPath, "/"), s.adminHome)
	s.app.Get(adminPath, s.adminHome)
	s.app.Get(usersPath, s.usersPage)
	s.app.Post(usersPath, s.usersAction)
	s.app.Get(rulesPath, s.rulesPage)
	s.app.Post(rulesPath, s.rulesAction)
	s.app.Get(strings.TrimSuffix(sharesPath, "/"), func(c fiber.Ctx) error { return s.redirect(c, sharesPath) })
	s.app.Get(sharesPath, s.sharesPage)
	s.app.Post(sharesPath, s.sharesAction)
	s.app.Get(strings.TrimSuffix(trashPath, "/"), func(c fiber.Ctx) error { return s.redirect(c, trashPath) })
	s.app.Get(trashPath, s.trashPage)
	s.app.Post(trashPath, s.trashAction)
	s.app.Get(strings.TrimSuffix(syncPath, "/"), func(c fiber.Ctx) error { return s.redirect(c, syncPath) })
	s.app.Get(syncPath, s.syncPage)
	s.app.Post(syncPath, s.syncAction)
	s.app.Get(strings.TrimSuffix(searchPath, "/"), func(c fiber.Ctx) error { return s.redirect(c, searchPath) })
	s.app.Get(searchPath, s.search)
	s.davRoutes()
	s.app.Get(sharePrefix+"*", s.shared)
	s.app.Post(sharePrefix+"*", s.sharePost)
	s.app.Head(uploadsPrefix+"*", s.headUpload)
	s.app.Patch(uploadsPrefix+"*", s.patchUpload)
	s.app.Delete(uploadsPrefix+"*", s.deleteUpload)
	s.app.Get("/*", s.handle)
	s.app.Put("/*", s.put)
	s.app.Post("/*", s.postForm)
	s.app.Delete("/*", s.deleteEntry)
	srv := s.app.Server()
	srv.Handler = s.wrapHandler(srv.Handler)
	return s, nil
}

// App exposes the Fiber application, mainly for tests.
func (s *Server) App() *fiber.App { return s.app }

// Listen serves until ctx is cancelled, then waits up to shutdown_timeout
// for in-flight requests before returning.
func (s *Server) Listen(ctx context.Context) error {
	ln, err := s.listen()
	if err != nil {
		return err
	}
	s.log.Info("listening",
		zap.String("addr", ln.Addr().String()),
		zap.String("dir", s.cfg.Dir),
		zap.Bool("tls", s.cfg.TLS.CertFile != ""))

	swept := make(chan struct{})
	go func() {
		defer close(swept)
		if n := s.removeLeftovers(ctx); n > 0 {
			s.log.Info("removed leftovers of interrupted uploads", zap.Int("files", n))
		}
	}()
	defer func() { <-swept }()
	purged := make(chan struct{})
	go func() {
		defer close(purged)
		s.purgeUploads(ctx)
	}()
	defer func() { <-purged }()
	emptied := make(chan struct{})
	go func() {
		defer close(emptied)
		s.purgeTrash(ctx)
	}()
	defer func() { <-emptied }()

	served := make(chan error, 1)
	go func() {
		served <- s.app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	}()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}

	s.log.Info("shutting down", zap.Duration("timeout", s.cfg.Server.ShutdownTimeout))
	err = s.app.ShutdownWithTimeout(s.cfg.Server.ShutdownTimeout)
	// Serve may not have registered the listener yet; closing it here
	// guarantees that it returns.
	_ = ln.Close()
	<-served
	if errors.Is(err, context.DeadlineExceeded) {
		s.log.Warn("shutdown timed out, in-flight requests will be cut off")
		return nil
	}
	return err
}

func (s *Server) listen() (net.Listener, error) {
	ln, err := net.Listen(fiber.NetworkTCP, s.cfg.Addr)
	if err != nil {
		return nil, err
	}
	ln = &retryListener{Listener: ln, log: s.log}
	if n := s.cfg.Server.MaxConnsPerIP; n > 0 {
		ln = newPerClientListener(ln, n)
	}
	if s.cfg.TLS.CertFile == "" {
		return ln, nil
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	return tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}), nil
}

func (s *Server) Close() error {
	return s.root.Close()
}

// escapeError captures os.Root's unexported "path escapes" error.
func escapeError(root *os.Root) error {
	f, err := root.Open("..")
	if err == nil {
		_ = f.Close()
		return nil
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return nil
}
