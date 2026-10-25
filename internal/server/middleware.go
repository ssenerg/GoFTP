package server

import (
	"errors"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey int

const (
	logStateKey ctxKey = iota
	bodyDoneKey
	sessionKey
	shareKey
	rulesKey
)

type logState struct {
	start    time.Time
	deferred bool
}

// logRequests writes one access log line per request. The query string is
// not logged.
func (s *Server) logRequests(c fiber.Ctx) error {
	st := &logState{start: time.Now()}
	c.Locals(logStateKey, st)

	err := c.Next()
	if err == nil && !c.Matched() {
		// Fiber's request-level error pass (malformed request, timeout,
		// 405...): the final status is set later, in handleError.
		st.deferred = true
		return nil
	}
	if err != nil {
		if herr := c.App().ErrorHandler(c, err); herr != nil {
			_ = c.SendStatus(fiber.StatusInternalServerError)
		}
	}

	// Downloads are logged once the body has been sent (or aborted).
	a := newAccess(c, st.start)
	if body, ok := c.Response().BodyStream().(finishing); ok {
		body.whenDone(func(sent int64, err error) { s.writeAccess(a, sent, err) })
		return nil
	}
	s.writeAccess(a, bodySize(c), nil)
	return nil
}

// finishing is a streamed response body that says when it is done, so its
// request can be logged with what was sent. Other streamed bodies would be
// read into memory for the log.
type finishing interface {
	whenDone(func(sent int64, err error))
}

// access holds copies of the request data: Fiber reuses its buffers once
// the handler returns, before a streamed body is finished.
type access struct {
	ip, method, path string
	status           int
	start            time.Time
}

func newAccess(c fiber.Ctx, start time.Time) access {
	return access{
		ip:     strings.Clone(c.IP()),
		method: string(c.Request().Header.Method()),
		path:   logPath(strings.Clone(c.Path())),
		status: c.Response().StatusCode(),
		start:  start,
	}
}

func bodySize(c fiber.Ctx) int64 {
	if c.Request().Header.IsHead() {
		return 0
	}
	return int64(len(c.Response().Body()))
}

func (s *Server) writeAccess(a access, bytes int64, err error) {
	level := zapcore.InfoLevel
	switch {
	case a.status == fiber.StatusNotImplemented:
		// An unknown method: the client's mistake, not the server's.
	case a.status >= fiber.StatusInternalServerError:
		level = zapcore.ErrorLevel
	case a.status == fiber.StatusRequestTimeout:
		// Usually an idle (pre)connection that never sent a request.
		level = zapcore.DebugLevel
	}
	ce := s.log.Check(level, "request")
	if ce == nil {
		return
	}
	fields := []zap.Field{
		zap.String("ip", a.ip),
		zap.String("method", a.method),
		zap.String("path", a.path),
		zap.Int("status", a.status),
		zap.Int64("bytes", bytes),
		zap.Duration("latency", time.Since(a.start)),
	}
	if err != nil {
		fields = append(fields, zap.Error(err))
	}
	ce.Write(fields...)
}

// handleError replies with a generic description of the error, so internal
// details never reach the client.
func (s *Server) handleError(c fiber.Ctx, err error) error {
	return s.sendError(c, err, "")
}

// sendError answers with err's status: a page for browsers, plain text for
// other clients. detail is shown as is.
func (s *Server) sendError(c fiber.Ctx, err error, detail string) error {
	code := fiber.StatusInternalServerError
	var (
		fe *fiber.Error
		ex *explained
	)
	if errors.As(err, &ex) && detail == "" {
		detail = ex.detail
	}
	if errors.As(err, &fe) {
		code = fe.Code
	} else {
		s.log.Error("request failed", zap.String("path", logPath(c.Path())), zap.Error(err))
	}
	if code == fiber.StatusMethodNotAllowed {
		allow := allowedMethods
		if inDav(c.Path()) {
			allow = davAllow
		}
		c.Set(fiber.HeaderAllow, allow)
	}
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	c.Set(fiber.HeaderCacheControl, "no-store")
	err = nil
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) ||
		s.render(c, code, "error", s.errorPage(c, code, detail)) != nil {
		text := http.StatusText(code)
		if detail != "" {
			text += "\n" + detail + "\n"
		}
		c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
		err = c.Status(code).SendString(text)
	}

	// Fiber calls the error handler outside the middleware chain for
	// request-level failures; log those here.
	switch st, _ := c.Locals(logStateKey).(*logState); {
	case st == nil:
		c.Locals(logStateKey, &logState{})
		s.writeAccess(newAccess(c, time.Now()), bodySize(c), nil)
	case st.deferred:
		s.writeAccess(newAccess(c, st.start), bodySize(c), nil)
	}
	return err
}

type errorPage struct {
	page
	Code    int
	Message string
	Detail  string
	Back    string
	SignIn  bool
}

var errorMessages = map[int]string{
	fiber.StatusBadRequest:            "The request could not be understood.",
	fiber.StatusUnauthorized:          "Sign in to continue.",
	fiber.StatusForbidden:             "You don't have access to this. Ask an administrator if you need it.",
	fiber.StatusNotFound:              "There is nothing here. It may have been moved or deleted, or it is still being uploaded.",
	fiber.StatusConflict:              "A file or folder with this name already exists, or is being uploaded right now.",
	fiber.StatusGone:                  "This link no longer works.",
	fiber.StatusRequestEntityTooLarge: "The file is larger than this server accepts.",
	fiber.StatusTooManyRequests:       "Too many attempts. Wait a moment and try again.",
	fiber.StatusServiceUnavailable:    "The server is busy. Try again in a moment.",
	fiber.StatusInsufficientStorage:   "The server is out of disk space.",
}

func (s *Server) errorPage(c fiber.Ctx, code int, detail string) errorPage {
	p := errorPage{page: s.page(c, http.StatusText(code)), Code: code, Detail: detail,
		Message: errorMessages[code], SignIn: code == fiber.StatusUnauthorized && userOf(c) == nil}
	if p.Message == "" {
		p.Message = "Something went wrong. Try again later."
	}
	if strings.HasPrefix(c.Path(), sharePrefix) {
		// Visitors of links get the way back to what the link leads to, if
		// it works, and nothing of the visitor's account.
		view, _ := c.Locals(shareKey).(*shareView)
		p.page = s.sharePage(c, view, p.Title)
		if view == nil && detail != "" {
			p.Message, p.Detail = detail, ""
		}
		return p
	}
	// Offer the way back to the folder of the failed request.
	if urlPath, _, err := cleanPath(c.Path()); err == nil && urlPath != "/" && !hidden(urlPath) {
		if c.Method() != fiber.MethodPost {
			urlPath = path.Dir(urlPath)
		}
		p.Back = escapePath(object(urlPath, true))
	}
	return p
}

func (s *Server) logPanic(c fiber.Ctx, e any) {
	s.log.Error("panic", zap.Any("panic", e), zap.String("path", logPath(c.Path())), zap.Stack("stack"))
}

// clientKey groups IPv6 clients by /64, since a single host usually owns
// the whole prefix.
func clientKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return strings.Clone(ip)
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return strings.Clone(ip)
	}
	return prefix.String()
}

// noteProxyHeaders warns once about forwarding headers from an untrusted
// address: behind a proxy that goftp does not know of, all clients share
// the proxy's address, and so one budget of failed sign-ins.
func (s *Server) noteProxyHeaders(c fiber.Ctx) error {
	if !s.proxyNoted.Load() && !c.IsProxyTrusted() {
		for _, h := range []string{fiber.HeaderXForwardedFor, "X-Real-Ip", "Forwarded"} {
			if c.Get(h) != "" && s.proxyNoted.CompareAndSwap(false, true) {
				s.log.Warn("ignoring proxy headers from an untrusted address; behind a reverse proxy, set server.proxy_header and server.trusted_proxies",
					zap.String("header", h), zap.String("from", c.IP()))
				break
			}
		}
	}
	return c.Next()
}
