package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

const (
	authPrefix   = "/.auth/"
	loginPath    = authPrefix + "login"
	logoutPath   = authPrefix + "logout"
	passwordPath = authPrefix + "password"

	cookieName = "goftp_session"
	// The __Host- prefix makes browsers refuse the cookie unless it is
	// Secure, host-only and scoped to "/".
	secureCookieName = "__Host-goftp_session"

	// Forms may name many entries at once (see manage).
	maxFormSize = 64 << 10
	dbTimeout   = 10 * time.Second
)

type session struct {
	user   *auth.User
	token  string
	cookie bool
}

func sessionOf(c fiber.Ctx) *session {
	sess, _ := c.Locals(sessionKey).(*session)
	return sess
}

func userOf(c fiber.Ctx) *auth.User {
	if sess := sessionOf(c); sess != nil {
		return sess.user
	}
	return nil
}

func dbContext(c fiber.Ctx) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Context(), dbTimeout)
}

// checkOrigin rejects cross-origin form posts and uploads the way Go's
// http.CrossOriginProtection does: modern browsers label requests with
// Sec-Fetch-Site, older ones at least with Origin.
func (s *Server) checkOrigin(c fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
		return c.Next()
	}
	switch c.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return c.Next()
	case "":
		origin := c.Get(fiber.HeaderOrigin)
		if origin == "" {
			// Not a browser, or a very old one; SameSite cookies still apply.
			return c.Next()
		}
		if u, err := url.Parse(origin); err == nil && u.Host != "" && u.Host == c.Host() {
			return c.Next()
		}
	}
	s.log.Warn("cross-origin request refused", zap.String("ip", c.IP()), zap.String("path", logPath(c.Path())))
	return fiber.ErrForbidden
}

// identify resolves the session from an "Authorization: Bearer" header or
// the session cookie.
func (s *Server) identify(c fiber.Ctx) error {
	token, fromCookie := bearerToken(c), false
	if token == "" {
		token = c.Cookies(s.cookieName(c))
		fromCookie = true
	}
	if token == "" {
		return c.Next()
	}

	ctx, cancel := dbContext(c)
	u, err := s.auth.Authenticate(ctx, token)
	cancel()
	switch {
	case errors.Is(err, auth.ErrNotFound) && fromCookie:
		// Expired or revoked: continue as anonymous.
		s.clearCookie(c)
		return c.Next()
	case errors.Is(err, auth.ErrNotFound):
		return s.unauthorized(c, `, error="invalid_token"`)
	case err != nil:
		return err
	}
	c.Locals(sessionKey, &session{user: u, token: strings.Clone(token), cookie: fromCookie})
	return c.Next()
}

// bearerToken returns the token of an "Authorization: Bearer" header. Other
// schemes are ignored, e.g. those of a reverse proxy.
func bearerToken(c fiber.Ctx) string {
	const prefix = "bearer "
	h := c.Get(fiber.HeaderAuthorization)
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

func (s *Server) unauthorized(c fiber.Ctx, detail string) error {
	c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="goftp"`+detail)
	return fiber.ErrUnauthorized
}

// requirePasswordChange confines users with a temporary password to the
// password form until they choose their own.
func (s *Server) requirePasswordChange(c fiber.Ctx) error {
	sess := sessionOf(c)
	if sess == nil || !sess.user.MustChangePassword {
		return c.Next()
	}
	// Links work for anyone, whatever their account.
	if c.Path() == passwordPath || c.Path() == logoutPath || strings.HasPrefix(c.Path(), sharePrefix) {
		return c.Next()
	}
	if browserNavigation(c) {
		return s.redirect(c, passwordPath+"?next="+url.QueryEscape(c.OriginalURL()))
	}
	return sendMessage(c, fiber.StatusForbidden, "password change required")
}

// browserNavigation reports whether a person is loading a page, who can be
// sent to a form instead of getting an error.
func browserNavigation(c fiber.Ctx) bool {
	return (c.Method() == fiber.MethodGet || c.Method() == fiber.MethodHead) &&
		strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML)
}

// deny answers a request that lacks permission: anonymous visitors of pages
// are sent to the login form, other anonymous clients get 401 and users 403.
func (s *Server) deny(c fiber.Ctx) error {
	switch {
	case sessionOf(c) != nil:
		return fiber.ErrForbidden
	case browserNavigation(c):
		return s.redirect(c, loginPath+"?next="+url.QueryEscape(c.OriginalURL()))
	default:
		return s.unauthorized(c, "")
	}
}

func (s *Server) allowed(c fiber.Ctx, obj, act string) (bool, error) {
	return s.visitorRules(c)(obj, act)
}

// object is the policy object of a clean URL path; directories end in "/".
func object(urlPath string, dir bool) string {
	if dir && urlPath != "/" {
		return urlPath + "/"
	}
	return urlPath
}

func (s *Server) redirect(c fiber.Ctx, to string) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Redirect().Status(fiber.StatusSeeOther).To(to)
}

// safeNext returns next if it is a path on this site, else "/", so the
// login form cannot be used to send people elsewhere.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.ContainsFunc(next, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '\\' }) {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return next
}

func (s *Server) cookieName(c fiber.Ctx) string {
	if c.Secure() {
		return secureCookieName
	}
	return cookieName
}

func (s *Server) setCookie(c fiber.Ctx, sess *auth.Session) {
	c.Cookie(&fiber.Cookie{
		Name:     s.cookieName(c),
		Value:    sess.Token,
		Path:     "/",
		Expires:  sess.Expires,
		Secure:   c.Secure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

func (s *Server) clearCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     s.cookieName(c),
		Path:     "/",
		Expires:  fasthttp.CookieExpireDelete,
		Secure:   c.Secure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// readForm reads a small URL-encoded or JSON object body, keeping the first
// value of each field (see readFormValues).
func (s *Server) readForm(c fiber.Ctx) (map[string]string, bool, error) {
	values, isJSON, err := s.readFormValues(c)
	if err != nil {
		return nil, isJSON, err
	}
	form := make(map[string]string, len(values))
	for k, v := range values {
		form[k] = v[0]
	}
	return form, isJSON, nil
}

// readFormValues reads a small URL-encoded or JSON object body, whose
// fields may repeat: in JSON, a field's value is a string or an array of
// them. The body is streamed, so fasthttp's own form parsing (which
// buffers it) is not used.
func (s *Server) readFormValues(c fiber.Ctx) (url.Values, bool, error) {
	mediaType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	isJSON := mediaType == fiber.MIMEApplicationJSON
	if !isJSON && mediaType != fiber.MIMEApplicationForm {
		return nil, false, fiber.ErrUnsupportedMediaType
	}
	body := s.requestBody(c)
	// Unlike an upload, a form has to arrive within one read timeout, so a
	// client trickling it cannot hold the connection.
	body.deadline = time.Now().Add(body.timeout)
	data, err := io.ReadAll(io.LimitReader(body, maxFormSize+1))
	if err != nil {
		return nil, isJSON, s.uploadError(body, err)
	}
	if len(data) > maxFormSize {
		return nil, isJSON, fiber.ErrRequestEntityTooLarge
	}
	s.finishBody(c, body)

	if !isJSON {
		values, err := url.ParseQuery(string(data))
		if err != nil {
			return nil, false, fiber.ErrBadRequest
		}
		return values, false, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return nil, true, fiber.ErrBadRequest
	}
	values := make(url.Values, len(fields))
	for k, raw := range fields {
		var one string
		if json.Unmarshal(raw, &one) == nil {
			values[k] = []string{one}
			continue
		}
		var many []string
		if json.Unmarshal(raw, &many) != nil {
			return nil, true, fiber.ErrBadRequest
		}
		if len(many) > 0 {
			values[k] = many
		}
	}
	return values, true, nil
}

// signInsPerMinute bounds a user's successful password checks: hashing
// costs as much for valid credentials as for guesses.
var signInsPerMinute = 30

// passwordCheck is a password check admitted by the rate limits.
type passwordCheck struct {
	s            *Server
	client, user string
}

// checkPassword admits a password check for user from the client, or says
// how long to wait. The check counts against the client's failure budget
// before it runs, so concurrent guesses cannot exceed the budget.
func (s *Server) checkPassword(c fiber.Ctx, user string) (*passwordCheck, time.Duration) {
	now := time.Now()
	p := &passwordCheck{s: s, user: auth.NormalizeUsername(user)}
	if wait := s.signIns.attempt(p.user, false, now); wait > 0 {
		return nil, wait
	}
	if s.limiter != nil {
		p.client = clientKey(c.IP())
		if wait := s.limiter.attempt(p.client, true, now); wait > 0 {
			return nil, wait
		}
	}
	return p, 0
}

// refund takes the check back from the client's failure budget.
func (p *passwordCheck) refund() {
	if p.s.limiter != nil {
		p.s.limiter.refund(p.client)
	}
}

// succeeded moves the check to the user's budget.
func (p *passwordCheck) succeeded() {
	p.refund()
	p.s.signIns.attempt(p.user, true, time.Now())
}

func retryAfter(c fiber.Ctx, wait time.Duration) {
	c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(math.Ceil(wait.Seconds()))))
}

const (
	tooMany = "Too many attempts, try again later."
	busy    = "The server is busy, try again in a moment."
)

type authPage struct {
	page
	Error    string
	Next     string
	Username string
	Forced   bool
	// Challenge is set when signing in waits for a two-factor code.
	Challenge string
}

func (s *Server) loginPage(c fiber.Ctx) error {
	next := safeNext(c.Query("next"))
	if sessionOf(c) != nil {
		return s.redirect(c, next)
	}
	return s.render(c, fiber.StatusOK, "login", authPage{page: s.page(c, "Sign in"), Next: next})
}

func (s *Server) login(c fiber.Ctx) error {
	form, isJSON, err := s.readForm(c)
	if err != nil {
		return err
	}
	next := safeNext(form["next"])
	fail := func(status int, msg string) error {
		if isJSON {
			return sendMessage(c, status, msg)
		}
		return s.render(c, status, "login", authPage{page: s.page(c, "Sign in"), Error: msg, Next: next, Username: form["username"]})
	}
	if form["challenge"] != "" {
		return s.loginCode(c, form, isJSON, next)
	}

	check, wait := s.checkPassword(c, form["username"])
	if wait > 0 {
		retryAfter(c, wait)
		return fail(fiber.StatusTooManyRequests, tooMany)
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	sess, err := s.auth.LoginWithCode(ctx, form["username"], form["password"], form["code"])
	var needed *auth.CodeNeeded
	switch {
	case errors.As(err, &needed):
		check.succeeded()
		return s.askCode(c, isJSON, needed.Challenge, next)
	case errors.Is(err, auth.ErrWrongCode):
		// The password was right; the failure still counts.
		s.log.Warn("login code wrong", zap.String("ip", c.IP()), zap.String("user", auth.NormalizeUsername(form["username"])))
		return fail(fiber.StatusUnauthorized, "Wrong two-factor code.")
	case errors.Is(err, auth.ErrInvalidCredentials):
		// A name that matches no user is not logged: it may be a password
		// typed into the wrong field.
		user := "(unknown)"
		if !errors.Is(err, auth.ErrNoSuchUser) {
			user = auth.NormalizeUsername(form["username"])
		}
		s.log.Warn("login failed", zap.String("ip", c.IP()), zap.String("user", user), zap.Error(err))
		return fail(fiber.StatusUnauthorized, "Wrong username or password.")
	case errors.Is(err, auth.ErrBusy):
		check.refund()
		retryAfter(c, time.Second)
		return fail(fiber.StatusServiceUnavailable, busy)
	case err != nil:
		check.refund()
		return err
	}
	check.succeeded()
	return s.signedIn(c, sess, isJSON, next)
}

// signedIn answers a sign-in that succeeded with sess: scripts get its
// token, browsers its cookie and go on to next.
func (s *Server) signedIn(c fiber.Ctx, sess *auth.Session, isJSON bool, next string) error {
	s.log.Info("login", zap.String("ip", c.IP()), zap.String("user", sess.User.Username), zap.Bool("two_factor", sess.User.TwoFactor),
		zap.Bool("recovery_code", sess.RecoveryCode))
	if isJSON {
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.JSON(fiber.Map{
			"token":                sess.Token,
			"expires_at":           sess.Expires.UTC().Format(time.RFC3339),
			"must_change_password": sess.User.MustChangePassword,
		})
	}
	s.setCookie(c, sess)
	switch {
	case sess.User.MustChangePassword:
		next = passwordPath + "?next=" + url.QueryEscape(next)
	case sess.RecoveryCode:
		// Say how many are left.
		next = twoFactorPath + "?recovered=1"
	}
	return s.redirect(c, next)
}

func (s *Server) logout(c fiber.Ctx) error {
	if sess := sessionOf(c); sess != nil {
		ctx, cancel := dbContext(c)
		defer cancel()
		if err := s.auth.Logout(ctx, sess.token); err != nil {
			return err
		}
		s.log.Info("logout", zap.String("ip", c.IP()), zap.String("user", sess.user.Username))
	}
	s.clearCookie(c)
	if strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		return s.redirect(c, loginPath)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) passwordPage(c fiber.Ctx) error {
	sess := sessionOf(c)
	if sess == nil {
		return s.deny(c)
	}
	return s.render(c, fiber.StatusOK, "password", authPage{
		page:   s.page(c, "Change password"),
		Next:   safeNext(c.Query("next")),
		Forced: sess.user.MustChangePassword,
	})
}

func (s *Server) changePassword(c fiber.Ctx) error {
	sess := sessionOf(c)
	if sess == nil {
		return s.deny(c)
	}
	form, isJSON, err := s.readForm(c)
	if err != nil {
		return err
	}
	next := safeNext(form["next"])
	fail := func(status int, msg string) error {
		if isJSON {
			return sendMessage(c, status, msg)
		}
		return s.render(c, status, "password", authPage{
			page: s.page(c, "Change password"), Error: msg, Next: next, Forced: sess.user.MustChangePassword,
		})
	}
	current, password := form["current_password"], form["new_password"]
	if !isJSON && form["confirm_password"] != password {
		return fail(fiber.StatusBadRequest, "The new passwords do not match.")
	}

	check, wait := s.checkPassword(c, sess.user.Username)
	if wait > 0 {
		retryAfter(c, wait)
		return fail(fiber.StatusTooManyRequests, tooMany)
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	changed, err := s.auth.ChangePassword(ctx, sess.user, current, password)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.log.Warn("password change failed", zap.String("ip", c.IP()), zap.String("user", sess.user.Username))
		return fail(fiber.StatusForbidden, "The current password is wrong.")
	case errors.Is(err, auth.ErrBusy):
		check.refund()
		retryAfter(c, time.Second)
		return fail(fiber.StatusServiceUnavailable, busy)
	case errors.Is(err, auth.ErrWeakPassword):
		check.succeeded()
		return fail(fiber.StatusBadRequest, strings.ToUpper(err.Error()[:1])+err.Error()[1:]+".")
	case err != nil:
		check.refund()
		return err
	}
	check.succeeded()
	s.log.Info("password changed", zap.String("ip", c.IP()), zap.String("user", sess.user.Username))

	if sess.cookie {
		s.setCookie(c, changed)
	}
	if isJSON {
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.JSON(fiber.Map{"token": changed.Token, "expires_at": changed.Expires.UTC().Format(time.RFC3339)})
	}
	return s.redirect(c, next)
}

// sendMessage replies with a short plain-text message.
func sendMessage(c fiber.Ctx, status int, msg string) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	return c.Status(status).SendString(msg + "\n")
}
