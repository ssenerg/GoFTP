package server

import (
	"errors"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"rsc.io/qr"

	"goftp/internal/auth"
)

// twoFactorPath is the page where users turn two-factor sign-in on and off
// (see auth.LoginWithCode).
const twoFactorPath = authPrefix + "two-factor"

type twoFactorPage struct {
	page
	On        bool
	CodesLeft int
	Setup     *twoFactorSetup
	Codes     []string // new recovery codes, shown once
	Recovered bool     // the visitor just signed in with a recovery code
	Notice    string
	Error     string
}

// twoFactorSetup is a secret being set up, for the visitor's app.
type twoFactorSetup struct {
	Secret string // in groups of four, as people type it
	URI    template.URL
	QR     template.HTML
}

var twoFactorNotices = map[string]string{
	"off": "Two-factor sign-in is off: your password alone signs you in.",
}

func (s *Server) twoFactorPage(c fiber.Ctx) error {
	if userOf(c) == nil {
		return s.deny(c)
	}
	return s.renderTwoFactor(c, fiber.StatusOK, twoFactorPage{Notice: twoFactorNotices[c.Query("done")], Recovered: c.Query("recovered") == "1"})
}

// renderTwoFactor shows data, with how far the visitor is with two-factor
// sign-in.
func (s *Server) renderTwoFactor(c fiber.Ctx, status int, data twoFactorPage) error {
	u := userOf(c)
	ctx, cancel := dbContext(c)
	defer cancel()
	st, err := s.auth.TwoFactorOf(ctx, u)
	if err != nil {
		return err
	}
	data.page, data.On, data.CodesLeft = s.page(c, "Two-factor sign-in"), st.On, st.RecoveryCodes
	if st.Pending != "" {
		if data.Setup, err = s.setupOf(c, u, st.Pending); err != nil {
			return err
		}
	}
	return s.render(c, status, "twofactor", data)
}

// setupOf describes the secret (in base32) that u is setting up.
func (s *Server) setupOf(c fiber.Ctx, u *auth.User, secret string) (*twoFactorSetup, error) {
	var groups []string
	for i := 0; i < len(secret); i += 4 {
		groups = append(groups, secret[i:min(i+4, len(secret))])
	}
	uri := auth.OTPAuthURI(c.Hostname(), u.Username, secret)
	setup := &twoFactorSetup{Secret: strings.Join(groups, " "), URI: template.URL(uri)}
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		return nil, err
	}
	setup.QR = qrSVG(code)
	return setup, nil
}

// qrSVG draws code, with the quiet zone around it that scanners need.
func qrSVG(code *qr.Code) template.HTML {
	const quiet = 4
	var b strings.Builder
	n := code.Size + 2*quiet
	fmt.Fprintf(&b, `<svg class="qr" viewBox="0 0 %d %d" role="img" aria-label="QR code of the key" shape-rendering="crispEdges">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := range code.Size {
		for x := 0; x < code.Size; x++ {
			if !code.Black(x, y) {
				continue
			}
			run := 1
			for code.Black(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run - 1
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String())
}

// twoFactorAction sets up two-factor sign-in, sent URL-encoded or as JSON:
//
//	action=start              makes a new secret for the visitor's app:
//	                          {"secret": BASE32, "uri": "otpauth://..."}
//	action=confirm&code=CODE  turns it on, given a code of the secret, and
//	                          answers with recovery codes, shown once; it
//	                          signs out everywhere, so with a new session
//	                          token too
//	action=codes&password=PW  makes new recovery codes
//	action=off&password=PW    turns it off
func (s *Server) twoFactorAction(c fiber.Ctx) error {
	sess := sessionOf(c)
	if sess == nil {
		return s.deny(c)
	}
	u := sess.user
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	// Scripts get JSON, as for links.
	isJSON := !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML)
	fail := func(status int, msg string) error {
		if isJSON {
			return sendMessage(c, status, msg)
		}
		return s.renderTwoFactor(c, status, twoFactorPage{Error: msg})
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	c.Set(fiber.HeaderCacheControl, "no-store")

	switch form["action"] {
	case "start":
		secret, err := s.auth.StartTwoFactor(ctx, u)
		if errors.Is(err, auth.ErrInvalid) {
			return fail(fiber.StatusConflict, "Two-factor sign-in is on already.")
		}
		if err != nil {
			return err
		}
		if isJSON {
			return c.JSON(fiber.Map{"secret": secret, "uri": auth.OTPAuthURI(c.Hostname(), u.Username, secret)})
		}
		return s.redirect(c, twoFactorPath)
	case "confirm":
		codes, changed, err := s.auth.ConfirmTwoFactor(ctx, u, form["code"])
		switch {
		case errors.Is(err, auth.ErrWrongCode):
			return fail(fiber.StatusBadRequest, "That is not the code the app shows now: check that its clock is right, and try the next one.")
		case errors.Is(err, auth.ErrNotFound):
			return fail(fiber.StatusConflict, "Set it up first.")
		case errors.Is(err, auth.ErrInvalid):
			return fail(fiber.StatusConflict, "Two-factor sign-in is on already.")
		case err != nil:
			return err
		}
		s.log.Info("two-factor sign-in on", zap.String("ip", c.IP()), zap.String("user", u.Username))
		if isJSON {
			return c.JSON(fiber.Map{"recovery_codes": codes, "token": changed.Token, "expires_at": changed.Expires.UTC().Format(time.RFC3339)})
		}
		if sess.cookie {
			s.setCookie(c, changed)
		}
		c.Locals(sessionKey, &session{user: changed.User, token: changed.Token, cookie: sess.cookie})
		return s.renderTwoFactor(c, fiber.StatusOK, twoFactorPage{Codes: codes,
			Notice: "Two-factor sign-in is on. You were signed out everywhere else."})
	case "codes", "off":
	default:
		return fiber.ErrBadRequest
	}

	// Both take the password.
	check, wait := s.checkPassword(c, u.Username)
	if wait > 0 {
		retryAfter(c, wait)
		return fail(fiber.StatusTooManyRequests, tooMany)
	}
	var codes []string
	if form["action"] == "codes" {
		codes, err = s.auth.NewRecoveryCodes(ctx, u, form["password"])
	} else {
		err = s.auth.DisableTwoFactor(ctx, u, form["password"])
	}
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.log.Warn("two-factor change refused: wrong password", zap.String("ip", c.IP()), zap.String("user", u.Username))
		return fail(fiber.StatusForbidden, "The password is wrong.")
	case errors.Is(err, auth.ErrInvalid):
		check.succeeded()
		return fail(fiber.StatusConflict, "Two-factor sign-in is off.")
	case errors.Is(err, auth.ErrBusy):
		check.refund()
		retryAfter(c, time.Second)
		return fail(fiber.StatusServiceUnavailable, busy)
	case err != nil:
		check.refund()
		return err
	}
	check.succeeded()
	if form["action"] == "off" {
		s.log.Info("two-factor sign-in off", zap.String("ip", c.IP()), zap.String("user", u.Username))
		if isJSON {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return s.redirect(c, twoFactorPath+"?done=off")
	}
	s.log.Info("recovery codes made", zap.String("ip", c.IP()), zap.String("user", u.Username))
	if isJSON {
		return c.JSON(fiber.Map{"recovery_codes": codes})
	}
	return s.renderTwoFactor(c, fiber.StatusOK, twoFactorPage{Codes: codes, Notice: "New recovery codes: the old ones no longer work."})
}

// checkCode admits a try of a two-factor code from the client, or says how
// long to wait: it counts against the client's failure budget, as a
// password check does.
func (s *Server) checkCode(c fiber.Ctx) (*passwordCheck, time.Duration) {
	p := &passwordCheck{s: s}
	if s.limiter != nil {
		p.client = clientKey(c.IP())
		if wait := s.limiter.attempt(p.client, true, time.Now()); wait > 0 {
			return nil, wait
		}
	}
	return p, 0
}

// loginCode goes on with a sign-in that waits for a two-factor code: the
// form has its challenge and the code.
func (s *Server) loginCode(c fiber.Ctx, form map[string]string, isJSON bool, next string) error {
	challenge := form["challenge"]
	fail := func(status int, msg string, again bool) error {
		if isJSON {
			return sendMessage(c, status, msg)
		}
		data := authPage{page: s.page(c, "Sign in"), Error: msg, Next: next}
		if !again {
			data.Challenge = challenge
		}
		return s.render(c, status, "login", data)
	}
	check, wait := s.checkCode(c)
	if wait > 0 {
		retryAfter(c, wait)
		return fail(fiber.StatusTooManyRequests, tooMany, false)
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	sess, err := s.auth.ContinueLogin(ctx, challenge, form["code"])
	switch {
	case errors.Is(err, auth.ErrWrongCode):
		s.log.Warn("login code wrong", zap.String("ip", c.IP()))
		return fail(fiber.StatusUnauthorized, "Wrong code. Enter the one your app shows now, or a recovery code.", false)
	case errors.Is(err, auth.ErrChallengeGone):
		return fail(fiber.StatusUnauthorized, "It took too long, or too many codes were wrong: sign in again.", true)
	case errors.Is(err, auth.ErrInvalidCredentials):
		// The password changed meanwhile.
		return fail(fiber.StatusUnauthorized, "Sign in again.", true)
	case err != nil:
		check.refund()
		return err
	}
	check.refund()
	return s.signedIn(c, sess, isJSON, next)
}

// askCode answers a sign-in that needs a two-factor code, with challenge to
// send back with it.
func (s *Server) askCode(c fiber.Ctx, isJSON bool, challenge, next string) error {
	if isJSON {
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "a two-factor code is needed", "two_factor": true, "challenge": challenge})
	}
	return s.render(c, fiber.StatusOK, "login", authPage{page: s.page(c, "Sign in"), Next: next, Challenge: challenge})
}
