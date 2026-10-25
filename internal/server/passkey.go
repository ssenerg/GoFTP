package server

import (
	"encoding/json"
	"errors"
	"mime"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// Passkeys (see auth.Passkey): the sign-in page offers them, the Passkeys
// page makes and deletes them. Browsers talk to both in JSON, as WebAuthn
// takes it.
const (
	passkeyLoginPath = authPrefix + "passkey"
	passkeysPath     = authPrefix + "passkeys"
)

// passkeyStartsPerMinute bounds how often a client may start signing in
// with a passkey: each start is kept a while.
var passkeyStartsPerMinute = 30

// passkeyRequest is what browsers send about passkeys.
type passkeyRequest struct {
	Action     string          `json:"action"`
	Token      string          `json:"token"`
	Name       string          `json:"name"`
	Password   string          `json:"password"`
	Next       string          `json:"next"`
	Credential json.RawMessage `json:"credential"`
}

// siteOf is where the visitor of c makes and uses passkeys. It is kept
// past the request, so the host name is copied out of its buffer, which
// the next request on the connection reuses.
func siteOf(c fiber.Ctx) auth.Site {
	return auth.Site{Host: strings.Clone(c.Hostname()), Origin: strings.Clone(c.BaseURL())}
}

// readJSON reads a small JSON body into v.
func (s *Server) readJSON(c fiber.Ctx, v any) error {
	if mediaType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType)); mediaType != fiber.MIMEApplicationJSON {
		return fiber.ErrUnsupportedMediaType
	}
	data, err := s.readSmallBody(c)
	if err != nil {
		return err
	}
	if json.Unmarshal(data, v) != nil {
		return fiber.ErrBadRequest
	}
	return nil
}

// sendOptions answers the start of a passkey ceremony: the options for the
// browser, and the token that goes with its answer.
func sendOptions(c fiber.Ctx, options []byte, token string) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(fiber.Map{"options": json.RawMessage(options), "token": token})
}

// passkeyLogin signs in with a passkey:
//
//	{"action": "begin"}                                   the options for
//	                                                      navigator.credentials.get
//	{"action": "finish", "token": ..., "credential": ...} what it answered,
//	                                                      with "next" for where
//	                                                      to go then
func (s *Server) passkeyLogin(c fiber.Ctx) error {
	var req passkeyRequest
	if err := s.readJSON(c, &req); err != nil {
		return err
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	switch req.Action {
	case "begin":
		if wait := s.passkeyStarts.attempt(clientKey(c.IP()), true, time.Now()); wait > 0 {
			retryAfter(c, wait)
			return fiber.ErrTooManyRequests
		}
		options, token, err := s.auth.BeginPasskeyLogin(siteOf(c))
		if errors.Is(err, auth.ErrBusy) {
			retryAfter(c, time.Second)
			return fiber.ErrServiceUnavailable
		}
		if err != nil {
			return err
		}
		return sendOptions(c, options, token)
	case "finish":
	default:
		return fiber.ErrBadRequest
	}

	check, wait := s.checkCode(c)
	if wait > 0 {
		retryAfter(c, wait)
		return explain(fiber.ErrTooManyRequests, tooMany)
	}
	sess, err := s.auth.PasskeyLogin(ctx, req.Token, req.Credential)
	switch {
	case errors.Is(err, auth.ErrCeremonyGone):
		check.refund()
		return explain(fiber.ErrUnauthorized, "It took too long: try again.")
	case errors.Is(err, auth.ErrPasskeyRefused), errors.Is(err, auth.ErrInvalidCredentials):
		s.log.Warn("passkey refused", zap.String("ip", c.IP()), zap.Error(err))
		return explain(fiber.ErrUnauthorized, "That passkey does not sign anyone in here. Sign in with your password, then add it under Passkeys.")
	case err != nil:
		check.refund()
		return err
	}
	check.refund()
	s.log.Info("login", zap.String("ip", c.IP()), zap.String("user", sess.User.Username), zap.Bool("passkey", true))
	s.setCookie(c, sess)
	next := safeNext(req.Next)
	if sess.User.MustChangePassword {
		next = passwordPath + "?next=" + url.QueryEscape(next)
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(fiber.Map{"next": next})
}

type passkeysPage struct {
	page
	Keys   []passkeyView
	Notice string
	Error  string
}

type passkeyView struct {
	ID                    int64
	Name                  string
	Created, CreatedISO   string
	LastUsed, LastUsedISO string // "" if never
}

var passkeyNotices = map[string]string{
	"added":   "The passkey was added: it signs you in on this site, without your password.",
	"deleted": "The passkey was deleted. Remove it from the device too, under its passwords or passkeys.",
}

func (s *Server) passkeysPage(c fiber.Ctx) error {
	if userOf(c) == nil {
		return s.deny(c)
	}
	return s.renderPasskeys(c, fiber.StatusOK, passkeyNotices[c.Query("done")], "")
}

func (s *Server) renderPasskeys(c fiber.Ctx, status int, notice, failure string) error {
	ctx, cancel := dbContext(c)
	defer cancel()
	keys, err := s.auth.Passkeys(ctx, userOf(c))
	if err != nil {
		return err
	}
	data := passkeysPage{page: s.page(c, "Passkeys"), Notice: notice, Error: failure}
	for _, k := range keys {
		v := passkeyView{ID: k.ID, Name: k.Name, Created: shownTime(k.CreatedAt), CreatedISO: isoTime(k.CreatedAt)}
		if !k.LastUsedAt.IsZero() {
			v.LastUsed, v.LastUsedISO = shownTime(k.LastUsedAt), isoTime(k.LastUsedAt)
		}
		data.Keys = append(data.Keys, v)
	}
	return s.render(c, status, "passkeys", data)
}

// passkeysAction makes and deletes the visitor's passkeys:
//
//	{"action": "begin", "password": ...}             the options for
//	                                                 navigator.credentials.create
//	{"action": "finish", "token": ..., "name": ...,  makes the passkey of what
//	 "credential": ...}                              it answered
//	action=delete&id=ID                              deletes the passkey ID
func (s *Server) passkeysAction(c fiber.Ctx) error {
	u := userOf(c)
	if u == nil {
		return s.deny(c)
	}
	if mediaType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType)); mediaType != fiber.MIMEApplicationJSON {
		form, _, err := s.readForm(c)
		if err != nil {
			return err
		}
		if form["action"] != "delete" {
			return fiber.ErrBadRequest
		}
		return s.deletePasskey(c, u, form["id"])
	}
	var req passkeyRequest
	if err := s.readJSON(c, &req); err != nil {
		return err
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	switch req.Action {
	case "begin":
		check, wait := s.checkPassword(c, u.Username)
		if wait > 0 {
			retryAfter(c, wait)
			return explain(fiber.ErrTooManyRequests, tooMany)
		}
		options, token, err := s.auth.BeginPasskey(ctx, u, req.Password, siteOf(c))
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			s.log.Warn("passkey refused: wrong password", zap.String("ip", c.IP()), zap.String("user", u.Username))
			return explain(fiber.ErrForbidden, "The password is wrong.")
		case errors.Is(err, auth.ErrTooMany):
			check.succeeded()
			return explain(fiber.ErrConflict, "You have "+strconv.Itoa(auth.MaxPasskeys)+" passkeys. Delete one first.")
		case errors.Is(err, auth.ErrBusy):
			check.refund()
			retryAfter(c, time.Second)
			return explain(fiber.ErrServiceUnavailable, busy)
		case err != nil:
			check.refund()
			return err
		}
		check.succeeded()
		return sendOptions(c, options, token)
	case "finish":
		pk, err := s.auth.FinishPasskey(ctx, u, req.Token, req.Name, req.Credential)
		switch {
		case errors.Is(err, auth.ErrInvalid):
			return explain(fiber.ErrBadRequest, "Name the passkey in up to 64 characters, e.g. the device it is on.")
		case errors.Is(err, auth.ErrCeremonyGone):
			return explain(fiber.ErrConflict, "It took too long: try again.")
		case errors.Is(err, auth.ErrPasskeyRefused):
			s.log.Warn("passkey refused", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.Error(err))
			return explain(fiber.ErrBadRequest, "The browser's answer did not check out: try again.")
		case errors.Is(err, auth.ErrExists):
			return explain(fiber.ErrConflict, "That passkey is in use already.")
		case errors.Is(err, auth.ErrTooMany):
			return explain(fiber.ErrConflict, "You have "+strconv.Itoa(auth.MaxPasskeys)+" passkeys. Delete one first.")
		case err != nil:
			return err
		}
		s.log.Info("passkey added", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.Int64("passkey", pk.ID))
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": pk.ID, "name": pk.Name})
	}
	return fiber.ErrBadRequest
}

func (s *Server) deletePasskey(c fiber.Ctx, u *auth.User, idText string) error {
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	html := strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML)
	err = s.auth.DeletePasskey(ctx, u, id)
	switch {
	case errors.Is(err, auth.ErrNotFound) && html:
		return s.renderPasskeys(c, fiber.StatusNotFound, "", "There is no such passkey: it may have been deleted already.")
	case errors.Is(err, auth.ErrNotFound):
		return fiber.ErrNotFound
	case err != nil:
		return err
	}
	s.log.Info("passkey deleted", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.Int64("passkey", id))
	if html {
		return s.redirect(c, passkeysPath+"?done=deleted")
	}
	return c.SendStatus(fiber.StatusNoContent)
}
