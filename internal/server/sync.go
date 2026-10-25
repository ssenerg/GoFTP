package server

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// syncPath is the page where users make app passwords for sync apps, and
// find how to set those up with goftp's WebDAV address (see dav.go).
const syncPath = "/.sync/"

type syncData struct {
	page
	SiteURL string // the WebDAV address of the site
	URL     string // the one to sync: of the visitor's home, if they have one
	Home    bool
	Path    string // URL's path
	// FileManagerURL is URL as file managers on Linux take it, e.g.
	// davs://host/.dav/
	FileManagerURL string
	Insecure       bool // app passwords would be sent unencrypted
	Username       string
	Apps           []appRow
	Max            int
	Created        *createdApp
	Notice         string
	Error          string
}

type appRow struct {
	ID                    int64
	Name                  string
	Created, CreatedISO   string
	LastUsed, LastUsedISO string // "" if never
}

// createdApp is a new app password, shown once.
type createdApp struct{ Name, Password string }

var syncNotices = map[string]string{"revoked": "The app password was revoked. Apps that used it can no longer sign in."}

func (s *Server) syncPage(c fiber.Ctx) error {
	if userOf(c) == nil {
		return s.deny(c)
	}
	return s.renderSync(c, fiber.StatusOK, syncNotices[c.Query("done")], "", nil)
}

func (s *Server) renderSync(c fiber.Ctx, status int, notice, failure string, created *createdApp) error {
	u := userOf(c)
	ctx, cancel := dbContext(c)
	defer cancel()
	apps, err := s.auth.AppPasswords(ctx, u)
	if err != nil {
		return err
	}
	data := syncData{page: s.page(c, "Sync"), SiteURL: c.BaseURL() + davPrefix + "/", Path: davPrefix + "/",
		Insecure: !c.Secure(), Username: u.Username, Max: auth.MaxAppPasswords, Created: created, Notice: notice, Error: failure}
	if home := s.homeOf(u); home != "" {
		data.Home, data.Path = true, davHref(home, true)
	}
	data.URL = c.BaseURL() + data.Path
	data.FileManagerURL = "dav" + strings.TrimPrefix(data.URL, "http")
	for _, ap := range apps {
		row := appRow{ID: ap.ID, Name: ap.Name, Created: shownTime(ap.CreatedAt),
			CreatedISO: isoTime(ap.CreatedAt)}
		if !ap.LastUsedAt.IsZero() {
			row.LastUsed = shownTime(ap.LastUsedAt)
			row.LastUsedISO = isoTime(ap.LastUsedAt)
		}
		data.Apps = append(data.Apps, row)
	}
	return s.render(c, status, "sync", data)
}

// syncAction makes and revokes app passwords:
//
//	action=create&name=NAME  a new app password for the app NAME, shown once
//	action=revoke&id=ID      ends the app password ID
//
// e.g. curl -H "Authorization: Bearer $TOKEN" -d action=create -d name=rclone https://host/.sync/
func (s *Server) syncAction(c fiber.Ctx) error {
	u := userOf(c)
	if u == nil {
		return s.deny(c)
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	html := strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML)
	ctx, cancel := dbContext(c)
	defer cancel()
	switch form["action"] {
	case "create":
		password, ap, err := s.auth.CreateAppPassword(ctx, u, form["name"])
		switch {
		case errors.Is(err, auth.ErrInvalid):
			return s.syncFailure(c, html, explain(fiber.ErrBadRequest, "Name the app password, in up to 64 characters, e.g. rclone on my laptop."))
		case errors.Is(err, auth.ErrTooMany):
			return s.syncFailure(c, html, explain(fiber.ErrConflict,
				"You have "+strconv.Itoa(auth.MaxAppPasswords)+" app passwords already: revoke one you no longer use first."))
		case err != nil:
			return err
		}
		s.log.Info("app password created", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.Int64("app", ap.ID),
			zap.String("name", ap.Name))
		c.Set(fiber.HeaderCacheControl, "no-store")
		if !html {
			return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": ap.ID, "name": ap.Name, "username": u.Username,
				"password": password, "url": c.BaseURL() + davPrefix + "/"})
		}
		return s.renderSync(c, fiber.StatusCreated, "", "", &createdApp{Name: ap.Name, Password: password})
	case "revoke":
		id, err := strconv.ParseInt(form["id"], 10, 64)
		if err != nil {
			return fiber.ErrBadRequest
		}
		if err := s.auth.RevokeAppPassword(ctx, u, id); errors.Is(err, auth.ErrNotFound) {
			return s.syncFailure(c, html, explain(fiber.ErrNotFound, "There is no such app password."))
		} else if err != nil {
			return err
		}
		s.log.Info("app password revoked", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.Int64("app", id))
		if html {
			return s.redirect(c, syncPath+"?done=revoked")
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
	return fiber.ErrBadRequest
}

// syncFailure shows why an action failed: on the page for browsers.
func (s *Server) syncFailure(c fiber.Ctx, html bool, err error) error {
	var e *explained
	if !html || !errors.As(err, &e) {
		return err
	}
	return s.renderSync(c, e.err.Code, "", e.detail, nil)
}
