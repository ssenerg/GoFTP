package server

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

const (
	sharePrefix = "/.share/"
	sharesPath  = "/.shares/"

	// The cookie that proves a visitor gave a link's password is scoped to
	// the link. Over HTTPS, the __Secure- prefix makes browsers refuse it
	// unless it is Secure.
	unlockCookie       = "goftp_unlock"
	secureUnlockCookie = "__Secure-goftp_unlock"

	// shareGuessesPerMinute bounds the password checks on one link, from
	// all clients together.
	shareGuessesPerMinute = 20

	deadLink = "This link has expired or was revoked, or what it shared was moved or deleted. Ask whoever sent it for a new one."
)

// shareTTL is a lifetime a link can be given.
type shareTTL struct {
	Value, Label string
	TTL          time.Duration
	Default      bool
}

var shareTTLs = []shareTTL{
	{"1h", "1 hour", time.Hour, false},
	{"1d", "1 day", 24 * time.Hour, false},
	{"7d", "7 days", 7 * 24 * time.Hour, true},
	{"30d", "30 days", 30 * 24 * time.Hour, false},
}

// shareView describes the link a page was reached through.
type shareView struct {
	token      string
	base       string // the link's path, without the trailing slash
	Root       string // the link's path: its file or folder
	Folder     bool
	By         string // who shared it
	Expires    string
	ExpiresISO string
}

// shareFile is the page of a link to a file.
type shareFile struct {
	Name, Kind, Size string
	ModTime, ModISO  string
	Href             string
	Preview          string // how it is shown: image, video, audio or pdf; "" if not
	Src              string // where it is shown from
}

type sharePage struct {
	page
	Locked bool // the link needs its password
	Error  string
	File   *shareFile
}

// shared serves what a link leads to, to anyone with the link (and its
// password, if it has one): the shared file, or the shared folder with
// everything in it that the link's creator may read and share.
func (s *Server) shared(c fiber.Ctx) error {
	sh, view, rel, wantDir, err := s.share(c)
	if err != nil || sh == nil {
		return err
	}
	if !s.unlocked(c, sh, view) {
		return s.askPassword(c, view, "", fiber.StatusOK)
	}
	allow := s.shareRules(sh)
	// The link works while its creator may read and share what it leads
	// to, and that is what it was.
	f, info, realPath, err := s.lookup(sh.Path, allow)
	if errors.Is(err, fiber.ErrNotFound) || err == nil && info.IsDir() != sh.IsDir {
		err = explain(fiber.ErrNotFound, deadLink)
	}
	if err != nil {
		if f != nil {
			_ = f.Close()
		}
		c.Locals(shareKey, nil)
		return err
	}

	if !sh.IsDir {
		name := path.Base(sh.Path)
		switch rel {
		case "/" + name:
			if c.Request().URI().QueryArgs().Has("view") {
				// The link's page shows it.
				_ = f.Close()
				return s.redirect(c, view.Root)
			}
			return s.serveFileAs(c, f, info, sh.Path, realPath, fileAt{base: view.base, rel: rel, allow: allow})
		case "/":
			_, preview := inlineType(f, name)
			_ = f.Close()
			href := escapePath(view.base + "/" + name)
			return s.render(c, fiber.StatusOK, "share", sharePage{page: s.sharePage(c, view, name), File: &shareFile{
				Name: name, Kind: kindOf(name), Size: formatSize(info.Size()),
				ModTime: info.ModTime().UTC().Format("Jan 2, 2006 15:04") + " UTC", ModISO: info.ModTime().UTC().Format(time.RFC3339),
				Href: href, Preview: preview, Src: href + "?inline",
			}})
		}
		_ = f.Close()
		return fiber.ErrNotFound
	}

	urlPath := path.Join(sh.Path, rel)
	if rel != "/" {
		_ = f.Close()
		if f, info, realPath, err = s.lookup(urlPath, allow); err != nil {
			return err
		}
	}
	if !info.IsDir() {
		// The file is closed once it is sent.
		return s.serveFileAs(c, f, info, urlPath, realPath, fileAt{
			base: view.base, rel: rel, page: func(title string) page { return s.sharePage(c, view, title) }, allow: allow,
		})
	}
	defer f.Close()
	if !wantDir && rel != "/" {
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.Redirect().Status(fiber.StatusMovedPermanently).To(escapePath(view.base + rel + "/"))
	}
	if c.Request().URI().QueryArgs().Has("zip") {
		return s.serveZip(c, urlPath, realPath, zipName(urlPath), allow)
	}
	return s.serveSharedDir(c, f, view, urlPath, realPath, rel, allow)
}

// share resolves the link of a request to /.share/TOKEN/PATH, and the
// clean PATH asked for in it. Without an error, a nil link means the
// request was answered already.
func (s *Server) share(c fiber.Ctx) (*auth.Share, *shareView, string, bool, error) {
	token, rest, slash := strings.Cut(strings.TrimPrefix(c.Path(), sharePrefix), "/")
	if !auth.ValidToken(token) {
		return nil, nil, "", false, explain(fiber.ErrNotFound, deadLink)
	}
	if !slash {
		return nil, nil, "", false, s.redirect(c, sharePrefix+token+"/")
	}
	rel, wantDir, err := cleanPath("/" + rest)
	if err != nil {
		return nil, nil, "", false, fiber.ErrBadRequest
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	sh, err := s.auth.ShareByToken(ctx, token)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		return nil, nil, "", false, explain(fiber.ErrNotFound, deadLink)
	case err != nil:
		return nil, nil, "", false, err
	}
	view := &shareView{token: token, base: sharePrefix + token, Root: sharePrefix + token + "/", Folder: sh.IsDir, By: sh.Creator,
		Expires: sh.ExpiresAt.UTC().Format("Jan 2, 2006 15:04") + " UTC", ExpiresISO: sh.ExpiresAt.UTC().Format(time.RFC3339)}
	// Error pages offer the way back to the link's root.
	c.Locals(shareKey, view)
	if hidden(rel) {
		return nil, nil, "", false, fiber.ErrNotFound
	}
	return sh, view, rel, wantDir, nil
}

// shareRules let a link's visitors read what its creator may read and
// share, and nothing else.
func (s *Server) shareRules(sh *auth.Share) allowFunc {
	allow := s.rulesOf(&auth.User{ID: sh.CreatedBy, Username: sh.Creator})
	return func(obj, act string) (bool, error) {
		if act != auth.ActRead {
			return false, nil
		}
		ok, err := allow(obj, auth.ActRead)
		if err == nil && ok {
			ok, err = allow(obj, auth.ActShare)
		}
		return ok, err
	}
}

// sharePage is what pages reached through the link of view show: nothing
// of the visitor's account, as they are meant for people without one.
func (s *Server) sharePage(c fiber.Ctx, view *shareView, title string) page {
	return page{Title: title, Here: c.OriginalURL(), Shared: true, Share: view}
}

// serveSharedDir lists the folder at urlPath, which is at rel in the
// shared folder of view, for the link's visitors.
func (s *Server) serveSharedDir(c fiber.Ctx, dir *os.File, view *shareView, urlPath, realPath, rel string, allow allowFunc) error {
	items, err := s.folderItems(dir, urlPath, realPath, allow)
	if err != nil {
		return err
	}
	for i := range items {
		it := &items[i]
		it.Href = escapePath(view.base + path.Join(rel, it.Name))
		if it.IsDir {
			it.Href += "/"
		}
	}
	data := listing{page: s.sharePage(c, view, shareName(urlPath)), Path: rel, Home: view.Root, Action: escapePath(view.base + object(rel, true)),
		Crumbs: crumbs(view.base, rel), Items: items, Summary: summaryOf(items)}
	if rel != "/" {
		data.Title = path.Base(rel)
		data.Parent = escapePath(view.base + object(path.Dir(rel), true))
	}
	data.Sort, data.Desc = sortOrder(c)
	sortItems(data.Items, data.Sort, data.Desc)
	return s.render(c, fiber.StatusOK, "listing", data)
}

// shareName names the file or folder at urlPath for people.
func shareName(urlPath string) string {
	if urlPath == "/" {
		return "All files"
	}
	return path.Base(urlPath)
}

func (s *Server) unlockCookieName(c fiber.Ctx) string {
	if c.Secure() {
		return secureUnlockCookie
	}
	return unlockCookie
}

// unlocked reports whether the visitor may open sh: links without a
// password are open, the others need proof that it was given.
func (s *Server) unlocked(c fiber.Ctx, sh *auth.Share, view *shareView) bool {
	return sh.PasswordHash == "" || auth.ShareUnlocked(sh, view.token, c.Cookies(s.unlockCookieName(c)), time.Now())
}

// askPassword answers in place of what a link leads to while its password
// was not given: a form for people, a refusal for other clients.
func (s *Server) askPassword(c fiber.Ctx, view *shareView, failure string, status int) error {
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		if failure == "" {
			failure = "This link needs a password: post it as the form field password, then send the cookie you get back."
		}
		if status == fiber.StatusOK {
			status = fiber.StatusForbidden
		}
		return sendMessage(c, status, failure)
	}
	return s.render(c, status, "share", sharePage{page: s.sharePage(c, view, "Password needed"), Locked: true, Error: failure})
}

// unlockShare checks the password of a link, and on success gives the
// visitor a cookie that proves it for the link's pages.
func (s *Server) unlockShare(c fiber.Ctx) error {
	sh, view, _, _, err := s.share(c)
	if err != nil || sh == nil {
		return err
	}
	if sh.PasswordHash == "" {
		return s.redirect(c, c.OriginalURL())
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	// The check counts against the client's failure budget and the link's
	// budget before it runs, so concurrent guesses cannot exceed them.
	now := time.Now()
	link := strconv.FormatInt(sh.ID, 10)
	client := ""
	if s.limiter != nil {
		client = clientKey(c.IP())
		if wait := s.limiter.attempt(client, true, now); wait > 0 {
			retryAfter(c, wait)
			return s.askPassword(c, view, tooMany, fiber.StatusTooManyRequests)
		}
	}
	refundClient := func() {
		if client != "" {
			s.limiter.refund(client)
		}
	}
	if wait := s.shareGuesses.attempt(link, true, now); wait > 0 {
		refundClient()
		retryAfter(c, wait)
		return s.askPassword(c, view, tooMany, fiber.StatusTooManyRequests)
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	ok, err := s.auth.CheckSharePassword(ctx, sh, form["password"])
	switch {
	case errors.Is(err, auth.ErrBusy):
		refundClient()
		s.shareGuesses.refund(link)
		retryAfter(c, time.Second)
		return s.askPassword(c, view, busy, fiber.StatusServiceUnavailable)
	case err != nil:
		refundClient()
		s.shareGuesses.refund(link)
		return err
	case !ok:
		s.log.Warn("share password wrong", zap.String("ip", c.IP()), zap.Int64("share", sh.ID))
		return s.askPassword(c, view, "Wrong password.", fiber.StatusForbidden)
	}
	refundClient()
	until := now.Add(s.cfg.Auth.SessionTTL)
	if sh.ExpiresAt.Before(until) {
		until = sh.ExpiresAt
	}
	c.Cookie(&fiber.Cookie{
		Name:     s.unlockCookieName(c),
		Value:    auth.UnlockShare(sh, view.token, until),
		Path:     view.Root,
		Expires:  until,
		Secure:   c.Secure(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
	s.log.Info("share unlocked", zap.String("ip", c.IP()), zap.Int64("share", sh.ID))
	return s.redirect(c, c.OriginalURL())
}

// sharesData is the page listing share links.
type sharesData struct {
	page
	All     bool // everyone's links, for a superadmin
	Links   []sharedLink
	Created *createdLink
	Notice  string
	Error   string
}

type sharedLink struct {
	ID                  int64
	Name, Path, Href    string
	Kind                string
	By                  string
	Password            bool
	Expires, ExpiresISO string
}

// createdLink is a new link, shown once.
type createdLink struct {
	URL, Name           string
	Password            bool
	Expires, ExpiresISO string
}

var shareNotices = map[string]string{"revoked": "The link was revoked. It no longer works."}

func (s *Server) sharesPage(c fiber.Ctx) error {
	if userOf(c) == nil {
		return s.deny(c)
	}
	return s.renderShares(c, fiber.StatusOK, shareNotices[c.Query("done")], "", nil)
}

func (s *Server) renderShares(c fiber.Ctx, status int, notice, failure string, created *createdLink) error {
	u := userOf(c)
	all := s.auth.IsSuperadmin(u.Username)
	ctx, cancel := dbContext(c)
	defer cancel()
	shares, err := s.auth.Shares(ctx, u, all)
	if err != nil {
		return err
	}
	data := sharesData{page: s.page(c, "Shared links"), All: all, Created: created, Notice: notice, Error: failure}
	for _, sh := range shares {
		l := sharedLink{ID: sh.ID, Name: shareName(sh.Path), Path: sh.Path, Href: escapePath(object(sh.Path, sh.IsDir)),
			Kind: kindOf(sh.Path), By: sh.Creator, Password: sh.PasswordHash != "",
			Expires: sh.ExpiresAt.UTC().Format("Jan 2, 2006 15:04") + " UTC", ExpiresISO: sh.ExpiresAt.UTC().Format(time.RFC3339)}
		if sh.IsDir {
			l.Kind = "folder"
		}
		data.Links = append(data.Links, l)
	}
	return s.render(c, status, "shares", data)
}

// sharesAction creates and revokes links:
//
//	action=create&path=PATH&expires=7d[&password=PW]  a link to the file or folder at PATH
//	action=revoke&id=ID                               ends the link ID
//
// e.g. curl -d action=create -d path=/docs/report.pdf -d expires=1d https://host/.shares/
func (s *Server) sharesAction(c fiber.Ctx) error {
	u := userOf(c)
	if u == nil {
		return s.deny(c)
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	switch form["action"] {
	case "create":
		return s.createShare(c, u, form)
	case "revoke":
		return s.revokeShare(c, u, form["id"])
	}
	return fiber.ErrBadRequest
}

// createShare makes a link to the file or folder at form["path"]. The
// visitor needs the rights to read and share it, at its path and where it
// really lives.
func (s *Server) createShare(c fiber.Ctx, u *auth.User, form map[string]string) error {
	var ttl time.Duration
	for _, t := range shareTTLs {
		if t.Value == form["expires"] {
			ttl = t.TTL
		}
	}
	if ttl == 0 {
		return explain(fiber.ErrBadRequest, "Choose when the link expires: 1h, 1d, 7d or 30d.")
	}
	urlPath, ok := formPath(form["path"])
	if !ok {
		return fiber.ErrBadRequest
	}
	if hidden(urlPath) {
		return fiber.ErrNotFound
	}
	// Checked before the entry is looked up, so that the answer does not
	// reveal what exists.
	if ok, err := s.mayEither(c, auth.ActShare, urlPath); err != nil {
		return err
	} else if !ok {
		return s.deny(c)
	}
	f, info, realPath, err := s.lookup(urlPath, s.rulesOf(u))
	if err != nil {
		return err
	}
	_ = f.Close()
	if ok, err := s.mayAt(c, auth.ActShare, urlPath, realPath, info.IsDir()); err != nil {
		return err
	} else if !ok {
		return fiber.ErrNotFound
	}

	ctx, cancel := dbContext(c)
	defer cancel()
	token, sh, err := s.auth.CreateShare(ctx, u, urlPath, info.IsDir(), ttl, form["password"])
	switch {
	case errors.Is(err, auth.ErrWeakPassword):
		return explain(fiber.ErrBadRequest, "Give the link a password of at least "+strconv.Itoa(auth.MinSharePasswordLength)+" characters, or none.")
	case errors.Is(err, auth.ErrTooMany):
		return explain(fiber.ErrConflict, "You have too many links. Revoke some under Shared links first.")
	case errors.Is(err, auth.ErrBusy):
		retryAfter(c, time.Second)
		return fiber.ErrServiceUnavailable
	case err != nil:
		return err
	}
	s.log.Info("share created", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.String("path", urlPath),
		zap.Int64("share", sh.ID), zap.Time("expires", sh.ExpiresAt), zap.Bool("password", sh.PasswordHash != ""))

	link := c.BaseURL() + sharePrefix + token + "/"
	expires := sh.ExpiresAt.UTC()
	c.Set(fiber.HeaderCacheControl, "no-store")
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": sh.ID, "url": link, "expires_at": expires.Format(time.RFC3339)})
	}
	return s.renderShares(c, fiber.StatusCreated, "", "", &createdLink{URL: link, Name: shareName(urlPath), Password: sh.PasswordHash != "",
		Expires: expires.Format("Jan 2, 2006 15:04") + " UTC", ExpiresISO: expires.Format(time.RFC3339)})
}

// revokeShare ends a link: users can end their own, superadmins anyone's.
func (s *Server) revokeShare(c fiber.Ctx, u *auth.User, idText string) error {
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	html := strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML)
	err = s.auth.RevokeShare(ctx, u, id, s.auth.IsSuperadmin(u.Username))
	switch {
	case errors.Is(err, auth.ErrNotFound) && html:
		return s.renderShares(c, fiber.StatusNotFound, "", "There is no such link: it may have expired or been revoked already.", nil)
	case errors.Is(err, auth.ErrNotFound):
		return fiber.ErrNotFound
	case err != nil:
		return err
	}
	s.log.Info("share revoked", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.Int64("share", id))
	if html {
		return s.redirect(c, sharesPath+"?done=revoked")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// formPath cleans a URL path sent in a form, which is not percent-encoded.
func formPath(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.IndexByte(p, 0) >= 0 ||
		(filepath.Separator != '/' && strings.ContainsRune(p, filepath.Separator)) {
		return "", false
	}
	return path.Clean(p), true
}

// logPath hides the token in the path of a share link or an upload: more
// people read logs than may open what links lead to.
func logPath(p string) string {
	for _, prefix := range []string{sharePrefix, uploadsPrefix} {
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok {
			continue
		}
		if _, after, found := strings.Cut(rest, "/"); found {
			return prefix + "***/" + after
		}
		return prefix + "***"
	}
	return p
}
