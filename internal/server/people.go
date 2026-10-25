package server

import (
	"context"
	"errors"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// Users share folders of their homes with other users (see
// auth.FolderShare): the People popover of the folder adds them, and the
// Shared page lists what is shared, both ways.

// folderShareView describes a folder shared with someone.
type folderShareView struct {
	ID              int64
	Name, Path      string // the folder; Path "" if it is not the visitor's to see
	Href            string // "" if it is not the visitor's to see
	Owner, User     string
	Write           bool
	Since, SinceISO string
	Until, UntilISO string // when it ends; "" for never
}

// folderShareTTLs are how long a folder may be shared, as the People
// popover offers it; "" is until it is stopped.
var folderShareTTLs = []shareTTL{
	{"", "No end date", 0, true},
	{"1d", "1 day", 24 * time.Hour, false},
	{"7d", "1 week", 7 * 24 * time.Hour, false},
	{"30d", "1 month", 30 * 24 * time.Hour, false},
	{"90d", "3 months", 90 * 24 * time.Hour, false},
}

// viewFolderShare describes fs to the visitor of c, who may see where it
// is unless private is set.
func (s *Server) viewFolderShare(c fiber.Ctx, fs auth.FolderShare, private bool) folderShareView {
	v := folderShareView{ID: fs.ID, Name: shareName(fs.Path), Path: fs.Path, Href: escapePath(object(fs.Path, true)),
		Owner: fs.Owner, User: fs.User, Write: fs.Write, Since: shownTime(fs.CreatedAt), SinceISO: isoTime(fs.CreatedAt)}
	if !fs.ExpiresAt.IsZero() {
		v.Until, v.UntilISO = shownTime(fs.ExpiresAt), isoTime(fs.ExpiresAt)
	}
	switch {
	case private:
		v.Name, v.Path, v.Href = "Private folder", "", ""
	case fs.Path != s.auth.HomeOf(fs.Owner):
	case fs.OwnerID == userOf(c).ID:
		v.Name = "My files"
	default:
		v.Name = "Home of " + fs.Owner
	}
	return v
}

// folderShares lists the folders the visitor u shares with people, those
// of everyone with all, and those shared with u.
func (s *Server) folderShares(c fiber.Ctx, u *auth.User, all bool) (shares, withYou []folderShareView, err error) {
	ctx, cancel := dbContext(c)
	defer cancel()
	mine, err := s.auth.FolderShares(ctx, u, all)
	if err != nil {
		return nil, nil, err
	}
	for _, fs := range mine {
		private := false
		if fs.OwnerID != u.ID {
			// Superadmins may stop any share, but learn nothing of where
			// they may not look, such as others' homes.
			ok, err := s.allowed(c, object(fs.Path, true), auth.ActRead)
			if err != nil {
				return nil, nil, err
			}
			private = !ok
		}
		shares = append(shares, s.viewFolderShare(c, fs, private))
	}
	for _, fs := range s.sharedWith(c) {
		withYou = append(withYou, s.viewFolderShare(c, fs, false))
	}
	return shares, withYou, nil
}

// sharedWith lists the folders shared with the visitor of c, looked up
// once per request.
func (s *Server) sharedWith(c fiber.Ctx) []auth.FolderShare {
	type cached struct {
		user   *auth.User
		shares []auth.FolderShare
	}
	u := userOf(c)
	if u == nil {
		return nil
	}
	if v, ok := c.Locals(sharedKey).(cached); ok && v.user == u {
		return v.shares
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	shares, err := s.auth.SharedWith(ctx, u)
	if err != nil {
		// Only how the way to them is shown depends on it.
		s.log.Error("folders shared with a user", zap.String("user", u.Username), zap.Error(err))
	}
	c.Locals(sharedKey, cached{u, shares})
	return shares
}

// shareAt returns the innermost folder shared with the visitor of c that
// the URL path urlPath is, or is in; nil if none.
func (s *Server) shareAt(c fiber.Ctx, urlPath string) *auth.FolderShare {
	var found *auth.FolderShare
	for _, fs := range s.sharedWith(c) {
		if inHome(s.folded(fs.Path), s.folded(urlPath)) != "" && (found == nil || len(fs.Path) > len(found.Path)) {
			found = &fs
		}
	}
	return found
}

// davWays returns the folders in the folder at urlPath on the way to the
// home of the visitor of c, or to folders shared with them, which rules
// may keep closed otherwise.
func (s *Server) davWays(c fiber.Ctx, urlPath string) []string {
	places := []string{s.homeOf(userOf(c))}
	for _, fs := range s.sharedWith(c) {
		places = append(places, fs.Path)
	}
	var ways []string
	for _, p := range places {
		rest, ok := strings.CutPrefix(p, strings.TrimSuffix(urlPath, "/")+"/")
		if p == "" || !ok || rest == "" {
			continue
		}
		next, _, _ := strings.Cut(rest, "/")
		if way := path.Join(urlPath, next); !slices.Contains(ways, way) {
			ways = append(ways, way)
		}
	}
	return ways
}

// foldersMoved has the folder shares of the folder at the real URL path
// from, and of those in it, follow it to to, where it moved; they end with
// to "", as it was deleted, or once it left its home. A folder deleted by
// other means than goftp keeps its shares, until its owner stops them.
func (s *Server) foldersMoved(from, to string) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	if err := s.auth.MoveFolderShares(ctx, from, to); err != nil {
		s.log.Error("move folder shares", zap.String("path", from), zap.String("to", to), zap.Error(err))
	}
}

// accessOf names what a folder share lets its user do.
func accessOf(write bool) string {
	if write {
		return "edit"
	}
	return "read"
}

// grantFolder shares the folder at form["path"], the visitor's home or a
// folder in it, with the user form["user"]: with form["access"] read to let
// them see what is in it, or edit to change it too, and with
// form["expires"] (1d, 7d, 30d or 90d) for that long. Sharing it with them
// again changes how and for how long. It needs the rights to share the
// folder, and to change it for edit.
func (s *Server) grantFolder(c fiber.Ctx, u *auth.User, form map[string]string) error {
	write := false
	switch form["access"] {
	case "", "read":
	case "edit":
		write = true
	default:
		return explain(fiber.ErrBadRequest, "People may read a folder (access=read) or edit it (access=edit).")
	}
	ttl, known := time.Duration(0), false
	for _, t := range folderShareTTLs {
		if t.Value == form["expires"] {
			ttl, known = t.TTL, true
		}
	}
	if !known {
		return explain(fiber.ErrBadRequest, "Share a folder for 1d, 7d, 30d or 90d, or without expires until you stop it.")
	}
	urlPath, ok := formPath(form["path"])
	if !ok {
		return fiber.ErrBadRequest
	}
	home := s.homeOf(u)
	if hidden(urlPath) || home == "" || inHome(s.folded(home), s.folded(urlPath)) == "" {
		return explain(fiber.ErrForbidden, "Only folders in your own home can be shared with people.")
	}
	username := strings.TrimSpace(form["user"])
	switch {
	case username == "":
		return explain(fiber.ErrBadRequest, "Say whom to share it with: their username.")
	case auth.NormalizeUsername(username) == u.Username:
		return explain(fiber.ErrBadRequest, "It is yours already: share it with someone else.")
	}
	f, info, realPath, err := s.lookup(urlPath, s.visitorRules(c))
	if err != nil {
		return err
	}
	_ = f.Close()
	if !info.IsDir() {
		return explain(fiber.ErrBadRequest, "Only folders can be shared with people: share files with a link.")
	}
	if ok, err := s.mayAt(c, auth.ActShare, urlPath, realPath, true); err != nil {
		return err
	} else if !ok {
		return explain(fiber.ErrForbidden, "You may not share this folder.")
	}
	if write {
		if ok, err := s.mayAt(c, auth.ActWrite, urlPath, realPath, true); err != nil {
			return err
		} else if !ok {
			return explain(fiber.ErrForbidden, "You may not change this folder, so you cannot let others do it.")
		}
	}

	ctx, cancel := dbContext(c)
	defer cancel()
	fs, err := s.auth.ShareFolder(ctx, u, realPath, username, write, ttl)
	switch {
	case errors.Is(err, auth.ErrInvalid):
		// It leads out of the home.
		return explain(fiber.ErrForbidden, "Only folders in your own home can be shared with people.")
	case errors.Is(err, auth.ErrNotFound):
		return explain(fiber.ErrNotFound, "There is no user "+username+".")
	case errors.Is(err, auth.ErrTooMany):
		return explain(fiber.ErrConflict, "You share too many folders. Stop sharing some under Shared first.")
	case err != nil:
		return err
	}
	s.log.Info("folder shared", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.String("path", fs.Path),
		zap.String("with", fs.User), zap.Bool("write", fs.Write), zap.Int64("folder_share", fs.ID), zap.Duration("for", ttl))
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		out := fiber.Map{"id": fs.ID, "path": fs.Path, "user": fs.User, "access": accessOf(fs.Write), "expires_at": nil}
		if !fs.ExpiresAt.IsZero() {
			out["expires_at"] = fs.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return c.Status(fiber.StatusCreated).JSON(out)
	}
	return s.redirect(c, escapePath(object(urlPath, true))+"?granted="+url.QueryEscape(fs.User))
}

// ungrantFolder ends the folder share form["id"]: its owner stops sharing
// the folder, or its user leaves it; superadmins may end any. Browsers go
// back to the folder with form["back"] set, if it is the visitor's.
func (s *Server) ungrantFolder(c fiber.Ctx, u *auth.User, form map[string]string) error {
	id, err := strconv.ParseInt(form["id"], 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}
	ctx, cancel := dbContext(c)
	defer cancel()
	html := strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML)
	fs, err := s.auth.UnshareFolder(ctx, u, id, s.auth.IsSuperadmin(u.Username))
	switch {
	case errors.Is(err, auth.ErrNotFound) && html:
		return s.renderShares(c, fiber.StatusNotFound, "", "It is not shared anymore: someone stopped sharing it already.", nil)
	case errors.Is(err, auth.ErrNotFound):
		return fiber.ErrNotFound
	case err != nil:
		return err
	}
	s.log.Info("folder unshared", zap.String("ip", c.IP()), zap.String("user", u.Username), zap.String("path", fs.Path),
		zap.Int64("folder_share", id))
	switch {
	case !html:
		return c.SendStatus(fiber.StatusNoContent)
	case form["back"] != "" && fs.OwnerID == u.ID:
		return s.redirect(c, escapePath(object(fs.Path, true))+"?ungranted=1")
	case fs.UserID == u.ID:
		return s.redirect(c, sharesPath+"?done=left")
	}
	return s.redirect(c, sharesPath+"?done=ungranted")
}

// peopleHere is what the People popover of a folder in the visitor's home
// shows: who it is shared with.
type peopleHere struct {
	Path   string // URL path of the folder
	Shares []folderShareView
	TTLs   []shareTTL // how long it may be shared
}

// peopleAt returns who the folder at urlPath, really at realPath, in the
// visitor's home, is shared with, if the visitor may share it.
func (s *Server) peopleAt(c fiber.Ctx, urlPath, realPath string) (*peopleHere, error) {
	if ok, err := s.mayAt(c, auth.ActShare, urlPath, realPath, true); err != nil || !ok {
		return nil, err
	}
	u := userOf(c)
	ctx, cancel := dbContext(c)
	defer cancel()
	shares, err := s.auth.FolderShares(ctx, u, false)
	if err != nil {
		return nil, err
	}
	p := &peopleHere{Path: urlPath, TTLs: folderShareTTLs}
	for _, fs := range shares {
		if s.folded(fs.Path) == s.folded(realPath) {
			p.Shares = append(p.Shares, s.viewFolderShare(c, fs, false))
		}
	}
	slices.SortFunc(p.Shares, func(a, b folderShareView) int { return strings.Compare(a.User, b.User) })
	return p, nil
}
