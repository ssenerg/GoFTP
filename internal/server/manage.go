package server

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

const badName = "Names cannot be empty or very long, start with a dot, or contain /, \\ or control characters."

// explained is an error answered with a detail for the visitor.
type explained struct {
	err    *fiber.Error
	detail string
}

func explain(err *fiber.Error, detail string) error { return &explained{err, detail} }
func (e *explained) Error() string                  { return e.err.Error() }
func (e *explained) Unwrap() error                  { return e.err }

// manage handles a folder's small forms, sent URL-encoded or as JSON:
//
//	folder=NAME         creates the folder NAME
//	delete=NAME         deletes the entry NAME, a folder with everything in it
//	rename=NAME&to=NEW  renames the entry NAME to NEW
//
// e.g. curl -d rename=a.txt -d to=b.txt https://host/dir/
func (s *Server) manage(c fiber.Ctx, urlPath string) error {
	// Visitors who may change nothing here are refused before the body is
	// read.
	dir := object(urlPath, true)
	ok, err := s.allowed(c, dir, auth.ActWrite)
	if err == nil && !ok {
		ok, err = s.allowed(c, dir, auth.ActDelete)
	}
	if err != nil {
		return err
	}
	if !ok {
		return s.deny(c)
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	if name, ok := form["folder"]; ok {
		return s.mkdir(c, urlPath, name)
	}
	if name, ok := form["delete"]; ok {
		if err := s.remove(c, urlPath, name); err != nil {
			return err
		}
		return s.done(c, urlPath, fiber.StatusNoContent, "", "deleted=1")
	}
	if name, ok := form["rename"]; ok {
		return s.rename(c, urlPath, name, form["to"])
	}
	return fiber.ErrBadRequest
}

// deleteEntry handles DELETE requests, e.g. curl -X DELETE https://host/dir/a.txt
func (s *Server) deleteEntry(c fiber.Ctx) error {
	urlPath, _, err := cleanPath(c.Path())
	if err != nil {
		return fiber.ErrBadRequest
	}
	if hidden(urlPath) || urlPath == "/" {
		return fiber.ErrForbidden
	}
	dirPath, name := path.Split(urlPath)
	if err := s.remove(c, dirPath, name); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// done answers a change that succeeded: scripts get status and the location
// of a new entry, browsers go back to the folder, where query confirms it.
func (s *Server) done(c fiber.Ctx, dirPath string, status int, location, query string) error {
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		if location != "" {
			c.Location(location)
		}
		return c.SendStatus(status)
	}
	return s.redirect(c, escapePath(object(dirPath, true))+"?"+query)
}

var (
	errDenied  = errors.New("not allowed")
	errBusy    = errors.New("being written")
	errMounted = errors.New("another file system is mounted inside")
)

// remove deletes the entry name of the folder at dirPath: a file, a symlink
// (not what it leads to), or a folder with everything in it.
func (s *Server) remove(c fiber.Ctx, dirPath, name string) error {
	dir, realDir, info, err := s.entry(c, dirPath, name, auth.ActDelete)
	if err != nil {
		return err
	}
	defer dir.Close()
	// The lock keeps uploads of the name out meanwhile.
	release, err := s.acquireLock(dir, name, tempPrefix+rand.Text()+tempSuffix)
	if err != nil {
		return err
	}
	defer release()

	target := path.Join(dirPath, name)
	contents := 0
	if info.IsDir() {
		contents, err = s.checkTree(c, dir, name, target, path.Join(realDir, name))
		switch {
		case errors.Is(err, errDenied):
			return explain(fiber.ErrForbidden, "You may not delete everything in this folder.")
		case errors.Is(err, errBusy):
			return explain(fiber.ErrConflict, "Something in this folder is being uploaded or written right now.")
		case errors.Is(err, errMounted):
			return explain(fiber.ErrConflict, "Another disk is mounted in this folder: deleting it would empty that disk too.")
		case err != nil:
			return s.openError(err)
		}
		err = dir.RemoveAll(name)
	} else {
		err = dir.Remove(name)
	}
	if err != nil {
		return s.openError(err)
	}
	syncDir(dir)
	s.log.Info("delete", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", target),
		zap.Bool("folder", info.IsDir()), zap.Int("contents", contents))
	return nil
}

// checkTree checks the folder name of dir before it is deleted with
// everything in it: the visitor needs the right to delete every entry (at
// its real path as well), nothing in it may be being written, and no other
// file system may be mounted in it. It returns the number of entries.
func (s *Server) checkTree(c fiber.Ctx, dir *os.Root, name, target, realTarget string) (int, error) {
	sub, err := dir.OpenRoot(name)
	if err != nil {
		return 0, err
	}
	defer sub.Close()
	top, err := sub.Stat(".")
	if err != nil {
		return 0, err
	}
	n := 0
	err = fs.WalkDir(sub.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		n++
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() && !sameDevice(top, info) {
			return errMounted
		}
		// A goftp upload refreshes its lock; other tools' locks always
		// count.
		if _, ok := lockTarget(d.Name()); ok && d.Type().IsRegular() {
			if _, err := readLock(sub, p); err != nil || time.Since(info.ModTime()) < lockExpiry {
				return errBusy
			}
		}
		ok, err := s.mayAt(c, auth.ActDelete, path.Join(target, p), path.Join(realTarget, p), d.IsDir())
		if err == nil && !ok {
			err = errDenied
		}
		return err
	})
	return n, err
}

// rename renames the entry from of the folder at dirPath to to, which must
// not exist yet. The visitor needs the rights to read and delete the entry,
// and to create one named to.
func (s *Server) rename(c fiber.Ctx, dirPath, from, to string) error {
	to = strings.TrimSpace(to)
	if !validName(to) {
		return explain(fiber.ErrBadRequest, badName)
	}
	dir, realDir, info, err := s.entry(c, dirPath, from, auth.ActDelete)
	if err != nil {
		return err
	}
	defer dir.Close()
	src, dst := path.Join(dirPath, from), path.Join(dirPath, to)
	if ok, err := s.mayAt(c, auth.ActRead, src, path.Join(realDir, from), info.IsDir()); err != nil {
		return err
	} else if !ok {
		return fiber.ErrNotFound
	}
	if ok, err := s.mayAt(c, auth.ActWrite, dst, path.Join(realDir, to), info.IsDir()); err != nil {
		return err
	} else if !ok {
		return s.deny(c)
	}

	if from != to {
		// The locks keep uploads of either name out meanwhile.
		for _, name := range []string{from, to} {
			release, err := s.acquireLock(dir, name, tempPrefix+rand.Text()+tempSuffix)
			if err != nil {
				return err
			}
			defer release()
		}
		if err := renameNoReplace(dir, from, to, info); errors.Is(err, errExists) {
			return explain(fiber.ErrConflict, "Something with this name already exists here.")
		} else if err != nil {
			return s.openError(err)
		}
		syncDir(dir)
		s.log.Info("rename", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", src), zap.String("to", dst))
	}
	return s.done(c, dirPath, fiber.StatusCreated, escapePath(object(dst, info.IsDir())), "renamed="+url.QueryEscape(to))
}

// renameNoReplace renames from to to in dir, unless to exists. Files are
// hard-linked first, which makes "only if absent" atomic even against
// writers that ignore lock files.
func renameNoReplace(dir *os.Root, from, to string, info fs.FileInfo) error {
	if existing, err := dir.Lstat(to); err == nil {
		if !os.SameFile(info, existing) {
			return errExists
		}
		// The same entry spelled differently, on a file system that
		// ignores case: renaming changes the spelling.
		return dir.Rename(from, to)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if info.Mode().IsRegular() {
		err := dir.Link(from, to)
		switch {
		case err == nil:
			if err := dir.Remove(from); err != nil {
				_ = dir.Remove(to)
				return err
			}
			return nil
		case errors.Is(err, fs.ErrExist):
			return errExists
		}
		// No hard links here: rename, as checked above.
	}
	return dir.Rename(from, to)
}

// entry opens the folder at dirPath and looks up its entry name, on which
// the visitor needs the right act, at the path asked for and at the real
// path (see resolve). Only entries that listings show qualify.
func (s *Server) entry(c fiber.Ctx, dirPath, name, act string) (*os.Root, string, fs.FileInfo, error) {
	if !entryName(name) {
		return nil, "", nil, fiber.ErrBadRequest
	}
	target := path.Join(dirPath, name)
	// Checked before the entry is looked up, so that the answer does not
	// reveal what exists.
	if ok, err := s.mayEither(c, act, target); err != nil {
		return nil, "", nil, err
	} else if !ok {
		return nil, "", nil, s.deny(c)
	}
	dir, realDir, err := s.uploadDir(dirPath)
	if err != nil {
		return nil, "", nil, err
	}
	info, err := dir.Lstat(name)
	if err == nil && !s.shown(dirPath, name, info) {
		err = fs.ErrNotExist
	}
	if err == nil {
		// Denials look like missing entries from here on, as for
		// downloads.
		var ok bool
		if ok, err = s.mayAt(c, act, target, path.Join(realDir, name), info.IsDir()); err == nil && !ok {
			err = fiber.ErrNotFound
		}
	}
	if err != nil {
		_ = dir.Close()
		return nil, "", nil, s.openError(err)
	}
	return dir, realDir, info, nil
}

// shown reports whether listings show the entry name of the folder at
// dirPath: files, folders, and symlinks to entries that may be shown,
// unless another tool's lock hides them.
func (s *Server) shown(dirPath, name string, info fs.FileInfo) bool {
	if s.locked(rootName(path.Clean(dirPath)), name) {
		return false
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return s.visible(rootName(path.Join(dirPath, name)), nil)
	case info.IsDir(), info.Mode().IsRegular():
		return true
	}
	return false
}

// entryName reports whether name could be an entry that listings show.
func entryName(name string) bool {
	return name != "" && !hidden(name) && !strings.ContainsRune(name, '/') && !strings.ContainsRune(name, 0) &&
		(filepath.Separator == '/' || !strings.ContainsRune(name, filepath.Separator))
}

// mayAt reports whether the visitor may perform act on the entry at urlPath:
// a symlink grants nothing its target's rules do not, so realPath (where
// symlinks lead, see resolve) has to allow it as well.
func (s *Server) mayAt(c fiber.Ctx, act, urlPath, realPath string, dir bool) (bool, error) {
	return mayBoth(s.visitorRules(c), act, urlPath, realPath, dir)
}

// allowFunc reports whether act is allowed on obj.
type allowFunc func(obj, act string) (bool, error)

// visitorRules applies the rules for the visitor of c, gathered once per
// request: listings check every entry.
func (s *Server) visitorRules(c fiber.Ctx) allowFunc {
	type cached struct {
		user  *auth.User
		allow allowFunc
	}
	u := userOf(c)
	if r, ok := c.Locals(rulesKey).(cached); ok && r.user == u {
		return r.allow
	}
	allow := s.rulesOf(u)
	c.Locals(rulesKey, cached{u, allow})
	return allow
}

// rulesOf applies the rules for u, nil for anonymous visitors, as they are
// now: gathered once for the many checks to come.
func (s *Server) rulesOf(u *auth.User) allowFunc {
	rules, err := s.auth.RulesFor(u)
	return func(obj, act string) (bool, error) {
		if err != nil {
			return false, err
		}
		return rules.Allow(obj, act), nil
	}
}

// mayBoth is mayAt for the rules of allow.
func mayBoth(allow allowFunc, act, urlPath, realPath string, dir bool) (bool, error) {
	ok, err := allow(object(urlPath, dir), act)
	if err != nil || !ok || realPath == urlPath {
		return ok, err
	}
	return allow(object(realPath, dir), act)
}

// mayEither reports whether the visitor may perform act on urlPath as a
// file or as a folder: checked before an entry is looked up, so that the
// answer does not reveal what exists.
func (s *Server) mayEither(c fiber.Ctx, act, urlPath string) (bool, error) {
	ok, err := s.allowed(c, object(urlPath, false), act)
	if err == nil && !ok {
		ok, err = s.allowed(c, object(urlPath, true), act)
	}
	return ok, err
}

// visitor names the signed-in user, or anonymous, for the logs.
func visitor(c fiber.Ctx) string {
	if u := userOf(c); u != nil {
		return u.Username
	}
	return auth.Anonymous
}
