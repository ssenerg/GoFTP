package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"goftp/internal/auth"
	"goftp/internal/config"
)

// Every user has a home, a private folder of their own at homes.path/NAME
// (see auth.Service.SetHomes for who may do what there). It is made when
// they first show up, with a hidden note of whose it is: a home that a
// deleted user left behind goes to the trash before a new user of the same
// name gets in, so that nothing of it reaches them.
const homeOwner = ".goftp-owner"

// homeOf returns the URL path of the home of u, "" without one.
func (s *Server) homeOf(u *auth.User) string {
	if u == nil {
		return ""
	}
	return s.auth.HomeOf(u.Username)
}

// inHome returns where urlPath is in the home at the URL path home: "/"
// for the home itself, "" if urlPath is not in it.
func inHome(home, urlPath string) string {
	switch {
	case home == "":
		return ""
	case urlPath == home:
		return "/"
	}
	if rest, ok := strings.CutPrefix(urlPath, home+"/"); ok {
		return "/" + rest
	}
	return ""
}

// homeName returns the name of the home that urlPath is in, or is.
func (s *Server) homeName(urlPath string) (string, bool) {
	if s.cfg.Homes.Path == "" {
		return "", false
	}
	rest, ok := strings.CutPrefix(urlPath, s.cfg.Homes.Path+"/")
	name, _, _ := strings.Cut(rest, "/")
	return name, ok && name != ""
}

// ownerNow reads whose the home name is now, and since when: when its
// owner note was written. ok is false if it has no owner.
func (s *Server) ownerNow(name string) (id int64, since time.Time, ok bool) {
	dir, err := s.root.OpenRoot(rootName(s.cfg.Homes.Path))
	if err != nil {
		return 0, time.Time{}, false
	}
	defer dir.Close()
	if id, _, err = readOwner(dir, name); err != nil || id <= 0 {
		return 0, time.Time{}, false
	}
	info, err := dir.Lstat(path.Join(name, homeOwner))
	if err != nil {
		return 0, time.Time{}, false
	}
	return id, info.ModTime(), true
}

// stillTheirs reports whether the trashed entry was deleted outside homes,
// or from the home of whoever has it now: what a deleted user deleted from
// their home stays out of reach of a new user of that name, until it
// expires.
func (s *Server) stillTheirs(note trashNote) bool {
	name, ok := s.homeName(note.Path)
	if !ok {
		return true
	}
	id, since, ok := s.ownerNow(name)
	switch {
	case !ok:
		return false
	case note.Owner != 0:
		return note.Owner == id
	}
	// Deleted before trash notes named owners: theirs if deleted since
	// the home became theirs.
	return !note.At.Before(since)
}

// warnOldHomes warns if homes are off while their usual folder still holds
// some: the ordinary rules apply to what is in them now.
func (s *Server) warnOldHomes() {
	if s.cfg.Homes.Path != "" {
		return
	}
	d, err := s.root.Open("home")
	if err != nil {
		return
	}
	entries, _ := d.ReadDir(1000)
	_ = d.Close()
	for _, e := range entries {
		if _, err := s.root.Lstat(path.Join("home", e.Name(), homeOwner)); e.IsDir() && err == nil {
			s.log.Warn("homes are off, but /home holds homes from before: whoever the rules let in may open them now")
			return
		}
	}
}

// checkHomes makes the folder of homes, which has to be a folder of its
// own: through a symlink, the rules of where it leads would apply too.
func (s *Server) checkHomes() error {
	homes := s.cfg.Homes.Path
	if homes == "" {
		return nil
	}
	info, err := s.root.Lstat(rootName(homes))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := s.mkdirAll(homes); err != nil {
			s.log.Warn("cannot make the folder of homes", zap.String("path", homes), zap.Error(err))
		}
		return nil
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("homes.path %s must be a folder, not a file or symlink", homes)
	}
	return nil
}

// mkdirAll makes the folder at the URL path p and those on the way to it.
func (s *Server) mkdirAll(p string) error {
	return s.root.MkdirAll(rootName(p), 0o755)
}

// claimHome makes sure that u has a home of their own before their rights
// are used: it makes one if there is none, and first moves one that a
// deleted user of the same name left behind to the trash. Each user is
// checked once per process. Only a home of someone else that stays is an
// error, so that the caller can keep u out of it.
func (s *Server) claimHome(u *auth.User) error {
	if s.cfg.Homes.Path == "" || u == nil {
		return nil
	}
	if _, ok := s.homesChecked.Load(u.ID); ok {
		return nil
	}
	s.homeMu.Lock()
	defer s.homeMu.Unlock()
	if _, ok := s.homesChecked.Load(u.ID); ok {
		return nil
	}
	if err := s.settleHome(u); err != nil {
		return err
	}
	s.homesChecked.Store(u.ID, true)
	return nil
}

func (s *Server) settleHome(u *auth.User) error {
	homes := s.cfg.Homes.Path
	dir, err := s.root.OpenRoot(rootName(homes))
	if err != nil {
		// Without the folder of homes, there is no home to reach.
		s.log.Warn("cannot open the folder of homes", zap.String("path", homes), zap.Error(err))
		return nil
	}
	defer dir.Close()
	name := u.Username
	owner, exists, err := readOwner(dir, name)
	switch {
	case err != nil:
		return err
	case exists && owner == u.ID:
		return nil
	case exists && owner == 0:
		// Made by hand, say by an administrator: it becomes theirs.
		return writeOwner(dir, name, u.ID)
	case exists:
		if _, err := s.trashHome(dir, name, "goftp"); err != nil {
			return fmt.Errorf("move the home %s of a deleted user to the trash: %w", path.Join(homes, name), err)
		}
		s.log.Info("home of a deleted user moved to the trash", zap.String("path", path.Join(homes, name)), zap.Int64("owner", owner))
	}
	if err := dir.Mkdir(name, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		s.log.Warn("cannot make a home", zap.String("user", name), zap.Error(err))
		return nil
	}
	return writeOwner(dir, name, u.ID)
}

// readOwner reads whose the home name of the folder of homes dir is: 0 for
// nobody yet, -1 if that cannot be read. exists is false if there is no
// home, also when something other than a folder takes its name.
func readOwner(dir *os.Root, name string) (owner int64, exists bool, err error) {
	info, err := dir.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !info.IsDir() {
		return 0, false, nil
	}
	f, err := dir.Open(path.Join(name, homeOwner))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, true, nil
	}
	if err != nil {
		return 0, true, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 32))
	if err != nil {
		return 0, true, err
	}
	id, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || id <= 0 {
		return -1, true, nil
	}
	return id, true, nil
}

// writeOwner notes that the home name of the folder of homes dir belongs
// to the user id.
func writeOwner(dir *os.Root, name string, id int64) error {
	tmp := path.Join(name, tempPrefix+rand.Text()+tempSuffix)
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(strconv.FormatInt(id, 10) + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = dir.Rename(tmp, path.Join(name, homeOwner))
	}
	if err != nil {
		_ = dir.Remove(tmp)
	}
	return err
}

// trashHome moves the home name of the folder of homes dir to the trash,
// as its user was deleted, noting by whom; with the trash off, it deletes
// it. It reports whether there was a home.
func (s *Server) trashHome(dir *os.Root, name, by string) (bool, error) {
	info, err := dir.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	release, err := s.acquireLock(dir, name, tempPrefix+rand.Text()+tempSuffix)
	if err != nil {
		return true, err
	}
	defer release()
	if s.cfg.Trash.Keep == 0 {
		err = dir.RemoveAll(name)
	} else {
		note := trashNote{Path: path.Join(s.cfg.Homes.Path, name), Dir: info.IsDir(), By: by, At: time.Now().UTC(), Home: true}
		if owner, _, err := readOwner(dir, name); err == nil && owner > 0 {
			note.Owner = owner
		}
		_, err = s.moveToTrash(dir, name, note)
	}
	if err != nil {
		return true, err
	}
	syncDir(dir)
	return true, nil
}

// trashHomeOf moves the home of the deleted user username to the trash, by
// the user by. It reports whether there was one.
func (s *Server) trashHomeOf(by, username string) (bool, error) {
	if s.cfg.Homes.Path == "" {
		return false, nil
	}
	dir, err := s.root.OpenRoot(rootName(s.cfg.Homes.Path))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer dir.Close()
	s.homeMu.Lock()
	defer s.homeMu.Unlock()
	return s.trashHome(dir, username, by)
}

// TrashHome moves the home of the deleted user username to the trash, by
// the user by, in the folder that cfg serves; with the trash off, it
// deletes it. It reports whether there was one. It is for the command line;
// a server that runs at the same time moves it to the trash anyway once a
// user of that name shows up.
func TrashHome(cfg *config.Config, by, username string) (bool, error) {
	if cfg.Homes.Path == "" {
		return false, nil
	}
	rootPath, err := filepath.EvalSymlinks(cfg.Dir)
	if err != nil {
		return false, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return false, err
	}
	defer root.Close()
	s := &Server{cfg: cfg, log: zap.NewNop(), root: root, rootPath: rootPath}
	return s.trashHomeOf(by, username)
}
