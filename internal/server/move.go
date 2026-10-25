package server

import (
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// relocate moves the entries names of the folder at dirPath into the folder
// at the URL path into, or with copying set copies them there, in turn,
// and stops at the first that fails. They keep their names.
func (s *Server) relocate(c fiber.Ctx, dirPath string, names []string, into string, copying bool) error {
	verb, did := "move", "Moved"
	if copying {
		verb, did = "copy", "Copied"
	}
	dest, ok := formPath(strings.TrimSpace(into))
	if !ok {
		return explain(fiber.ErrBadRequest, "Say which folder to "+verb+" it to, as a path such as /photos/2024.")
	}
	if hidden(dest) {
		return explain(fiber.ErrNotFound, "There is no folder "+dest+".")
	}
	var (
		done []string
		last string
	)
	for _, name := range unique(names) {
		var err error
		if copying {
			last, err = s.copyEntry(c, dirPath, name, dest, name, false)
		} else {
			last, err = s.moveEntry(c, dirPath, name, dest, name, false)
		}
		if err != nil {
			return s.partialError(c, did, done, err)
		}
		done = append(done, name)
	}
	if len(done) > 1 {
		last = object(dest, true)
	}
	return s.done(c, dirPath, fiber.StatusCreated, escapePath(last),
		strings.ToLower(did)+"="+strconv.Itoa(len(done))+"&to="+url.QueryEscape(dest))
}

// moveEntry moves the entry name of the folder at dirPath into the folder
// at dest, as newName, and returns its new URL path. The visitor needs the
// rights to read and delete it, everything in it as well, and to create it
// there. With replace, a file takes the place of the file newName there in
// one step, which the visitor needs the right to overwrite. Where the file
// system finds names in any case, newName may spell name anew.
func (s *Server) moveEntry(c fiber.Ctx, dirPath, name, dest, newName string, replace bool) (string, error) {
	if !validName(newName) {
		return "", explain(fiber.ErrBadRequest, badName)
	}
	dir, realDir, info, err := s.entry(c, dirPath, name, auth.ActDelete)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	src, realSrc := path.Join(dirPath, name), path.Join(realDir, name)
	if ok, err := s.mayAt(c, auth.ActRead, src, realSrc, info.IsDir()); err != nil {
		return "", err
	} else if !ok {
		return "", fiber.ErrNotFound
	}
	dst := path.Join(dest, newName)
	to, realTo, err := s.destination(c, dst, info.IsDir())
	if err != nil {
		return "", err
	}
	defer to.Close()
	respell := realTo == realDir && newName != name && s.folded(newName) == s.folded(name)
	switch {
	case realTo == realDir && newName == name:
		return "", explain(fiber.ErrConflict, name+" is in that folder already.")
	case info.IsDir() && within(realTo, realSrc):
		return "", explain(fiber.ErrConflict, "A folder cannot be moved into itself.")
	case respell:
		replace = false
	case replace:
		if ok, err := s.mayAt(c, auth.ActOverwrite, dst, path.Join(realTo, newName), false); err != nil {
			return "", err
		} else if !ok {
			return "", s.deny(c)
		}
	}

	// The locks keep uploads of the names out of both folders meanwhile; a
	// name spelled anew has one lock.
	type lock struct {
		dir  *os.Root
		name string
	}
	locks := []lock{{dir, name}}
	if !respell {
		locks = append(locks, lock{to, newName})
	}
	for _, l := range locks {
		release, err := s.acquireLock(l.dir, l.name, tempPrefix+rand.Text()+tempSuffix)
		if err != nil {
			return "", err
		}
		defer release()
	}
	if err := sameEntry(dir, name, info); err != nil {
		return "", err
	}
	freed := int64(0)
	if replace {
		switch old, err := to.Lstat(newName); {
		case errors.Is(err, fs.ErrNotExist):
			replace = false
		case err != nil:
			return "", s.openError(err)
		case !old.Mode().IsRegular() || !info.Mode().IsRegular():
			return "", explain(fiber.ErrConflict, newName+" changed meanwhile: try again.")
		default:
			freed = old.Size()
		}
	}
	// What is in a folder gets new paths, where other rules may apply: it
	// may only move if all of it could be read and deleted here, and
	// created there.
	if info.IsDir() {
		_, err := s.checkTreeTo(c, dir, name, src, realSrc, &treeDest{dst, path.Join(realTo, newName)}, auth.ActRead, auth.ActDelete)
		if err := s.treeError(err, "move"); err != nil {
			return "", err
		}
	}
	// Moving into a home takes room there, less what it replaces.
	fromHome, _ := s.homeName(realSrc)
	toHome, _ := s.homeName(path.Join(realTo, newName))
	if toHome != "" && toHome != fromHome {
		if err := s.homeRoom(toHome, entryBytes(dir, name, info)-freed); err != nil {
			return "", s.uploadError(nil, err)
		}
	}
	switch {
	case respell:
		err = renameNoReplace(dir, name, newName, info)
	case replace:
		err = renameBetween(dir, name, to, newName)
	default:
		err = moveNoReplace(dir, name, to, newName, info)
	}
	switch {
	case errors.Is(err, errExists):
		return "", explain(fiber.ErrConflict, "Something named "+newName+" is in that folder already.")
	case errors.Is(err, syscall.EXDEV):
		return "", explain(fiber.ErrConflict, "That folder is on another disk: copy it there, then delete it here.")
	case err != nil:
		return "", s.openError(err)
	}
	syncDir(dir)
	syncDir(to)
	if info.IsDir() {
		s.foldersMoved(realSrc, path.Join(realTo, newName))
	}
	if toHome != fromHome {
		s.recount(fromHome)
		s.recount(toHome)
	} else {
		s.unuse(toHome, freed)
	}
	s.log.Info("move", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", src), zap.String("to", dst),
		zap.Bool("replaced", replace))
	return object(dst, info.IsDir()), nil
}

// copyEntry copies the entry name of the folder at dirPath into the folder
// at dest, as newName, and returns the copy's URL path: a file, or a folder
// with what the visitor may read in it, as a zip of it would hold. The
// visitor needs the right to create all of the copy there. With replace, a
// copy of a file takes the place of the file newName there in one step,
// which the visitor needs the right to overwrite.
func (s *Server) copyEntry(c fiber.Ctx, dirPath, name, dest, newName string, replace bool) (string, error) {
	if !entryName(name) {
		return "", fiber.ErrBadRequest
	}
	if !validName(newName) {
		return "", explain(fiber.ErrBadRequest, badName)
	}
	src := path.Join(dirPath, name)
	// Checked before the entry is looked up, so that the answer does not
	// reveal what exists.
	if ok, err := s.mayEither(c, auth.ActRead, src); err != nil {
		return "", err
	} else if !ok {
		return "", s.deny(c)
	}
	allow := s.visitorRules(c)
	f, info, realSrc, err := s.lookup(src, allow)
	if err != nil {
		return "", err
	}
	_ = f.Close()
	dst := path.Join(dest, newName)
	to, realTo, err := s.destination(c, dst, info.IsDir())
	if err != nil {
		return "", err
	}
	defer to.Close()
	if replace {
		if ok, err := mayBoth(allow, auth.ActOverwrite, dst, path.Join(realTo, newName), false); err != nil {
			return "", err
		} else if !ok || info.IsDir() {
			return "", s.deny(c)
		}
	}

	contents := 0
	if info.IsDir() {
		if within(realTo, realSrc) {
			return "", explain(fiber.ErrConflict, "A folder cannot be copied into itself.")
		}
		contents, err = s.copyFolder(to, newName, src, realSrc, dst, path.Join(realTo, newName), allow)
	} else {
		err = s.copyFile(to, newName, realSrc, replace)
	}
	switch {
	case errors.Is(err, errExists):
		return "", explain(fiber.ErrConflict, "Something named "+newName+" is in that folder already.")
	case errors.Is(err, errDenied):
		return "", explain(fiber.ErrForbidden, "You may not create everything in it there.")
	case errors.Is(err, errTooMuch):
		return "", explain(fiber.ErrConflict, "There is too much in it to copy at once: copy the folders in it one by one.")
	case errors.Is(err, errChanged):
		return "", explain(fiber.ErrConflict, "Something in it changed while it was copied: try again.")
	case err != nil:
		return "", s.uploadError(nil, err)
	}
	syncDir(to)
	s.log.Info("copy", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", src), zap.String("to", dst),
		zap.Bool("folder", info.IsDir()), zap.Int("contents", contents))
	return object(dst, info.IsDir()), nil
}

// destination opens the folder that an entry is moved or copied into, to
// become dst, and returns where the folder really lives (see resolve). The
// visitor needs the right to create dst, at both places.
func (s *Server) destination(c fiber.Ctx, dst string, isDir bool) (*os.Root, string, error) {
	if ok, err := s.allowed(c, object(dst, isDir), auth.ActWrite); err != nil {
		return nil, "", err
	} else if !ok {
		return nil, "", s.deny(c)
	}
	folder := path.Dir(dst)
	to, realTo, err := s.uploadDir(folder)
	if errors.Is(err, fiber.ErrNotFound) {
		return nil, "", explain(fiber.ErrNotFound, "There is no folder "+folder+".")
	}
	if err != nil {
		return nil, "", err
	}
	if ok, err := s.mayAt(c, auth.ActWrite, dst, path.Join(realTo, path.Base(dst)), isDir); err != nil || !ok {
		_ = to.Close()
		if err == nil {
			err = s.deny(c)
		}
		return nil, "", err
	}
	return to, realTo, nil
}

// entryBytes adds up the entry name of dir, info, with what is in it.
func entryBytes(dir *os.Root, name string, info fs.FileInfo) int64 {
	switch {
	case info.Mode().IsRegular():
		return info.Size()
	case !info.IsDir():
		return 0
	}
	sub, err := dir.OpenRoot(name)
	if err != nil {
		return 0
	}
	defer sub.Close()
	return treeBytes(sub)
}

// within reports whether the URL path p is dir or inside it.
func within(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}

// copyFile copies the file at realSrc as the new file name of dst, keeping
// its modification time; with replace, the file name there may be
// replaced. The data goes through a temp file, as uploads do. A file that
// is no longer at realSrc, where its rights were checked, is not copied
// (404).
func (s *Server) copyFile(dst *os.Root, name, realSrc string, replace bool) error {
	f, err := s.root.OpenFile(rootName(realSrc), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return s.openError(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fiber.ErrNotFound
	}
	if real, ok := s.resolve(rootName(realSrc), f); !ok || real != realSrc {
		return fiber.ErrNotFound
	}
	if _, _, _, err := s.store(dst, name, f, replace, uploadRights{create: true, replace: replace}, io.Copy); err != nil {
		return err
	}
	_ = dst.Chtimes(name, time.Now(), info.ModTime())
	return nil
}

// Copies stop at maxCopyEntries entries, or folders maxCopyDepth deep:
// symlinks can make a folder hold far more than is on the disk.
var (
	maxCopyEntries = 100_000
	maxCopyDepth   = 64
)

var (
	errTooMuch = errors.New("too much to copy at once")
	errChanged = errors.New("changed while copied")
)

// copyFolder copies the folder at urlPath, really at realPath, as the new
// folder name of dst, at dstPath (really at realDst), and returns how many
// entries it copied. The rights to create all of it there are checked
// first, so that a refused copy leaves nothing behind. The copy is made
// under a hidden name, which nothing else writes in and nothing copied can
// lead to, and gets its name once complete; a copy that fails midway is
// removed.
func (s *Server) copyFolder(dst *os.Root, name, urlPath, realPath, dstPath, realDst string, allow allowFunc) (int, error) {
	n, err := s.copyTree(nil, urlPath, realPath, dstPath, realDst, allow, []string{realPath}, new(int))
	if err != nil {
		return 0, err
	}
	tmp := tempPrefix + rand.Text() + tempSuffix
	release, err := s.acquireLock(dst, name, tmp)
	if err != nil {
		return 0, err
	}
	defer release()
	if _, err := dst.Lstat(name); err == nil {
		return 0, errExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if err := dst.Mkdir(tmp, 0o755); err != nil {
		return 0, err
	}
	sub, err := dst.OpenRoot(tmp)
	if err == nil {
		_, err = s.copyTree(sub, urlPath, realPath, dstPath, realDst, allow, []string{realPath}, new(int))
		_ = sub.Close()
	}
	if err == nil {
		err = renameExclBetween(dst, tmp, dst, name)
	}
	if err != nil {
		_ = dst.RemoveAll(tmp)
		return 0, err
	}
	return n, nil
}

// copyTree copies what the folder at urlPath (really at realPath) holds that
// allow lets the visitor read into the folder dst, at dstPath (really at
// realDst), and what the folders in it hold in turn, if the visitor may
// create each copy there (errDenied otherwise). ancestors are the real
// paths of the folders being copied; total counts the entries met, against
// maxCopyEntries. Without dst, it only checks. It returns how many entries
// it copied, or would.
func (s *Server) copyTree(dst *os.Root, urlPath, realPath, dstPath, realDst string, allow allowFunc, ancestors []string, total *int) (int, error) {
	if len(ancestors) > maxCopyDepth {
		return 0, errTooMuch
	}
	items, err := s.readable(urlPath, realPath, allow)
	if errors.Is(err, errChanged) && dst == nil {
		err = nil
	}
	if err != nil {
		return 0, err
	}
	if *total += len(items); *total > maxCopyEntries {
		return 0, errTooMuch
	}
	n := 0
	for _, it := range items {
		if it.IsDir && loops(it.real, ancestors) {
			continue
		}
		target, realTarget := path.Join(dstPath, it.Name), path.Join(realDst, it.Name)
		// Checked again while copying, for what appeared since.
		if ok, err := mayBoth(allow, auth.ActWrite, target, realTarget, it.IsDir); err != nil {
			return n, err
		} else if !ok {
			return n, errDenied
		}
		n++
		switch {
		case !it.IsDir && dst != nil:
			if err := s.copyFile(dst, it.Name, it.real, false); err != nil && !errors.Is(err, fiber.ErrNotFound) {
				return n, err
			}
			continue
		case !it.IsDir:
			continue
		}
		var sub *os.Root
		if dst != nil {
			if err := dst.Mkdir(it.Name, 0o755); errors.Is(err, fs.ErrExist) {
				return n, errExists
			} else if err != nil {
				return n, err
			}
			if sub, err = dst.OpenRoot(it.Name); err != nil {
				return n, err
			}
		}
		m, err := s.copyTree(sub, it.Path, it.real, target, realTarget, allow, append(ancestors, it.real), total)
		if sub != nil {
			_ = sub.Close()
		}
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
