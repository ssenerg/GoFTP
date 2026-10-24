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
			last, err = s.copyEntry(c, dirPath, name, dest)
		} else {
			last, err = s.moveEntry(c, dirPath, name, dest)
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
// at dest, and returns its new URL path. The visitor needs the rights to
// read and delete it, everything in it as well, and to create it there.
func (s *Server) moveEntry(c fiber.Ctx, dirPath, name, dest string) (string, error) {
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
	dst := path.Join(dest, name)
	to, realTo, err := s.destination(c, dst, info.IsDir())
	if err != nil {
		return "", err
	}
	defer to.Close()
	switch {
	case realTo == realDir:
		return "", explain(fiber.ErrConflict, name+" is in that folder already.")
	case info.IsDir() && within(realTo, realSrc):
		return "", explain(fiber.ErrConflict, "A folder cannot be moved into itself.")
	}

	// The locks keep uploads of the name out of both folders meanwhile.
	for _, d := range []*os.Root{dir, to} {
		release, err := s.acquireLock(d, name, tempPrefix+rand.Text()+tempSuffix)
		if err != nil {
			return "", err
		}
		defer release()
	}
	// What is in a folder gets new paths, where other rules may apply: it
	// may only move if all of it could be read and deleted here.
	if info.IsDir() {
		_, err := s.checkTree(c, dir, name, src, realSrc, auth.ActRead, auth.ActDelete)
		if err := s.treeError(err, "move"); err != nil {
			return "", err
		}
	}
	switch err := moveNoReplace(dir, name, to, name, info); {
	case errors.Is(err, errExists):
		return "", explain(fiber.ErrConflict, "Something named "+name+" is in that folder already.")
	case errors.Is(err, syscall.EXDEV):
		return "", explain(fiber.ErrConflict, "That folder is on another disk: copy it there, then delete it here.")
	case err != nil:
		return "", s.openError(err)
	}
	syncDir(dir)
	syncDir(to)
	s.log.Info("move", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", src), zap.String("to", dst))
	return object(dst, info.IsDir()), nil
}

// copyEntry copies the entry name of the folder at dirPath into the folder
// at dest, and returns the copy's URL path: a file, or a folder with what
// the visitor may read in it, as a zip of it would hold. The visitor needs
// the right to create all of the copy there.
func (s *Server) copyEntry(c fiber.Ctx, dirPath, name, dest string) (string, error) {
	if !entryName(name) {
		return "", fiber.ErrBadRequest
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
	dst := path.Join(dest, name)
	to, realTo, err := s.destination(c, dst, info.IsDir())
	if err != nil {
		return "", err
	}
	defer to.Close()

	contents := 0
	if info.IsDir() {
		if within(realTo, realSrc) {
			return "", explain(fiber.ErrConflict, "A folder cannot be copied into itself.")
		}
		contents, err = s.copyFolder(to, name, src, realSrc, dst, path.Join(realTo, name), allow)
	} else {
		err = s.copyFile(to, name, realSrc)
	}
	switch {
	case errors.Is(err, errExists):
		return "", explain(fiber.ErrConflict, "Something named "+name+" is in that folder already.")
	case errors.Is(err, errDenied):
		return "", explain(fiber.ErrForbidden, "You may not create everything in it there.")
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

// within reports whether the URL path p is dir or inside it.
func within(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}

// copyFile copies the file at realSrc as the new file name of dst, keeping
// its modification time. The data goes through a temp file, as uploads do.
func (s *Server) copyFile(dst *os.Root, name, realSrc string) error {
	f, err := s.root.OpenFile(rootName(realSrc), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return s.openError(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !s.visible(rootName(realSrc), f) {
		return fiber.ErrNotFound
	}
	if _, _, _, err := s.store(dst, name, f, false, uploadRights{create: true}, io.Copy); err != nil {
		return err
	}
	_ = dst.Chtimes(name, time.Now(), info.ModTime())
	return nil
}

// copyFolder copies the folder at urlPath, really at realPath, as the new
// folder name of dst, at dstPath (really at realDst), and returns how many
// entries it copied. The rights to create all of it there are checked
// first, so that a refused copy leaves nothing behind; a copy that fails
// midway is removed.
func (s *Server) copyFolder(dst *os.Root, name, urlPath, realPath, dstPath, realDst string, allow allowFunc) (int, error) {
	n, err := s.copyTree(nil, urlPath, realPath, dstPath, realDst, allow, []string{realPath})
	if err != nil {
		return 0, err
	}
	release, err := s.acquireLock(dst, name, tempPrefix+rand.Text()+tempSuffix)
	if err != nil {
		return 0, err
	}
	defer release()
	if err := dst.Mkdir(name, 0o755); errors.Is(err, fs.ErrExist) {
		return 0, errExists
	} else if err != nil {
		return 0, err
	}
	sub, err := dst.OpenRoot(name)
	if err == nil {
		_, err = s.copyTree(sub, urlPath, realPath, dstPath, realDst, allow, []string{realPath})
		_ = sub.Close()
	}
	if err != nil {
		_ = dst.RemoveAll(name)
		return 0, err
	}
	return n, nil
}

// copyTree copies what the folder at urlPath (really at realPath) holds that
// allow lets the visitor read into the folder dst, at dstPath (really at
// realDst), and what the folders in it hold in turn. ancestors are the real
// paths of the folders being copied. Without dst, it only checks that the
// visitor may create all of it there (errDenied). It returns how many
// entries it copied, or would.
func (s *Server) copyTree(dst *os.Root, urlPath, realPath, dstPath, realDst string, allow allowFunc, ancestors []string) (int, error) {
	items, err := s.readable(urlPath, realPath, allow)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if it.IsDir && loops(it.real, ancestors) {
			continue
		}
		target, realTarget := path.Join(dstPath, it.Name), path.Join(realDst, it.Name)
		if dst == nil {
			if ok, err := mayBoth(allow, auth.ActWrite, target, realTarget, it.IsDir); err != nil {
				return n, err
			} else if !ok {
				return n, errDenied
			}
		}
		n++
		switch {
		case !it.IsDir && dst != nil:
			if err := s.copyFile(dst, it.Name, it.real); err != nil && !errors.Is(err, fiber.ErrNotFound) {
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
		m, err := s.copyTree(sub, it.Path, it.real, target, realTarget, allow, append(ancestors, it.real))
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
