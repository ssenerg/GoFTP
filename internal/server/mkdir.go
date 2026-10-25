package server

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"net/url"
	"path"
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

const badFolderName = "Folder names cannot be empty or very long, start with a dot, or contain /, \\ or control characters."

// mkdir creates the folder name in the directory at urlPath, for the form
// field "folder" (see manage), e.g. curl -d folder=photos https://host/dir/
func (s *Server) mkdir(c fiber.Ctx, urlPath, name string) error {
	name = strings.TrimSpace(name)
	if err := s.makeFolder(c, urlPath, name); err != nil {
		return err
	}
	return s.done(c, urlPath, fiber.StatusCreated, escapePath(path.Join(urlPath, name)+"/"), "created="+url.QueryEscape(name))
}

// makeFolder creates the folder name in the directory at urlPath: 409 if
// something has that name, 404 if there is no such directory.
func (s *Server) makeFolder(c fiber.Ctx, urlPath, name string) error {
	if !validName(name) {
		return explain(fiber.ErrBadRequest, badFolderName)
	}
	target := path.Join(urlPath, name)
	if ok, err := s.allowed(c, object(target, true), auth.ActWrite); err != nil {
		return err
	} else if !ok {
		return s.deny(c)
	}
	dir, realDir, err := s.uploadDir(urlPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	// Through symlinks, the rules of the real folder apply as well.
	if ok, err := s.mayAt(c, auth.ActWrite, target, path.Join(realDir, name), true); err != nil {
		return err
	} else if !ok {
		return s.deny(c)
	}

	// The lock keeps uploads of the same name out meanwhile.
	release, err := s.acquireLock(dir, name, tempPrefix+rand.Text()+tempSuffix)
	if err != nil {
		return err
	}
	defer release()
	if err := s.folderRoom(dir); err != nil {
		return s.uploadError(&requestBody{}, err)
	}
	if err := dir.Mkdir(name, 0o755); errors.Is(err, fs.ErrExist) {
		return fiber.ErrConflict
	} else if err != nil {
		return s.uploadError(&requestBody{}, err)
	}
	syncDir(dir)

	s.log.Info("mkdir", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", target))
	return nil
}
