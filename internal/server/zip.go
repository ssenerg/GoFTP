package server

import (
	"archive/zip"
	"errors"
	"io"
	"mime"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
)

// serveZip streams the folder at urlPath, which really lives at realPath,
// as name.zip: everything in it that allow lets the visitor open, the way
// listings show it. Dotfiles, entries other tools are writing and folders
// that symlinks lead back into are left out. Files are stored as they are:
// a zip is for taking a folder along, and large files rarely compress.
func (s *Server) serveZip(c fiber.Ctx, urlPath, realPath, name string, allow allowFunc) error {
	c.Set(fiber.HeaderContentType, "application/zip")
	c.Set(fiber.HeaderContentDisposition, mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"}))
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set(fiber.HeaderContentSecurityPolicy, fileSecurityPolicy)
	z := &zipStream{conn: c.RequestCtx().Conn(), timeout: s.cfg.Server.WriteTimeout}
	z.produce = func(w io.Writer) error {
		zw := zip.NewWriter(w)
		if err := s.zipFolder(zw, urlPath, realPath, "", allow, []string{realPath}); err != nil {
			return err
		}
		return zw.Close()
	}
	return c.Status(fiber.StatusOK).SendStream(z, -1)
}

// zipName names the zip of the folder at urlPath.
func zipName(urlPath string) string {
	if urlPath == "/" {
		return "files"
	}
	return path.Base(urlPath)
}

// zipFolder adds what the folder at urlPath (really at realPath) holds to
// zw under prefix, and what the folders in it hold in turn. ancestors are
// the real paths of the folders being added.
func (s *Server) zipFolder(zw *zip.Writer, urlPath, realPath, prefix string, allow allowFunc, ancestors []string) error {
	items, err := s.readable(urlPath, realPath, allow)
	if err != nil {
		return err
	}
	for _, item := range items {
		hdr := &zip.FileHeader{Name: prefix + item.Name, Modified: item.mod}
		if !item.IsDir {
			if err := s.zipFile(zw, hdr, item.real); err != nil {
				return err
			}
			continue
		}
		if loops(item.real, ancestors) {
			continue
		}
		hdr.Name += "/"
		if _, err := zw.CreateHeader(hdr); err != nil {
			return err
		}
		if err := s.zipFolder(zw, item.Path, item.real, hdr.Name, allow, append(ancestors, item.real)); err != nil {
			return err
		}
	}
	return nil
}

// readable lists the entries of the folder at urlPath, which really lives
// at realPath, that allow lets the visitor read, as listings show them,
// ordered by name.
func (s *Server) readable(urlPath, realPath string, allow allowFunc) ([]listItem, error) {
	d, err := s.root.Open(rootName(realPath))
	if err != nil {
		return nil, err
	}
	items, err := s.folderItems(d, urlPath, realPath, allow)
	_ = d.Close()
	if err != nil {
		return nil, err
	}
	slices.SortFunc(items, func(a, b listItem) int { return strings.Compare(a.Name, b.Name) })
	return items, nil
}

// loops reports whether the folder at realPath contains, or is, one of the
// folders being added: adding it would never end.
func loops(realPath string, ancestors []string) bool {
	for _, a := range ancestors {
		if a == realPath || realPath == "/" || strings.HasPrefix(a, realPath+"/") {
			return true
		}
	}
	return false
}

// zipFile adds the file at realPath, unless it is gone or may no longer be
// shown.
func (s *Server) zipFile(zw *zip.Writer, hdr *zip.FileHeader, realPath string) error {
	f, err := s.root.OpenFile(rootName(realPath), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || !s.visible(rootName(realPath), f) {
		return nil
	}
	hdr.Method = zip.Store
	w, err := zw.CreateHeader(hdr)
	if err == nil {
		_, err = io.Copy(w, f)
	}
	return err
}

var errClientGone = errors.New("the response was closed")

// zipStream is a response body that produce writes into a pipe. It starts
// with the first read, so a body that is never sent (HEAD) costs nothing,
// and ends when fasthttp closes it, also when the client goes away.
type zipStream struct {
	produce func(io.Writer) error
	conn    net.Conn
	timeout time.Duration
	pr      *io.PipeReader
	sent    int64
	done    func(sent int64, err error)
}

func (z *zipStream) Read(p []byte) (int, error) {
	if z.pr == nil {
		pr, pw := io.Pipe()
		z.pr = pr
		go func() { _ = pw.CloseWithError(z.produce(pw)) }()
	}
	// As for downloads, only a client that stops reading times out.
	if z.conn != nil {
		_ = z.conn.SetWriteDeadline(time.Now().Add(z.timeout))
	}
	n, err := z.pr.Read(p)
	z.sent += int64(n)
	return n, err
}

// CloseWithError is called by fasthttp once the response is written.
func (z *zipStream) CloseWithError(err error) error {
	if z.pr != nil {
		_ = z.pr.CloseWithError(errClientGone)
	}
	if z.done != nil {
		z.done(z.sent, err)
	}
	return nil
}

func (z *zipStream) whenDone(f func(sent int64, err error)) { z.done = f }
