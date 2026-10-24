package server

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// uploadRights reports whether the visitor may create new files and replace
// existing ones at obj.
func (s *Server) uploadRights(c fiber.Ctx, obj string) (create, replace bool, err error) {
	return uploadRightsOf(s.visitorRules(c), obj)
}

// uploadRightsAt narrows the upload rights at obj to those the visitor also
// has at realObj, where symlinks lead (see resolve): a symlink grants
// nothing its target's rules do not.
func (s *Server) uploadRightsAt(c fiber.Ctx, obj, realObj string) (create, replace bool, err error) {
	return uploadRightsAtOf(s.visitorRules(c), obj, realObj)
}

// uploadRightsOf is uploadRights for the rules of allow.
func uploadRightsOf(allow allowFunc, obj string) (create, replace bool, err error) {
	if create, err = allow(obj, auth.ActWrite); err != nil {
		return false, false, err
	}
	replace, err = allow(obj, auth.ActOverwrite)
	return create, replace, err
}

// uploadRightsAtOf is uploadRightsAt for the rules of allow.
func uploadRightsAtOf(allow allowFunc, obj, realObj string) (create, replace bool, err error) {
	create, replace, err = uploadRightsOf(allow, obj)
	if err != nil || obj == realObj || (!create && !replace) {
		return create, replace, err
	}
	realCreate, realReplace, err := uploadRightsOf(allow, realObj)
	return create && realCreate, replace && realReplace, err
}

// put stores the request body as the file at the request path, e.g.
// curl -T file.iso -H "Authorization: Bearer $TOKEN" https://host/dir/
// The parent directory must exist. "If-None-Match: *" refuses to replace an
// existing file.
func (s *Server) put(c fiber.Ctx) error {
	urlPath, wantDir, err := cleanPath(c.Path())
	if err != nil || wantDir || urlPath == "/" {
		return fiber.ErrBadRequest
	}
	if hidden(urlPath) {
		return fiber.ErrForbidden
	}
	dirPath, name := path.Split(urlPath)
	if !validName(name) {
		return fiber.ErrBadRequest
	}
	create, replace, err := s.uploadRights(c, urlPath)
	if err != nil {
		return err
	}
	if !create && !replace {
		return s.deny(c)
	}
	// A chunked body cut off between chunks looks complete; only a declared
	// length lets truncated uploads be detected.
	length := int64(c.Request().Header.ContentLength())
	if length < 0 {
		return fiber.ErrLengthRequired
	}
	if limit := int64(s.cfg.Upload.MaxSize); limit > 0 && length > limit {
		return fiber.ErrRequestEntityTooLarge
	}
	dir, realDir, err := s.uploadDir(dirPath)
	if errors.Is(err, fiber.ErrNotFound) {
		return fiber.ErrConflict
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if create, replace, err = s.uploadRightsAt(c, urlPath, path.Join(realDir, name)); err != nil {
		return err
	} else if !create && !replace {
		return s.deny(c)
	}

	body := s.requestBody(c)
	rights := uploadRights{create: create, replace: replace}
	created, size, err := s.receive(dir, name, body, c.Get(fiber.HeaderIfNoneMatch) != "*", rights)
	if errors.Is(err, errExists) {
		return fiber.ErrPreconditionFailed
	}
	if err != nil {
		return s.uploadError(body, err)
	}
	s.logUpload(c, urlPath, size, created)
	s.finishBody(c, body)
	if created {
		return c.SendStatus(fiber.StatusCreated)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// postForm stores the files of a multipart/form-data upload (the listing
// page's form) in the directory at the request path. The replace field has
// to come before the files. Existing files are only replaced when asked to.
// Other forms create, delete and rename entries there (see manage), and
// tus requests start resumable uploads (see createUpload).
func (s *Server) postForm(c fiber.Ctx) error {
	urlPath, _, err := cleanPath(c.Path())
	if err != nil {
		return fiber.ErrBadRequest
	}
	if hidden(urlPath) {
		return fiber.ErrForbidden
	}
	if c.Get("Tus-Resumable") != "" {
		return s.createUpload(c, urlPath, nil)
	}
	switch mediaType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType)); mediaType {
	case fiber.MIMEApplicationForm, fiber.MIMEApplicationJSON:
		return s.manage(c, urlPath)
	}
	// Each file is checked on its own; this spares reading the body of
	// visitors who may not upload here at all.
	if create, replace, err := s.uploadRights(c, object(urlPath, true)); err != nil {
		return err
	} else if !create && !replace {
		return s.deny(c)
	}
	mediaType, params, err := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return fiber.ErrUnsupportedMediaType
	}

	body := s.requestBody(c)
	form := multipart.NewReader(body, params["boundary"])
	replace := false
	var (
		dir     *os.Root
		realDir string
		stored  []string
	)
	defer func() {
		if dir != nil {
			_ = dir.Close()
		}
	}()
	for {
		part, err := form.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return s.formError(c, stored, s.uploadError(body, fiber.ErrBadRequest))
		}
		switch name := part.FileName(); {
		case part.FormName() == "replace" && name == "":
			v, err := io.ReadAll(io.LimitReader(part, 16))
			if err != nil {
				return s.formError(c, stored, s.uploadError(body, fiber.ErrBadRequest))
			}
			replace = slices.Contains([]string{"1", "on", "true"}, string(v))
		case part.FormName() == "file" && name != "":
			if dir == nil {
				if dir, realDir, err = s.uploadDir(urlPath); err != nil {
					return err
				}
			}
			if !validName(name) {
				return s.formError(c, stored, fiber.ErrBadRequest)
			}
			create, mayReplace, err := s.uploadRightsAt(c, path.Join(urlPath, name), path.Join(realDir, name))
			if err != nil {
				return s.formError(c, stored, err)
			}
			// Checked before the name is looked up: without rights on the
			// file, whether it exists is none of the visitor's business.
			if !create && !mayReplace {
				return s.formError(c, stored, s.deny(c))
			}
			created, size, err := s.receive(dir, name, part, replace, uploadRights{create: create, replace: mayReplace})
			if errors.Is(err, errExists) {
				err = fiber.ErrConflict
			}
			if err != nil {
				return s.formError(c, stored, s.uploadError(body, err))
			}
			s.logUpload(c, path.Join(urlPath, name), size, created)
			stored = append(stored, name)
		}
		_ = part.Close()
	}
	if len(stored) == 0 {
		return fiber.ErrBadRequest
	}
	s.finishBody(c, body)
	// Scripts upload with Accept: */* and need no page.
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		return c.SendStatus(fiber.StatusCreated)
	}
	return c.Redirect().Status(fiber.StatusSeeOther).To(escapePath(object(urlPath, true)) + "?uploaded=" + strconv.Itoa(len(stored)))
}

// linkUpload takes files sent through an upload link: a resumable upload
// (tus), or the files of a form. They go into the link's folder; a name
// taken there gets a number, as the sender cannot see what is there. Every
// file counts as a use of the link.
func (s *Server) linkUpload(c fiber.Ctx, tus bool) error {
	sh, view, rel, _, err := s.share(c)
	if err != nil || sh == nil {
		return err
	}
	if !sh.Upload || rel != "/" {
		return explain(fiber.ErrForbidden, "Files cannot be sent through this link.")
	}
	if !s.unlocked(c, sh, view) {
		return explain(fiber.ErrForbidden, "This link needs its password: open it first.")
	}
	if tus {
		return s.createUpload(c, sh.Path, sh)
	}
	_, params, err := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	if err != nil || params["boundary"] == "" {
		return fiber.ErrUnsupportedMediaType
	}
	dir, realDir, err := s.uploadDir(sh.Path)
	if errors.Is(err, fiber.ErrNotFound) {
		err = explain(fiber.ErrNotFound, deadLink)
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	allow := s.linkUploadRules(sh)
	body := s.requestBody(c)
	form := multipart.NewReader(body, params["boundary"])
	var stored []string
	for {
		part, err := form.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return s.formError(c, stored, s.uploadError(body, fiber.ErrBadRequest))
		}
		name := part.FileName()
		if part.FormName() != "file" || name == "" {
			_ = part.Close()
			continue
		}
		if !validName(name) {
			return s.formError(c, stored, explain(fiber.ErrBadRequest, badName))
		}
		if create, _, err := uploadRightsAtOf(allow, path.Join(sh.Path, name), path.Join(realDir, name)); err != nil {
			return s.formError(c, stored, err)
		} else if !create {
			return s.formError(c, stored, linkClosed())
		}
		if err := s.spendLink(c, sh); err != nil {
			return s.formError(c, stored, err)
		}
		got, _, size, err := s.store(dir, name, part, false, uploadRights{create: true, rename: true}, s.copyUpload)
		if err != nil {
			return s.formError(c, stored, s.uploadError(body, err))
		}
		s.logUpload(c, path.Join(sh.Path, got), size, true)
		stored = append(stored, name)
		_ = part.Close()
	}
	if len(stored) == 0 {
		return fiber.ErrBadRequest
	}
	s.finishBody(c, body)
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		return c.SendStatus(fiber.StatusCreated)
	}
	return s.redirect(c, view.Root+"?uploaded="+strconv.Itoa(len(stored)))
}

// formError reports a failed form upload, naming the files that were
// already stored before the failure.
func (s *Server) formError(c fiber.Ctx, stored []string, err error) error {
	if len(stored) == 0 {
		return err
	}
	return s.sendError(c, err, "Stored before the error: "+strings.Join(stored, ", "))
}

// uploadDir opens the existing directory at urlPath for writing, and
// returns the URL path where it really lives (see resolve). Its fd pins the
// directory, so later operations cannot be redirected by symlink swaps.
func (s *Server) uploadDir(urlPath string) (*os.Root, string, error) {
	name := rootName(path.Clean(urlPath))
	// OpenRoot reports non-directories with an unexported error.
	if info, err := s.root.Stat(name); err != nil {
		return nil, "", s.openError(err)
	} else if !info.IsDir() {
		return nil, "", fiber.ErrNotFound
	}
	dir, err := s.root.OpenRoot(name)
	if err != nil {
		return nil, "", s.openError(err)
	}
	f, err := dir.Open(".")
	if err == nil {
		real, visible := s.resolve(name, f)
		_ = f.Close()
		if visible {
			return dir, real, nil
		}
		err = fiber.ErrNotFound
	}
	_ = dir.Close()
	return nil, "", err
}

var errExists = errors.New("file exists")

// uploadRights are the visitor's permissions for one upload target. With
// rename, a file of that name stays, and the upload gets a free name like
// it (see placeFree).
type uploadRights struct{ create, replace, rename bool }

// receive stores body as name in dir. The data goes to a hidden temp file
// that is renamed into place once complete, so partial data never appears
// under the real name; the lock file keeps concurrent uploads out. Without
// replace, an existing name yields errExists.
func (s *Server) receive(dir *os.Root, name string, body io.Reader, replace bool, rights uploadRights) (created bool, size int64, err error) {
	_, created, size, err = s.store(dir, name, body, replace, rights, s.copyUpload)
	return created, size, err
}

// store is receive with copy moving the data, which for uploads is limited
// in size (copyUpload). It also returns the name the file got, which with
// rights.rename may differ.
func (s *Server) store(dir *os.Root, name string, body io.Reader, replace bool, rights uploadRights,
	copy func(io.Writer, io.Reader) (int64, error)) (stored string, created bool, size int64, err error) {
	tmp := tempPrefix + rand.Text() + tempSuffix
	release, err := s.acquireLock(dir, name, tmp)
	if err != nil {
		return "", false, 0, err
	}
	defer func() {
		_ = dir.Remove(tmp)
		release()
	}()

	created = true
	if !rights.rename {
		if created, err = checkTarget(dir, name, replace, rights); err != nil {
			return "", false, 0, err
		}
	} else if !rights.create {
		return "", false, 0, fiber.ErrForbidden
	}
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", false, 0, err
	}
	size, err = copy(f, body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	stored = name
	switch {
	case err != nil:
	case rights.rename:
		stored, err = s.placeFree(dir, tmp, name)
	default:
		err = place(dir, tmp, name, replace, rights)
	}
	if err != nil {
		return "", false, size, err
	}
	return stored, created, size, nil
}

// placeFree moves the complete temp file tmp in dir to name, which the
// caller has locked, or if that is taken to the first free name like it:
// "a (2).txt", "a (3).txt" and so on.
func (s *Server) placeFree(dir *os.Root, tmp, name string) (string, error) {
	for i := 1; i <= 100; i++ {
		candidate := numbered(name, i)
		if !validName(candidate) {
			break
		}
		release := func() {}
		if i > 1 {
			var err error
			if release, err = s.acquireLock(dir, candidate, tempPrefix+rand.Text()+tempSuffix); errors.Is(err, fiber.ErrConflict) {
				continue
			} else if err != nil {
				return "", err
			}
		}
		err := commit(dir, tmp, candidate, false)
		release()
		if errors.Is(err, errExists) {
			continue
		}
		if err != nil {
			return "", err
		}
		syncDir(dir)
		return candidate, nil
	}
	return "", errExists
}

// numbered is the ith name like name: name itself, then "a (2).txt" for
// "a.txt", and so on.
func numbered(name string, i int) string {
	if i == 1 {
		return name
	}
	ext := path.Ext(name)
	if ext == name {
		ext = ""
	}
	return strings.TrimSuffix(name, ext) + " (" + strconv.Itoa(i) + ")" + ext
}

// checkTarget reports whether storing name in dir would create it, or why
// it may not be stored: name is a folder (409), or it exists and replacing
// was not asked for (errExists) or is not allowed (403), or it does not
// exist and may not be created (403).
func checkTarget(dir *os.Root, name string, replace bool, rights uploadRights) (created bool, err error) {
	switch info, err := dir.Lstat(name); {
	case err == nil && info.IsDir():
		return false, fiber.ErrConflict
	case err == nil && !replace:
		return false, errExists
	case err == nil && !rights.replace:
		return false, fiber.ErrForbidden
	case err == nil:
		return false, nil
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	case !rights.create:
		return false, fiber.ErrForbidden
	}
	return true, nil
}

// place moves the complete temp file tmp in dir to name, which the caller
// has locked and checked with checkTarget.
func place(dir *os.Root, tmp, name string, replace bool, rights uploadRights) error {
	if !rights.create {
		// Replacing is all the visitor may do, so the file has to still
		// be there.
		if _, err := dir.Lstat(name); err != nil {
			return fiber.ErrForbidden
		}
	}
	if err := commit(dir, tmp, name, replace && rights.replace); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// commit moves a finished temp file into place. Without replace, a hard
// link makes "only if absent" atomic even against writers that ignore lock
// files; without hard link support it falls back to check-then-rename.
func commit(dir *os.Root, tmp, name string, replace bool) error {
	if !replace {
		err := dir.Link(tmp, name)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, fs.ErrExist):
			return errExists
		}
		if _, err := dir.Lstat(name); err == nil {
			return errExists
		}
	}
	return dir.Rename(tmp, name)
}

func (s *Server) copyUpload(dst io.Writer, body io.Reader) (int64, error) {
	limit := int64(s.cfg.Upload.MaxSize)
	if limit <= 0 {
		return io.Copy(dst, body)
	}
	n, err := io.Copy(dst, io.LimitReader(body, limit+1))
	if err == nil && n > limit {
		err = fiber.ErrRequestEntityTooLarge
	}
	return n, err
}

// syncDir makes a rename durable; not every platform can sync directories.
func syncDir(dir *os.Root) {
	if d, err := dir.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// validName reports whether name is acceptable for an uploaded file.
func validName(name string) bool {
	if name == "" || hidden(name) || len(lockName(name)) > 255 || !utf8.ValidString(name) {
		return false
	}
	bad := `/\`
	if filepath.Separator == '\\' {
		bad += `:*?"<>|`
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.In(r, unicode.Zl, unicode.Zp) || bidiControl(r) || strings.ContainsRune(bad, r) {
			return false
		}
	}
	return true
}

// bidiControl reports whether r reorders the text around it, which lets a
// name pass for another: "invoice\u202efdp.exe" shows as "invoiceexe.pdf".
// Joiners and direction marks, which cannot, are fine.
func bidiControl(r rune) bool {
	return (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

func (s *Server) logUpload(c fiber.Ctx, urlPath string, size int64, created bool) {
	s.log.Info("upload",
		zap.String("ip", c.IP()),
		zap.String("user", visitor(c)),
		zap.String("path", urlPath),
		zap.Int64("bytes", size),
		zap.Bool("replaced", !created))
}

// uploadError maps a failed upload to a response status, also when body,
// the request body read, is nil; other errors are server-side faults (500,
// logged).
func (s *Server) uploadError(body *requestBody, err error) error {
	var (
		fe      *fiber.Error
		timeout interface{ Timeout() bool }
		berr    error
	)
	if body != nil {
		berr = body.err
	}
	switch {
	case errors.As(err, &fe):
		return err
	case errors.Is(berr, errAborted):
		return fiber.ErrLocked
	case errors.As(berr, &timeout) && timeout.Timeout():
		return fiber.ErrRequestTimeout
	case berr != nil:
		return fiber.ErrBadRequest
	case errors.Is(err, syscall.ENOSPC):
		return fiber.ErrInsufficientStorage
	case errors.Is(err, syscall.ENAMETOOLONG):
		return fiber.ErrBadRequest
	default:
		return err
	}
}

// requestBody reads a streamed request body. fasthttp applies ReadTimeout
// to the whole request, so the read deadline is re-armed before every
// read: an upload only times out when the client stops sending.
type requestBody struct {
	r        io.Reader
	conn     net.Conn
	timeout  time.Duration
	deadline time.Time // if set, for the whole body instead
	length   int64     // declared Content-Length, or -1
	read     int64
	eof      bool
	err      error
	aborted  atomic.Bool
}

var errAborted = errors.New("reading the request was stopped")

func (s *Server) requestBody(c fiber.Ctx) *requestBody {
	r := c.Request().BodyStream()
	if r == nil {
		r = bytes.NewReader(c.Request().Body())
	}
	return &requestBody{
		r:       r,
		conn:    c.RequestCtx().Conn(),
		timeout: s.cfg.Server.ReadTimeout,
		length:  max(int64(c.Request().Header.ContentLength()), -1),
	}
}

func (b *requestBody) Read(p []byte) (int, error) {
	if b.conn != nil {
		deadline := b.deadline
		if deadline.IsZero() {
			deadline = time.Now().Add(b.timeout)
		}
		_ = b.conn.SetReadDeadline(deadline)
	}
	// Checked after the deadline is re-armed, which could undo an abort.
	if b.aborted.Load() {
		b.err = errAborted
		return 0, errAborted
	}
	n, err := b.r.Read(p)
	b.read += int64(n)
	// fasthttp reports a connection closed mid-body as a clean EOF.
	if err == io.EOF && b.length >= 0 && b.read != b.length {
		err = io.ErrUnexpectedEOF
	}
	switch {
	case err != nil && b.aborted.Load():
		err = errAborted
		b.err = err
	case err == io.EOF:
		b.eof = true
	case err != nil:
		b.err = err
	}
	return n, err
}

// abort makes reading the body fail from now on, also a read that waits
// for data.
func (b *requestBody) abort() {
	b.aborted.Store(true)
	if b.conn != nil {
		_ = b.conn.SetReadDeadline(time.Now())
	}
}

// finishBody drains a small remainder of the body (such as a multipart
// epilogue) and marks the body consumed, which keeps the connection open.
func (s *Server) finishBody(c fiber.Ctx, b *requestBody) {
	if !b.eof && b.err == nil {
		_, _ = io.CopyN(io.Discard, b, 64<<10)
	}
	if b.eof {
		c.RequestCtx().SetUserValue(bodyDoneKey, true)
	}
}

// wrapHandler wraps the fasthttp handler, so it also covers responses Fiber
// sends outside the middleware chain. fasthttp does not drain a streamed
// request body the handler left unread and would parse the rest as the next
// request, so such connections are closed.
func (s *Server) wrapHandler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		next(ctx)
		// ContentLength is -1 for chunked bodies, -2 when there is none.
		if n := ctx.Request.Header.ContentLength(); (n > 0 || n == -1) && ctx.UserValue(bodyDoneKey) == nil {
			ctx.SetConnectionClose()
		}
		// Fiber answers unknown methods without running any middleware; the
		// client address is logged without proxy header processing.
		if ctx.UserValue(logStateKey) == nil {
			s.writeAccess(access{
				ip:     ctx.RemoteIP().String(),
				method: string(ctx.Method()),
				path:   string(ctx.URI().PathOriginal()),
				status: ctx.Response.StatusCode(),
				start:  ctx.Time(),
			}, int64(len(ctx.Response.Body())), nil)
		}
	}
}
