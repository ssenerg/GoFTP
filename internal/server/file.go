package server

import (
	"crypto/rand"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
)

// fileSecurityPolicy applies to downloads, which are always attachments:
// should a browser still render one, its scripts neither run nor share the
// site's origin.
const fileSecurityPolicy = "default-src 'none'; sandbox"

// serveFile streams f (taking ownership of it) as an attachment, with Range
// and conditional request support. A non-nil use is called before a
// download is sent, and may refuse it; see sendContent.
func (s *Server) serveFile(c fiber.Ctx, f *os.File, info fs.FileInfo, name string, use func() error) error {
	return s.sendContent(c, f, info, name, "", "", use)
}

// sendContent streams f (taking ownership of it) as serveFile does, or,
// given the policy to show it with, as ctype to be shown in the browser. An
// empty ctype is sniffed. use, if not nil, is called before content from
// the start of the file is sent: the whole file, or ranges of it that
// include its first byte. Ranges further on resume a download that was
// counted already. An error from use is returned instead.
func (s *Server) sendContent(c fiber.Ctx, f *os.File, info fs.FileInfo, name, ctype, inlinePolicy string, use func() error) error {
	size := info.Size()
	modTime := info.ModTime()
	etag := etagOf(modTime, size)
	unchanged := notModified(c.Get(fiber.HeaderIfNoneMatch), c.Get(fiber.HeaderIfModifiedSince), etag, modTime)
	var (
		ranges   []byteRange
		rangeErr error
	)
	if h := c.Get(fiber.HeaderRange); !unchanged && h != "" && size > 0 && ifRangeMatch(c.Get(fiber.HeaderIfRange), etag, modTime) {
		ranges, rangeErr = parseRange(h, size)
	}
	if use != nil && !unchanged && rangeErr == nil && c.Method() != fiber.MethodHead && fromStart(ranges) {
		if err := use(); err != nil {
			_ = f.Close()
			return err
		}
	}

	disposition, policy := "attachment", fileSecurityPolicy
	if inlinePolicy != "" {
		disposition, policy = "inline", inlinePolicy
		c.Set(fiber.HeaderXFrameOptions, "SAMEORIGIN")
	}
	c.Set(fiber.HeaderContentSecurityPolicy, policy)
	c.Set(fiber.HeaderETag, etag)
	c.Set(fiber.HeaderLastModified, modTime.UTC().Format(http.TimeFormat))
	c.Set(fiber.HeaderAcceptRanges, "bytes")
	c.Set(fiber.HeaderCacheControl, "no-store")

	if unchanged {
		_ = f.Close()
		return c.SendStatus(fiber.StatusNotModified)
	}
	if rangeErr != nil {
		_ = f.Close()
		c.Set(fiber.HeaderContentRange, "bytes */"+strconv.FormatInt(size, 10))
		return fiber.ErrRequestedRangeNotSatisfiable
	}

	if ctype == "" {
		ctype = sniffType(f)
	}
	c.Set(fiber.HeaderContentDisposition, mime.FormatMediaType(disposition, map[string]string{"filename": name}))
	body := s.newBodyStream(c, f)

	switch len(ranges) {
	case 0:
		c.Set(fiber.HeaderContentType, ctype)
		body.r = io.NewSectionReader(f, 0, size)
		return sendStream(c, fiber.StatusOK, body, size)
	case 1:
		r := ranges[0]
		c.Set(fiber.HeaderContentType, ctype)
		c.Set(fiber.HeaderContentRange, r.contentRange(size))
		body.r = io.NewSectionReader(f, r.start, r.length)
		return sendStream(c, fiber.StatusPartialContent, body, r.length)
	default:
		boundary := rand.Text()
		var length int64
		body.r, length = multipartBody(f, ranges, boundary, ctype, size)
		c.Set(fiber.HeaderContentType, "multipart/byteranges; boundary="+boundary)
		return sendStream(c, fiber.StatusPartialContent, body, length)
	}
}

// etagOf is the entity tag of a file modified at mod, size bytes long.
func etagOf(mod time.Time, size int64) string {
	return `"` + strconv.FormatInt(mod.UnixNano(), 16) + "-" + strconv.FormatInt(size, 16) + `"`
}

// fromStart reports whether sending ranges, or the whole file if there are
// none, sends the file's first byte.
func fromStart(ranges []byteRange) bool {
	return len(ranges) == 0 || slices.ContainsFunc(ranges, func(r byteRange) bool { return r.start == 0 })
}

func sendStream(c fiber.Ctx, status int, body io.Reader, length int64) error {
	n := int(length)
	if int64(n) != length {
		n = -1 // too large for int on 32-bit platforms: use chunked encoding
	}
	return c.Status(status).SendStream(body, n)
}

func multipartBody(f *os.File, ranges []byteRange, boundary, ctype string, size int64) (io.Reader, int64) {
	parts := make([]io.Reader, 0, 2*len(ranges)+1)
	var length int64
	for i, r := range ranges {
		head := "--" + boundary + "\r\nContent-Type: " + ctype +
			"\r\nContent-Range: " + r.contentRange(size) + "\r\n\r\n"
		if i > 0 {
			head = "\r\n" + head
		}
		parts = append(parts, strings.NewReader(head), io.NewSectionReader(f, r.start, r.length))
		length += int64(len(head)) + r.length
	}
	tail := "\r\n--" + boundary + "--\r\n"
	parts = append(parts, strings.NewReader(tail))
	return io.MultiReader(parts...), length + int64(len(tail))
}

func sniffType(f *os.File) string {
	var buf [512]byte
	n, _ := f.ReadAt(buf[:], 0)
	if n == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(buf[:n])
}

// bodyStream feeds a response body from an open file. fasthttp applies
// WriteTimeout once per response, so the stream re-arms the write deadline
// before every write: a transfer only times out when the client stops
// reading, not when a large download simply takes long.
type bodyStream struct {
	r       io.Reader
	file    *os.File
	conn    net.Conn
	timeout time.Duration
	sent    int64
	onClose func(sent int64, err error)
}

var copyBufs = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}

func (s *Server) newBodyStream(c fiber.Ctx, f *os.File) *bodyStream {
	return &bodyStream{file: f, conn: c.RequestCtx().Conn(), timeout: s.cfg.Server.WriteTimeout}
}

func (b *bodyStream) arm() {
	if b.conn != nil {
		_ = b.conn.SetWriteDeadline(time.Now().Add(b.timeout))
	}
}

// WriteTo is fasthttp's fixed-length path; it copies in large chunks.
func (b *bodyStream) WriteTo(w io.Writer) (int64, error) {
	bp := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(bp)
	var n int64
	for {
		nr, rerr := b.r.Read(*bp)
		if nr > 0 {
			b.arm()
			nw, werr := w.Write((*bp)[:nr])
			n += int64(nw)
			b.sent += int64(nw)
			if werr != nil {
				return n, werr
			}
		}
		if rerr == io.EOF {
			return n, nil
		}
		if rerr != nil {
			return n, rerr
		}
	}
}

// Read is used for chunked responses.
func (b *bodyStream) Read(p []byte) (int, error) {
	b.arm()
	n, err := b.r.Read(p)
	b.sent += int64(n)
	return n, err
}

// CloseWithError is called by fasthttp once the response is written.
func (b *bodyStream) CloseWithError(err error) error {
	if b.onClose != nil {
		b.onClose(b.sent, err)
	}
	return b.file.Close()
}

func (b *bodyStream) whenDone(f func(sent int64, err error)) { b.onClose = f }
