package server

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// Previews show images, audio, video and PDFs in the browser. Files are
// otherwise always downloaded, so that nothing uploaded runs as part of this
// site. Only types that a file's own bytes prove it to have are shown, never
// its name: no SVG, HTML or anything else that could hold a script.

// Files shown in the browser may be framed by this site only. PDFs, which
// can hold scripts and forms, are sandboxed like downloads. Images, audio
// and video run nothing; opened on their own, the browser's page for one
// loads it again from this site, which a sandbox would not let it do.
const (
	pdfPolicy   = "default-src 'none'; sandbox; frame-ancestors 'self'"
	mediaPolicy = "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'"
)

// previewExts guess from names which files listings offer to view.
var previewExts = map[string]string{
	".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image", ".webp": "image", ".bmp": "image", ".avif": "image",
	".mp4": "video", ".m4v": "video", ".webm": "video", ".mov": "video", ".ogv": "video",
	".mp3": "audio", ".m4a": "audio", ".aac": "audio", ".wav": "audio", ".flac": "audio", ".ogg": "audio", ".oga": "audio", ".opus": "audio",
	".pdf": "pdf",
}

// previewKind says how a file named name would be shown, judging by its
// name: image, video, audio or pdf; "" for none.
func previewKind(name string) string {
	return previewExts[strings.ToLower(path.Ext(name))]
}

// thumbExts guess from names which images listings show thumbnails of.
var thumbExts = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".bmp": true}

// inlineType sniffs the start of f, named name, and returns the type it
// may be shown as in the browser and its kind (image, video, audio or pdf),
// or "" if it may not.
func inlineType(f io.ReaderAt, name string) (ctype, kind string) {
	var buf [512]byte
	n, _ := f.ReadAt(buf[:], 0)
	head := buf[:n]
	ext := strings.ToLower(path.Ext(name))
	switch ct := http.DetectContentType(head); ct {
	case "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp":
		return ct, "image"
	case "video/mp4":
		if ext == ".m4a" {
			return "audio/mp4", "audio"
		}
		return ct, "video"
	case "video/webm":
		return ct, "video"
	case "audio/mpeg":
		return ct, "audio"
	case "audio/wave":
		return "audio/wav", "audio"
	case "application/ogg":
		if ext == ".ogv" {
			return "video/ogg", "video"
		}
		return "audio/ogg", "audio"
	case "application/pdf":
		return ct, "pdf"
	}
	// Formats Go does not sniff.
	switch {
	case len(head) >= 12 && string(head[4:8]) == "ftyp":
		switch string(head[8:12]) {
		case "avif", "avis":
			return "image/avif", "image"
		case "qt  ":
			return "video/quicktime", "video"
		case "M4A ", "M4B ":
			return "audio/mp4", "audio"
		case "isom", "iso2", "mp41", "mp42", "M4V ", "dash", "avc1":
			return "video/mp4", "video"
		}
	case bytes.HasPrefix(head, []byte("fLaC")):
		return "audio/flac", "audio"
	case len(head) >= 2 && head[0] == 0xFF && head[1]&0xF6 == 0xF0:
		return "audio/aac", "audio" // ADTS
	case ext == ".mp3" && len(head) >= 2 && head[0] == 0xFF && head[1]&0xE0 == 0xE0 && head[1]&0x06 != 0:
		return "audio/mpeg", "audio" // MPEG audio without ID3
	}
	return "", ""
}

// fileAt places a file in URLs and pages: on the site, or under a share
// link.
type fileAt struct {
	base  string // "" or the path of the share link
	rel   string // the file's path under base
	page  func(title string) page
	allow allowFunc
	use   func() error // counts a download through a share link, or refuses it
}

// serveFileAs serves the file f at urlPath, which really lives at realPath,
// as the query asks: ?view shows it in a page of its own, ?inline in the
// browser if it may be, ?thumb as a thumbnail. Otherwise it is downloaded.
func (s *Server) serveFileAs(c fiber.Ctx, f *os.File, info fs.FileInfo, urlPath, realPath string, at fileAt) error {
	q := c.Request().URI().QueryArgs()
	switch {
	case q.Has("view"):
		return s.serveViewer(c, f, info, urlPath, at)
	case q.Has("inline"):
		return s.serveInline(c, f, info, path.Base(urlPath))
	case q.Has("thumb"):
		return s.serveThumb(c, f, info, realPath)
	}
	return s.serveFile(c, f, info, path.Base(urlPath), at.use)
}

// serveInline sends f (taking ownership of it) to be shown in the browser,
// if its content may be (415 otherwise).
func (s *Server) serveInline(c fiber.Ctx, f *os.File, info fs.FileInfo, name string) error {
	ctype, kind := inlineType(f, name)
	if ctype == "" {
		_ = f.Close()
		return explain(fiber.ErrUnsupportedMediaType, "This file cannot be shown in the browser. Download it instead.")
	}
	policy := mediaPolicy
	if kind == "pdf" {
		policy = pdfPolicy
	}
	return s.sendContent(c, f, info, name, ctype, policy, nil)
}

type viewerPage struct {
	page
	Home       string
	Crumbs     []crumb
	Name       string
	Kind       string // image, video, audio or pdf; "" when it cannot be shown
	Src        string // the file, shown inline
	Download   string
	Folder     string
	Size       string
	ModTime    string
	ModISO     string
	Position   string // e.g. "3 of 12"
	Prev, Next *viewerLink
}

type viewerLink struct{ Name, Href string }

// serveViewer shows the file f at urlPath in a page of its own, with links
// to the previous and next files of its folder that can be shown too.
func (s *Server) serveViewer(c fiber.Ctx, f *os.File, info fs.FileInfo, urlPath string, at fileAt) error {
	name := path.Base(urlPath)
	ctype, kind := inlineType(f, name)
	_ = f.Close()
	dirRel := path.Dir(at.rel)
	href := escapePath(at.base + at.rel)
	mod := info.ModTime().UTC()
	v := viewerPage{
		page: at.page(name), Home: at.base + "/", Crumbs: crumbs(at.base, dirRel), Name: name, Src: href + "?inline",
		Download: href, Folder: escapePath(at.base + object(dirRel, true)), Size: formatSize(info.Size()),
		ModTime: shownTime(mod), ModISO: isoTime(mod),
	}
	if ctype != "" {
		v.Kind = kind
	}
	v.Position, v.Prev, v.Next = s.around(path.Dir(urlPath), name, at)
	return s.render(c, fiber.StatusOK, "viewer", v)
}

// around places the file name in its folder dirPath among the files that
// can be shown, as the folder lists them: its position, and the files
// before and after it. Folders the visitor may not list place it nowhere.
func (s *Server) around(dirPath, name string, at fileAt) (string, *viewerLink, *viewerLink) {
	d, _, dirReal, err := s.lookup(dirPath, at.allow)
	if err != nil {
		return "", nil, nil
	}
	items, err := s.folderItems(d, dirPath, dirReal, at.allow)
	_ = d.Close()
	if err != nil {
		return "", nil, nil
	}
	shown := slices.DeleteFunc(items, func(it listItem) bool { return it.IsDir || it.Preview == "" })
	sortItems(shown, "name", false)
	i := slices.IndexFunc(shown, func(it listItem) bool { return it.Name == name })
	if i < 0 {
		return "", nil, nil
	}
	link := func(j int) *viewerLink {
		if j < 0 || j >= len(shown) {
			return nil
		}
		return &viewerLink{Name: shown[j].Name, Href: escapePath(at.base+path.Join(path.Dir(at.rel), shown[j].Name)) + "?view"}
	}
	return strconv.Itoa(i+1) + " of " + strconv.Itoa(len(shown)), link(i - 1), link(i + 1)
}
