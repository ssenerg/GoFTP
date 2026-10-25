package server

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
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

// WebDAV (RFC 4918) at /.dav/, for sync apps and file managers: the same
// files as the site, with the same rules, homes, quotas and trash, signed
// in to with HTTP Basic authentication and an app password (see
// auth.AppPassword). /.dav/PATH is PATH. Locks are advisory: they keep other
// WebDAV clients that ask from taking the same lock, and nothing else, as
// goftp's own locks guard every change.
const davPrefix = "/.dav"

// davMethods are the methods WebDAV adds to HTTP's.
var davMethods = []string{"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

const davAllow = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"

// davBodyLimit bounds the XML bodies of WebDAV requests.
const davBodyLimit = 64 << 10

// davRoutes serves WebDAV under davPrefix.
func (s *Server) davRoutes() {
	methods := append([]string{fiber.MethodGet, fiber.MethodHead, fiber.MethodPut, fiber.MethodDelete, fiber.MethodOptions}, davMethods...)
	s.app.Add(methods, davPrefix, s.dav)
	s.app.Add(methods, davPrefix+"/*", s.dav)
}

func (s *Server) dav(c fiber.Ctx) error {
	c.Set("DAV", "1, 2")
	c.Set("MS-Author-Via", "DAV")
	c.Set(fiber.HeaderCacheControl, "no-store")
	if c.Method() == fiber.MethodOptions {
		c.Set(fiber.HeaderAllow, davAllow)
		return c.SendStatus(fiber.StatusOK)
	}
	if err := s.davSignIn(c); err != nil {
		return err
	}
	urlPath, ok := davPath(c.Path())
	if !ok {
		return fiber.ErrBadRequest
	}
	switch c.Method() {
	case "PROPFIND":
		return s.davPropfind(c, urlPath)
	case "PROPPATCH":
		return s.davProppatch(c, urlPath)
	case "MKCOL":
		return s.davMkcol(c, urlPath)
	case "COPY":
		return s.davCopyMove(c, urlPath, false)
	case "MOVE":
		return s.davCopyMove(c, urlPath, true)
	case "LOCK":
		return s.davLock(c, urlPath)
	case "UNLOCK":
		return s.davUnlock(c, urlPath)
	case fiber.MethodGet, fiber.MethodHead:
		return s.davGet(c, urlPath)
	case fiber.MethodPut:
		return s.davPut(c, urlPath)
	case fiber.MethodDelete:
		return s.davDelete(c, urlPath)
	}
	return fiber.ErrMethodNotAllowed
}

// davPath returns the clean URL path that the request path p, under
// davPrefix, stands for.
func davPath(p string) (string, bool) {
	rest, ok := strings.CutPrefix(p, davPrefix)
	if !ok || rest != "" && rest[0] != '/' {
		return "", false
	}
	if rest == "" {
		rest = "/"
	}
	clean, _, err := cleanPath(rest)
	return clean, err == nil
}

// davHref is the WebDAV URL of the entry at urlPath.
func davHref(urlPath string, dir bool) string {
	return escapePath(davPrefix + object(urlPath, dir))
}

// davSignIn signs the request in with HTTP Basic authentication: a username
// and one of their app passwords. Wrong ones count against the client's
// budget of failed sign-ins, as passwords do, but only once they failed:
// app passwords are too long to guess even in parallel, and sync apps send
// many requests at once, which counting each before it runs would refuse.
func (s *Server) davSignIn(c fiber.Ctx) error {
	username, password, ok := basicAuth(c.Get(fiber.HeaderAuthorization))
	if !ok {
		return davUnauthorized(c)
	}
	client := clientKey(c.IP())
	if s.limiter != nil {
		if wait := s.limiter.attempt(client, false, time.Now()); wait > 0 {
			retryAfter(c, wait)
			return explain(fiber.ErrTooManyRequests, tooMany)
		}
	}
	ctx, cancel := dbContext(c)
	u, err := s.auth.AppPasswordUser(ctx, username, password)
	cancel()
	switch {
	case errors.Is(err, auth.ErrNotFound):
		s.log.Warn("app password refused", zap.String("ip", c.IP()))
		if s.limiter != nil {
			s.limiter.attempt(client, true, time.Now())
		}
		return davUnauthorized(c)
	case err != nil:
		return err
	}
	c.Locals(sessionKey, &session{user: u})
	return nil
}

func davUnauthorized(c fiber.Ctx) error {
	c.Set(fiber.HeaderWWWAuthenticate, `Basic realm="goftp", charset="UTF-8"`)
	return explain(fiber.ErrUnauthorized, "Sign in with your username and an app password: make one under Sync.")
}

// basicAuth returns the username and password of an "Authorization: Basic"
// header.
func basicAuth(h string) (username, password string, ok bool) {
	const prefix = "basic "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(b), ":")
}

// davBody reads the XML body of a WebDAV request.
func (s *Server) davBody(c fiber.Ctx) ([]byte, error) {
	body := s.requestBody(c)
	data, err := io.ReadAll(io.LimitReader(body, davBodyLimit+1))
	if err != nil {
		return nil, s.uploadError(body, err)
	}
	if len(data) > davBodyLimit {
		return nil, fiber.ErrRequestEntityTooLarge
	}
	s.finishBody(c, body)
	return data, nil
}

// appleDouble reports whether name is one of the files that macOS keeps
// beside others, which goftp, hiding names that start with a dot, takes
// and drops.
func appleDouble(name string) bool {
	return strings.HasPrefix(name, "._") || name == ".DS_Store"
}

// statusOf returns the HTTP status of err.
func statusOf(err error) int {
	var fe *fiber.Error
	if errors.As(err, &fe) {
		return fe.Code
	}
	return fiber.StatusInternalServerError
}

// davResource is an entry as PROPFIND describes it.
type davResource struct {
	path string // URL path
	dir  bool
	size int64
	mod  time.Time
	real string // URL path where it really lives; "" for the way to a home
}

// propfind is the body of a PROPFIND request: allprop, propname, or the
// properties asked for.
type propfind struct {
	XMLName  xml.Name  `xml:"DAV: propfind"`
	Allprop  *struct{} `xml:"DAV: allprop"`
	Propname *struct{} `xml:"DAV: propname"`
	Prop     *struct {
		Names []xmlName `xml:",any"`
	} `xml:"DAV: prop"`
}

type xmlName struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// davProps are the properties allprop returns.
var davProps = []string{"resourcetype", "getcontentlength", "getlastmodified", "creationdate", "getetag", "displayname",
	"getcontenttype", "supportedlock", "lockdiscovery"}

func (s *Server) davPropfind(c fiber.Ctx, urlPath string) error {
	depth := c.Get("Depth")
	if depth == "" {
		depth = "1"
	}
	if depth != "0" && depth != "1" {
		return davError(c, fiber.StatusForbidden, "propfind-finite-depth")
	}
	data, err := s.davBody(c)
	if err != nil {
		return err
	}
	var req propfind
	if len(bytes.TrimSpace(data)) > 0 {
		if err := xml.Unmarshal(data, &req); err != nil {
			return fiber.ErrBadRequest
		}
	}
	allow := s.visitorRules(c)
	var res []davResource
	f, info, realPath, err := s.lookup(urlPath, allow)
	switch {
	case err == nil:
		res = append(res, davResource{path: urlPath, dir: info.IsDir(), size: info.Size(), mod: info.ModTime(), real: realPath})
		if info.IsDir() && depth == "1" {
			items, err := s.folderItems(f, urlPath, realPath, allow)
			if err != nil {
				_ = f.Close()
				return err
			}
			for _, it := range items {
				res = append(res, davResource{path: it.Path, dir: it.IsDir, size: it.size, mod: it.mod, real: it.real})
			}
		}
		_ = f.Close()
	case statusOf(err) == fiber.StatusNotFound && s.towardHome(c, urlPath) != "":
		res = append(res, s.wayHome(urlPath))
	default:
		return err
	}
	// Folders that rules close can still be the way to one's home.
	if next := s.towardHome(c, urlPath); depth == "1" && res[0].dir && next != "" &&
		!slices.ContainsFunc(res[1:], func(r davResource) bool { return r.path == next }) {
		res = append(res, s.wayHome(next))
	}

	var b bytes.Buffer
	b.WriteString(xml.Header + `<D:multistatus xmlns:D="DAV:">`)
	for _, r := range res {
		b.WriteString("<D:response><D:href>")
		xmlText(&b, davHref(r.path, r.dir))
		b.WriteString("</D:href>")
		switch {
		case req.Propname != nil:
			b.WriteString("<D:propstat><D:prop>")
			for _, name := range davProps {
				b.WriteString("<D:" + name + "/>")
			}
			b.WriteString("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>")
		case req.Prop != nil:
			var found, missing bytes.Buffer
			for _, n := range req.Prop.Names {
				if v, ok := s.davProp(c, r, n.XMLName); ok {
					found.WriteString(v)
				} else {
					emptyElement(&missing, n.XMLName)
				}
			}
			propstat(&b, found.String(), "200 OK")
			propstat(&b, missing.String(), "404 Not Found")
		default:
			var found bytes.Buffer
			for _, name := range davProps {
				if v, ok := s.davProp(c, r, xml.Name{Space: "DAV:", Local: name}); ok {
					found.WriteString(v)
				}
			}
			propstat(&b, found.String(), "200 OK")
		}
		b.WriteString("</D:response>")
	}
	b.WriteString("</D:multistatus>")
	c.Set(fiber.HeaderContentType, "application/xml; charset=utf-8")
	return c.Status(fiber.StatusMultiStatus).Send(b.Bytes())
}

// towardHome returns, for the folder at urlPath on the way to the home of
// the visitor of c, the next folder on that way; "" for other paths.
func (s *Server) towardHome(c fiber.Ctx, urlPath string) string {
	home := s.homeOf(userOf(c))
	rest, ok := strings.CutPrefix(home, strings.TrimSuffix(urlPath, "/")+"/")
	if home == "" || !ok || rest == "" {
		return ""
	}
	next, _, _ := strings.Cut(rest, "/")
	return path.Join(urlPath, next)
}

// wayHome describes the folder at urlPath on the way to a home, which says
// nothing of what else it holds.
func (s *Server) wayHome(urlPath string) davResource {
	r := davResource{path: urlPath, dir: true, mod: time.Now()}
	if info, err := s.root.Stat(rootName(urlPath)); err == nil {
		r.mod = info.ModTime()
	}
	return r
}

// davProp returns the property name of r, as XML, if it has it.
func (s *Server) davProp(c fiber.Ctx, r davResource, name xml.Name) (string, bool) {
	if name.Space != "DAV:" {
		return "", false
	}
	var v string
	switch name.Local {
	case "resourcetype":
		if r.dir {
			v = "<D:collection/>"
		}
	case "getcontentlength":
		if r.dir {
			return "", false
		}
		v = strconv.FormatInt(r.size, 10)
	case "getlastmodified":
		v = r.mod.UTC().Format(http.TimeFormat)
	case "creationdate":
		v = r.mod.UTC().Format(time.RFC3339)
	case "getetag":
		v = xmlEscape(etagOf(r.mod, r.size))
	case "displayname":
		v = xmlEscape(path.Base(r.path))
		if r.path == "/" {
			v = ""
		}
	case "getcontenttype":
		if r.dir {
			return "", false
		}
		v = xmlEscape(contentTypeOf(r.path))
	case "supportedlock":
		v = "<D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>" +
			"<D:lockentry><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>"
	case "lockdiscovery":
		v = s.lockDiscovery(r.path)
	case "quota-used-bytes", "quota-available-bytes":
		used, avail, ok := s.davQuota(r)
		if !ok || name.Local == "quota-used-bytes" && used < 0 {
			return "", false
		}
		v = strconv.FormatInt(avail, 10)
		if name.Local == "quota-used-bytes" {
			v = strconv.FormatInt(used, 10)
		}
	default:
		return "", false
	}
	return "<D:" + name.Local + ">" + v + "</D:" + name.Local + ">", true
}

// davQuota returns how much the folder r holds and how much more it may
// (RFC 4331): in a home with a quota, against it; elsewhere, how much the
// disk takes before upload.min_free, with used -1 as it is not counted.
func (s *Server) davQuota(r davResource) (used, avail int64, ok bool) {
	if !r.dir || r.real == "" {
		return 0, 0, false
	}
	if name, isHome := s.homeName(r.real); isHome {
		if u, _, q, err := s.homeUsage(name); err == nil && q > 0 {
			return u, max(q-u, 0), true
		}
	}
	free, known := freeSpace(s.root)
	if !known {
		return 0, 0, false
	}
	return -1, max(free-int64(s.cfg.Upload.MinFree), 0), true
}

// contentTypeOf guesses the type of the file at urlPath from its name.
func contentTypeOf(urlPath string) string {
	if t := mime.TypeByExtension(path.Ext(urlPath)); t != "" {
		return t
	}
	return "application/octet-stream"
}

func propstat(b *bytes.Buffer, props, status string) {
	if props == "" {
		return
	}
	b.WriteString("<D:propstat><D:prop>" + props + "</D:prop><D:status>HTTP/1.1 " + status + "</D:status></D:propstat>")
}

// emptyElement writes an element named name, without content.
func emptyElement(b *bytes.Buffer, name xml.Name) {
	if name.Space == "DAV:" {
		b.WriteString("<D:" + name.Local + "/>")
		return
	}
	b.WriteString("<x:" + name.Local + ` xmlns:x="`)
	xmlText(b, name.Space)
	b.WriteString(`"/>`)
}

func xmlText(b *bytes.Buffer, s string) { _ = xml.EscapeText(b, []byte(s)) }

func xmlEscape(s string) string {
	var b bytes.Buffer
	xmlText(&b, s)
	return b.String()
}

// davError answers with a WebDAV error element (RFC 4918 section 16).
func davError(c fiber.Ctx, status int, condition string) error {
	c.Set(fiber.HeaderContentType, "application/xml; charset=utf-8")
	return c.Status(status).SendString(xml.Header + `<D:error xmlns:D="DAV:"><D:` + condition + "/></D:error>")
}

func (s *Server) davGet(c fiber.Ctx, urlPath string) error {
	f, info, _, err := s.lookup(urlPath, s.visitorRules(c))
	if err != nil {
		return err
	}
	if info.IsDir() {
		// Folders are for browsers to show.
		_ = f.Close()
		return s.redirect(c, escapePath(object(urlPath, true)))
	}
	return s.serveFile(c, f, info, path.Base(urlPath), nil)
}

func (s *Server) davPut(c fiber.Ctx, urlPath string) error {
	if appleDouble(path.Base(urlPath)) {
		_, _ = s.davBody(c)
		return c.SendStatus(fiber.StatusCreated)
	}
	if urlPath == "/" {
		return fiber.ErrMethodNotAllowed
	}
	length := int64(c.Request().Header.ContentLength())
	if length < 0 {
		// Finder sends files in chunks, saying how long they are.
		n, err := strconv.ParseInt(c.Get("X-Expected-Entity-Length"), 10, 64)
		if err != nil || n < 0 {
			return fiber.ErrLengthRequired
		}
		length = n
	}
	mtime, keep := unixTime(c.Get("X-OC-Mtime"))
	created, err := s.putFile(c, urlPath, length, mtime)
	if err != nil {
		return err
	}
	if info, err := s.root.Stat(rootName(urlPath)); err == nil {
		c.Set(fiber.HeaderETag, etagOf(info.ModTime(), info.Size()))
	}
	if keep {
		c.Set("X-OC-Mtime", "accepted")
	}
	if created {
		return c.SendStatus(fiber.StatusCreated)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// unixTime parses a time in seconds since 1970, as the X-OC-Mtime header of
// ownCloud's clients and rclone gives a file's modification time.
func unixTime(v string) (time.Time, bool) {
	secs, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || secs <= 0 || secs > 1<<40 {
		return time.Time{}, false
	}
	whole := int64(secs)
	return time.Unix(whole, int64((secs-float64(whole))*1e9)), true
}

func (s *Server) davDelete(c fiber.Ctx, urlPath string) error {
	if urlPath == "/" {
		return fiber.ErrForbidden
	}
	dirPath, name := path.Split(urlPath)
	if appleDouble(name) {
		return c.SendStatus(fiber.StatusNoContent)
	}
	if _, err := s.remove(c, dirPath, name, false); err != nil {
		return err
	}
	s.dropLocks(urlPath)
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) davMkcol(c fiber.Ctx, urlPath string) error {
	data, err := s.davBody(c)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		return fiber.ErrUnsupportedMediaType
	}
	if urlPath == "/" {
		return fiber.ErrMethodNotAllowed
	}
	dirPath, name := path.Split(urlPath)
	switch err := s.makeFolder(c, dirPath, name); statusOf(err) {
	case fiber.StatusConflict:
		// Something has the name already.
		return fiber.ErrMethodNotAllowed
	case fiber.StatusNotFound:
		// The folder it would be in is missing.
		return fiber.ErrConflict
	default:
		if err != nil {
			return err
		}
	}
	return c.SendStatus(fiber.StatusCreated)
}

// davCopyMove copies or moves the entry at urlPath to the Destination
// header's path, replacing what is there (into the trash) unless
// "Overwrite: F" says not to.
func (s *Server) davCopyMove(c fiber.Ctx, urlPath string, move bool) error {
	dst, ok := davDestination(c.Get("Destination"))
	switch {
	case !ok:
		return explain(fiber.ErrBadRequest, "Say where it goes, in a Destination header under "+davPrefix+"/.")
	case urlPath == "/" || dst == "/" || dst == urlPath || hidden(dst):
		return fiber.ErrForbidden
	case within(urlPath, dst) || within(dst, urlPath):
		// Replacing a folder the entry is in would trash the entry too.
		return explain(fiber.ErrConflict, "An entry cannot go where it is, or into itself.")
	}
	overwrite := !strings.EqualFold(strings.TrimSpace(c.Get("Overwrite")), "F")
	depth := c.Get("Depth")
	allow := s.visitorRules(c)
	f, info, _, err := s.lookup(urlPath, allow)
	if err != nil {
		return err
	}
	_ = f.Close()
	if info.IsDir() && depth != "" && depth != "infinity" && (move || depth != "0") {
		return fiber.ErrBadRequest
	}
	replaced := false
	if g, _, _, err := s.lookup(dst, allow); err == nil {
		_ = g.Close()
		if !overwrite {
			return fiber.ErrPreconditionFailed
		}
		// Checked before what is there goes to the trash, so that it does
		// not go for nothing; the move or copy checks everything again.
		may, err := s.mayEither(c, auth.ActWrite, dst)
		if err == nil && may && move {
			may, err = s.mayEither(c, auth.ActDelete, urlPath)
		}
		if err != nil {
			return err
		} else if !may {
			return s.deny(c)
		}
		dir, name := path.Split(dst)
		if _, err := s.remove(c, dir, name, false); err != nil {
			return err
		}
		s.dropLocks(dst)
		replaced = true
	}
	srcDir, srcName := path.Split(urlPath)
	dstDir, dstName := path.Split(dst)
	switch {
	case move:
		_, err = s.moveEntry(c, srcDir, srcName, path.Clean(dstDir), dstName)
	case info.IsDir() && depth == "0":
		err = s.makeFolder(c, dstDir, dstName)
	default:
		_, err = s.copyEntry(c, srcDir, srcName, path.Clean(dstDir), dstName)
	}
	if statusOf(err) == fiber.StatusNotFound {
		// The folder it would go into is missing.
		return fiber.ErrConflict
	}
	if err != nil {
		return err
	}
	if move {
		s.dropLocks(urlPath)
	}
	if replaced {
		return c.SendStatus(fiber.StatusNoContent)
	}
	return c.SendStatus(fiber.StatusCreated)
}

// davDestination returns the clean URL path that the Destination header h
// names under davPrefix. Its host is not checked: behind proxies it may
// differ, and only paths here are served.
func davDestination(h string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(h))
	if err != nil || h == "" {
		return "", false
	}
	return davPath(u.EscapedPath())
}

// propertyupdate is the body of a PROPPATCH request.
type propertyupdate struct {
	XMLName xml.Name    `xml:"DAV: propertyupdate"`
	Set     []propGroup `xml:"DAV: set"`
	Remove  []propGroup `xml:"DAV: remove"`
}

type propGroup struct {
	Prop struct {
		Props []xmlName `xml:",any"`
	} `xml:"DAV: prop"`
}

// mtimeProps name the properties that clients set a file's modification
// time with: WebDAV's own, Windows', and those of other clients.
var mtimeProps = []string{"getlastmodified", "lastmodified", "win32lastmodifiedtime", "modificationdate", "mtime"}

// ignoredProps are properties Windows sets after it writes a file, which
// goftp has no use for but takes, as Windows reports failure otherwise.
var ignoredProps = []string{"win32creationtime", "win32lastaccesstime", "win32fileattributes"}

// davProppatch sets the modification time of the entry at urlPath, as sync
// apps and file managers ask to after uploading; other properties are not
// kept.
func (s *Server) davProppatch(c fiber.Ctx, urlPath string) error {
	data, err := s.davBody(c)
	if err != nil {
		return err
	}
	var req propertyupdate
	if err := xml.Unmarshal(data, &req); err != nil {
		return fiber.ErrBadRequest
	}
	may, isDir, realPath := true, false, ""
	if !appleDouble(path.Base(urlPath)) {
		f, info, real, err := s.lookup(urlPath, s.visitorRules(c))
		if err != nil {
			return err
		}
		_ = f.Close()
		isDir, realPath = info.IsDir(), real
		create, replace, err := s.uploadRightsAt(c, object(urlPath, isDir), object(realPath, isDir))
		if err != nil {
			return err
		}
		may = create || replace
	}
	var ok, forbidden, bad bytes.Buffer
	var mtime time.Time
	for _, set := range req.Set {
		for _, p := range set.Prop.Props {
			name := strings.ToLower(p.XMLName.Local)
			switch {
			case !may:
				emptyElement(&forbidden, p.XMLName)
			case slices.Contains(mtimeProps, name):
				if t, valid := davTime(p.Value); valid {
					mtime = t
					emptyElement(&ok, p.XMLName)
				} else {
					emptyElement(&bad, p.XMLName)
				}
			case slices.Contains(ignoredProps, name):
				emptyElement(&ok, p.XMLName)
			default:
				emptyElement(&forbidden, p.XMLName)
			}
		}
	}
	for _, remove := range req.Remove {
		for _, p := range remove.Prop.Props {
			emptyElement(&forbidden, p.XMLName)
		}
	}
	if !mtime.IsZero() && realPath != "" {
		if err := s.root.Chtimes(rootName(realPath), time.Now(), mtime); err != nil {
			return s.openError(err)
		}
	}
	var b bytes.Buffer
	b.WriteString(xml.Header + `<D:multistatus xmlns:D="DAV:"><D:response><D:href>`)
	xmlText(&b, davHref(urlPath, isDir))
	b.WriteString("</D:href>")
	propstat(&b, ok.String(), "200 OK")
	propstat(&b, forbidden.String(), "403 Forbidden")
	propstat(&b, bad.String(), "409 Conflict")
	b.WriteString("</D:response></D:multistatus>")
	c.Set(fiber.HeaderContentType, "application/xml; charset=utf-8")
	return c.Status(fiber.StatusMultiStatus).Send(b.Bytes())
}

// davTime parses a modification time as clients send it: an HTTP date,
// RFC 3339, or seconds since 1970.
func davTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if t, err := http.ParseTime(v); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, true
	}
	return unixTime(v)
}

// davLock is an advisory WebDAV lock.
type davLock struct {
	token, path, owner string
	exclusive, deep    bool // deep: it covers what is in the folder too
	timeout            time.Duration
	expires            time.Time
}

const (
	maxLockTimeout = time.Hour
	maxLocks       = 10000
)

// lockinfo is the body of a LOCK request.
type lockinfo struct {
	XMLName   xml.Name  `xml:"DAV: lockinfo"`
	Exclusive *struct{} `xml:"DAV: lockscope>exclusive"`
	Owner     struct {
		Href string `xml:"DAV: href"`
		Text string `xml:",chardata"`
	} `xml:"DAV: owner"`
}

func (s *Server) davLock(c fiber.Ctx, urlPath string) error {
	data, err := s.davBody(c)
	if err != nil {
		return err
	}
	timeout := lockTimeout(c.Get("Timeout"))
	now := time.Now()
	s.davMu.Lock()
	defer s.davMu.Unlock()
	for token, l := range s.davLocks {
		if now.After(l.expires) {
			delete(s.davLocks, token)
		}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// A refresh of a lock the client holds.
		l := s.davLocks[ifToken(c.Get("If"))]
		if l == nil || !covers(l, urlPath) {
			return fiber.ErrPreconditionFailed
		}
		l.timeout, l.expires = timeout, now.Add(timeout)
		return s.sendLock(c, fiber.StatusOK, l)
	}
	var req lockinfo
	if err := xml.Unmarshal(data, &req); err != nil {
		return fiber.ErrBadRequest
	}
	create, replace, err := s.uploadRights(c, urlPath)
	if err != nil {
		return err
	}
	if !create && !replace {
		return s.deny(c)
	}
	l := &davLock{path: urlPath, exclusive: req.Exclusive != nil, deep: c.Get("Depth") != "0", timeout: timeout,
		expires: now.Add(timeout), owner: strings.TrimSpace(cmp.Or(req.Owner.Href, req.Owner.Text))}
	for _, other := range s.davLocks {
		if (other.exclusive || l.exclusive) && (covers(other, urlPath) || covers(l, other.path)) {
			return davError(c, fiber.StatusLocked, "no-conflicting-lock")
		}
	}
	if len(s.davLocks) >= maxLocks {
		return fiber.ErrServiceUnavailable
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	h := hex.EncodeToString(b[:])
	l.token = "opaquelocktoken:" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	s.davLocks[l.token] = l
	c.Set("Lock-Token", "<"+l.token+">")
	status := fiber.StatusOK
	if f, _, _, err := s.lookup(urlPath, s.visitorRules(c)); err == nil {
		_ = f.Close()
	} else {
		status = fiber.StatusCreated
	}
	return s.sendLock(c, status, l)
}

// covers reports whether the lock l covers the entry at urlPath.
func covers(l *davLock, urlPath string) bool {
	return l.path == urlPath || l.deep && within(urlPath, l.path)
}

// lockTimeout reads the Timeout header of a LOCK request (e.g.
// "Second-600"), up to maxLockTimeout.
func lockTimeout(h string) time.Duration {
	for v := range strings.SplitSeq(h, ",") {
		if n, ok := strings.CutPrefix(strings.TrimSpace(v), "Second-"); ok {
			if secs, err := strconv.Atoi(n); err == nil && secs > 0 {
				return min(time.Duration(secs)*time.Second, maxLockTimeout)
			}
		}
	}
	return maxLockTimeout
}

// ifToken returns the first lock token of an If header.
func ifToken(h string) string {
	_, rest, ok := strings.Cut(h, "<opaquelocktoken:")
	if !ok {
		return ""
	}
	token, _, _ := strings.Cut(rest, ">")
	return "opaquelocktoken:" + token
}

func (s *Server) sendLock(c fiber.Ctx, status int, l *davLock) error {
	c.Set(fiber.HeaderContentType, "application/xml; charset=utf-8")
	return c.Status(status).SendString(xml.Header + `<D:prop xmlns:D="DAV:"><D:lockdiscovery>` + activeLock(l) +
		"</D:lockdiscovery></D:prop>")
}

func activeLock(l *davLock) string {
	scope, depth := "<D:shared/>", "0"
	if l.exclusive {
		scope = "<D:exclusive/>"
	}
	if l.deep {
		depth = "infinity"
	}
	owner := ""
	if l.owner != "" {
		owner = "<D:owner>" + xmlEscape(l.owner) + "</D:owner>"
	}
	return "<D:activelock><D:locktype><D:write/></D:locktype><D:lockscope>" + scope + "</D:lockscope><D:depth>" + depth +
		"</D:depth>" + owner + "<D:timeout>Second-" + strconv.Itoa(int(l.timeout.Seconds())) + "</D:timeout><D:locktoken><D:href>" +
		l.token + "</D:href></D:locktoken><D:lockroot><D:href>" + xmlEscape(davHref(l.path, false)) + "</D:href></D:lockroot></D:activelock>"
}

// lockDiscovery describes the locks on the entry at urlPath.
func (s *Server) lockDiscovery(urlPath string) string {
	s.davMu.Lock()
	defer s.davMu.Unlock()
	var b strings.Builder
	now := time.Now()
	for _, l := range s.davLocks {
		if l.path == urlPath && now.Before(l.expires) {
			b.WriteString(activeLock(l))
		}
	}
	return b.String()
}

func (s *Server) davUnlock(c fiber.Ctx, urlPath string) error {
	token := strings.Trim(strings.TrimSpace(c.Get("Lock-Token")), "<>")
	s.davMu.Lock()
	defer s.davMu.Unlock()
	l := s.davLocks[token]
	if l == nil || l.path != urlPath {
		return davError(c, fiber.StatusConflict, "lock-token-matches-request-uri")
	}
	delete(s.davLocks, token)
	return c.SendStatus(fiber.StatusNoContent)
}

// dropLocks ends the locks on the entry at urlPath and what is in it, which
// was moved or deleted.
func (s *Server) dropLocks(urlPath string) {
	s.davMu.Lock()
	defer s.davMu.Unlock()
	for token, l := range s.davLocks {
		if within(l.path, urlPath) {
			delete(s.davLocks, token)
		}
	}
}
