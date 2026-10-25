package server

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
	"goftp/internal/config"
)

// davClient sends requests to a fixture's WebDAV, signed in with an app
// password.
type davClient struct {
	f    *fixture
	auth string // the Authorization header
}

func basicAuthHeader(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// davAs returns a client of f's WebDAV that signs in as the user name, with
// a new app password.
func davAs(t *testing.T, f *fixture, name string) *davClient {
	t.Helper()
	u, err := f.auth.svc.UserNamed(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	password, _, err := f.auth.svc.CreateAppPassword(t.Context(), u, "test")
	if err != nil {
		t.Fatal(err)
	}
	return &davClient{f: f, auth: basicAuthHeader(name, password)}
}

// newDavFixture serves a temporary directory with users of its own, who may
// get app passwords, and returns a WebDAV client of the superadmin.
func newDavFixture(t *testing.T, mutate ...func(*config.Config)) (*fixture, *davClient) {
	t.Helper()
	f := newFixtureWith(t, newTestAuth(t), mutate...)
	return f, davAs(t, f, userOfRole("superadmin"))
}

func (d *davClient) do(t *testing.T, method, uri string, headers ...string) (*http.Response, string) {
	t.Helper()
	return d.send(t, method, uri, nil, headers...)
}

func (d *davClient) send(t *testing.T, method, uri string, body io.Reader, headers ...string) (*http.Response, string) {
	t.Helper()
	return d.f.send(t, method, uri, body, append([]string{"Authorization", d.auth}, headers...)...)
}

// davProperties are the properties of an entry that tests look at.
type davProperties struct {
	Collection *struct{} `xml:"resourcetype>collection"`
	Length     string    `xml:"getcontentlength"`
	Modified   string    `xml:"getlastmodified"`
	ETag       string    `xml:"getetag"`
	Name       string    `xml:"displayname"`
	Type       string    `xml:"getcontenttype"`
	Used       string    `xml:"quota-used-bytes"`
	Available  string    `xml:"quota-available-bytes"`
	Locks      []string  `xml:"lockdiscovery>activelock>locktoken>href"`
	Raw        string    `xml:",innerxml"`
}

type multistatus struct {
	Responses []struct {
		Href      string `xml:"DAV: href"`
		Propstats []struct {
			Prop   davProperties `xml:"DAV: prop"`
			Status string        `xml:"DAV: status"`
		} `xml:"DAV: propstat"`
	} `xml:"DAV: response"`
}

// davEntry is what a multistatus says of an entry: its properties by the
// status given for them.
type davEntry map[int]davProperties

// parseMultistatus returns the entries of a multistatus by their decoded
// paths.
func parseMultistatus(t *testing.T, body string) map[string]davEntry {
	t.Helper()
	var ms multistatus
	if err := xml.Unmarshal([]byte(body), &ms); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	entries := map[string]davEntry{}
	for _, r := range ms.Responses {
		p, err := url.PathUnescape(r.Href)
		if err != nil {
			t.Fatal(err)
		}
		e := davEntry{}
		for _, ps := range r.Propstats {
			fields := strings.Fields(ps.Status)
			if len(fields) < 2 {
				t.Fatalf("status %q", ps.Status)
			}
			code, _ := strconv.Atoi(fields[1])
			e[code] = ps.Prop
		}
		entries[p] = e
	}
	return entries
}

func (d *davClient) propfind(t *testing.T, uri, depth, body string) map[string]davEntry {
	t.Helper()
	resp, out := d.send(t, "PROPFIND", uri, strings.NewReader(body), "Depth", depth, "Content-Type", "application/xml")
	expectStatus(t, resp, http.StatusMultiStatus)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("Content-Type %q", ct)
	}
	return parseMultistatus(t, out)
}

func mtimeOf(t *testing.T, p string) time.Time {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime()
}

func TestDavSignIn(t *testing.T) {
	f, _ := newDavFixture(t, func(c *config.Config) { c.Limiter = config.LimiterConfig{MaxFailures: 4, Window: time.Minute} })
	ctx := t.Context()
	svc := f.auth.svc

	// Clients ask what the server can do before they sign in.
	resp, _ := f.as("").do(t, "OPTIONS", "/.dav/")
	expectStatus(t, resp, http.StatusOK)
	if resp.Header.Get("DAV") != "1, 2" || !strings.Contains(resp.Header.Get("Allow"), "PROPFIND") {
		t.Errorf("OPTIONS: %v", resp.Header)
	}

	name := userOfRole("user")
	u, err := svc.UserNamed(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	password, _, err := svc.CreateAppPassword(ctx, u, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	propfind := func(authorization string) (*http.Response, string) {
		t.Helper()
		return f.send(t, "PROPFIND", "/.dav/", nil, "Authorization", authorization, "Depth", "0")
	}
	refused := func(what string, resp *http.Response, body string) {
		t.Helper()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != `Basic realm="goftp", charset="UTF-8"` ||
			!strings.Contains(body, "app password") {
			t.Errorf("%s: %d %v %q", what, resp.StatusCode, resp.Header, body)
		}
	}
	// Only app passwords sign in, not sessions or the account's password.
	for _, h := range []string{"", "Bearer " + f.auth.tokens["user"], "Basic !!!", basicAuthHeader(name, testPassword(name))} {
		resp, body := propfind(h)
		refused(h, resp, body)
	}
	// However they were copied.
	for _, p := range []string{password, strings.ToUpper(password), strings.ReplaceAll(password, "-", "")} {
		resp, _ := propfind(basicAuthHeader(name, p))
		expectStatus(t, resp, http.StatusMultiStatus)
	}
	// Sync apps send many requests at once, which do not count as
	// failures while they run.
	codes := make([]int, 12)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Go(func() {
			req := httptest.NewRequest("PROPFIND", "/.dav/", nil)
			req.Header.Set("Authorization", basicAuthHeader(name, password))
			req.Header.Set("Depth", "0")
			if resp, err := f.srv.App().Test(req, fiber.TestConfig{Timeout: 5 * time.Second}); err == nil {
				codes[i] = resp.StatusCode
				_ = resp.Body.Close()
			}
		})
	}
	wg.Wait()
	if slices.ContainsFunc(codes, func(code int) bool { return code != http.StatusMultiStatus }) {
		t.Errorf("at once: %v", codes)
	}

	// Revoked ones stop working, and so do all once the password changes.
	revoked, ap, err := svc.CreateAppPassword(ctx, u, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeAppPassword(ctx, u, ap.ID); err != nil {
		t.Fatal(err)
	}
	resp, body := propfind(basicAuthHeader(name, revoked))
	refused("revoked", resp, body)
	sess, err := svc.Login(ctx, name, testPassword(name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangePassword(ctx, sess.User, testPassword(name), "another long password"); err != nil {
		t.Fatal(err)
	}
	resp, body = propfind(basicAuthHeader(name, password))
	refused("after a password change", resp, body)
	if n := len(f.logs.entries("app password refused")); n != 3 {
		t.Errorf("%d refusals logged", n)
	}

	// Failures count against the client as wrong passwords do.
	fresh, _, err := svc.CreateAppPassword(ctx, u, "new laptop")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = propfind(basicAuthHeader(name, strings.Repeat("a", 24)))
	expectStatus(t, resp, http.StatusUnauthorized)
	resp, _ = propfind(basicAuthHeader(name, fresh))
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("after 4 failures: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestDavPropfind(t *testing.T) {
	f, dav := newDavFixture(t)
	f.write(t, "docs/a.txt", "hello")
	f.write(t, "docs/.secret", "x")
	f.write(t, "docs/sub/b.txt", "b")
	f.write(t, "docs/naïve.txt", "n")
	mod := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(f.dir, "docs", "a.txt"), mod, mod); err != nil {
		t.Fatal(err)
	}

	got := dav.propfind(t, "/.dav/docs/", "1", "")
	if paths := slices.Sorted(maps.Keys(got)); !slices.Equal(paths, []string{"/.dav/docs/", "/.dav/docs/a.txt", "/.dav/docs/naïve.txt", "/.dav/docs/sub/"}) {
		t.Fatalf("listed %v", paths)
	}
	if a := got["/.dav/docs/a.txt"][200]; a.Collection != nil || a.Length != "5" || a.Modified != "Tue, 14 Nov 2023 22:13:20 GMT" ||
		a.Name != "a.txt" || !strings.HasPrefix(a.Type, "text/plain") || a.ETag != etagOf(mod, 5) {
		t.Errorf("a.txt: %+v", a)
	}
	if sub := got["/.dav/docs/sub/"][200]; sub.Collection == nil || sub.Length != "" || sub.Name != "sub" {
		t.Errorf("sub: %+v", sub)
	}
	if got := dav.propfind(t, "/.dav/docs/", "0", ""); len(got) != 1 || got["/.dav/docs/"][200].Collection == nil {
		t.Errorf("depth 0: %v", got)
	}
	if got := dav.propfind(t, "/.dav", "1", ""); got["/.dav/"][200].Collection == nil || got["/.dav/docs/"][200].Collection == nil {
		t.Errorf("the root: %v", got)
	}
	resp, body := dav.do(t, "PROPFIND", "/.dav/docs/", "Depth", "infinity")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "propfind-finite-depth") {
		t.Errorf("depth infinity: %d %s", resp.StatusCode, body)
	}

	// Properties asked for by name; those it lacks are listed as missing.
	e := dav.propfind(t, "/.dav/docs/a.txt", "0", `<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:" xmlns:x="urn:x"><D:prop><D:getcontentlength/><x:color/></D:prop></D:propfind>`)["/.dav/docs/a.txt"]
	if e[200].Length != "5" || e[200].Modified != "" || !strings.Contains(e[404].Raw, `color xmlns:x="urn:x"`) {
		t.Errorf("by name: %+v", e)
	}
	e = dav.propfind(t, "/.dav/docs/a.txt", "0", `<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`)["/.dav/docs/a.txt"]
	if !strings.Contains(e[200].Raw, "<D:getetag/>") || e[200].Length != "" {
		t.Errorf("propname: %+v", e)
	}
	for uri, want := range map[string]int{"/.dav/docs/none.txt": 404, "/.dav/docs/.secret": 404} {
		if resp, _ := dav.do(t, "PROPFIND", uri, "Depth", "0"); resp.StatusCode != want {
			t.Errorf("%s: %d", uri, resp.StatusCode)
		}
	}
	if resp, _ := dav.send(t, "PROPFIND", "/.dav/docs/", strings.NewReader("<propfind"), "Depth", "0"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad XML: %d", resp.StatusCode)
	}

	// What rules close is not there.
	if _, err := f.auth.svc.AddPolicy("user", "!/docs/sub/*", "*"); err != nil {
		t.Fatal(err)
	}
	user := davAs(t, f, userOfRole("user"))
	if got := user.propfind(t, "/.dav/docs/", "1", ""); len(got) != 3 || got["/.dav/docs/sub/"] != nil {
		t.Errorf("listed for a user: %v", slices.Sorted(maps.Keys(got)))
	}
	if resp, _ := user.do(t, "PROPFIND", "/.dav/docs/sub/", "Depth", "0"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a closed folder: %d", resp.StatusCode)
	}
}

func TestDavPut(t *testing.T) {
	f, dav := newDavFixture(t)
	f.write(t, "docs/a.txt", "hello")
	docs := filepath.Join(f.dir, "docs")

	// Uploads keep the modification time rclone and ownCloud's clients
	// send.
	resp, _ := dav.send(t, "PUT", "/.dav/docs/new.txt", strings.NewReader("new"), "X-OC-Mtime", "1700000000")
	expectStatus(t, resp, http.StatusCreated)
	if resp.Header.Get("X-OC-Mtime") != "accepted" || resp.Header.Get("ETag") == "" {
		t.Errorf("headers: %v", resp.Header)
	}
	if got := mtimeOf(t, filepath.Join(docs, "new.txt")); !got.Equal(time.Unix(1700000000, 0)) || readFile(t, f.dir, "docs/new.txt") != "new" {
		t.Errorf("kept %v", got)
	}
	if e := dav.propfind(t, "/.dav/docs/new.txt", "0", "")["/.dav/docs/new.txt"][200]; e.Modified != "Tue, 14 Nov 2023 22:13:20 GMT" ||
		e.ETag != resp.Header.Get("ETag") {
		t.Errorf("listed as %+v, ETag %s", e, resp.Header.Get("ETag"))
	}
	resp, _ = dav.send(t, "PUT", "/.dav/docs/new.txt", strings.NewReader("newer"), "X-OC-Mtime", "1600000000.5")
	expectStatus(t, resp, http.StatusNoContent)
	if got := mtimeOf(t, filepath.Join(docs, "new.txt")); !got.Equal(time.Unix(1600000000, 5e8)) || readFile(t, f.dir, "docs/new.txt") != "newer" {
		t.Errorf("replaced: %v", got)
	}
	resp, _ = dav.send(t, "PUT", "/.dav/docs/now.txt", strings.NewReader("now"))
	expectStatus(t, resp, http.StatusCreated)
	if got := mtimeOf(t, filepath.Join(docs, "now.txt")); time.Since(got) > time.Minute || resp.Header.Get("X-OC-Mtime") != "" {
		t.Errorf("without a time: %v", got)
	}

	// Finder sends files in chunks, saying how long they are.
	addr, _ := startServer(t, f)
	chunked := func(name, content, length string) (*http.Response, string) {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if length != "" {
			length = "X-Expected-Entity-Length: " + length + "\r\n"
		}
		fmt.Fprintf(conn, "PUT /.dav/docs/%s HTTP/1.1\r\nHost: t\r\nAuthorization: %s\r\n%sTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n",
			name, dav.auth, length, len(content), content)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}
	resp, _ = chunked("finder.txt", "chunked", "7")
	expectStatus(t, resp, http.StatusCreated)
	if got := readFile(t, f.dir, "docs/finder.txt"); got != "chunked" {
		t.Errorf("chunked: %q", got)
	}
	if resp, _ := chunked("unknown.txt", "x", ""); resp.StatusCode != http.StatusLengthRequired {
		t.Errorf("without a length: %d", resp.StatusCode)
	}
	resp, body := chunked("short.txt", "short", "10")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not as long") {
		t.Errorf("shorter than said: %d %s", resp.StatusCode, body)
	}
	if exists(filepath.Join(docs, "short.txt")) || len(leftovers(f.dir)) != 0 {
		t.Errorf("left behind: %v", leftovers(f.dir))
	}

	resp, body = dav.send(t, "PUT", "/.dav/docs/new.txt", strings.NewReader("ab"), "Content-Range", "bytes 0-1/5")
	if resp.StatusCode != http.StatusBadRequest || readFile(t, f.dir, "docs/new.txt") != "newer" {
		t.Errorf("a part: %d %s", resp.StatusCode, body)
	}

	for uri, want := range map[string]int{
		"/.dav/none/x.txt": http.StatusConflict,  // the folder is missing
		"/.dav/docs/.env":  http.StatusForbidden, // goftp hides names that start with a dot
		"/.dav/":           http.StatusMethodNotAllowed,
	} {
		if resp, _ := dav.send(t, "PUT", uri, strings.NewReader("x")); resp.StatusCode != want {
			t.Errorf("PUT %s: %d, want %d", uri, resp.StatusCode, want)
		}
	}
	// macOS's files beside files are taken and dropped.
	for _, name := range []string{"._a.txt", ".DS_Store"} {
		resp, _ := dav.send(t, "PUT", "/.dav/docs/"+name, strings.NewReader("mac"))
		expectStatus(t, resp, http.StatusCreated)
		if exists(filepath.Join(docs, name)) {
			t.Errorf("%s was kept", name)
		}
	}
	resp, body = dav.send(t, "PROPPATCH", "/.dav/docs/._a.txt", strings.NewReader(`<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>`+
		`<D:getlastmodified>Wed, 01 Jan 2020 00:00:00 GMT</D:getlastmodified></D:prop></D:set></D:propertyupdate>`))
	expectStatus(t, resp, http.StatusMultiStatus)
	if resp, _ := dav.do(t, "DELETE", "/.dav/docs/._a.txt"); resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE ._a.txt: %d", resp.StatusCode)
	}

	// Users upload where they may.
	user := davAs(t, f, userOfRole("user"))
	if resp, _ := user.send(t, "PUT", "/.dav/docs/mine.txt", strings.NewReader("x")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a reader's PUT: %d", resp.StatusCode)
	}
	if exists(filepath.Join(docs, "mine.txt")) {
		t.Error("uploaded anyway")
	}
}

func TestDavGet(t *testing.T) {
	f, dav := newDavFixture(t)
	f.write(t, "docs/a.txt", "hello")

	resp, body := dav.do(t, "GET", "/.dav/docs/a.txt")
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Errorf("GET: %d %q", resp.StatusCode, body)
	}
	resp, body = dav.do(t, "GET", "/.dav/docs/a.txt", "Range", "bytes=1-2")
	if resp.StatusCode != http.StatusPartialContent || body != "el" {
		t.Errorf("a range: %d %q", resp.StatusCode, body)
	}
	resp, body = dav.do(t, "HEAD", "/.dav/docs/a.txt")
	if resp.StatusCode != http.StatusOK || body != "" || resp.Header.Get("Content-Length") != "5" {
		t.Errorf("HEAD: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	// Folders are for browsers to show.
	resp, _ = dav.do(t, "GET", "/.dav/docs/")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/docs/" {
		t.Errorf("a folder: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := dav.do(t, "GET", "/.dav/docs/none.txt"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing: %d", resp.StatusCode)
	}
}

func TestDavMkcol(t *testing.T) {
	f, dav := newDavFixture(t)
	f.write(t, "docs/a.txt", "a")

	resp, _ := dav.do(t, "MKCOL", "/.dav/docs/new")
	expectStatus(t, resp, http.StatusCreated)
	if info, err := os.Stat(filepath.Join(f.dir, "docs", "new")); err != nil || !info.IsDir() {
		t.Errorf("made %v, %v", info, err)
	}
	for uri, want := range map[string]int{
		"/.dav/docs/new":   http.StatusMethodNotAllowed, // there already
		"/.dav/docs/a.txt": http.StatusMethodNotAllowed,
		"/.dav/none/new":   http.StatusConflict, // the folder is missing
		"/.dav/":           http.StatusMethodNotAllowed,
	} {
		if resp, _ := dav.do(t, "MKCOL", uri); resp.StatusCode != want {
			t.Errorf("MKCOL %s: %d, want %d", uri, resp.StatusCode, want)
		}
	}
	if resp, _ := dav.send(t, "MKCOL", "/.dav/docs/x", strings.NewReader("<x/>")); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("with a body: %d", resp.StatusCode)
	}
	if resp, _ := dav.do(t, "MKCOL", "/.dav/docs/.git"); resp.StatusCode < 400 || exists(filepath.Join(f.dir, "docs", ".git")) {
		t.Errorf("a hidden name: %d", resp.StatusCode)
	}
	user := davAs(t, f, userOfRole("user"))
	if resp, _ := user.do(t, "MKCOL", "/.dav/docs/mine"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a reader's MKCOL: %d", resp.StatusCode)
	}
}

func TestDavCopyMove(t *testing.T) {
	f, dav := newDavFixture(t, withTrash)
	f.write(t, "docs/a.txt", "a")
	f.write(t, "docs/b.txt", "b")
	f.write(t, "docs/sub/c.txt", "c")
	docs := filepath.Join(f.dir, "docs")

	// Destinations are URLs; their host is not looked at.
	resp, _ := dav.do(t, "MOVE", "/.dav/docs/a.txt", "Destination", "https://elsewhere.example/.dav/docs/moved.txt")
	expectStatus(t, resp, http.StatusCreated)
	if exists(filepath.Join(docs, "a.txt")) || readFile(t, f.dir, "docs/moved.txt") != "a" {
		t.Error("not moved")
	}
	// What is there is kept with "Overwrite: F", and otherwise replaced,
	// into the trash.
	resp, _ = dav.do(t, "COPY", "/.dav/docs/b.txt", "Destination", "/.dav/docs/moved.txt", "Overwrite", "F")
	expectStatus(t, resp, http.StatusPreconditionFailed)
	if readFile(t, f.dir, "docs/moved.txt") != "a" || len(trashedOnDisk(t, f)) != 0 {
		t.Error("replaced anyway")
	}
	resp, _ = dav.do(t, "COPY", "/.dav/docs/b.txt", "Destination", "/.dav/docs/moved.txt")
	expectStatus(t, resp, http.StatusNoContent)
	if readFile(t, f.dir, "docs/moved.txt") != "b" || readFile(t, f.dir, "docs/b.txt") != "b" || len(trashedOnDisk(t, f)) == 0 {
		t.Error("not replaced")
	}
	trashed := len(trashedOnDisk(t, f))

	// Folders, with what they hold, or alone with "Depth: 0".
	resp, _ = dav.do(t, "COPY", "/.dav/docs/sub/", "Destination", "/.dav/docs/sub2/")
	expectStatus(t, resp, http.StatusCreated)
	resp, _ = dav.do(t, "COPY", "/.dav/docs/sub/", "Destination", "/.dav/docs/empty/", "Depth", "0")
	expectStatus(t, resp, http.StatusCreated)
	if readFile(t, f.dir, "docs/sub2/c.txt") != "c" || !exists(filepath.Join(docs, "empty")) || exists(filepath.Join(docs, "empty", "c.txt")) {
		t.Error("folders not copied")
	}
	resp, _ = dav.do(t, "MOVE", "/.dav/docs/sub2/", "Destination", "/.dav/sub3/")
	expectStatus(t, resp, http.StatusCreated)
	if readFile(t, f.dir, "sub3/c.txt") != "c" || exists(filepath.Join(docs, "sub2")) {
		t.Error("folder not moved")
	}
	resp, _ = dav.do(t, "MOVE", "/.dav/docs/b.txt", "Destination", "/.dav/docs/na%C3%AFve%20b.txt")
	expectStatus(t, resp, http.StatusCreated)
	if readFile(t, f.dir, "docs/naïve b.txt") != "b" {
		t.Error("not moved to an escaped name")
	}

	for _, tc := range []struct {
		method, uri, dest string
		want              int
	}{
		{"MOVE", "/.dav/docs/", "/.dav/docs/sub/in/", http.StatusConflict},     // into itself
		{"MOVE", "/.dav/docs/sub/c.txt", "/.dav/docs/", http.StatusConflict},   // over what holds it
		{"COPY", "/.dav/docs/sub/c.txt", "/.dav/docs", http.StatusConflict},    // the same
		{"MOVE", "/.dav/docs/moved.txt", "", http.StatusBadRequest},            // nowhere
		{"MOVE", "/.dav/docs/moved.txt", "/docs/x.txt", http.StatusBadRequest}, // not WebDAV
		{"MOVE", "/.dav/docs/moved.txt", "/.dav/none/x.txt", http.StatusConflict},
		{"MOVE", "/.dav/docs/moved.txt", "/.dav/docs/.x", http.StatusForbidden},
		{"MOVE", "/.dav/docs/moved.txt", "/.dav/docs/moved.txt", http.StatusForbidden},
		{"MOVE", "/.dav/docs/none.txt", "/.dav/docs/x.txt", http.StatusNotFound},
	} {
		resp, body := dav.do(t, tc.method, tc.uri, "Destination", tc.dest)
		if resp.StatusCode != tc.want {
			t.Errorf("%s %s to %q: %d, want %d: %s", tc.method, tc.uri, tc.dest, resp.StatusCode, tc.want, body)
		}
	}
	if !exists(filepath.Join(docs, "sub", "c.txt")) || len(trashedOnDisk(t, f)) != trashed {
		t.Error("refused, but changed")
	}

	// Users may not replace what they could not move.
	user := davAs(t, f, userOfRole("user"))
	resp, _ = user.do(t, "MOVE", "/.dav/docs/moved.txt", "Destination", "/.dav/docs/sub/c.txt")
	expectStatus(t, resp, http.StatusForbidden)
	if !exists(filepath.Join(docs, "moved.txt")) || !exists(filepath.Join(docs, "sub", "c.txt")) || len(trashedOnDisk(t, f)) != trashed {
		t.Error("a reader moved")
	}
}

func TestDavDelete(t *testing.T) {
	f, dav := newDavFixture(t, withTrash)
	f.write(t, "docs/a.txt", "a")
	f.write(t, "docs/sub/b.txt", "b")

	resp, _ := dav.do(t, "DELETE", "/.dav/docs/a.txt")
	expectStatus(t, resp, http.StatusNoContent)
	if exists(filepath.Join(f.dir, "docs", "a.txt")) || len(trashedOnDisk(t, f)) == 0 {
		t.Error("not deleted into the trash")
	}
	user := davAs(t, f, userOfRole("user"))
	for _, tc := range []struct {
		dav  *davClient
		uri  string
		want int
	}{
		{dav, "/.dav/docs/a.txt", http.StatusNotFound},
		{dav, "/.dav/", http.StatusForbidden},
		{user, "/.dav/docs/sub/", http.StatusForbidden},
		{dav, "/.dav/docs/sub/", http.StatusNoContent},
	} {
		if resp, _ := tc.dav.do(t, "DELETE", tc.uri); resp.StatusCode != tc.want {
			t.Errorf("DELETE %s: %d, want %d", tc.uri, resp.StatusCode, tc.want)
		}
	}
	if exists(filepath.Join(f.dir, "docs", "sub")) {
		t.Error("folder not deleted")
	}
}

func TestDavProppatch(t *testing.T) {
	f, dav := newDavFixture(t)
	f.write(t, "docs/a.txt", "a")
	file := filepath.Join(f.dir, "docs", "a.txt")
	proppatch := func(d *davClient, props string) davEntry {
		t.Helper()
		resp, body := d.send(t, "PROPPATCH", "/.dav/docs/a.txt", strings.NewReader(`<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop>`+props+`</D:prop></D:set></D:propertyupdate>`),
			"Content-Type", "application/xml")
		expectStatus(t, resp, http.StatusMultiStatus)
		return parseMultistatus(t, body)["/.dav/docs/a.txt"]
	}

	// As Windows sets it after uploading: what goftp has no use for is
	// taken anyway, what it cannot keep refused.
	e := proppatch(dav, `<Z:Win32CreationTime>Wed, 01 Jan 2020 00:00:00 GMT</Z:Win32CreationTime>
<Z:Win32LastModifiedTime>Wed, 01 Jan 2020 00:00:00 GMT</Z:Win32LastModifiedTime>
<Z:Win32FileAttributes>00000020</Z:Win32FileAttributes><D:color>red</D:color>`)
	if !strings.Contains(e[200].Raw, "Win32LastModifiedTime") || !strings.Contains(e[200].Raw, "Win32FileAttributes") ||
		!strings.Contains(e[403].Raw, "color") || strings.Contains(e[200].Raw, "color") {
		t.Errorf("Windows: %+v", e)
	}
	if got := mtimeOf(t, file); !got.Equal(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("kept %v", got)
	}
	e = proppatch(dav, `<D:getlastmodified>2021-02-03T04:05:06Z</D:getlastmodified>`)
	if got := mtimeOf(t, file); !got.Equal(time.Date(2021, 2, 3, 4, 5, 6, 0, time.UTC)) || len(e) != 1 {
		t.Errorf("RFC 3339: %v, %+v", got, e)
	}
	e = proppatch(dav, `<D:getlastmodified>yesterday</D:getlastmodified>`)
	if !strings.Contains(e[409].Raw, "getlastmodified") || !mtimeOf(t, file).Equal(time.Date(2021, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Errorf("not a time: %+v", e)
	}
	// Only by those who may change the file.
	e = proppatch(davAs(t, f, userOfRole("user")), `<D:getlastmodified>Wed, 01 Jan 2020 00:00:00 GMT</D:getlastmodified>`)
	if !strings.Contains(e[403].Raw, "getlastmodified") || !mtimeOf(t, file).Equal(time.Date(2021, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Errorf("by a reader: %+v", e)
	}
	if resp, _ := dav.send(t, "PROPPATCH", "/.dav/docs/a.txt", strings.NewReader("<x")); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad XML: %d", resp.StatusCode)
	}
}

func TestDavLocks(t *testing.T) {
	f, dav := newDavFixture(t)
	f.write(t, "docs/a.txt", "a")
	lock := func(d *davClient, uri, scope, depth string) (*http.Response, string) {
		t.Helper()
		return d.send(t, "LOCK", uri, strings.NewReader(`<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:`+scope+
			`/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>mailto:me@example.com</D:href></D:owner></D:lockinfo>`),
			"Timeout", "Second-600", "Depth", depth)
	}

	resp, body := lock(dav, "/.dav/docs/a.txt", "exclusive", "0")
	expectStatus(t, resp, http.StatusOK)
	token := strings.Trim(resp.Header.Get("Lock-Token"), "<>")
	if !strings.HasPrefix(token, "opaquelocktoken:") || !strings.Contains(body, token) || !strings.Contains(body, "Second-600") ||
		!strings.Contains(body, "mailto:me@example.com") {
		t.Errorf("locked: %s %s", token, body)
	}
	for _, tc := range []struct{ uri, scope, depth string }{
		{"/.dav/docs/a.txt", "exclusive", "0"},
		{"/.dav/docs/a.txt", "shared", "0"},
		{"/.dav/docs/", "exclusive", "infinity"}, // the folder, with the file in it
	} {
		if resp, body := lock(dav, tc.uri, tc.scope, tc.depth); resp.StatusCode != http.StatusLocked || !strings.Contains(body, "no-conflicting-lock") {
			t.Errorf("%s lock of %s: %d %s", tc.scope, tc.uri, resp.StatusCode, body)
		}
	}
	e := dav.propfind(t, "/.dav/docs/a.txt", "0", `<D:propfind xmlns:D="DAV:"><D:prop><D:lockdiscovery/></D:prop></D:propfind>`)
	if locks := e["/.dav/docs/a.txt"][200].Locks; !slices.Equal(locks, []string{token}) {
		t.Errorf("lockdiscovery: %v", locks)
	}

	// Refreshed by its token.
	resp, _ = dav.do(t, "LOCK", "/.dav/docs/a.txt", "If", "(<"+token+">)", "Timeout", "Second-60")
	expectStatus(t, resp, http.StatusOK)
	if resp, _ := dav.do(t, "LOCK", "/.dav/docs/a.txt", "If", "(<opaquelocktoken:nope>)"); resp.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("refreshed with another token: %d", resp.StatusCode)
	}
	// Ended by it.
	if resp, _ := dav.do(t, "UNLOCK", "/.dav/docs/a.txt", "Lock-Token", "<opaquelocktoken:nope>"); resp.StatusCode != http.StatusConflict {
		t.Errorf("unlocked with another token: %d", resp.StatusCode)
	}
	resp, _ = dav.do(t, "UNLOCK", "/.dav/docs/a.txt", "Lock-Token", "<"+token+">")
	expectStatus(t, resp, http.StatusNoContent)
	resp, _ = lock(dav, "/.dav/docs/a.txt", "shared", "0")
	expectStatus(t, resp, http.StatusOK)
	// Deleting the file ends its locks.
	resp, _ = dav.do(t, "DELETE", "/.dav/docs/a.txt")
	expectStatus(t, resp, http.StatusNoContent)
	if resp, _ := lock(dav, "/.dav/docs/a.txt", "exclusive", "0"); resp.StatusCode != http.StatusCreated {
		t.Errorf("a new name: %d", resp.StatusCode)
	}
	if resp, _ := lock(davAs(t, f, userOfRole("user")), "/.dav/docs/b.txt", "exclusive", "0"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("by a reader: %d", resp.StatusCode)
	}
}

// WebDAV keeps homes as private, and as full, as the site does.
func TestDavHomes(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes, func(cfg *config.Config) { cfg.Homes.Quota = 10 })
	ta.addUser(t, "dora", "user")
	ta.addUser(t, "erin", "user")
	dora, erin := davAs(t, f, "dora"), davAs(t, f, "erin")

	resp, _ := erin.send(t, "PUT", "/.dav/home/erin/e.txt", strings.NewReader("e"))
	expectStatus(t, resp, http.StatusCreated)
	if got := dora.propfind(t, "/.dav/", "1", ""); got["/.dav/home/"][200].Collection == nil {
		t.Errorf("the root: %v", slices.Sorted(maps.Keys(got)))
	}
	if got := dora.propfind(t, "/.dav/home/", "1", ""); !slices.Equal(slices.Sorted(maps.Keys(got)), []string{"/.dav/home/", "/.dav/home/dora/"}) {
		t.Errorf("homes: %v", slices.Sorted(maps.Keys(got)))
	}
	for _, tc := range []struct {
		method, uri string
		body        io.Reader
	}{
		{"PROPFIND", "/.dav/home/erin/", nil},
		{"GET", "/.dav/home/erin/e.txt", nil},
		{"PUT", "/.dav/home/erin/x.txt", strings.NewReader("x")},
		{"DELETE", "/.dav/home/erin/e.txt", nil},
	} {
		if resp, _ := dora.send(t, tc.method, tc.uri, tc.body, "Depth", "0"); resp.StatusCode != http.StatusForbidden &&
			resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: %d", tc.method, tc.uri, resp.StatusCode)
		}
	}
	if readFile(t, f.dir, "home/erin/e.txt") != "e" || exists(filepath.Join(f.dir, "home", "erin", "x.txt")) {
		t.Error("into someone else's home")
	}

	quota := func() davProperties {
		t.Helper()
		return dora.propfind(t, "/.dav/home/dora/", "0", `<D:propfind xmlns:D="DAV:"><D:prop><D:quota-used-bytes/><D:quota-available-bytes/></D:prop></D:propfind>`)["/.dav/home/dora/"][200]
	}
	if q := quota(); q.Used != "0" || q.Available != "10" {
		t.Errorf("quota of an empty home: %+v", q)
	}
	resp, _ = dora.send(t, "PUT", "/.dav/home/dora/a.txt", strings.NewReader("123456"))
	expectStatus(t, resp, http.StatusCreated)
	resp, _ = dora.send(t, "PUT", "/.dav/home/dora/b.txt", strings.NewReader("12345"))
	expectStatus(t, resp, http.StatusInsufficientStorage)
	if q := quota(); q.Used != "6" || q.Available != "4" {
		t.Errorf("quota: %+v", q)
	}
}

func TestSyncPage(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	user, name := f.as("user"), userOfRole("user")
	html := []string{"Accept", "text/html"}
	syncForm := func(form string, headers ...string) (*http.Response, string) {
		t.Helper()
		return post(t, user, "/.sync/", form, headers...)
	}

	resp, _ := f.as("").do(t, "GET", "/.sync/", html...)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), loginPath) {
		t.Errorf("anonymous: %d %v", resp.StatusCode, resp.Header)
	}
	if _, body := user.do(t, "GET", "/", html...); !strings.Contains(body, `<a href="/.sync/"><svg class="i" aria-hidden="true"><use href="#i-sync"/></svg>Sync</a>`) {
		t.Errorf("menu: %s", body)
	}
	resp, body := user.do(t, "GET", "/.sync/", html...)
	expectStatus(t, resp, http.StatusOK)
	home := "http://example.com/.dav/home/" + name + "/"
	for _, want := range []string{
		`<code id="dav-url">` + home + `</code>`,
		"The rest of the site is at http://example.com/.dav/",
		"rclone config create goftp webdav url=" + home + " vendor=owncloud user=" + name + " pass=APP-PASSWORD --obscure",
		"<code>dav://example.com/.dav/home/" + name + "/</code>",
		"You have no app passwords",
		"not served over HTTPS",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("no %q in %s", want, body)
		}
	}

	// A new app password is shown once, and signs in to WebDAV.
	resp, body = syncForm("action=create&name=laptop", html...)
	expectStatus(t, resp, http.StatusCreated)
	m := regexp.MustCompile(`<code id="app-password">([a-z2-7]{4}(?:-[a-z2-7]{4}){5})</code>`).FindStringSubmatch(body)
	if m == nil || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(body, "<strong>laptop</strong>") {
		t.Fatalf("created: %v %s", resp.Header, body)
	}
	resp, _ = f.send(t, "PROPFIND", "/.dav/", nil, "Authorization", basicAuthHeader(name, m[1]), "Depth", "0")
	expectStatus(t, resp, http.StatusMultiStatus)
	_, body = user.do(t, "GET", "/.sync/", html...)
	if !strings.Contains(body, "<span>laptop</span>") || strings.Contains(body, m[1]) || strings.Contains(body, `"faint">never`) {
		t.Errorf("listed: %s", body)
	}

	// Scripts get JSON.
	resp, body = syncForm("action=create&name=phone")
	expectStatus(t, resp, http.StatusCreated)
	var created struct {
		ID                            int64
		Name, Username, Password, URL string
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.Name != "phone" || created.Username != name ||
		created.URL != "http://example.com/.dav/" || len(created.Password) != 29 {
		t.Errorf("JSON: %v %s", err, body)
	}
	if _, body := user.do(t, "GET", "/.sync/", html...); !strings.Contains(body, "<span>phone</span>") || !strings.Contains(body, `"faint">never`) {
		t.Errorf("listed: %s", body)
	}

	for _, tc := range []struct {
		form    string
		headers []string
		want    int
		says    string
	}{
		{"action=create&name=", html, http.StatusBadRequest, "Name the app password"},
		{"action=create&name=", nil, http.StatusBadRequest, "Name the app password"},
		{"action=revoke&id=99999", html, http.StatusNotFound, "no such app password"},
		{"action=revoke&id=x", nil, http.StatusBadRequest, ""},
		{"action=dance", nil, http.StatusBadRequest, ""},
	} {
		if resp, body := syncForm(tc.form, tc.headers...); resp.StatusCode != tc.want || !strings.Contains(body, tc.says) {
			t.Errorf("%s: %d %s", tc.form, resp.StatusCode, body)
		}
	}

	// Revoked, it stops working.
	resp, _ = syncForm("action=revoke&id="+strconv.FormatInt(created.ID, 10), html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/.sync/?done=revoked" {
		t.Errorf("revoked: %d %v", resp.StatusCode, resp.Header)
	}
	if _, body := user.do(t, "GET", "/.sync/?done=revoked", html...); !strings.Contains(body, "The app password was revoked") ||
		strings.Contains(body, "<span>phone</span>") {
		t.Errorf("after revoking: %s", body)
	}
	resp, _ = f.send(t, "PROPFIND", "/.dav/", nil, "Authorization", basicAuthHeader(name, created.Password), "Depth", "0")
	expectStatus(t, resp, http.StatusUnauthorized)

	// A user has only so many.
	for i := 1; i < auth.MaxAppPasswords; i++ {
		resp, _ := syncForm("action=create&name=app")
		expectStatus(t, resp, http.StatusCreated)
	}
	if resp, body := syncForm("action=create&name=app", html...); resp.StatusCode != http.StatusConflict || !strings.Contains(body, "revoke one") {
		t.Errorf("too many: %d %s", resp.StatusCode, body)
	}

	// Without a home, apps sync the site.
	g := newFixtureWith(t, ta)
	if _, body := g.as("user").do(t, "GET", "/.sync/", html...); !strings.Contains(body, `<code id="dav-url">http://example.com/.dav/</code>`) ||
		strings.Contains(body, "The rest of the site") {
		t.Errorf("without homes: %s", body)
	}
}
