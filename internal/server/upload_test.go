package server

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
	"goftp/internal/config"
)

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// leftovers lists lock and temp files under dir.
func leftovers(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && (strings.HasSuffix(d.Name(), lockSuffix) || strings.HasPrefix(d.Name(), tempPrefix)) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

type formPart struct{ field, filename, content string }

func multipartForm(t *testing.T, parts ...formPart) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		var (
			pw  io.Writer
			err error
		)
		if p.filename != "" {
			pw, err = w.CreateFormFile(p.field, p.filename)
		} else {
			pw, err = w.CreateFormField(p.field)
		}
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(pw, p.content)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

// Uploading takes write permission; replacing a file takes overwrite.
func TestUploadRoles(t *testing.T) {
	f := newFixture(t)
	f.write(t, "old.txt", "old")

	cases := []struct {
		role, target, ifNoneMatch string
		want                      int
	}{
		{"", "/new.txt", "", 401},
		{"user", "/new.txt", "", 403},
		{"operator", "/old.txt", "", 403},
		{"operator", "/old.txt", "*", 412},
		{"operator", "/new.txt", "", 201},
		{"admin", "/old.txt", "", 204},
		{"superadmin", "/old.txt", "", 204},
	}
	for _, tc := range cases {
		headers := []string{}
		if tc.ifNoneMatch != "" {
			headers = append(headers, "If-None-Match", tc.ifNoneMatch)
		}
		resp, _ := f.as(tc.role).send(t, "PUT", tc.target, strings.NewReader(tc.role), headers...)
		if resp.StatusCode != tc.want {
			t.Errorf("%q PUT %s: status %d, want %d", tc.role, tc.target, resp.StatusCode, tc.want)
		}
		if tc.want == 401 && resp.Header.Get("WWW-Authenticate") != `Bearer realm="goftp"` {
			t.Errorf("401 without challenge: %q", resp.Header.Get("WWW-Authenticate"))
		}
	}
	if got := readFile(t, f.dir, "old.txt"); got != "superadmin" {
		t.Errorf("old.txt = %q", got)
	}
	if got := readFile(t, f.dir, "new.txt"); got != "operator" {
		t.Errorf("new.txt = %q", got)
	}

	// The form offers what the visitor may do.
	for role, want := range map[string][]string{
		"user":     {},
		"operator": {`name="file"`},
		"admin":    {`name="file"`, `name="replace"`},
	} {
		_, body := f.as(role).do(t, "GET", "/")
		for _, field := range []string{`name="file"`, `name="replace"`} {
			if strings.Contains(body, field) != slices.Contains(want, field) {
				t.Errorf("%s: form field %s shown: %v", role, field, strings.Contains(body, field))
			}
		}
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}
}

func TestPutUpload(t *testing.T) {
	f := newFixture(t)
	f.write(t, "sub/keep.txt", "k")

	resp, _ := f.send(t, "PUT", "/sub/new.txt", strings.NewReader("first"))
	expectStatus(t, resp, http.StatusCreated)
	resp, _ = f.as("admin").send(t, "PUT", "/sub/new.txt", strings.NewReader("second"))
	expectStatus(t, resp, http.StatusNoContent)
	resp, _ = f.send(t, "PUT", "/sub/new.txt", strings.NewReader("third"), "If-None-Match", "*")
	expectStatus(t, resp, http.StatusPreconditionFailed)
	if got := readFile(t, f.dir, "sub/new.txt"); got != "second" {
		t.Errorf("content %q", got)
	}
	if _, body := f.do(t, "GET", "/sub/"); !strings.Contains(body, `href="/sub/new.txt"`) {
		t.Error("uploaded file not listed")
	}
	if resp, body := f.do(t, "GET", "/sub/new.txt"); resp.StatusCode != 200 || body != "second" {
		t.Errorf("download: %d %q", resp.StatusCode, body)
	}

	tests := map[string]int{
		"/nope/x.txt":         409,
		"/sub/keep.txt/x":     409,
		"/sub":                409,
		"/sub/":               400,
		"/":                   400,
		"/.env":               403,
		"/sub/.hidden":        403,
		"/sub/..%2f.x":        403,
		"/sub/a%0Ab.txt":      400,
		"/sub/%FF.txt":        400,
		"/sub/%2e%2e%2fx.txt": 201, // cleans to /x.txt
	}
	for target, want := range tests {
		if resp, _ := f.send(t, "PUT", target, strings.NewReader("x")); resp.StatusCode != want {
			t.Errorf("PUT %s: status %d, want %d", target, resp.StatusCode, want)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "sub", "x.txt")); err == nil {
		t.Error("rejected upload created a file")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}

	resp, _ = f.do(t, "PATCH", "/sub/new.txt")
	expectStatus(t, resp, 405)
	if got := resp.Header.Get("Allow"); got != allowedMethods {
		t.Errorf("Allow %q", got)
	}
}

func TestUploadMaxSize(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Upload.MaxSize = 10 })
	resp, _ := f.send(t, "PUT", "/big.txt", strings.NewReader(strings.Repeat("x", 11)))
	expectStatus(t, resp, http.StatusRequestEntityTooLarge)
	if !resp.Close {
		t.Error("connection kept open with an unread body")
	}
	resp, _ = f.send(t, "PUT", "/ok.txt", strings.NewReader(strings.Repeat("x", 10)))
	expectStatus(t, resp, http.StatusCreated)
	if _, err := os.Stat(filepath.Join(f.dir, "big.txt")); err == nil {
		t.Error("oversized upload stored")
	}
}

func TestFormUpload(t *testing.T) {
	f := newFixture(t)
	f.write(t, "sub/keep.txt", "k")

	resp, body := f.do(t, "GET", "/sub/")
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.HasSuffix(csp, "form-action 'self'") {
		t.Errorf("CSP %q", csp)
	}
	// Folders can be uploaded too, as the page's script creates them.
	for _, want := range []string{`<form id="upload" class="upload" method="post" enctype="multipart/form-data" action="/sub/" data-folders="true">`,
		`name="replace"`, `name="file"`, `Drop files or folders here`, `class="folder-picker" webkitdirectory`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}

	form, ctype := multipartForm(t,
		formPart{field: "file", filename: "a.txt", content: "alpha"},
		formPart{field: "file", filename: "../../b.txt", content: "beta"},
	)
	resp, _ = f.send(t, "POST", "/sub", form, "Content-Type", ctype, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/sub/?uploaded=2" {
		t.Errorf("Location %q", got)
	}
	// Scripts get a status instead of a page.
	form, ctype = multipartForm(t, formPart{field: "file", filename: "s.txt", content: "s"})
	resp, _ = f.send(t, "POST", "/sub/", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusCreated)
	if readFile(t, f.dir, "sub/a.txt") != "alpha" || readFile(t, f.dir, "sub/b.txt") != "beta" {
		t.Error("uploaded files have the wrong content")
	}

	file := formPart{field: "file", filename: "c.txt", content: "gamma"}
	cases := []struct {
		name   string
		role   string
		target string
		parts  []formPart
		want   int
	}{
		{"anonymous", "", "/sub/", []formPart{file}, 401},
		{"user", "user", "/sub/", []formPart{file}, 403},
		{"operator replacing", "operator", "/sub/", []formPart{{field: "replace", content: "1"}, {field: "file", filename: "a.txt", content: "x"}}, 403},
		{"no files", "admin", "/sub/", nil, 400},
		{"hidden name", "admin", "/sub/", []formPart{{field: "file", filename: ".c.txt", content: "x"}}, 400},
		{"not a directory", "admin", "/sub/keep.txt", []formPart{file}, 404},
	}
	for _, tc := range cases {
		form, ctype := multipartForm(t, tc.parts...)
		if resp, _ := f.as(tc.role).send(t, "POST", tc.target, form, "Content-Type", ctype); resp.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "sub", "c.txt")); err == nil {
		t.Error("rejected form upload stored a file")
	}
	resp, _ = f.send(t, "POST", "/sub/", strings.NewReader("x=1"), "Content-Type", "text/plain")
	expectStatus(t, resp, http.StatusUnsupportedMediaType)

	// Existing files are kept unless replace is checked; the reply names
	// the files stored before the failure.
	form, ctype = multipartForm(t,
		formPart{field: "file", filename: "d.txt", content: "delta"},
		formPart{field: "file", filename: "a.txt", content: "changed"},
	)
	resp, body = f.send(t, "POST", "/sub/", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusConflict)
	if body != "Conflict\nStored before the error: d.txt\n" || readFile(t, f.dir, "sub/a.txt") != "alpha" {
		t.Errorf("no-replace upload: %q, a.txt=%q", body, readFile(t, f.dir, "sub/a.txt"))
	}
	form, ctype = multipartForm(t,
		formPart{field: "replace", content: "0"},
		formPart{field: "file", filename: "a.txt", content: "changed"},
	)
	resp, _ = f.send(t, "POST", "/sub/", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusConflict)
	form, ctype = multipartForm(t,
		formPart{field: "replace", content: "1"},
		formPart{field: "file", filename: "a.txt", content: "changed"},
	)
	resp, _ = f.send(t, "POST", "/sub/", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusCreated)
	if readFile(t, f.dir, "sub/a.txt") != "changed" {
		t.Error("replace did not replace")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}
}

func TestLockFiles(t *testing.T) {
	f := newFixture(t)
	past := time.Now().Add(-2 * time.Hour)
	// Abandoned by a crashed goftp: taken over by the next upload.
	f.write(t, "stale.txt", "old")
	f.write(t, ".stale.txt.lock", lockMagic+".goftp-STALE.part\n")
	f.write(t, ".goftp-STALE.part", "partial")
	for _, name := range []string{".stale.txt.lock", ".goftp-STALE.part"} {
		if err := os.Chtimes(filepath.Join(f.dir, name), past, past); err != nil {
			t.Fatal(err)
		}
	}
	// Still running in another goftp process, e.g. during a restart.
	f.write(t, "live.txt", "old")
	f.write(t, ".live.txt.lock", lockMagic+".goftp-LIVE.part\n")
	f.write(t, ".goftp-LIVE.part", "partial")
	// Written by another tool: hides the file.
	f.write(t, "busy.txt", "partial")
	f.write(t, ".busy.txt.lock", "rsync\n")
	f.write(t, "busydir/x", "x")
	f.write(t, ".busydir.lock", "")
	// A crafted lock must not make goftp delete other files.
	f.write(t, "victim.txt", "keep")
	f.write(t, "evil.txt", "old")
	f.write(t, ".evil.txt.lock", lockMagic+"../victim.txt\n")

	_, body := f.do(t, "GET", "/")
	for _, name := range []string{"stale.txt", "live.txt"} {
		if !strings.Contains(body, `href="/`+name+`"`) {
			t.Errorf("goftp lock hides %s", name)
		}
	}
	for _, name := range []string{"busy.txt", "busydir", "evil.txt"} {
		if strings.Contains(body, name) {
			t.Errorf("locked %s is listed", name)
		}
	}
	for target, want := range map[string]int{"/busy.txt": 404, "/busydir/": 404, "/live.txt": 200} {
		if resp, _ := f.do(t, "GET", target); resp.StatusCode != want {
			t.Errorf("GET %s: status %d, want %d", target, resp.StatusCode, want)
		}
	}

	for target, want := range map[string]int{"/busy.txt": 409, "/evil.txt": 409, "/live.txt": 409, "/stale.txt": 204} {
		if resp, _ := f.send(t, "PUT", target, strings.NewReader("new")); resp.StatusCode != want {
			t.Errorf("PUT %s: status %d, want %d", target, resp.StatusCode, want)
		}
	}
	for name, want := range map[string]string{"stale.txt": "new", "live.txt": "old", "victim.txt": "keep", "busy.txt": "partial", ".goftp-LIVE.part": "partial"} {
		if got := readFile(t, f.dir, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, gone := range []string{".stale.txt.lock", ".goftp-STALE.part"} {
		if exists(filepath.Join(f.dir, gone)) {
			t.Errorf("stale %s not cleaned up", gone)
		}
	}
}

// "Only if absent" must hold even against writers that ignore lock files.
func TestCommitWithoutReplaceIsAtomic(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, content := range map[string]string{".goftp-T.part": "new", "f.txt": "written meanwhile"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := commit(root, ".goftp-T.part", "f.txt", false); !errors.Is(err, errExists) {
		t.Fatalf("commit = %v, want errExists", err)
	}
	if got := readFile(t, dir, "f.txt"); got != "written meanwhile" {
		t.Errorf("existing file replaced: %q", got)
	}
	if err := commit(root, ".goftp-T.part", "g.txt", false); err != nil || readFile(t, dir, "g.txt") != "new" {
		t.Errorf("commit to a free name: %v", err)
	}
}

// With uploads on, bodyless requests must keep their connection alive.
func TestKeepAliveWithUploads(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "a")
	for _, target := range []string{"/", "/a.txt"} {
		for _, method := range []string{"GET", "HEAD"} {
			if resp, _ := f.do(t, method, target); resp.Close {
				t.Errorf("%s %s closes the connection", method, target)
			}
		}
	}
	if resp, _ := f.send(t, "PUT", "/b.txt", strings.NewReader("b")); resp.StatusCode != 201 || resp.Close {
		t.Errorf("completed upload: status %d, close %v", resp.StatusCode, resp.Close)
	}
}

// A form upload by a visitor without rights on the file reveals nothing
// about it, not even whether it exists.
func TestFormUploadWithoutRightsRevealsNothing(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "drop/secret-plan.pdf", "plan")
	// The folder, but none of its files.
	if _, err := ta.svc.AddPolicy(auth.Anonymous, "/drop/", auth.ActWrite); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret-plan.pdf", "no-such.pdf"} {
		form, ctype := multipartForm(t, formPart{field: "file", filename: name, content: "x"})
		if resp, _ := f.as("").send(t, "POST", "/drop/", form, "Content-Type", ctype); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, resp.StatusCode)
		}
	}
	if got := readFile(t, f.dir, "drop/secret-plan.pdf"); got != "plan" {
		t.Errorf("file changed: %q", got)
	}
	if exists(filepath.Join(f.dir, "drop", "no-such.pdf")) {
		t.Error("file created")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// A user who may only replace files cannot create one by having it removed
// while the upload runs.
func TestReplaceOnlyCannotCreate(t *testing.T) {
	f := newFixture(t)
	f.write(t, "doc.txt", "old")
	dir, _, err := f.srv.uploadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	body := io.MultiReader(strings.NewReader("new"), readerFunc(func([]byte) (int, error) {
		if err := os.Remove(filepath.Join(f.dir, "doc.txt")); err != nil {
			t.Error(err)
		}
		return 0, io.EOF
	}))
	if _, _, err := f.srv.receive(dir, "doc.txt", body, true, uploadRights{replace: true}); !errors.Is(err, fiber.ErrForbidden) {
		t.Errorf("error %v, want 403", err)
	}
	if exists(filepath.Join(f.dir, "doc.txt")) {
		t.Error("file created")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"report.pdf":             true,
		"Holiday 2026":           true,
		"رسید.pdf":               true,
		"می‌خواهم.txt":           true, // zero-width non-joiner, common in Persian
		"👨‍👩‍👧.png":              true, // zero-width joiners
		"":                       false,
		".env":                   false,
		"a/b":                    false,
		`a\b`:                    false,
		"a\x00b":                 false,
		"a\nb":                   false,
		"a\x7fb":                 false,
		"a\u0085b":               false, // C1 control
		"a b":                    false, // line separator
		"invoice‮fdp.exe":        false, // right-to-left override: shows as "invoiceexe.pdf"
		"invoice⁧fdp.exe":        false, // right-to-left isolate
		strings.Repeat("x", 249): true,
		strings.Repeat("x", 250): false, // its lock file name would be too long
		"\xff":                   false,
	} {
		if got := validName(name); got != want {
			t.Errorf("validName(%q) = %v, want %v", name, got, want)
		}
	}
}
