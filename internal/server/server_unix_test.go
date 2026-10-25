//go:build unix

package server

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"goftp/internal/auth"
)

func TestSymlinks(t *testing.T) {
	f := newFixture(t)
	f.write(t, "real/file.txt", "inside")
	f.write(t, ".git/config", "secret")
	f.write(t, ".env", "secret")
	f.write(t, "real/.hidden/x", "secret")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"to-real":     "real",
		"to-file.txt": "real/file.txt",
		"to-outside":  outside,
		"to-secret":   filepath.Join(outside, "secret.txt"),
		"to-parent":   "..",
		"abs-inside":  filepath.Join(f.dir, "real"),
		"dangling":    "missing",
		"pub":         ".git",
		"env":         ".env",
		"deep":        "real/.hidden",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	tests := map[string]int{
		"/to-real/file.txt":       200,
		"/to-file.txt":            200,
		"/to-outside/secret.txt":  404,
		"/to-secret":              404,
		"/to-parent/":             404,
		"/abs-inside/file.txt":    404, // os.Root rejects absolute link targets
		"/dangling":               404,
		"/to-real/../to-file.txt": 200,
		"/pub/config":             404, // links into hidden paths count as hidden
		"/pub/":                   404,
		"/env":                    404,
		"/deep/x":                 404,
	}
	for p, want := range tests {
		resp, body := f.do(t, "GET", p)
		if resp.StatusCode != want || strings.Contains(body, "secret") {
			t.Errorf("%s: status %d, want %d (body %q)", p, resp.StatusCode, want, body)
		}
	}

	_, body := f.do(t, "GET", "/")
	for _, want := range []string{`href="/to-real/"`, `href="/to-file.txt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
	for _, hidden := range []string{"to-outside", "to-secret", "to-parent", "abs-inside", "dangling", "pub", "env", "deep"} {
		if strings.Contains(body, `data-name="`+hidden+`"`) || strings.Contains(body, `href="/`+hidden) || strings.Contains(body, ">"+hidden+"<") {
			t.Errorf("listing shows unusable link %s", hidden)
		}
	}
}

func TestSpecialFilesDoNotBlock(t *testing.T) {
	f := newFixture(t)
	if err := syscall.Mkfifo(filepath.Join(f.dir, "fifo"), 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	start := time.Now()
	resp, _ := f.do(t, "GET", "/fifo")
	expectStatus(t, resp, 404)
	if time.Since(start) > 2*time.Second {
		t.Error("FIFO request blocked")
	}
	if _, body := f.do(t, "GET", "/"); strings.Contains(body, "fifo") {
		t.Error("listing shows FIFO")
	}
}

func TestNoFileDescriptorLeaks(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("needs /proc")
	}
	f := newFixture(t)
	f.write(t, "f.txt", "0123456789")
	f.write(t, "d/x", "x")
	resp, _ := f.do(t, "GET", "/f.txt")
	etag := resp.Header.Get("ETag")

	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := countFDs()
	for i := 0; i < 20; i++ {
		f.do(t, "GET", "/f.txt")
		f.do(t, "HEAD", "/f.txt")
		f.do(t, "GET", "/f.txt")
		f.do(t, "GET", "/f.txt", "If-None-Match", etag)
		f.do(t, "GET", "/f.txt", "Range", "bytes=99-")
		f.do(t, "GET", "/f.txt", "Range", "bytes=0-1,3-4")
		f.do(t, "GET", "/d/")
		f.do(t, "GET", "/d")
	}
	deadline := time.Now().Add(2 * time.Second)
	for countFDs() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := countFDs(); after > before {
		t.Errorf("file descriptors leaked: %d before, %d after", before, after)
	}
}

func TestUploadIntoHiddenDirViaSymlink(t *testing.T) {
	f := newFixture(t)
	f.write(t, ".git/config", "secret")
	if err := os.Symlink(".git", filepath.Join(f.dir, "pub")); err != nil {
		t.Fatal(err)
	}
	if resp, _ := f.send(t, "PUT", "/pub/x.txt", strings.NewReader("x")); resp.StatusCode != 409 {
		t.Errorf("PUT through link: %d", resp.StatusCode)
	}
	form, ctype := multipartForm(t, formPart{field: "file", filename: "y.txt", content: "y"})
	if resp, _ := f.send(t, "POST", "/pub/", form, "Content-Type", ctype); resp.StatusCode != 404 {
		t.Errorf("form upload through link: %d", resp.StatusCode)
	}
	entries, _ := os.ReadDir(filepath.Join(f.dir, ".git"))
	if len(entries) != 1 {
		t.Errorf("files written into .git: %v", entries)
	}
}

// A symlink never grants more than the rules of where it leads: visitors
// need access to both the path they ask for and the entry's real path.
func TestSymlinksFollowTargetRules(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "public/readme.txt", "public")
	f.write(t, "private/secret.txt", "TOP SECRET")
	f.write(t, "private/docs/a.txt", "TOP SECRET")
	f.write(t, "shared/open.txt", "shared")
	f.write(t, "incoming/x.txt", "x")
	f.write(t, "protected/keep.txt", "keep")
	for name, target := range map[string]string{
		"public/ok.txt":     "readme.txt",
		"public/link.txt":   "../private/secret.txt",
		"public/linkdir":    "../private/docs",
		"public/shared":     "../shared",
		"incoming/esc":      "../protected",
		"incoming/incoming": ".",
	} {
		if err := os.Symlink(target, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range [][]string{
		{"/public/*", auth.ActRead},
		{"/shared/*", auth.ActRead},
		{"/incoming/*", auth.ActWrite},
	} {
		if _, err := ta.svc.AddPolicy(auth.Anonymous, rule[0], rule[1]); err != nil {
			t.Fatal(err)
		}
	}
	anon := f.as("")

	for p, want := range map[string]int{
		"/public/readme.txt":      200,
		"/public/ok.txt":          200,
		"/public/shared/open.txt": 200,
		"/public/link.txt":        404,
		"/public/linkdir/":        404,
		"/public/linkdir/a.txt":   404,
		"/public/linkdir":         404,
	} {
		if resp, body := anon.do(t, "GET", p); resp.StatusCode != want || strings.Contains(body, "SECRET") {
			t.Errorf("GET %s: status %d, want %d", p, resp.StatusCode, want)
		}
	}
	_, body := anon.do(t, "GET", "/public/")
	for _, want := range []string{`href="/public/readme.txt"`, `href="/public/ok.txt"`, `href="/public/shared/"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
	for _, hidden := range []string{"link.txt", "linkdir"} {
		if strings.Contains(body, hidden) {
			t.Errorf("listing shows %s, which leads where the visitor may not go", hidden)
		}
	}

	// Writes through a symlinked folder need the rights of its target too.
	if resp, _ := anon.send(t, "PUT", "/incoming/new.txt", strings.NewReader("new")); resp.StatusCode != http.StatusCreated {
		t.Errorf("PUT into /incoming/: %d", resp.StatusCode)
	}
	if resp, _ := anon.send(t, "PUT", "/incoming/incoming/same.txt", strings.NewReader("same")); resp.StatusCode != http.StatusCreated {
		t.Errorf("PUT through a link to the same folder: %d", resp.StatusCode)
	}
	if resp, _ := anon.send(t, "PUT", "/incoming/esc/planted.txt", strings.NewReader("x")); resp.StatusCode < 400 {
		t.Errorf("PUT through link: %d", resp.StatusCode)
	}
	form, ctype := multipartForm(t, formPart{field: "file", filename: "planted2.txt", content: "x"})
	if resp, _ := anon.send(t, "POST", "/incoming/esc/", form, "Content-Type", ctype); resp.StatusCode < 400 {
		t.Errorf("form upload through link: %d", resp.StatusCode)
	}
	if resp, _ := anon.send(t, "POST", "/incoming/esc/", strings.NewReader("folder=planted3"), "Content-Type", "application/x-www-form-urlencoded"); resp.StatusCode < 400 {
		t.Errorf("mkdir through link: %d", resp.StatusCode)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.dir, "protected")); len(entries) != 1 {
		t.Errorf("written through the link: %v", entries)
	}

	// With rights on both ends, links work as before.
	if resp, _ := f.as("operator").send(t, "PUT", "/incoming/esc/allowed.txt", strings.NewReader("ok")); resp.StatusCode != http.StatusCreated {
		t.Errorf("operator PUT through link: %d", resp.StatusCode)
	}
	if resp, _ := f.as("user").do(t, "GET", "/public/link.txt"); resp.StatusCode != 200 {
		t.Errorf("user GET through link: %d", resp.StatusCode)
	}
}

// A folder another tool is writing in place is hidden with everything in
// it, and so are symlinks leading into locked entries.
func TestLockedFolderHidesContents(t *testing.T) {
	f := newFixture(t)
	f.write(t, "busy/partial.bin", "half")
	f.write(t, ".busy.lock", "")
	f.write(t, "file.txt", "half")
	f.write(t, ".file.txt.lock", "")
	f.write(t, "free.txt", "done")
	for name, target := range map[string]string{"alias": "file.txt", "aliasdir": "busy"} {
		if err := os.Symlink(target, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	op := f.as("operator")
	for _, p := range []string{"/busy/", "/busy/partial.bin", "/file.txt", "/alias", "/aliasdir/", "/aliasdir/partial.bin"} {
		if resp, _ := op.do(t, "GET", p); resp.StatusCode != 404 {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := op.do(t, "GET", "/free.txt"); resp.StatusCode != 200 {
		t.Errorf("GET /free.txt: %d", resp.StatusCode)
	}
	_, body := op.do(t, "GET", "/")
	for _, hidden := range []string{"busy", "file.txt", "alias"} {
		if strings.Contains(body, `href="/`+hidden) {
			t.Errorf("listing shows %s", hidden)
		}
	}
	if resp, _ := op.send(t, "PUT", "/busy/new.bin", strings.NewReader("x")); resp.StatusCode < 400 {
		t.Errorf("PUT into locked folder: %d", resp.StatusCode)
	}
	if resp, _ := op.send(t, "POST", "/busy/", strings.NewReader("folder=sub"), "Content-Type", "application/x-www-form-urlencoded"); resp.StatusCode < 400 {
		t.Errorf("mkdir in locked folder: %d", resp.StatusCode)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.dir, "busy")); len(entries) != 1 {
		t.Errorf("written into the locked folder: %v", entries)
	}
}

// Deleting or renaming a symlink affects the link, not what it leads to.
// Through a symlinked folder, the rules of the real folder apply.
func TestDeleteAndRenameSymlinks(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "keep/k.txt", "keep")
	f.write(t, "box/x.txt", "x")
	f.write(t, "protected/p.txt", "protected")
	f.write(t, "incoming/i.txt", "i")
	for name, target := range map[string]string{
		"box/link.txt":  "../keep/k.txt",
		"box/dirlink":   "../keep",
		"box/inner":     "../keep",
		"box/renamable": "../keep/k.txt",
		"incoming/esc":  "../protected",
	} {
		if err := os.Symlink(target, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	admin := f.as("admin")
	for _, p := range []string{"/box/link.txt", "/box/dirlink"} {
		if resp, _ := admin.do(t, "DELETE", p); resp.StatusCode != http.StatusNoContent {
			t.Errorf("DELETE %s: %d", p, resp.StatusCode)
		}
	}
	resp, _ := admin.send(t, "POST", "/box/", strings.NewReader("rename=renamable&to=renamed"), "Content-Type", formType)
	expectStatus(t, resp, http.StatusCreated)
	if target, err := os.Readlink(filepath.Join(f.dir, "box", "renamed")); err != nil || target != "../keep/k.txt" {
		t.Errorf("renamed link: %q %v", target, err)
	}
	// A folder goes with the links in it, but not with what they lead to.
	if resp, _ := admin.do(t, "DELETE", "/box/"); resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE /box/: %d", resp.StatusCode)
	}
	if readFile(t, f.dir, "keep/k.txt") != "keep" {
		t.Error("deleted through a link")
	}

	for _, rule := range []string{auth.ActRead, auth.ActWrite, auth.ActDelete} {
		if _, err := ta.svc.AddPolicy(auth.Anonymous, "/incoming/*", rule); err != nil {
			t.Fatal(err)
		}
	}
	anon := f.as("")
	if resp, _ := anon.do(t, "DELETE", "/incoming/esc/p.txt"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE through link: %d", resp.StatusCode)
	}
	if resp, _ := anon.send(t, "POST", "/incoming/esc/", strings.NewReader("rename=p.txt&to=q.txt"), "Content-Type", formType); resp.StatusCode != http.StatusNotFound {
		t.Errorf("rename through link: %d", resp.StatusCode)
	}
	if readFile(t, f.dir, "protected/p.txt") != "protected" {
		t.Error("changed through a link")
	}
	// The link itself lives in /incoming/, so it may go.
	if resp, _ := anon.do(t, "DELETE", "/incoming/esc"); resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE the link: %d", resp.StatusCode)
	}
	if !exists(filepath.Join(f.dir, "protected", "p.txt")) {
		t.Error("deleting the link deleted its target")
	}
}

// Zips follow symlinks the way listings do, and stop at loops.
func TestZipSymlinks(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "pub/a.txt", "a")
	f.write(t, "private/p.txt", "secret")
	for name, target := range map[string]string{
		"pub/loop":       "..",
		"pub/self":       ".",
		"pub/alias.txt":  "a.txt",
		"pub/secret.txt": "../private/p.txt",
		"pub/privdir":    "../private",
	} {
		if err := os.Symlink(target, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ta.svc.AddPolicy(auth.Anonymous, "/pub/*", auth.ActRead); err != nil {
		t.Fatal(err)
	}
	for who, want := range map[string][]string{
		"":      {"a.txt", "alias.txt"},
		"admin": {"a.txt", "alias.txt", "privdir/", "privdir/p.txt", "secret.txt"},
	} {
		_, body := f.as(who).do(t, "GET", "/pub/?zip")
		names, contents := zipEntries(t, body)
		if !slices.Equal(names, want) || contents["alias.txt"] != "a" {
			t.Errorf("%q gets %q", who, names)
		}
	}
}

// Links follow symlinks the way listings do, with the rights of the link's
// creator where they lead.
func TestShareSymlinks(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "pub/a.txt", "a")
	f.write(t, "private/p.txt", "secret")
	for name, target := range map[string]string{
		"pub/loop":       "..",
		"pub/alias.txt":  "a.txt",
		"pub/secret.txt": "../private/p.txt",
		"pub/privdir":    "../private",
	} {
		if err := os.Symlink(target, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	erin := ta.addUser(t, "erin", "user")
	if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/pub/*", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	e := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: erin}
	link := sharePrefix + createShare(t, e, "", "/pub", "1d", "")
	visitor := f.as("")

	_, body := visitor.do(t, "GET", link+"/", "Accept", "text/html")
	for name, want := range map[string]bool{"a.txt": true, "alias.txt": true, "secret.txt": false, "privdir": false, "loop": false} {
		if strings.Contains(body, `data-name="`+name+`"`) != want {
			t.Errorf("%s listed = %v", name, !want)
		}
	}
	for p, want := range map[string]int{"/alias.txt": 200, "/secret.txt": 404, "/privdir/p.txt": 404, "/loop/private/p.txt": 404} {
		if resp, body := visitor.do(t, "GET", link+p); resp.StatusCode != want || strings.Contains(body, "secret") {
			t.Errorf("%s: %d, want %d", p, resp.StatusCode, want)
		}
	}
	if _, body := visitor.do(t, "GET", link+"/?zip"); !slices.Equal(func() []string { n, _ := zipEntries(t, body); return n }(), []string{"a.txt", "alias.txt"}) {
		t.Error("the zip goes where erin may not share")
	}
	// Nor can erin share the symlink itself.
	if resp, _ := e.send(t, "POST", sharesPath, strings.NewReader("action=create&expires=1d&path=/pub/secret.txt"), "Content-Type", formType); resp.StatusCode != http.StatusNotFound {
		t.Errorf("sharing a symlink out of reach: %d", resp.StatusCode)
	}
}
