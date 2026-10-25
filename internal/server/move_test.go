package server

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
)

func post(t *testing.T, f *fixture, dir, form string, headers ...string) (*http.Response, string) {
	t.Helper()
	return f.send(t, "POST", dir, strings.NewReader(form), append([]string{"Content-Type", formType}, headers...)...)
}

func TestMove(t *testing.T) {
	f := newFixture(t)
	f.write(t, "docs/a.txt", "alpha")
	f.write(t, "docs/b.txt", "beta")
	f.write(t, "docs/x.txt", "x")
	f.write(t, "docs/y.txt", "y")
	f.write(t, "docs/sub/c.txt", "gamma")
	f.write(t, "docs/taken.txt", "mine")
	f.write(t, "photos/taken.txt", "theirs")
	admin := f.as("admin")

	resp, _ := post(t, admin, "/docs/", "move=a.txt&into=/photos")
	expectStatus(t, resp, http.StatusCreated)
	if got := resp.Header.Get("Location"); got != "/photos/a.txt" {
		t.Errorf("Location %q", got)
	}
	if readFile(t, f.dir, "photos/a.txt") != "alpha" || exists(filepath.Join(f.dir, "docs", "a.txt")) {
		t.Error("not moved")
	}
	// Browsers return to the folder, which says where it went.
	resp, _ = post(t, admin, "/docs/", "move=b.txt&into=/photos/", "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/docs/?moved=1&to=%2Fphotos" {
		t.Errorf("Location %q", got)
	}
	if _, body := admin.do(t, "GET", "/docs/?moved=1&to=%2Fphotos"); !strings.Contains(body, `Moved to <a href="/photos/">/photos</a>.`) {
		t.Error("move not confirmed")
	}
	if _, body := admin.do(t, "GET", "/docs/?copied=2&to=%2Fphotos"); !strings.Contains(body, `Copied 2 items to <a href="/photos/">/photos</a>.`) {
		t.Error("copy not confirmed")
	}
	for _, q := range []string{"moved=1&to=%2Fnope", "moved=1&to=%2F.git", "moved=1&to=%2Fdocs%2Fx.txt", "moved=0&to=%2Fphotos", "moved=1&to=photos"} {
		if _, body := admin.do(t, "GET", "/docs/?"+q); strings.Contains(body, `id="moved"`) {
			t.Errorf("?%s confirms a move", q)
		}
	}

	// Folders keep what is in them.
	resp, _ = post(t, admin, "/docs/", "move=sub&into=/photos")
	expectStatus(t, resp, http.StatusCreated)
	if got := resp.Header.Get("Location"); got != "/photos/sub/" || readFile(t, f.dir, "photos/sub/c.txt") != "gamma" {
		t.Errorf("folder moved to %q", got)
	}
	// Picked entries move together.
	resp, _ = post(t, admin, "/docs/", "op=move&pick=x.txt&pick=y.txt&into=/photos")
	expectStatus(t, resp, http.StatusCreated)
	if got := resp.Header.Get("Location"); got != "/photos/" || !exists(filepath.Join(f.dir, "photos", "x.txt")) || !exists(filepath.Join(f.dir, "photos", "y.txt")) {
		t.Errorf("picked entries: %q", got)
	}

	for _, tc := range []struct {
		who, dir, form string
		want           int
		says           string
	}{
		{"admin", "/docs/", "move=taken.txt&into=/photos", 409, "Something named taken.txt is in that folder already."},
		{"admin", "/", "move=photos&into=/photos/sub", 409, "A folder cannot be moved into itself."},
		{"admin", "/", "move=photos&into=/photos", 409, "A folder cannot be moved into itself."},
		{"admin", "/docs/", "move=taken.txt&into=/docs", 409, "taken.txt is in that folder already."},
		{"admin", "/docs/", "move=taken.txt&into=/nope", 404, "There is no folder /nope."},
		{"admin", "/docs/", "move=taken.txt&into=/photos/taken.txt", 404, "There is no folder /photos/taken.txt."},
		{"admin", "/docs/", "move=taken.txt&into=/.git", 404, "There is no folder /.git."},
		{"admin", "/docs/", "move=taken.txt&into=photos", 400, "as a path"},
		{"admin", "/docs/", "move=taken.txt", 400, "as a path"},
		{"admin", "/docs/", "move=nope.txt&into=/photos", 404, ""},
		{"admin", "/docs/", "move=.env&into=/photos", 400, ""},
		{"admin", "/docs/", "op=move&into=/photos", 400, "Pick what to move first."},
		{"admin", "/docs/", "op=shred&pick=taken.txt", 400, ""},
		{"operator", "/docs/", "move=taken.txt&into=/photos", 403, ""},
		{"user", "/docs/", "move=taken.txt&into=/photos", 403, ""},
		{"", "/docs/", "move=taken.txt&into=/photos", 401, ""},
	} {
		resp, body := post(t, f.as(tc.who), tc.dir, tc.form)
		if resp.StatusCode != tc.want || !strings.Contains(body, tc.says) {
			t.Errorf("%q posts %s to %s: %d %q, want %d %q", tc.who, tc.form, tc.dir, resp.StatusCode, body, tc.want, tc.says)
		}
	}
	if readFile(t, f.dir, "docs/taken.txt") != "mine" || readFile(t, f.dir, "photos/taken.txt") != "theirs" {
		t.Error("a refused move changed something")
	}

	// Several entries stop at the first that fails, saying what moved.
	f.write(t, "docs/z.txt", "z")
	resp, body := post(t, admin, "/docs/", "move=z.txt&move=taken.txt&into=/photos")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "Moved before the error: z.txt") {
		t.Errorf("partial move: %d %q", resp.StatusCode, body)
	}
	// Nothing in it may be being written.
	f.write(t, "busy/"+lockName("big.iso"), lockMagic+tempPrefix+"LIVE"+tempSuffix+"\n")
	if resp, _ := post(t, admin, "/", "move=busy&into=/photos"); resp.StatusCode != http.StatusConflict {
		t.Errorf("moving a folder being written to: %d", resp.StatusCode)
	}
	if n := len(f.logs.entries("move")); n != 6 {
		t.Errorf("%d moves logged", n)
	}
	if l := leftovers(f.dir); len(l) != 1 {
		t.Errorf("leftover files: %v", l)
	}
}

// Moving or renaming a folder gives what is in it new paths, where other
// rules apply: all of it has to be readable and deletable where it is.
func TestMoveFollowsRules(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "box/folder/keep/k.txt", "k")
	f.write(t, "box/folder/free.txt", "f")
	if _, err := ta.svc.AddPolicy("admin", "!/box/folder/keep/*", auth.ActDelete); err != nil {
		t.Fatal(err)
	}
	admin := f.as("admin")
	for form, says := range map[string]string{
		"rename=folder&to=renamed":     "You may not rename everything in this folder.",
		"move=folder&into=/":           "You may not move everything in this folder.",
		"op=delete&pick=folder":        "You may not delete everything in this folder.",
		"delete=folder&permanent=true": "You may not delete everything in this folder.",
	} {
		if resp, body := post(t, admin, "/box/", form); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, says) {
			t.Errorf("%s: %d %q", form, resp.StatusCode, body)
		}
	}
	if !exists(filepath.Join(f.dir, "box", "folder", "keep", "k.txt")) {
		t.Error("a refused change moved the folder")
	}
}

func TestCopy(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "src/a.txt", "alpha")
	f.write(t, "src/deep/b.txt", "beta")
	f.write(t, "src/deep/.env", "secret")
	f.write(t, "src/private/p.txt", "private")
	f.write(t, "src/"+lockName("tool.db"), "another tool's lock")
	f.write(t, "src/tool.db", "being written")
	f.write(t, "dest/taken.txt", "theirs")
	old := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(f.dir, "src", "a.txt"), old, old); err != nil {
		t.Fatal(err)
	}
	// dora may read everything but /src/private/, and add files in /dest/
	// only.
	dora := ta.addUser(t, "dora", "user")
	for _, rule := range [][2]string{
		{"!/src/private/*", auth.ActRead},
		{"/dest/*", auth.ActWrite},
	} {
		if _, err := ta.svc.AddPolicy(auth.Subject("dora"), rule[0], rule[1]); err != nil {
			t.Fatal(err)
		}
	}
	d := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: dora}

	// A file, from a folder she may only read.
	resp, _ := post(t, d, "/src/", "copy=a.txt&into=/dest")
	expectStatus(t, resp, http.StatusCreated)
	if got := resp.Header.Get("Location"); got != "/dest/a.txt" || readFile(t, f.dir, "dest/a.txt") != "alpha" || readFile(t, f.dir, "src/a.txt") != "alpha" {
		t.Errorf("copied to %q", got)
	}
	if info, err := os.Stat(filepath.Join(f.dir, "dest", "a.txt")); err != nil || !info.ModTime().Equal(old) {
		t.Errorf("modification time %v, %v", info.ModTime(), err)
	}
	// A folder, with what she may read in it.
	resp, _ = post(t, d, "/", "copy=src&into=/dest", "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/?copied=1&to=%2Fdest" {
		t.Errorf("Location %q", got)
	}
	if readFile(t, f.dir, "dest/src/deep/b.txt") != "beta" || readFile(t, f.dir, "dest/src/a.txt") != "alpha" {
		t.Error("folder not copied")
	}
	for _, p := range []string{"dest/src/deep/.env", "dest/src/private", "dest/src/tool.db"} {
		if exists(filepath.Join(f.dir, filepath.FromSlash(p))) {
			t.Errorf("copied %s", p)
		}
	}

	for _, tc := range []struct {
		who, dir, form string
		want           int
		says           string
	}{
		{"dora", "/src/", "copy=a.txt&into=/dest", 409, "Something named a.txt is in that folder already."},
		{"dora", "/dest/", "copy=src&into=/dest/src/deep", 409, "A folder cannot be copied into itself."},
		{"dora", "/dest/", "copy=taken.txt&into=/dest", 409, "Something named taken.txt is in that folder already."},
		{"dora", "/src/", "copy=a.txt&into=/src", 403, ""},
		{"dora", "/src/", "copy=private&into=/dest", 404, ""},
		{"dora", "/src/", "copy=nope.txt&into=/dest", 404, ""},
		{"dora", "/src/", "copy=a.txt&into=/dest/nope", 404, "There is no folder /dest/nope."},
		{"user", "/src/", "copy=a.txt&into=/dest", 403, ""},
	} {
		var ff *fixture
		if tc.who == "dora" {
			ff = d
		} else {
			ff = f.as(tc.who)
		}
		resp, body := post(t, ff, tc.dir, tc.form)
		if resp.StatusCode != tc.want || !strings.Contains(body, tc.says) {
			t.Errorf("%q posts %s to %s: %d %q, want %d %q", tc.who, tc.form, tc.dir, resp.StatusCode, body, tc.want, tc.says)
		}
	}

	// What she may not create there stops the copy before it starts.
	f.write(t, "dest/x/.keep", "")
	if _, err := ta.svc.AddPolicy(auth.Subject("dora"), "!/dest/x/src/deep/*", auth.ActWrite); err != nil {
		t.Fatal(err)
	}
	resp, body := post(t, d, "/", "copy=src&into=/dest/x")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "You may not create everything in it there.") ||
		exists(filepath.Join(f.dir, "dest", "x", "src")) {
		t.Errorf("copy with a denied folder in it: %d %q", resp.StatusCode, body)
	}
	if n := len(f.logs.entries("copy")); n != 2 {
		t.Errorf("%d copies logged", n)
	}
	if l := leftovers(f.dir); len(l) != 1 {
		t.Errorf("leftover files: %v", l)
	}
}

// A copy never copies itself, also when a symlink in what it copies leads
// to where the copy goes.
func TestCopyDoesNotCopyItself(t *testing.T) {
	f := newFixture(t)
	f.write(t, "src/a.txt", "a")
	f.write(t, "shared/dest/x.txt", "x")
	if err := os.Symlink("../shared", filepath.Join(f.dir, "src", "l")); err != nil {
		t.Fatal(err)
	}
	resp, body := post(t, f.as("admin"), "/", "copy=src&into=/shared/dest")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("copy: %d %s", resp.StatusCode, body)
	}
	if readFile(t, f.dir, "shared/dest/src/l/dest/x.txt") != "x" || exists(filepath.Join(f.dir, "shared", "dest", "src", "l", "dest", "src")) {
		t.Error("the copy holds itself")
	}
	if got := leftovers(f.dir); len(got) != 0 {
		t.Errorf("left behind: %v", got)
	}
}

// Copies are limited in how much they hold.
func TestCopyLimits(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"a", "b", "c", "d"} {
		f.write(t, "src/"+name+".txt", name)
	}
	f.write(t, "dest/.keep", "")
	defer func(n int) { maxCopyEntries = n }(maxCopyEntries)
	maxCopyEntries = 3
	resp, body := post(t, f.as("admin"), "/", "copy=src&into=/dest")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "too much in it to copy at once") {
		t.Errorf("copy: %d %s", resp.StatusCode, body)
	}
	if exists(filepath.Join(f.dir, "dest", "src")) {
		t.Error("copied anyway")
	}
}

// A copy that fails midway removes what it made, and only that.
func TestCopyFailureLeavesNothing(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads everything")
	}
	f := newFixture(t)
	f.write(t, "src/a.txt", "a")
	f.write(t, "src/b.txt", "b")
	f.write(t, "dest/mine.txt", "mine")
	if err := os.Chmod(filepath.Join(f.dir, "src", "b.txt"), 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(f.dir, "src", "b.txt"), 0o644)
	if resp, _ := post(t, f.as("admin"), "/", "copy=src&into=/dest"); resp.StatusCode < 400 {
		t.Fatalf("copy: %d", resp.StatusCode)
	}
	entries, _ := os.ReadDir(filepath.Join(f.dir, "dest"))
	if len(entries) != 1 || readFile(t, f.dir, "dest/mine.txt") != "mine" {
		t.Errorf("left in dest: %v", entries)
	}
}

// Moving and renaming a folder need the right to create everything in it
// where it goes, as copying does.
func TestMoveChecksWhereItGoes(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "mine/2024/final/report.txt", "r")
	f.write(t, "incoming/x/final/report.txt", "r")
	if _, err := ta.svc.AddPolicy("admin", "!/incoming/2024/final/*", auth.ActWrite); err != nil {
		t.Fatal(err)
	}
	admin := f.as("admin")
	for dir, form := range map[string]string{"/mine/": "move=2024&into=/incoming", "/incoming/": "rename=x&to=2024"} {
		if resp, body := post(t, admin, dir, form); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d %s", form, resp.StatusCode, body)
		}
	}
	if exists(filepath.Join(f.dir, "incoming", "2024")) {
		t.Error("moved anyway")
	}
}

// Copies and zips skip what is no longer where its rights were checked,
// such as after a symlink on the way was swapped.
func TestCopyChecksWhereItReads(t *testing.T) {
	f := newFixture(t)
	f.write(t, "b/c.txt", "c")
	f.write(t, "dest/.keep", "")
	if err := os.Symlink("b", filepath.Join(f.dir, "a")); err != nil {
		t.Fatal(err)
	}
	allow := f.srv.rulesOf(nil)
	if _, err := f.srv.readable("/a", "/a", allow); !errors.Is(err, errChanged) {
		t.Errorf("a folder elsewhere: %v", err)
	}
	if _, err := f.srv.readable("/a", "/b", allow); err != nil {
		t.Errorf("where it really is: %v", err)
	}
	dst, err := f.srv.root.OpenRoot("dest")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := f.srv.copyFile(dst, "c.txt", "/a/c.txt", false); !errors.Is(err, fiber.ErrNotFound) {
		t.Errorf("a file elsewhere: %v", err)
	}
	if err := f.srv.copyFile(dst, "c.txt", "/b/c.txt", false); err != nil {
		t.Errorf("where it really is: %v", err)
	}
	if err := renameExclBetween(dst, "c.txt", f.srv.root, "b"); !errors.Is(err, errExists) {
		t.Errorf("renaming over a folder: %v", err)
	}
}
