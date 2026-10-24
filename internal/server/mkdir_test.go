package server

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
)

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func TestMkdir(t *testing.T) {
	f := newFixture(t)
	f.write(t, "sub/file.txt", "f")
	mkdir := func(ff *fixture, dir, name string, headers ...string) *http.Response {
		body := strings.NewReader(url.Values{"folder": {name}}.Encode())
		resp, _ := ff.send(t, "POST", dir, body, append([]string{"Content-Type", "application/x-www-form-urlencoded"}, headers...)...)
		return resp
	}

	// Browsers return to the listing, which confirms the new folder.
	resp := mkdir(f.as("operator"), "/sub/", "  Holiday 2026 ", "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/sub/?created=Holiday+2026" {
		t.Errorf("Location %q", got)
	}
	if !isDir(filepath.Join(f.dir, "sub", "Holiday 2026")) {
		t.Fatal("folder not created")
	}
	_, body := f.do(t, "GET", "/sub/?created=Holiday+2026")
	if !strings.Contains(body, `Created the folder <a href="/sub/Holiday%202026/">Holiday 2026</a>.`) ||
		!strings.Contains(body, `<tr data-name="holiday 2026" class="new">`) {
		t.Error("listing does not confirm the new folder")
	}
	// Only folders that exist are confirmed.
	for _, q := range []string{"?created=Nope", "?created=file.txt"} {
		if _, body := f.do(t, "GET", "/sub/"+q); strings.Contains(body, "Created the folder") {
			t.Errorf("%s: confirmed a folder that does not exist", q)
		}
	}

	// Scripts get 201 and the new folder's location.
	resp = mkdir(f, "/", "top")
	expectStatus(t, resp, http.StatusCreated)
	if got := resp.Header.Get("Location"); got != "/top/" || !isDir(filepath.Join(f.dir, "top")) {
		t.Errorf("Location %q", got)
	}
	resp, _ = f.send(t, "POST", "/top/", strings.NewReader(`{"folder":"deeper"}`), "Content-Type", "application/json")
	expectStatus(t, resp, http.StatusCreated)

	for _, tc := range []struct {
		who, dir, name string
		want           int
	}{
		{"", "/sub/", "x", 401},
		{"user", "/sub/", "x", 403},
		{"operator", "/sub/", "Holiday 2026", 409},
		{"operator", "/sub/", "file.txt", 409},
		{"operator", "/sub/", "", 400},
		{"operator", "/sub/", ".hidden", 400},
		{"operator", "/sub/", "a/b", 400},
		{"operator", "/sub/", `a\b`, 400},
		{"operator", "/sub/", "a\nb", 400},
		{"operator", "/sub/", strings.Repeat("x", 300), 400},
		{"operator", "/nope/", "x", 404},
		{"operator", "/sub/file.txt", "x", 404},
		{"operator", "/.git/", "x", 403},
	} {
		if resp := mkdir(f.as(tc.who), tc.dir, tc.name); resp.StatusCode != tc.want {
			t.Errorf("%q mkdir %s %q: status %d, want %d", tc.who, tc.dir, tc.name, resp.StatusCode, tc.want)
		}
	}
	// Refused names are explained, to browsers and scripts alike.
	for _, accept := range []string{"text/html", "*/*"} {
		body := strings.NewReader("folder=.hidden")
		if _, got := f.as("operator").send(t, "POST", "/sub/", body, "Content-Type", "application/x-www-form-urlencoded", "Accept", accept); !strings.Contains(got, "start with a dot") {
			t.Errorf("Accept %s: refused name not explained: %q", accept, got)
		}
	}
	if isDir(filepath.Join(f.dir, "sub", "x")) {
		t.Error("a refused request created a folder")
	}
	// Visitors who may not create anything here are refused before the
	// body is read.
	resp, _ = f.as("").send(t, "POST", "/sub/", strings.NewReader("{"), "Content-Type", "application/json")
	expectStatus(t, resp, http.StatusUnauthorized)
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}
	if n := len(f.logs.entries("mkdir")); n != 3 {
		t.Errorf("%d folder creations logged", n)
	}
}

// A folder is not created while a file of that name is being uploaded.
func TestMkdirRespectsUploadLocks(t *testing.T) {
	f := newFixture(t)
	f.write(t, lockName("busy"), lockMagic+tempPrefix+"X"+tempSuffix+"\n")
	now := time.Now()
	if err := os.Chtimes(filepath.Join(f.dir, lockName("busy")), now, now); err != nil {
		t.Fatal(err)
	}
	body := strings.NewReader("folder=busy")
	resp, _ := f.send(t, "POST", "/", body, "Content-Type", "application/x-www-form-urlencoded")
	expectStatus(t, resp, http.StatusConflict)
	if isDir(filepath.Join(f.dir, "busy")) {
		t.Error("folder created despite the lock")
	}
}

// The button is offered where the visitor may create folders.
func TestMkdirButton(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "shared/a.txt", "a")
	for role, want := range map[string]bool{"operator": true, "admin": true, "user": false} {
		_, body := f.as(role).do(t, "GET", "/")
		if got := strings.Contains(body, `<summary class="btn">`); got != want {
			t.Errorf("%s: New folder button shown = %v", role, got)
		}
	}

	// Rules decide per path.
	bob := ta.addUser(t, "bob", "user")
	for _, rule := range [][]string{{auth.Subject("bob"), "/*", auth.ActRead}, {auth.Subject("bob"), "/shared/*", auth.ActWrite}} {
		if _, err := ta.svc.AddPolicy(rule[0], rule[1], rule[2]); err != nil {
			t.Fatal(err)
		}
	}
	b := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: bob}
	if _, body := b.do(t, "GET", "/"); strings.Contains(body, `<summary class="btn">`) {
		t.Error("bob is offered folders at the top")
	}
	if _, body := b.do(t, "GET", "/shared/"); !strings.Contains(body, `<summary class="btn">`) {
		t.Error("bob is not offered folders in /shared/")
	}
	// Replacing files does not allow creating folders.
	carol := ta.addUser(t, "carol", "user")
	if _, err := ta.svc.AddPolicy(auth.Subject("carol"), "/shared/*", auth.ActOverwrite); err != nil {
		t.Fatal(err)
	}
	_, body := (&fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: carol}).do(t, "GET", "/shared/")
	if strings.Contains(body, `<summary class="btn">`) || !strings.Contains(body, `id="upload"`) || strings.Contains(body, `data-folders`) {
		t.Error("carol, who may only replace files, is offered folders or no uploads")
	}
	for dir, want := range map[string]int{"/shared/": 201, "/": 403} {
		resp, _ := b.send(t, "POST", dir, strings.NewReader("folder=mine"), "Content-Type", "application/x-www-form-urlencoded")
		if resp.StatusCode != want {
			t.Errorf("bob mkdir in %s: %d, want %d", dir, resp.StatusCode, want)
		}
	}
}
