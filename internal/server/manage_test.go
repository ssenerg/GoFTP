package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
)

const formType = "application/x-www-form-urlencoded"

func TestDelete(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "a")
	f.write(t, "docs/b.txt", "b")
	f.write(t, "docs/deep/c.txt", "c")
	f.write(t, "docs/.git/config", "goes with the folder")
	f.write(t, "keep/k.txt", "k")
	admin := f.as("admin")

	resp, _ := admin.do(t, "DELETE", "/a.txt")
	expectStatus(t, resp, http.StatusNoContent)
	if exists(filepath.Join(f.dir, "a.txt")) {
		t.Error("file not deleted")
	}

	// Folders go with everything in them. Browsers return to the folder.
	resp, _ = admin.send(t, "POST", "/", strings.NewReader("delete=docs"), "Content-Type", formType, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/?deleted=1" {
		t.Errorf("Location %q", got)
	}
	if exists(filepath.Join(f.dir, "docs")) {
		t.Error("folder not deleted")
	}
	if _, body := admin.do(t, "GET", "/?deleted=1"); !strings.Contains(body, `id="deleted"`) {
		t.Error("deletion not confirmed")
	}

	for _, tc := range []struct {
		who, method, target, form string
		want                      int
	}{
		{"", "DELETE", "/keep/k.txt", "", 401},
		{"user", "DELETE", "/keep/k.txt", "", 403},
		{"operator", "DELETE", "/keep/k.txt", "", 403},
		{"operator", "POST", "/keep/", "delete=k.txt", 403},
		{"admin", "DELETE", "/nope.txt", "", 404},
		{"admin", "DELETE", "/keep/nope/x", "", 404},
		{"admin", "DELETE", "/", "", 403},
		{"admin", "DELETE", "/.git/config", "", 403},
		{"admin", "POST", "/keep/", "delete=", 400},
		{"admin", "POST", "/keep/", "delete=.env", 400},
		{"admin", "POST", "/keep/", "delete=a/b", 400},
		{"admin", "POST", "/keep/", "delete=nope", 404},
	} {
		var resp *http.Response
		if tc.method == "DELETE" {
			resp, _ = f.as(tc.who).do(t, "DELETE", tc.target)
		} else {
			resp, _ = f.as(tc.who).send(t, "POST", tc.target, strings.NewReader(tc.form), "Content-Type", formType)
		}
		if resp.StatusCode != tc.want {
			t.Errorf("%q %s %s %s: status %d, want %d", tc.who, tc.method, tc.target, tc.form, resp.StatusCode, tc.want)
		}
	}
	if !exists(filepath.Join(f.dir, "keep", "k.txt")) {
		t.Error("a refused request deleted a file")
	}
	if n := len(f.logs.entries("delete")); n != 2 {
		t.Errorf("%d deletions logged", n)
	}
}

// A folder is only deleted when the visitor may delete everything in it,
// and nothing in it is being written.
func TestDeleteFolderChecks(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	admin := f.as("admin")
	fresh := lockMagic + tempPrefix + "LIVE" + tempSuffix + "\n"

	f.write(t, "up/done.txt", "x")
	f.write(t, "up/"+lockName("big.iso"), fresh)
	f.write(t, "tool/"+lockName("db"), "another tool's lock")
	for _, dir := range []string{"/up/", "/tool/"} {
		if resp, _ := admin.do(t, "DELETE", dir); resp.StatusCode != http.StatusConflict {
			t.Errorf("DELETE %s while written to: %d", dir, resp.StatusCode)
		}
	}
	if !exists(filepath.Join(f.dir, "up", "done.txt")) || !exists(filepath.Join(f.dir, "tool")) {
		t.Error("deleted while written to")
	}
	// A lock left behind by a goftp that stopped does not count.
	old := time.Now().Add(-2 * lockExpiry)
	if err := os.Chtimes(filepath.Join(f.dir, "up", lockName("big.iso")), old, old); err != nil {
		t.Fatal(err)
	}
	if resp, _ := admin.do(t, "DELETE", "/up/"); resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE with a stale lock: %d", resp.StatusCode)
	}

	// Rules decide per entry.
	f.write(t, "box/a.txt", "a")
	f.write(t, "box/b.txt", "b")
	dora := ta.addUser(t, "dora", "user")
	for _, obj := range []string{"/box/", "/box/a.txt"} {
		if _, err := ta.svc.AddPolicy(auth.Subject("dora"), obj, auth.ActDelete); err != nil {
			t.Fatal(err)
		}
	}
	d := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: dora}
	resp, body := d.do(t, "DELETE", "/box/")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "everything in this folder") {
		t.Errorf("DELETE /box/ without rights on b.txt: %d %q", resp.StatusCode, body)
	}
	if !exists(filepath.Join(f.dir, "box", "b.txt")) {
		t.Error("deleted without the rights")
	}
	if resp, _ := d.do(t, "DELETE", "/box/a.txt"); resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE /box/a.txt: %d", resp.StatusCode)
	}
	// Deleting is allowed without the right to create anything, which
	// renaming needs.
	f.write(t, "box/c.txt", "c")
	if _, err := ta.svc.AddPolicy(auth.Subject("dora"), "/box/c.txt", auth.ActDelete); err != nil {
		t.Fatal(err)
	}
	for form, want := range map[string]int{"folder=x": 403, "rename=c.txt&to=d.txt": 403} {
		if resp, _ := d.send(t, "POST", "/box/", strings.NewReader(form), "Content-Type", formType); resp.StatusCode != want {
			t.Errorf("dora posts %s: %d, want %d", form, resp.StatusCode, want)
		}
	}
	if !exists(filepath.Join(f.dir, "box", "c.txt")) {
		t.Error("renamed without the right to create")
	}
	resp, _ = d.send(t, "POST", "/box/", strings.NewReader("delete=c.txt"), "Content-Type", formType)
	expectStatus(t, resp, http.StatusNoContent)

	// A file being uploaded stays.
	f.write(t, "keep/"+lockName("busy.txt"), fresh)
	f.write(t, "keep/busy.txt", "previous version")
	resp, _ = admin.do(t, "DELETE", "/keep/busy.txt")
	expectStatus(t, resp, http.StatusConflict)
	if !exists(filepath.Join(f.dir, "keep", "busy.txt")) {
		t.Error("deleted while being uploaded")
	}
}

func TestRename(t *testing.T) {
	f := newFixture(t)
	f.write(t, "docs/report.txt", "report")
	f.write(t, "docs/old/x.txt", "x")
	f.write(t, "docs/taken.txt", "taken")
	admin := f.as("admin")
	rename := func(ff *fixture, dir, from, to string, headers ...string) *http.Response {
		body := strings.NewReader("rename=" + from + "&to=" + to)
		resp, _ := ff.send(t, "POST", dir, body, append([]string{"Content-Type", formType}, headers...)...)
		return resp
	}

	resp := rename(admin, "/docs/", "report.txt", "Final+report.txt", "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/docs/?renamed=Final+report.txt" {
		t.Errorf("Location %q", got)
	}
	if got := readFile(t, f.dir, "docs/Final report.txt"); got != "report" || exists(filepath.Join(f.dir, "docs", "report.txt")) {
		t.Errorf("renamed file holds %q", got)
	}
	_, body := admin.do(t, "GET", "/docs/?renamed=Final+report.txt")
	if !strings.Contains(body, `Renamed to <a href="/docs/Final%20report.txt">Final report.txt</a>.`) ||
		!strings.Contains(body, `<tr data-name="final report.txt" class="new">`) {
		t.Error("listing does not confirm the new name")
	}

	// Scripts get 201 and the new location; folders keep their contents.
	resp, _ = admin.send(t, "POST", "/docs/", strings.NewReader(`{"rename":"old","to":"new"}`), "Content-Type", "application/json")
	expectStatus(t, resp, http.StatusCreated)
	if got := resp.Header.Get("Location"); got != "/docs/new/" || readFile(t, f.dir, "docs/new/x.txt") != "x" {
		t.Errorf("Location %q", got)
	}
	// The same name changes nothing.
	expectStatus(t, rename(admin, "/docs/", "taken.txt", "taken.txt"), http.StatusCreated)

	busy := lockMagic + tempPrefix + "LIVE" + tempSuffix + "\n"
	f.write(t, "docs/"+lockName("incoming.iso"), busy)
	for _, tc := range []struct {
		who, from, to string
		want          int
	}{
		{"admin", "new", "taken.txt", 409},
		{"admin", "taken.txt", "new", 409},
		{"admin", "taken.txt", "incoming.iso", 409},
		{"admin", "taken.txt", "", 400},
		{"admin", "taken.txt", ".hidden", 400},
		{"admin", "taken.txt", "a%2Fb", 400},
		{"admin", "taken.txt", "x%E2%80%AEtxt.exe", 400},
		{"admin", "nope.txt", "x.txt", 404},
		{"admin", ".env", "x.txt", 400},
		{"operator", "taken.txt", "x.txt", 403},
		{"user", "taken.txt", "x.txt", 403},
		{"", "taken.txt", "x.txt", 401},
	} {
		if resp := rename(f.as(tc.who), "/docs/", tc.from, tc.to); resp.StatusCode != tc.want {
			t.Errorf("%q renames %q to %q: status %d, want %d", tc.who, tc.from, tc.to, resp.StatusCode, tc.want)
		}
	}
	if readFile(t, f.dir, "docs/taken.txt") != "taken" || !exists(filepath.Join(f.dir, "docs", "new", "x.txt")) {
		t.Error("a refused rename changed something")
	}
	resp, body = admin.send(t, "POST", "/docs/", strings.NewReader("rename=taken.txt&to=.x"), "Content-Type", formType)
	if resp.StatusCode != 400 || !strings.Contains(body, "start with a dot") {
		t.Errorf("refused name not explained: %q", body)
	}
	if n := len(f.logs.entries("rename")); n != 2 {
		t.Errorf("%d renames logged", n)
	}
	if l := leftovers(f.dir); len(l) != 1 {
		t.Errorf("leftover files: %v", l)
	}
}

func TestManageForms(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "sub/a.txt", "a")
	resp, _ := f.as("admin").send(t, "POST", "/sub/", strings.NewReader("unknown=1"), "Content-Type", formType)
	expectStatus(t, resp, http.StatusBadRequest)
	// Visitors who may change nothing are refused before the body is read.
	resp, _ = f.as("").send(t, "POST", "/sub/", strings.NewReader("{"), "Content-Type", "application/json")
	expectStatus(t, resp, http.StatusUnauthorized)
	resp, _ = f.as("user").send(t, "POST", "/sub/", strings.NewReader("{"), "Content-Type", "application/json")
	expectStatus(t, resp, http.StatusForbidden)

	// Renaming needs the right to read the entry; deleting does not.
	f.write(t, "drop/a.txt", "a")
	f.write(t, "drop/b.txt", "b")
	for _, act := range []string{auth.ActWrite, auth.ActDelete} {
		if _, err := ta.svc.AddPolicy(auth.Anonymous, "/drop/*", act); err != nil {
			t.Fatal(err)
		}
	}
	anon := f.as("")
	resp, _ = anon.send(t, "POST", "/drop/", strings.NewReader("rename=a.txt&to=c.txt"), "Content-Type", formType)
	expectStatus(t, resp, http.StatusNotFound)
	resp, _ = anon.do(t, "DELETE", "/drop/b.txt")
	expectStatus(t, resp, http.StatusNoContent)

	// Entries another tool hides are left alone.
	f.write(t, "sub/"+lockName("hidden.db"), "another tool's lock")
	f.write(t, "sub/hidden.db", "half written")
	resp, _ = f.as("admin").do(t, "DELETE", "/sub/hidden.db")
	expectStatus(t, resp, http.StatusNotFound)
	if !exists(filepath.Join(f.dir, "sub", "hidden.db")) || !exists(filepath.Join(f.dir, "drop", "a.txt")) {
		t.Error("changed what it should not")
	}
}

// Entries offer renaming, moving, copying, sharing and deleting to visitors
// who may do that.
func TestItemActions(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "a.txt", "a")
	f.write(t, "box/mine.txt", "m")
	f.write(t, "box/other.txt", "o")

	_, body := f.as("admin").do(t, "GET", "/")
	for _, want := range []string{
		`href="?item=a.txt" data-item="a.txt" data-path="/a.txt" data-dir="false" data-rename="true" data-move="true" data-share="true" data-delete="true" aria-label="Rename, move, copy, share or delete a.txt"`,
		`data-item="box" data-path="/box" data-dir="true"`, `<template id="item-actions">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("admin's listing lacks %s", want)
		}
	}
	// Operators may add files, so they may copy entries.
	if _, body := f.as("operator").do(t, "GET", "/"); !strings.Contains(body,
		`data-item="a.txt" data-path="/a.txt" data-dir="false" data-rename="false" data-move="true" data-share="false" data-delete="false" aria-label="Copy a.txt"`) {
		t.Error("operator is not offered copying alone")
	}
	if _, body := f.as("user").do(t, "GET", "/"); strings.Contains(body, `data-item="`) || strings.Contains(body, `<template id="item-actions">`) {
		t.Error("user is offered something to do")
	}

	// Rules decide per entry; renaming also needs the right to create.
	erin := ta.addUser(t, "erin", "user")
	if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/box/mine.txt", auth.ActDelete); err != nil {
		t.Fatal(err)
	}
	e := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: erin}
	_, body = e.do(t, "GET", "/box/")
	if !strings.Contains(body, `data-item="mine.txt" data-path="/box/mine.txt" data-dir="false" data-rename="false" data-move="false" data-share="false" data-delete="true" aria-label="Delete mine.txt"`) ||
		strings.Contains(body, `data-item="other.txt"`) || strings.Contains(body, `class="share-here"`) {
		t.Error("erin's actions do not follow her rules")
	}
	if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/box/other.txt", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	if _, body = e.do(t, "GET", "/box/"); !strings.Contains(body, `data-item="other.txt" data-path="/box/other.txt" data-dir="false" data-rename="false" data-move="false" data-share="true" data-delete="false" aria-label="Share other.txt"`) {
		t.Error("erin may not share what she may")
	}
	for role, want := range map[string]bool{"admin": true, "operator": false} {
		if _, body := f.as(role).do(t, "GET", "/box/"); strings.Contains(body, `<details class="share-here">`) != want {
			t.Errorf("%s: sharing the folder offered = %v", role, !want)
		}
	}

	// Without the page's script, the forms come from the server.
	_, body = f.as("admin").do(t, "GET", "/?item=a.txt")
	for _, want := range []string{`<section class="card manage"`, `name="rename" value="a.txt"`, `name="delete" value="a.txt"`,
		`<input type="hidden" name="path" value="/a.txt">`, `<tr data-name="a.txt" class="selected">`} {
		if !strings.Contains(body, want) {
			t.Errorf("selected entry lacks %s", want)
		}
	}
	if _, body := f.as("user").do(t, "GET", "/?item=a.txt"); strings.Contains(body, `<section class="card manage"`) {
		t.Error("user is shown the forms")
	}
}
