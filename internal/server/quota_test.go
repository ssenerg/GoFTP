package server

import (
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"goftp/internal/config"
)

// A home holds up to its quota, along with what its user deleted from it.
func TestHomeQuota(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes, func(cfg *config.Config) { cfg.Homes.Quota = 10 })
	f.write(t, "docs/big.txt", "0123456789ab")
	f.write(t, "docs/small.txt", "abc")
	dora := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "dora", "user")}

	resp, _ := dora.send(t, "PUT", "/home/dora/a.txt", strings.NewReader("123456"))
	expectStatus(t, resp, http.StatusCreated)
	resp, body := dora.send(t, "PUT", "/home/dora/b.txt", strings.NewReader("12345"))
	if resp.StatusCode != http.StatusInsufficientStorage || !strings.Contains(body, "no room for it in this home") {
		t.Errorf("over the quota: %d %q", resp.StatusCode, body)
	}
	// Replacing a file makes room for its new content.
	resp, _ = dora.send(t, "PUT", "/home/dora/a.txt", strings.NewReader("1234567890"))
	expectStatus(t, resp, http.StatusNoContent)
	// Resumable and form uploads too.
	if resp, _ := tus(t, dora, "POST", "/home/dora/", "", "Upload-Length", "1", "Upload-Metadata", metadata("c.txt")); resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("resumable: %d", resp.StatusCode)
	}
	form, ctype := multipartForm(t, formPart{field: "file", filename: "d.txt", content: "d"})
	if resp, _ := dora.send(t, "POST", "/home/dora/", form, "Content-Type", ctype); resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("form: %d", resp.StatusCode)
	}
	if got := slices.DeleteFunc(leftovers(filepath.Join(f.dir, "home", "dora")), func(p string) bool {
		return filepath.Base(p) == homeOwner
	}); len(got) != 0 {
		t.Errorf("left behind: %v", got)
	}
	_, body = dora.do(t, "GET", "/home/dora/")
	if !strings.Contains(body, "10 B of 10 B used") || !strings.Contains(body, `class="usage full"`) || !strings.Contains(body, `aria-valuenow="100"`) {
		t.Errorf("usage bar: %s", body)
	}

	// Deleting makes room once the trash is emptied.
	resp, _ = dora.do(t, "DELETE", "/home/dora/a.txt")
	expectStatus(t, resp, http.StatusNoContent)
	id := resp.Header.Get(trashIDsHeader)
	if resp, _ := dora.send(t, "PUT", "/home/dora/b.txt", strings.NewReader("1")); resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("with a full trash: %d", resp.StatusCode)
	}
	if _, body := dora.do(t, "GET", "/home/dora/"); !strings.Contains(body, "10 B of 10 B used, 10 B of it in the <a href=\"/.trash/\">trash</a>") {
		t.Errorf("usage bar with the trash: %s", body)
	}
	resp, _ = trashForm(t, dora, "action=purge&id="+id)
	expectStatus(t, resp, http.StatusNoContent)
	resp, _ = dora.send(t, "PUT", "/home/dora/b.txt", strings.NewReader("1234"))
	expectStatus(t, resp, http.StatusCreated)

	// Moving and copying into a home take room there.
	admin := f.as("superadmin")
	if _, err := ta.svc.AddPolicy("superadmin", "/home/*", "*"); err != nil {
		t.Fatal(err)
	}
	if resp, _ := post(t, admin, "/docs/", "move=big.txt&into=/home/dora"); resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("moving in: %d", resp.StatusCode)
	}
	if resp, _ := post(t, admin, "/", "copy=docs&into=/home/dora"); resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("copying in: %d", resp.StatusCode)
	}
	if exists(filepath.Join(f.dir, "home", "dora", "docs")) || !exists(filepath.Join(f.dir, "docs", "big.txt")) {
		t.Error("moved or copied anyway")
	}
	resp, _ = post(t, admin, "/docs/", "move=small.txt&into=/home/dora")
	expectStatus(t, resp, http.StatusCreated)

	// What is set for a user comes first.
	resp, _ = post(t, admin, usersPath, "action=quota&user=dora&quota=1KiB", "Accept", "text/html")
	if got := resp.Header.Get("Location"); got != usersPath+"?done=quota" {
		t.Errorf("Location %q", got)
	}
	resp, _ = dora.send(t, "PUT", "/home/dora/big.txt", strings.NewReader(strings.Repeat("x", 500)))
	expectStatus(t, resp, http.StatusCreated)
	if _, body := admin.do(t, "GET", usersPath); !strings.Contains(body, `name="quota" value="1KiB"`) || !strings.Contains(body, `placeholder="Default (10B)"`) {
		t.Errorf("users page: %s", body)
	}
	post(t, admin, usersPath, "action=quota&user=dora&quota=none")
	resp, _ = dora.send(t, "PUT", "/home/dora/huge.txt", strings.NewReader(strings.Repeat("x", 2000)))
	expectStatus(t, resp, http.StatusCreated)
	if _, body := dora.do(t, "GET", "/home/dora/"); strings.Contains(body, `class="usage-bar"`) || !strings.Contains(body, " used") {
		t.Errorf("no limit: %s", body)
	}
	if resp, body := post(t, admin, usersPath, "action=quota&user=dora&quota=lots"); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Give a home quota") {
		t.Errorf("a bad quota: %d", resp.StatusCode)
	}
}

// What is sent through an upload link into a home counts against its
// quota; a link may also take a limited size itself.
func TestLinkMaxSize(t *testing.T) {
	f := newFixture(t)
	f.write(t, "inbox/.keep", "")
	admin, anon := f.as("admin"), f.as("")
	if resp, _ := admin.send(t, "POST", sharesPath, strings.NewReader("action=create&expires=1d&path=/inbox&max_size=10"),
		"Content-Type", formType); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a size for a read link: %d", resp.StatusCode)
	}
	drop, info := createLink(t, admin, url.Values{"path": {"/inbox"}, "kind": {"upload"}, "max_size": {"10B"}})
	if info["max_bytes"] != 10.0 || info["max_size"] != "10 B" {
		t.Errorf("created %v", info)
	}
	if _, body := anon.do(t, "GET", drop+"/", "Accept", "text/html"); !strings.Contains(body, "up to 10 B more") {
		t.Error("the drop box does not say how much it takes")
	}
	loc := startResumable(t, anon, drop+"/", "a.txt", 6)
	if resp, body := tus(t, anon, "POST", drop+"/", "", "Upload-Length", "6", "Upload-Metadata", metadata("b.txt")); resp.StatusCode != http.StatusRequestEntityTooLarge ||
		!strings.Contains(body, "at most 4 B more") {
		t.Errorf("past the size: %d %q", resp.StatusCode, body)
	}
	// A cancelled upload gives its size back.
	if resp, _ := tus(t, anon, "DELETE", loc, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel: %d", resp.StatusCode)
	}
	loc = startResumable(t, anon, drop+"/", "b.txt", 6)
	expectStatus(t, patchAt(t, anon, loc, 0, "123456"), http.StatusNoContent)
	// Forms take as much as the whole request at first.
	form, ctype := multipartForm(t, formPart{field: "file", filename: "c.txt", content: "c"})
	if resp, _ := anon.send(t, "POST", drop+"/", form, "Content-Type", ctype); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("a form past the size: %d", resp.StatusCode)
	}
	_, body := admin.do(t, "GET", sharesPath, "Accept", "text/html")
	if !strings.Contains(body, "1 file, 6 B of 10 B") {
		t.Errorf("Shared tab: %s", body)
	}

	// Without a size, what was sent is still counted.
	free, _ := createLink(t, admin, url.Values{"path": {"/inbox"}, "kind": {"upload"}})
	form, ctype = multipartForm(t, formPart{field: "file", filename: "d.txt", content: "dddd"})
	if resp, _ := anon.send(t, "POST", free+"/", form, "Content-Type", ctype); resp.StatusCode != http.StatusCreated {
		t.Fatalf("form: %d", resp.StatusCode)
	}
	if _, body := admin.do(t, "GET", sharesPath, "Accept", "text/html"); !strings.Contains(body, "1 file, 4 B") {
		t.Errorf("Shared tab without a size: %s", body)
	}

	// Into a home, what its quota leaves.
	ta := newTestAuth(t)
	g := newFixtureWith(t, ta, withHomes, func(cfg *config.Config) { cfg.Homes.Quota = 5 })
	ed := &fixture{srv: g.srv, dir: g.dir, logs: g.logs, auth: ta, token: ta.addUser(t, "ed", "user")}
	inbox, _ := createLink(t, ed, url.Values{"path": {"/home/ed"}, "kind": {"upload"}})
	if resp, _ := tus(t, g.as(""), "POST", inbox+"/", "", "Upload-Length", "6", "Upload-Metadata", metadata("e.txt")); resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("into a full home: %d", resp.StatusCode)
	}
}
