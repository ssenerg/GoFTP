package server

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// Entries can be ticked to be downloaded, moved, copied or deleted
// together.
func TestPick(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "alpha")
	f.write(t, "b.txt", "beta")
	f.write(t, "c.txt", "gamma")
	f.write(t, "sub/d.txt", "delta")
	f.write(t, "to/.keep", "")

	for role, want := range map[string]string{
		"user":     "Tick entries to download them together.",
		"operator": "Tick entries to download or copy them together.",
		"admin":    "Tick entries to download, move, copy or delete them together.",
	} {
		_, body := f.as(role).do(t, "GET", "/")
		if !strings.Contains(body, `<input type="checkbox" name="pick" value="a.txt" form="picked" aria-label="Pick a.txt">`) ||
			!strings.Contains(body, want) {
			t.Errorf("%s: no checkboxes, or no %q", role, want)
		}
		if strings.Contains(body, `value="delete"`) != (role == "admin") || strings.Contains(body, `value="copy"`) != (role != "user") {
			t.Errorf("%s is offered the wrong actions", role)
		}
	}

	// A zip of what is picked.
	resp, body := f.as("user").do(t, "GET", "/?pick=a.txt&pick=sub&pick=nope&pick=.keep&zip=")
	expectStatus(t, resp, http.StatusOK)
	names, contents := zipEntries(t, body)
	if strings.Join(names, " ") != "a.txt sub/ sub/d.txt" || contents["sub/d.txt"] != "delta" {
		t.Errorf("zip holds %v", names)
	}

	// Picked entries are deleted together; the first that fails stops
	// the rest, saying what was deleted.
	admin := f.as("admin")
	resp, _ = post(t, admin, "/", "op=delete&pick=a.txt&pick=b.txt", "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/?deleted=2" {
		t.Errorf("Location %q", got)
	}
	if exists(filepath.Join(f.dir, "a.txt")) || exists(filepath.Join(f.dir, "b.txt")) {
		t.Error("not deleted")
	}
	resp, body = post(t, admin, "/", "op=delete&pick=c.txt&pick=nope.txt")
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Deleted before the error: c.txt.") {
		t.Errorf("partial deletion: %d %q", resp.StatusCode, body)
	}
	if resp, body := post(t, admin, "/", "op=delete"); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Pick what to delete first.") {
		t.Errorf("nothing picked: %d %q", resp.StatusCode, body)
	}
	// JSON clients send several names as an array.
	f.write(t, "x.txt", "x")
	f.write(t, "y.txt", "y")
	resp, _ = admin.send(t, "POST", "/", strings.NewReader(`{"copy":["x.txt","y.txt"],"into":"/to"}`), "Content-Type", "application/json")
	expectStatus(t, resp, http.StatusCreated)
	if readFile(t, f.dir, "to/x.txt") != "x" || readFile(t, f.dir, "to/y.txt") != "y" {
		t.Error("not copied")
	}
	for _, body := range []string{`{"copy":[1],"into":"/to"}`, `{"copy":{"a":"b"}}`} {
		if resp, _ := admin.send(t, "POST", "/", strings.NewReader(body), "Content-Type", "application/json"); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", body, resp.StatusCode)
		}
	}

	// Through a link, picked entries download too.
	f.write(t, "docs/e.txt", "epsilon")
	f.write(t, "docs/f.txt", "phi")
	link := sharePrefix + createShare(t, f, "admin", "/docs", "1h", "")
	_, body = f.as("").do(t, "GET", link+"/", "Accept", "text/html")
	if !strings.Contains(body, `<form id="picked" class="picked" method="post" action="`+link+`/">`) || strings.Contains(body, `value="delete"`) {
		t.Errorf("link page: %s", body)
	}
	resp, body = f.as("").do(t, "GET", link+"/?pick=f.txt&zip=")
	expectStatus(t, resp, http.StatusOK)
	if names, _ := zipEntries(t, body); strings.Join(names, " ") != "f.txt" {
		t.Errorf("link zip holds %v", names)
	}
}
