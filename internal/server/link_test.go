package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goftp/internal/auth"
)

// createLink makes a link as f's user with the fields of form, and returns
// its path and what the server said of it.
func createLink(t *testing.T, f *fixture, form url.Values) (string, map[string]any) {
	t.Helper()
	form.Set("action", "create")
	if !form.Has("expires") {
		form.Set("expires", "1h")
	}
	resp, body := f.send(t, "POST", sharesPath, strings.NewReader(form.Encode()), "Content-Type", formType)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating %v: %d %s", form, resp.StatusCode, body)
	}
	var link map[string]any
	if err := json.Unmarshal([]byte(body), &link); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(u.Path, "/"), link
}

func TestUploadLink(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "inbox/secret.txt", "mine")
	f.write(t, "inbox/sub/deep.txt", "deep")
	f.write(t, "file.txt", "f")
	admin := f.as("admin")
	link, info := createLink(t, admin, url.Values{"path": {"/inbox"}, "kind": {"upload"}})
	if info["upload"] != true || info["max_uses"] != 0.0 {
		t.Errorf("created %v", info)
	}
	anon := f.as("")

	// The page takes files, and shows nothing of what is there.
	resp, body := anon.do(t, "GET", link+"/", "Accept", "text/html")
	expectStatus(t, resp, http.StatusOK)
	if !strings.Contains(body, "Send files to inbox") || !strings.Contains(body, `<form id="upload" class="upload" method="post" enctype="multipart/form-data" action="`+link+`/" data-dropbox="true">`) ||
		strings.Contains(body, "secret") || strings.Contains(body, "sub/") || strings.Contains(body, "deep") {
		t.Errorf("drop box page: %s", body)
	}
	for _, p := range []string{"/secret.txt", "/sub/", "/sub/deep.txt", "/?zip"} {
		resp, body := anon.do(t, "GET", link+p)
		if strings.Contains(body, "mine") || strings.Contains(body, "deep") || (p != "/?zip" && resp.StatusCode != http.StatusNotFound) {
			t.Errorf("GET %s through an upload link: %d %q", p, resp.StatusCode, body)
		}
	}

	// Resumable uploads, under a free name when it is taken.
	loc := startResumable(t, anon, link+"/", "secret.txt", 5)
	expectStatus(t, patchAt(t, anon, loc, 0, "yours"), http.StatusNoContent)
	if readFile(t, f.dir, "inbox/secret.txt") != "mine" || readFile(t, f.dir, "inbox/secret (2).txt") != "yours" {
		t.Error("a taken name was not kept, or the upload not stored")
	}
	loc = startResumable(t, anon, link+"/", "new.txt", 3, "replace=1")
	expectStatus(t, patchAt(t, anon, loc, 0, "new"), http.StatusNoContent)
	if readFile(t, f.dir, "inbox/new.txt") != "new" {
		t.Error("not stored")
	}
	// Forms, for browsers without the page's script.
	form, ctype := multipartForm(t, formPart{field: "file", filename: "secret.txt", content: "form"}, formPart{field: "file", filename: "b.txt", content: "b"})
	resp, _ = anon.send(t, "POST", link+"/", form, "Content-Type", ctype, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != link+"/?uploaded=2" {
		t.Errorf("Location %q", got)
	}
	if readFile(t, f.dir, "inbox/secret (3).txt") != "form" || readFile(t, f.dir, "inbox/b.txt") != "b" {
		t.Error("form upload not stored")
	}
	if _, body := anon.do(t, "GET", link+"/?uploaded=2", "Accept", "text/html"); !strings.Contains(body, "Sent 2 files.") {
		t.Error("not thanked")
	}
	if e := f.logs.entries("upload"); len(e) != 4 || e[0]["path"] != "/inbox/secret (2).txt" || e[0]["user"] != auth.Anonymous {
		t.Errorf("logged %v", e)
	}

	for _, tc := range []struct {
		name string
		form url.Values
		want int
	}{
		{"file", url.Values{"path": {"/file.txt"}, "kind": {"upload"}}, 400},
		{"bad kind", url.Values{"path": {"/inbox"}, "kind": {"write"}}, 400},
		{"bad limit", url.Values{"path": {"/inbox"}, "max_uses": {"many"}}, 400},
		{"negative limit", url.Values{"path": {"/inbox"}, "max_uses": {"-1"}}, 400},
	} {
		tc.form.Set("action", "create")
		tc.form.Set("expires", "1h")
		if resp, _ := admin.send(t, "POST", sharesPath, strings.NewReader(tc.form.Encode()), "Content-Type", formType); resp.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
	// Files go through upload links only, and with their password.
	readLink, _ := createLink(t, admin, url.Values{"path": {"/inbox"}})
	locked, _ := createLink(t, admin, url.Values{"path": {"/inbox"}, "kind": {"upload"}, "password": {"correct horse"}})
	for _, l := range []string{readLink, locked} {
		resp, body := tus(t, anon, "POST", l+"/", "", "Upload-Length", "1", "Upload-Metadata", metadata("x.txt"))
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST to %s: %d %q", l, resp.StatusCode, body)
		}
	}
	if resp, _ := tus(t, anon, "POST", link+"/sub/", "", "Upload-Length", "1", "Upload-Metadata", metadata("x.txt")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST into a folder below: %d", resp.StatusCode)
	}

	// A link works while its creator may add files there.
	erin := ta.addUser(t, "erin", "user")
	for _, act := range []string{auth.ActShare, auth.ActWrite} {
		if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/inbox/*", act); err != nil {
			t.Fatal(err)
		}
	}
	e := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: erin}
	erinLink, _ := createLink(t, e, url.Values{"path": {"/inbox"}, "kind": {"upload"}})
	loc = startResumable(t, anon, erinLink+"/", "late.txt", 4)
	if _, err := ta.svc.RemovePolicy(auth.Subject("erin"), "/inbox/*", auth.ActWrite); err != nil {
		t.Fatal(err)
	}
	if resp := patchAt(t, anon, loc, 0, "late"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("upload after the creator lost the right: %d", resp.StatusCode)
	}
	// The sender may still cancel it.
	if resp, _ := tus(t, anon, "DELETE", loc, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("cancelling: %d", resp.StatusCode)
	}
	if resp, _ := anon.do(t, "GET", erinLink+"/"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("page after the creator lost the right: %d", resp.StatusCode)
	}
	if resp, _ := e.send(t, "POST", sharesPath, strings.NewReader("action=create&expires=1h&kind=upload&path=/inbox"), "Content-Type", formType); resp.StatusCode != http.StatusForbidden {
		t.Errorf("creating an upload link without the right to add files: %d", resp.StatusCode)
	}
	// Revoked links take no more data.
	loc = startResumable(t, anon, link+"/", "cut.txt", 4)
	var id int64
	shares, _ := ta.svc.Shares(t.Context(), nil, true)
	for _, sh := range shares {
		if sh.Upload && sh.Path == "/inbox" && sh.PasswordHash == "" && sh.Creator == userOfRole("admin") {
			id = sh.ID
		}
	}
	if err := ta.svc.RevokeShare(t.Context(), nil, id, true); err != nil {
		t.Fatal(err)
	}
	if resp := patchAt(t, anon, loc, 0, "cut!"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("upload through a revoked link: %d", resp.StatusCode)
	}
	if exists(filepath.Join(f.dir, "inbox", "cut.txt")) || len(partials(f.dir)) != 0 {
		t.Errorf("left %v", partials(f.dir))
	}
}

func TestLinkLimits(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "0123456789")
	f.write(t, "docs/b.txt", "b")
	admin := f.as("admin")
	anon := f.as("")

	// A file link that allows two downloads.
	link, info := createLink(t, admin, url.Values{"path": {"/a.txt"}, "max_uses": {"2"}})
	if info["max_uses"] != 2.0 {
		t.Errorf("created %v", info)
	}
	_, body := admin.do(t, "GET", sharesPath, "Accept", "text/html")
	if !strings.Contains(body, "0 of 2 downloads<span class=\"faint\">, never opened") {
		t.Errorf("fresh link: %s", body)
	}
	// Its page, HEAD requests and parts from later on do not count.
	for _, req := range [][]string{{"GET", "/"}, {"HEAD", "/a.txt"}, {"GET", "/a.txt", "Range", "bytes=5-"}} {
		resp, _ := anon.do(t, req[0], link+req[1], req[2:]...)
		if resp.StatusCode >= 300 {
			t.Errorf("%v: %d", req, resp.StatusCode)
		}
	}
	for i, want := range []int{200, 206, 410} {
		headers := []string{}
		if i == 1 {
			headers = []string{"Range", "bytes=0-3"}
		}
		if resp, _ := anon.do(t, "GET", link+"/a.txt", headers...); resp.StatusCode != want {
			t.Errorf("download %d: %d, want %d", i+1, resp.StatusCode, want)
		}
	}
	// Used up, nothing of it works, and it says why.
	resp, body := anon.do(t, "GET", link+"/", "Accept", "text/html")
	if resp.StatusCode != http.StatusGone || !strings.Contains(body, "used as often as it may be") {
		t.Errorf("used up: %d %s", resp.StatusCode, body)
	}
	if resp, _ := anon.do(t, "GET", link+"/a.txt", "Range", "bytes=5-"); resp.StatusCode != http.StatusGone {
		t.Errorf("part of a used-up link: %d", resp.StatusCode)
	}
	_, body = admin.do(t, "GET", sharesPath, "Accept", "text/html")
	if !strings.Contains(body, "2 of 2 downloads") || !strings.Contains(body, ">used up</span>") || !strings.Contains(body, ", last <time datetime=") {
		t.Errorf("Shared tab: %s", body)
	}

	// A zip is one download.
	folder, _ := createLink(t, admin, url.Values{"path": {"/docs"}, "max_uses": {"1"}})
	if resp, _ := anon.do(t, "GET", folder+"/?zip"); resp.StatusCode != http.StatusOK {
		t.Errorf("zip: %d", resp.StatusCode)
	}
	if resp, _ := anon.do(t, "GET", folder+"/b.txt"); resp.StatusCode != http.StatusGone {
		t.Errorf("after the zip: %d", resp.StatusCode)
	}

	// Upload links count files.
	f.write(t, "inbox/.keep", "")
	drop, _ := createLink(t, admin, url.Values{"path": {"/inbox"}, "kind": {"upload"}, "max_uses": {"1"}})
	if _, body := anon.do(t, "GET", drop+"/", "Accept", "text/html"); !strings.Contains(body, "1 more file may be sent") {
		t.Error("the drop box does not say how many files it takes")
	}
	loc := startResumable(t, anon, drop+"/", "one.txt", 1)
	expectStatus(t, patchAt(t, anon, loc, 0, "1"), http.StatusNoContent)
	if resp, _ := tus(t, anon, "POST", drop+"/", "", "Upload-Length", "1", "Upload-Metadata", metadata("two.txt")); resp.StatusCode != http.StatusGone {
		t.Errorf("a second file: %d", resp.StatusCode)
	}
	_, body = admin.do(t, "GET", sharesPath, "Accept", "text/html")
	if !strings.Contains(body, "1 of 1 file") || !strings.Contains(body, ">upload</span>") {
		t.Errorf("Shared tab: %s", body)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "inbox", "two.txt")); err == nil {
		t.Error("stored past the limit")
	}

	// Browsers are told of the limit when the link is made.
	resp, body = admin.send(t, "POST", sharesPath, strings.NewReader("action=create&expires=1d&path=/inbox&kind=upload&max_uses=5"),
		"Content-Type", formType, "Accept", "text/html")
	expectStatus(t, resp, http.StatusCreated)
	if !strings.Contains(body, "can upload files to <strong>inbox</strong> until") || !strings.Contains(body, ", 5 files at most:") {
		t.Errorf("created page: %s", body)
	}
}
