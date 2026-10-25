package server

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"goftp/internal/auth"
	"goftp/internal/config"
)

// signedIn returns a copy of f that sends requests with the session token.
func (f *fixture) signedIn(token string) *fixture {
	c := *f
	c.token = token
	return &c
}

// grant shares the folder at p as owner with user, read or edit, and
// returns the share's ID.
func grant(t *testing.T, owner *fixture, p, user, access string) int64 {
	t.Helper()
	resp, body := post(t, owner, sharesPath, "action=grant&path="+p+"&user="+user+"&access="+access)
	expectStatus(t, resp, http.StatusCreated)
	var out struct {
		ID         int64
		Path, User string
		Access     string
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID == 0 || out.User != user || out.Access != access {
		t.Errorf("granted %s", body)
	}
	return out.ID
}

func TestFolderSharing(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes, func(cfg *config.Config) { cfg.Homes.Quota = 1000 })
	dora := f.signedIn(ta.addUser(t, "dora", "user"))
	erin := f.signedIn(ta.addUser(t, "erin", "user"))
	finn := f.signedIn(ta.addUser(t, "finn", "user"))
	html := []string{"Accept", "text/html"}
	f.write(t, "home/dora/docs/a.txt", "alpha")
	f.write(t, "home/dora/other/o.txt", "other")

	_, body := dora.do(t, "GET", "/home/dora/docs/", html...)
	if !strings.Contains(body, `<details class="people-here">`) || !strings.Contains(body, "Only you can open this folder.") {
		t.Errorf("dora's folder: %s", body)
	}
	if resp, _ := erin.do(t, "GET", "/home/dora/docs/a.txt"); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("erin before: %d", resp.StatusCode)
	}

	for _, tc := range []struct {
		who    *fixture
		form   string
		status int
		detail string
	}{
		{dora, "action=grant&path=/home/dora/docs&user=nobody", 404, "There is no user nobody."},
		{dora, "action=grant&path=/home/dora/docs&user=Dora", 400, "It is yours already"},
		{dora, "action=grant&path=/home/dora/docs&user=", 400, "Say whom"},
		{dora, "action=grant&path=/home/dora/docs&user=erin&access=all", 400, "access=edit"},
		{dora, "action=grant&path=/home/dora/docs/a.txt&user=erin", 400, "Only folders"},
		{dora, "action=grant&path=/home/dora/missing&user=erin", 404, ""},
		{dora, "action=grant&path=/home/erin&user=erin", 403, "your own home"},
		{dora, "action=grant&path=/docs&user=erin", 403, "your own home"},
		{dora, "action=grant&path=/home/dora/.goftp-trash&user=erin", 403, "your own home"},
		{erin, "action=grant&path=/home/dora/docs&user=finn", 403, "your own home"},
		{f.as(""), "action=grant&path=/home/dora/docs&user=erin", 401, ""},
	} {
		resp, body := post(t, tc.who, sharesPath, tc.form)
		if resp.StatusCode != tc.status || !strings.Contains(body, tc.detail) {
			t.Errorf("%s: %d %q", tc.form, resp.StatusCode, body)
		}
	}

	// To see what is in it.
	grant(t, dora, "/home/dora/docs", "erin", "read")
	if resp, body := erin.do(t, "GET", "/home/dora/docs/a.txt"); resp.StatusCode != http.StatusOK || body != "alpha" {
		t.Errorf("erin reads: %d %q", resp.StatusCode, body)
	}
	_, body = erin.do(t, "GET", "/home/dora/docs/", html...)
	if !strings.Contains(body, "Shared with you by <strong>dora</strong>") || !strings.Contains(body, "View only") ||
		!strings.Contains(body, `<a href="/.shares/" aria-current="true">`) ||
		strings.Contains(body, `href="/home/"`) || strings.Contains(body, `href="/home/dora/"`) || strings.Contains(body, "Parent folder") ||
		strings.Contains(body, `<details class="people-here">`) || strings.Contains(body, `<details class="share-here">`) {
		t.Errorf("erin's view: %s", body)
	}
	for _, tc := range []struct {
		who         *fixture
		method, uri string
		form        string
	}{
		{erin, "PUT", "/home/dora/docs/b.txt", "b"},
		{erin, "DELETE", "/home/dora/docs/a.txt", ""},
		{erin, "GET", "/home/dora/other/o.txt", ""},
		{erin, "GET", "/home/dora/", ""},
		{finn, "GET", "/home/dora/docs/a.txt", ""},
	} {
		resp, _ := tc.who.send(t, tc.method, tc.uri, strings.NewReader(tc.form))
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: %d", tc.method, tc.uri, resp.StatusCode)
		}
	}

	// To change it too, from the folder's page.
	resp, _ := post(t, dora, sharesPath, "action=grant&path=/home/dora/docs&user=erin&access=edit", html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/home/dora/docs/?granted=erin" {
		t.Fatalf("granted from a browser: %d %v", resp.StatusCode, resp.Header)
	}
	_, body = dora.do(t, "GET", "/home/dora/docs/?granted=erin", html...)
	if !strings.Contains(body, "Shared with <strong>erin</strong>: they can change what is in it.") ||
		!strings.Contains(body, `<span class="count">1</span>`) || !strings.Contains(body, "erin<span class=\"faint\">Can edit</span>") {
		t.Errorf("confirmed: %s", body)
	}
	if _, body := dora.do(t, "GET", "/home/dora/docs/?granted=finn", html...); strings.Contains(body, `id="granted"`) {
		t.Error("confirms who it is not shared with")
	}
	for _, tc := range []struct {
		method, uri, form string
		want              int
	}{
		{"PUT", "/home/dora/docs/b.txt", "beta", 201},
		{"PUT", "/home/dora/docs/b.txt", "beta 2", 204},
		{"POST", "/home/dora/docs/", "folder=sub", 201},
		{"POST", "/home/dora/docs/", "rename=b.txt&to=c.txt", 201},
		{"DELETE", "/home/dora/docs/c.txt", "", 204},
		{"DELETE", "/home/dora/docs/sub", "", 204},
		// The folder itself stays.
		{"DELETE", "/home/dora/docs", "", 403},
		{"POST", "/home/dora/", "rename=docs&to=mine", 403},
		{"PUT", "/home/dora/x.txt", "x", 403},
		// It is not erin's to share with others.
		{"POST", sharesPath, "action=create&path=/home/dora/docs/a.txt&expires=1d", 403},
	} {
		headers := []string{}
		if tc.method == "POST" {
			headers = []string{"Content-Type", formType}
		}
		if resp, body := erin.send(t, tc.method, tc.uri, strings.NewReader(tc.form), headers...); resp.StatusCode != tc.want {
			t.Errorf("erin %s %s %s: %d %s", tc.method, tc.uri, tc.form, resp.StatusCode, body)
		}
	}
	if readFile(t, f.dir, "home/dora/docs/a.txt") != "alpha" || exists(f.dir+"/home/dora/docs/c.txt") {
		t.Error("what erin did")
	}
	// What erin deleted is in the trash, for both.
	for _, who := range []*fixture{erin, dora} {
		if _, body := who.do(t, "GET", "/.trash/", html...); !strings.Contains(body, "c.txt") {
			t.Errorf("trash: %s", body)
		}
	}
	// What they add counts against the owner's home.
	resp, _ = erin.send(t, "PUT", "/home/dora/docs/big.bin", strings.NewReader(strings.Repeat("x", 1200)))
	expectStatus(t, resp, http.StatusInsufficientStorage)
	resp, _ = erin.send(t, "PUT", "/home/erin/big.bin", strings.NewReader(strings.Repeat("x", 900)))
	expectStatus(t, resp, http.StatusCreated)

	// The Shared pages of both, and of a superadmin, who sees nothing of
	// where it is.
	_, body = dora.do(t, "GET", sharesPath, html...)
	if !strings.Contains(body, "Folders you share with people") || !strings.Contains(body, `<a href="/home/dora/docs/">`) ||
		!strings.Contains(body, "Can edit") || strings.Contains(body, "Shared with you") {
		t.Errorf("dora's Shared: %s", body)
	}
	_, body = erin.do(t, "GET", sharesPath, html...)
	if !strings.Contains(body, "Shared with you") || !strings.Contains(body, `<a href="/home/dora/docs/">`) || !strings.Contains(body, "You share no folders with people.") {
		t.Errorf("erin's Shared: %s", body)
	}
	_, body = f.as("superadmin").do(t, "GET", sharesPath, html...)
	if !strings.Contains(body, "Private folder") || strings.Contains(body, "/home/dora/docs") || !strings.Contains(body, "<th>Owner</th>") {
		t.Errorf("superadmin's Shared: %s", body)
	}
	if _, body := erin.do(t, "GET", "/", html...); !strings.Contains(body, `href="/.shares/"`) {
		t.Error("no Shared tab")
	}

	// It follows the folder within the home.
	resp, _ = post(t, dora, "/home/dora/", "rename=docs&to=papers")
	expectStatus(t, resp, http.StatusCreated)
	resp, _ = post(t, dora, "/home/dora/", "folder=archive")
	expectStatus(t, resp, http.StatusCreated)
	resp, _ = post(t, dora, "/home/dora/", "move=papers&into=/home/dora/archive")
	expectStatus(t, resp, http.StatusCreated)
	if resp, body := erin.do(t, "GET", "/home/dora/archive/papers/a.txt"); resp.StatusCode != http.StatusOK || body != "alpha" {
		t.Errorf("after moves: %d %q", resp.StatusCode, body)
	}
	if resp, _ := erin.do(t, "GET", "/home/dora/archive/"); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("the folder it moved to: %d", resp.StatusCode)
	}
	// And ends with it.
	resp, _ = dora.do(t, "DELETE", "/home/dora/archive")
	expectStatus(t, resp, http.StatusNoContent)
	if shares, err := ta.svc.SharedWith(t.Context(), &auth.User{ID: idOf(t, ta, "erin")}); err != nil || len(shares) != 0 {
		t.Errorf("after the folder was deleted: %v, %v", shares, err)
	}
	// Restored, it is dora's alone.
	_, body = dora.do(t, "GET", "/.trash/", html...)
	if !strings.Contains(body, "archive") {
		t.Fatalf("trash: %s", body)
	}

	// Its owner stops sharing it, or its user leaves it; superadmins may
	// end any share, nobody else.
	id := grant(t, dora, "/home/dora/other", "erin", "read")
	if resp, _ := post(t, finn, sharesPath, "action=ungrant&id="+strconv.FormatInt(id, 10)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("finn ended it: %d", resp.StatusCode)
	}
	resp, _ = post(t, erin, sharesPath, "action=ungrant&id="+strconv.FormatInt(id, 10), html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != sharesPath+"?done=left" {
		t.Errorf("erin left: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := erin.do(t, "GET", "/home/dora/other/o.txt"); resp.StatusCode == http.StatusOK {
		t.Error("erin still reads")
	}
	id = grant(t, dora, "/home/dora/other", "erin", "read")
	resp, _ = post(t, dora, sharesPath, "action=ungrant&back=1&id="+strconv.FormatInt(id, 10), html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/home/dora/other/?ungranted=1" {
		t.Errorf("dora stopped: %d %v", resp.StatusCode, resp.Header)
	}
	id = grant(t, dora, "/home/dora/other", "finn", "read")
	if resp, _ := post(t, f.as("superadmin"), sharesPath, "action=ungrant&id="+strconv.FormatInt(id, 10)); resp.StatusCode != http.StatusNoContent {
		t.Errorf("superadmin: %d", resp.StatusCode)
	}
	resp, body = post(t, dora, sharesPath, "action=ungrant&id="+strconv.FormatInt(id, 10), html...)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "It is not shared anymore") {
		t.Errorf("twice: %d %s", resp.StatusCode, body)
	}

	// A home shared whole.
	grant(t, dora, "/home/dora", "finn", "read")
	if _, body := finn.do(t, "GET", "/home/dora/", html...); !strings.Contains(body, "<h1>Home of dora") {
		t.Errorf("dora's home: %s", body)
	}
}

func TestFolderSharesInDav(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	dora := f.signedIn(ta.addUser(t, "dora", "user"))
	ta.addUser(t, "erin", "user")
	ta.addUser(t, "finn", "user")
	f.write(t, "home/dora/docs/a.txt", "alpha")
	f.write(t, "home/dora/new/n.txt", "new")
	f.write(t, "home/dora/other/o.txt", "other")
	grant(t, dora, "/home/dora/docs", "erin", "edit")
	grant(t, dora, "/home/dora/new", "finn", "read")
	erin, finn, doraDav := davAs(t, f, "erin"), davAs(t, f, "finn"), davAs(t, f, "dora")

	// The way to it is shown, and nothing else of dora's.
	keys := func(m map[string]davEntry) []string { return slices.Sorted(maps.Keys(m)) }
	if got := keys(erin.propfind(t, "/.dav/home/", "1", "")); !slices.Equal(got, []string{"/.dav/home/", "/.dav/home/dora/", "/.dav/home/erin/"}) {
		t.Errorf("homes: %v", got)
	}
	if got := keys(erin.propfind(t, "/.dav/home/dora/", "1", "")); !slices.Equal(got, []string{"/.dav/home/dora/", "/.dav/home/dora/docs/"}) {
		t.Errorf("dora's home: %v", got)
	}
	if got := keys(erin.propfind(t, "/.dav/home/dora/docs/", "1", "")); !slices.Equal(got, []string{"/.dav/home/dora/docs/", "/.dav/home/dora/docs/a.txt"}) {
		t.Errorf("the shared folder: %v", got)
	}
	if resp, _ := erin.do(t, "PROPFIND", "/.dav/home/dora/other/", "Depth", "0"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another folder: %d", resp.StatusCode)
	}
	resp, _ := erin.send(t, "PUT", "/.dav/home/dora/docs/b.txt", strings.NewReader("b"))
	expectStatus(t, resp, http.StatusCreated)

	// A folder that takes the place of a shared one does not take its
	// shares, but keeps its own.
	resp, _ = doraDav.do(t, "MOVE", "/.dav/home/dora/new/", "Destination", "/.dav/home/dora/docs/", "Overwrite", "T")
	expectStatus(t, resp, http.StatusNoContent)
	if resp, _ := erin.do(t, "GET", "/.dav/home/dora/docs/n.txt"); resp.StatusCode == http.StatusOK {
		t.Error("erin reads what replaced the folder")
	}
	if resp, body := finn.do(t, "GET", "/.dav/home/dora/docs/n.txt"); resp.StatusCode != http.StatusOK || body != "new" {
		t.Errorf("finn: %d %q", resp.StatusCode, body)
	}
	// A move that fails, once the folder was set aside, keeps them.
	f.write(t, "home/dora/other/keep/k.txt", "kept")
	if ok, err := ta.svc.AddPolicy(auth.Subject("dora"), "!/home/dora/other/keep/*", auth.ActDelete); !ok || err != nil {
		t.Fatal(ok, err)
	}
	resp, _ = doraDav.do(t, "MOVE", "/.dav/home/dora/other/", "Destination", "/.dav/home/dora/docs/", "Overwrite", "T")
	if resp.StatusCode != http.StatusForbidden || readFile(t, f.dir, "home/dora/docs/n.txt") != "new" {
		t.Fatalf("move: %d", resp.StatusCode)
	}
	if resp, _ := finn.do(t, "GET", "/.dav/home/dora/docs/n.txt"); resp.StatusCode != http.StatusOK {
		t.Errorf("finn after a failed move: %d", resp.StatusCode)
	}
}
