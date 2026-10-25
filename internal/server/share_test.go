package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
)

// createShare makes a link as role, or as f's user for "", and returns its
// token.
func createShare(t *testing.T, f *fixture, role, p, expires, password string) string {
	t.Helper()
	if role != "" {
		f = f.as(role)
	}
	form := url.Values{"action": {"create"}, "path": {p}, "expires": {expires}, "password": {password}}
	resp, body := f.send(t, "POST", sharesPath, strings.NewReader(form.Encode()), "Content-Type", formType)
	expectStatus(t, resp, http.StatusCreated)
	var link struct {
		ID        int64  `json:"id"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(body), &link); err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	token, ok := strings.CutPrefix(link.URL, "http://example.com"+sharePrefix)
	if !ok || !strings.HasSuffix(token, "/") || !auth.ValidToken(strings.TrimSuffix(token, "/")) || link.ID == 0 {
		t.Fatalf("link %+v", link)
	}
	if exp, err := time.Parse(time.RFC3339, link.ExpiresAt); err != nil || exp.Before(time.Now()) {
		t.Errorf("expires_at %q", link.ExpiresAt)
	}
	return strings.TrimSuffix(token, "/")
}

func TestShareCreate(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/a.txt", "alpha")
	f.write(t, "docs/b.txt", "beta")
	f.write(t, ".env", "x")
	post := func(role, form string, headers ...string) (*http.Response, string) {
		return f.as(role).send(t, "POST", sharesPath, strings.NewReader(form), append([]string{"Content-Type", formType}, headers...)...)
	}

	createShare(t, f, "admin", "/docs/a.txt", "1d", "")
	createShare(t, f, "superadmin", "/", "1h", "")
	for role, want := range map[string]int{"": 401, "user": 403, "operator": 403} {
		if resp, _ := post(role, "action=create&path=/docs/a.txt&expires=1d"); resp.StatusCode != want {
			t.Errorf("%q: %d, want %d", role, resp.StatusCode, want)
		}
	}
	for form, want := range map[string]int{
		"action=create&path=/docs/a.txt&expires=2d":                400,
		"action=create&path=/docs/a.txt":                           400,
		"action=create&expires=1d":                                 400,
		"action=create&path=docs/a.txt&expires=1d":                 400,
		"action=create&path=/docs/a.txt%00&expires=1d":             400,
		"action=create&path=/.env&expires=1d":                      404,
		"action=create&path=/docs/nope.txt&expires=1d":             404,
		"action=create&path=/docs/a.txt&expires=1d&password=short": 400,
		"action=share&path=/docs/a.txt&expires=1d":                 400,
	} {
		if resp, _ := post("admin", form); resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", form, resp.StatusCode, want)
		}
	}

	// Rules decide per path, also for users who may not share elsewhere.
	erin := ta.addUser(t, "erin", "user")
	if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/docs/a.txt", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	e := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: erin}
	for p, want := range map[string]int{"/docs/a.txt": 201, "/docs/b.txt": 403, "/docs": 403} {
		if resp, _ := e.send(t, "POST", sharesPath, strings.NewReader("action=create&expires=1h&path="+p), "Content-Type", formType); resp.StatusCode != want {
			t.Errorf("erin sharing %s: %d, want %d", p, resp.StatusCode, want)
		}
	}

	// Browsers get the link on a page, once.
	resp, body := post("admin", "action=create&path=/docs/&expires=7d&password=correct+horse", "Accept", "text/html")
	expectStatus(t, resp, http.StatusCreated)
	if !regexp.MustCompile(`<code id="share-link">http://example.com/\.share/[A-Za-z0-9_-]{43}/</code>`).MatchString(body) ||
		!strings.Contains(body, "and its password") || !strings.Contains(body, "<strong>docs</strong>") {
		t.Errorf("link not shown: %s", body)
	}
	created := f.logs.entries("share created")
	if len(created) != 4 || created[3]["path"] != "/docs" || created[3]["password"] != true || created[3]["user"] != userOfRole("admin") {
		t.Errorf("logged %v", created)
	}
	if strings.Contains(f.logs.raw(), "correct horse") {
		t.Error("a link password was logged")
	}
}

func TestShareFolder(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/a.txt", "alpha")
	f.write(t, "docs/sub/b.txt", "beta")
	f.write(t, "docs/.hidden", "h")
	f.write(t, "docs/busy.txt", "half written")
	f.write(t, "docs/"+lockName("busy.txt"), "another tool's lock")
	f.write(t, "secret.txt", "outside the link")
	token := createShare(t, f, "admin", "/docs", "1d", "")
	link := sharePrefix + token
	visitor := f.as("")

	resp, _ := visitor.do(t, "GET", link)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != link+"/" {
		t.Errorf("without the slash: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := visitor.do(t, "GET", link+"/", "Accept", "text/html")
	expectStatus(t, resp, http.StatusOK)
	for _, want := range []string{`<h1>docs`, `href="` + link + `/a.txt"`, `href="` + link + `/sub/"`, `Shared by <strong>` + userOfRole("admin") + `</strong>`, `href="?zip"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
	for _, unwanted := range []string{`data-name=".hidden"`, `data-name="busy.txt"`, "/.auth/login", "Account menu", "secret.txt", `class="share-here"`, `<template id="item-actions">`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("listing shows %s", unwanted)
		}
	}
	// A signed-in visitor sees the same, without their account.
	if _, body := f.as("user").do(t, "GET", link+"/", "Accept", "text/html"); strings.Contains(body, "Account menu") || !strings.Contains(body, "a.txt") {
		t.Error("a signed-in visitor sees their account")
	}

	for p, want := range map[string]string{"/a.txt": "alpha", "/sub/b.txt": "beta", "/sub//b.txt": "beta"} {
		resp, body := visitor.do(t, "GET", link+p)
		if resp.StatusCode != http.StatusOK || body != want || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment") {
			t.Errorf("%s: %d %q", p, resp.StatusCode, body)
		}
	}
	resp, body = visitor.do(t, "GET", link+"/sub/b.txt", "Range", "bytes=1-2")
	if resp.StatusCode != http.StatusPartialContent || body != "et" {
		t.Errorf("range: %d %q", resp.StatusCode, body)
	}
	resp, _ = visitor.do(t, "GET", link+"/sub")
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != link+"/sub/" {
		t.Errorf("folder without the slash: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = visitor.do(t, "GET", link+"/sub/", "Accept", "text/html")
	if !strings.Contains(body, `href="`+link+`/sub/b.txt"`) || !strings.Contains(body, `href="`+link+`/"`) {
		t.Error("subfolder links lead elsewhere")
	}

	// Nothing outside the shared folder, hidden or being written.
	for _, p := range []string{"/.hidden", "/busy.txt", "/../secret.txt", "/%2e%2e/secret.txt", "/sub/..%2f..%2fsecret.txt", "/nope.txt", "/%2e%2e%2f%2e%2e%2fsecret.txt"} {
		resp, body := visitor.do(t, "GET", link+p)
		if resp.StatusCode != http.StatusNotFound || strings.Contains(body, "outside") {
			t.Errorf("%s: %d %q", p, resp.StatusCode, body)
		}
	}
	resp, body = visitor.do(t, "GET", link+"/nope.txt", "Accept", "text/html")
	if !strings.Contains(body, `href="`+link+`/">Back to the shared folder`) || strings.Contains(body, "Go to all files") {
		t.Errorf("error page of a link: %s", body)
	}

	resp, body = visitor.do(t, "GET", link+"/?zip")
	expectStatus(t, resp, http.StatusOK)
	if names, _ := zipEntries(t, body); !slices.Equal(names, []string{"a.txt", "sub/", "sub/b.txt"}) {
		t.Errorf("zip holds %v", names)
	}
	if resp, body := visitor.do(t, "HEAD", link+"/a.txt"); resp.StatusCode != http.StatusOK || body != "" || resp.Header.Get("Content-Length") != "5" {
		t.Errorf("HEAD: %d %q", resp.StatusCode, body)
	}

	// Links only read; posting to one without a password unlocks nothing.
	for req, want := range map[[2]string]int{{"PUT", link + "/new.txt"}: 403, {"DELETE", link + "/a.txt"}: 403, {"POST", link + "/"}: 303} {
		if resp, _ := visitor.send(t, req[0], req[1], strings.NewReader("delete=a.txt"), "Content-Type", formType); resp.StatusCode != want {
			t.Errorf("%s %s: %d, want %d", req[0], req[1], resp.StatusCode, want)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "docs", "a.txt")); err != nil {
		t.Error("a visitor deleted a file")
	}

	// Tokens stay out of the logs.
	if strings.Contains(f.logs.raw(), token) {
		t.Error("a link's token was logged")
	}
	found := false
	for _, e := range f.logs.entries("request") {
		found = found || e["path"] == sharePrefix+"***/sub/b.txt"
	}
	if !found {
		t.Error("requests through links are not logged")
	}
}

func TestShareFile(t *testing.T) {
	f := newFixture(t)
	f.write(t, "docs/report été.pdf", "%PDF")
	f.write(t, "docs/other.txt", "other")
	token := createShare(t, f, "admin", "/docs/report été.pdf", "1h", "")
	link := sharePrefix + token
	visitor := f.as("")

	resp, body := visitor.do(t, "GET", link+"/", "Accept", "text/html")
	expectStatus(t, resp, http.StatusOK)
	for _, want := range []string{"<h1>report été.pdf</h1>", `href="` + link + `/report%20%C3%A9t%C3%A9.pdf" download`, "4 B"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	resp, body = visitor.do(t, "GET", link+"/report%20%C3%A9t%C3%A9.pdf")
	if resp.StatusCode != http.StatusOK || body != "%PDF" {
		t.Errorf("download: %d %q", resp.StatusCode, body)
	}
	for _, p := range []string{"/other.txt", "/report.pdf", "/docs/other.txt", "/%2e%2e/other.txt"} {
		if resp, _ := visitor.do(t, "GET", link+p); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

// A link gives what its creator may read and share, as long as they may.
func TestShareFollowsRights(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/a.txt", "alpha")
	f.write(t, "docs/sub/b.txt", "beta")
	erin := ta.addUser(t, "erin", "user")
	for _, obj := range []string{"/docs/", "/docs/a.txt"} {
		if _, err := ta.svc.AddPolicy(auth.Subject("erin"), obj, auth.ActShare); err != nil {
			t.Fatal(err)
		}
	}
	e := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: erin}
	token := createShare(t, e, "", "/docs/", "1d", "")
	link := sharePrefix + token
	visitor := f.as("")

	_, body := visitor.do(t, "GET", link+"/", "Accept", "text/html")
	if !strings.Contains(body, `data-name="a.txt"`) || strings.Contains(body, `data-name="sub"`) {
		t.Error("the listing does not follow erin's rights")
	}
	if resp, _ := visitor.do(t, "GET", link+"/sub/b.txt"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unshared file: %d", resp.StatusCode)
	}
	if _, body := visitor.do(t, "GET", link+"/?zip"); !strings.Contains(body, "a.txt") || strings.Contains(body, "b.txt") {
		t.Error("the zip does not follow erin's rights")
	}

	// Once erin may no longer share the folder, the link is dead.
	if _, err := ta.svc.RemovePolicy(auth.Subject("erin"), "/docs/", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/a.txt"} {
		resp, body := visitor.do(t, "GET", link+p, "Accept", "text/html")
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "This link has expired or was revoked") || strings.Contains(body, "Back to the shared") {
			t.Errorf("%s after losing the right: %d", p, resp.StatusCode)
		}
	}
	if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/docs/", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	if resp, _ := visitor.do(t, "GET", link+"/a.txt"); resp.StatusCode != http.StatusOK {
		t.Errorf("after regaining the right: %d", resp.StatusCode)
	}

	// A folder replaced by a file is not what was shared.
	if err := os.RemoveAll(filepath.Join(f.dir, "docs")); err != nil {
		t.Fatal(err)
	}
	f.write(t, "docs", "a file now")
	if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/docs", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	if resp, body := visitor.do(t, "GET", link+"/"); resp.StatusCode != http.StatusNotFound || strings.Contains(body, "a file now") {
		t.Errorf("replaced folder: %d %q", resp.StatusCode, body)
	}

	// Deleting erin deletes her links.
	f.write(t, "pub/c.txt", "gamma")
	if _, err := ta.svc.AddPolicy(auth.Subject("erin"), "/pub/*", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	pub := createShare(t, e, "", "/pub/c.txt", "1d", "")
	if err := ta.svc.DeleteUser(context.Background(), "erin"); err != nil {
		t.Fatal(err)
	}
	if resp, _ := visitor.do(t, "GET", sharePrefix+pub+"/c.txt"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("link of a deleted user: %d", resp.StatusCode)
	}

	// Made-up and malformed tokens.
	for _, p := range []string{sharePrefix + strings.Repeat("A", 43) + "/", sharePrefix + "x/", sharePrefix, sharePrefix + "%41" + strings.Repeat("A", 42) + "/"} {
		if resp, _ := visitor.do(t, "GET", p); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

func TestSharePassword(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/a.txt", "alpha")
	token := createShare(t, f, "admin", "/docs", "1d", "correct horse")
	other := createShare(t, f, "admin", "/docs", "1d", "battery staple")
	link := sharePrefix + token
	visitor := f.as("")

	resp, body := visitor.do(t, "GET", link+"/", "Accept", "text/html")
	expectStatus(t, resp, http.StatusOK)
	if !strings.Contains(body, "This link needs a password") || strings.Contains(body, "a.txt") {
		t.Errorf("no password asked: %s", body)
	}
	for _, p := range []string{"/a.txt", "/?zip", "/nope.txt"} {
		if resp, body := visitor.do(t, "GET", link+p); resp.StatusCode != http.StatusForbidden || strings.Contains(body, "alpha") {
			t.Errorf("%s without the password: %d", p, resp.StatusCode)
		}
	}

	unlock := func(password string, headers ...string) (*http.Response, string) {
		return visitor.send(t, "POST", link+"/a.txt", strings.NewReader(url.Values{"password": {password}}.Encode()),
			append([]string{"Content-Type", formType, "Accept", "text/html"}, headers...)...)
	}
	resp, body = unlock("wrong password")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Wrong password.") || resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	if n := len(f.logs.entries("share password wrong")); n != 1 {
		t.Errorf("%d failures logged", n)
	}
	resp, _ = unlock("correct horse")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != link+"/a.txt" {
		t.Fatalf("right password: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	cookie := resp.Header.Get("Set-Cookie")
	for _, want := range []string{unlockCookie + "=", "path=" + link + "/", "HttpOnly", "SameSite=Lax", "expires="} {
		if !strings.Contains(cookie, want) {
			t.Errorf("cookie %q lacks %s", cookie, want)
		}
	}
	jar := strings.SplitN(cookie, ";", 2)[0]
	if resp, body := visitor.do(t, "GET", link+"/a.txt", "Cookie", jar); resp.StatusCode != http.StatusOK || body != "alpha" {
		t.Errorf("with the cookie: %d %q", resp.StatusCode, body)
	}
	// The proof opens this link only, and only as it was given.
	if resp, _ := visitor.do(t, "GET", sharePrefix+other+"/a.txt", "Cookie", jar); resp.StatusCode != http.StatusForbidden {
		t.Errorf("another link with this cookie: %d", resp.StatusCode)
	}
	exp, mac, _ := strings.Cut(strings.TrimPrefix(jar, unlockCookie+"="), ".")
	for _, forged := range []string{unlockCookie + "=9" + exp + "." + mac, unlockCookie + "=" + exp + "." + strings.Repeat("A", len(mac))} {
		if resp, _ := visitor.do(t, "GET", link+"/a.txt", "Cookie", forged); resp.StatusCode != http.StatusForbidden {
			t.Errorf("forged cookie %q: %d", forged, resp.StatusCode)
		}
	}

	// Checks are limited per link, whoever makes them: two were made.
	for range shareGuessesPerMinute - 2 {
		if resp, _ := unlock("wrong again"); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("guess within the limit: %d", resp.StatusCode)
		}
	}
	resp, _ = unlock("correct horse")
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("checks not limited: %d", resp.StatusCode)
	}
	if resp, _ := visitor.send(t, "POST", sharePrefix+other+"/", strings.NewReader("password=battery+staple"), "Content-Type", formType); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("another link was limited too: %d", resp.StatusCode)
	}
}

func TestSharesPage(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/a.txt", "alpha")
	mine := createShare(t, f, "admin", "/docs/a.txt", "1d", "correct horse")
	theirs := createShare(t, f, "superadmin", "/docs", "7d", "")

	_, body := f.as("admin").do(t, "GET", sharesPath, "Accept", "text/html")
	if !strings.Contains(body, "/docs/a.txt") || strings.Contains(body, `<span class="where">/docs</span>`) || !strings.Contains(body, "</svg>password</span>") {
		t.Errorf("admin's links: %s", body)
	}
	_, body = f.as("superadmin").do(t, "GET", sharesPath, "Accept", "text/html")
	if !strings.Contains(body, `<span class="where">/docs</span>`) || !strings.Contains(body, "/docs/a.txt") || !strings.Contains(body, "<th>By</th>") {
		t.Error("superadmins do not see every link")
	}
	if _, body := f.as("admin").do(t, "GET", sharesPath, "Accept", "text/html"); strings.Contains(body, "No links are active.") {
		t.Error("admin has no links")
	}
	// Who may not share links, and has none, has no links to see.
	if _, body := f.as("operator").do(t, "GET", sharesPath, "Accept", "text/html"); strings.Contains(body, "/docs") || strings.Contains(body, `id="links-title"`) {
		t.Errorf("operator sees links: %s", body)
	}
	if resp, _ := f.as("").do(t, "GET", sharesPath); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", resp.StatusCode)
	}
	for role, want := range map[string]bool{"superadmin": true, "admin": true, "operator": false} {
		if _, body := f.as(role).do(t, "GET", "/"); strings.Contains(body, `href="/.shares/"`) != want {
			t.Errorf("%s: Shared tab shown = %v", role, !want)
		}
	}
	// The top bar's tabs say where the visitor is.
	const filesTab, sharedTab = `<a href="/" aria-current="true">`, `<a href="/.shares/" aria-current="page">`
	for target, want := range map[string]string{"/": filesTab, "/docs/": filesTab, sharesPath: sharedTab} {
		_, body := f.as("admin").do(t, "GET", target, "Accept", "text/html")
		if !strings.Contains(body, want) || strings.Contains(body, filesTab) && strings.Contains(body, sharedTab) {
			t.Errorf("%s: tabs do not mark %s", target, want)
		}
	}

	shares, err := ta.svc.Shares(context.Background(), nil, true)
	if err != nil || len(shares) != 2 {
		t.Fatal(shares, err)
	}
	theirID, myID := shares[0].ID, shares[1].ID
	revoke := func(role string, id int64, headers ...string) *http.Response {
		resp, _ := f.as(role).send(t, "POST", sharesPath, strings.NewReader("action=revoke&id="+strconv.FormatInt(id, 10)), append([]string{"Content-Type", formType}, headers...)...)
		return resp
	}
	if resp := revoke("admin", theirID); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoking another's link: %d", resp.StatusCode)
	}
	if resp := revoke("admin", myID, "Accept", "text/html"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != sharesPath+"?done=revoked" {
		t.Errorf("revoking: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := f.as("").do(t, "GET", sharePrefix+mine+"/"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoked link: %d", resp.StatusCode)
	}
	if resp := revoke("superadmin", theirID); resp.StatusCode != http.StatusNoContent {
		t.Errorf("superadmin revoking: %d", resp.StatusCode)
	}
	if resp, _ := f.as("").do(t, "GET", sharePrefix+theirs+"/"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoked link: %d", resp.StatusCode)
	}
	if resp := revoke("admin", myID, "Accept", "text/html"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoking twice: %d", resp.StatusCode)
	}
	if n := len(f.logs.entries("share revoked")); n != 2 {
		t.Errorf("%d revocations logged", n)
	}
	// Another site cannot make a browser create or revoke links.
	resp, _ := f.as("admin").send(t, "POST", sharesPath, strings.NewReader("action=create&path=/docs&expires=1d"),
		"Content-Type", formType, "Sec-Fetch-Site", "cross-site")
	expectStatus(t, resp, http.StatusForbidden)
}

// Users who still have to choose a password can open links like anyone.
func TestShareForUsersWithTemporaryPasswords(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/a.txt", "alpha")
	token := createShare(t, f, "admin", "/docs", "1d", "")
	ctx := context.Background()
	temp, err := ta.svc.CreateUser(ctx, "newbie", "user")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ta.svc.Login(ctx, "newbie", temp)
	if err != nil {
		t.Fatal(err)
	}
	newbie := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: sess.Token}
	if resp, body := newbie.do(t, "GET", sharePrefix+token+"/a.txt"); resp.StatusCode != http.StatusOK || body != "alpha" {
		t.Errorf("%d %q", resp.StatusCode, body)
	}
	if resp, _ := newbie.do(t, "GET", "/docs/a.txt"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("the rest stays closed: %d", resp.StatusCode)
	}
}

func TestLogPath(t *testing.T) {
	for in, want := range map[string]string{
		"/docs/a.txt":                     "/docs/a.txt",
		sharePrefix:                       sharePrefix + "***",
		sharePrefix + "TOKEN":             sharePrefix + "***",
		sharePrefix + "TOKEN/":            sharePrefix + "***/",
		sharePrefix + "TOKEN/sub/a b.txt": sharePrefix + "***/sub/a b.txt",
		"/x" + sharePrefix + "TOKEN/":     "/x" + sharePrefix + "TOKEN/",
	} {
		if got := logPath(in); got != want {
			t.Errorf("logPath(%q) = %q, want %q", in, got, want)
		}
	}
}
