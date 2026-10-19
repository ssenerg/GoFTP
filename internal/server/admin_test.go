package server

import (
	"context"
	"errors"
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"goftp/internal/auth"
)

func TestAdminAccess(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	for who, want := range map[string]int{"": 401, "user": 403, "operator": 403, "admin": 403, "superadmin": 200} {
		for _, p := range []string{usersPath, rulesPath} {
			if resp, _ := f.as(who).do(t, "GET", p); resp.StatusCode != want {
				t.Errorf("%q GET %s: %d, want %d", who, p, resp.StatusCode, want)
			}
		}
		if who == "superadmin" {
			continue
		}
		resp, _ := f.as(who).send(t, "POST", usersPath, strings.NewReader("action=add&user=intruder&role=superadmin"), "Content-Type", formType)
		if resp.StatusCode != want {
			t.Errorf("%q POST: %d, want %d", who, resp.StatusCode, want)
		}
	}
	// Another site cannot make a superadmin's browser add one either.
	resp, _ := f.as("superadmin").send(t, "POST", usersPath, strings.NewReader("action=add&user=intruder&role=superadmin"),
		"Content-Type", formType, "Sec-Fetch-Site", "cross-site")
	expectStatus(t, resp, http.StatusForbidden)
	if _, err := ta.store.UserByName(context.Background(), "intruder"); !errors.Is(err, auth.ErrNotFound) {
		t.Error("a refused request added a user")
	}
	resp, _ = f.as("").do(t, "GET", usersPath, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/.auth/login?next=%2F.admin%2Fusers" {
		t.Errorf("Location %q", got)
	}
	for _, p := range []string{"/.admin", "/.admin/"} {
		resp, _ := f.as("superadmin").do(t, "GET", p)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != usersPath {
			t.Errorf("GET %s: %d %q", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	for role, want := range map[string]bool{"superadmin": true, "admin": false} {
		if _, body := f.as(role).do(t, "GET", "/"); strings.Contains(body, `href="/.admin/users"`) != want {
			t.Errorf("%s: menu entry shown = %v", role, !want)
		}
	}
}

var secretRe = regexp.MustCompile(`<code id="temp-password">([A-Z0-9]+)</code>`)

func TestAdminUsers(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	ctx := context.Background()
	post := func(form string) (*http.Response, string) {
		return f.as("superadmin").send(t, "POST", usersPath, strings.NewReader(form), "Content-Type", formType, "Accept", "text/html")
	}

	// A new user's temporary password is shown once, and works.
	resp, body := post("action=add&user=Dana&role=operator")
	expectStatus(t, resp, http.StatusOK)
	m := secretRe.FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, "Added <strong>dana</strong>") {
		t.Fatalf("no temporary password shown: %s", body)
	}
	sess, err := ta.svc.Login(ctx, "dana", m[1])
	if err != nil || !sess.User.MustChangePassword || ta.svc.Role("dana") != "operator" {
		t.Fatalf("new user: %v %+v %q", err, sess, ta.svc.Role("dana"))
	}

	for form, want := range map[string]int{
		"action=add&user=dana&role=user":    409,
		"action=add&user=-x&role=user":      400,
		"action=add&user=eve&role=king":     400,
		"action=role&user=nobody&role=user": 404,
		"action=frobnicate&user=dana":       400,
	} {
		if resp, body := post(form); resp.StatusCode != want || (want != 400 && !strings.Contains(body, `class="alert error banner"`)) {
			t.Errorf("%s: %d, want %d", form, resp.StatusCode, want)
		}
	}

	// A new temporary password signs the user out.
	resp, body = post("action=password&user=dana")
	expectStatus(t, resp, http.StatusOK)
	if m2 := secretRe.FindStringSubmatch(body); m2 == nil || m2[1] == m[1] {
		t.Error("no new temporary password shown")
	}
	if _, err := ta.svc.Authenticate(ctx, sess.Token); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("session survived: %v", err)
	}

	resp, _ = post("action=role&user=dana&role=admin")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != usersPath+"?done=role" || ta.svc.Role("dana") != "admin" {
		t.Errorf("role change: %d %q %q", resp.StatusCode, resp.Header.Get("Location"), ta.svc.Role("dana"))
	}
	if _, body := f.as("superadmin").do(t, "GET", usersPath+"?done=role"); !strings.Contains(body, "The role was changed.") {
		t.Error("role change not confirmed")
	}
	resp, _ = post("action=delete&user=dana")
	expectStatus(t, resp, http.StatusSeeOther)
	if _, err := ta.store.UserByName(ctx, "dana"); !errors.Is(err, auth.ErrNotFound) {
		t.Error("user not deleted")
	}

	// Superadmins cannot lock themselves out here.
	me := userOfRole("superadmin")
	for _, form := range []string{"action=delete&user=" + me, "action=role&user=" + me + "&role=user", "action=password&user=" + me} {
		if resp, body := post(form); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "your own account") {
			t.Errorf("%s: %d", form, resp.StatusCode)
		}
	}
	if !ta.svc.IsSuperadmin(me) {
		t.Error("superadmin demoted themselves")
	}
	for msg, want := range map[string]int{"user added": 1, "password reset": 1, "role changed": 1, "user deleted": 1} {
		if n := len(f.logs.entries(msg)); n != want {
			t.Errorf("%d %q entries", n, msg)
		}
	}
}

func TestAdminRules(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "pub/a.txt", "a")
	post := func(form string) (*http.Response, string) {
		return f.as("superadmin").send(t, "POST", rulesPath, strings.NewReader(form), "Content-Type", formType, "Accept", "text/html")
	}
	rule := "subject=anonymous&path=/pub/*&act=read"

	resp, _ := post("action=add&" + rule)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != rulesPath+"?done=rule-added" {
		t.Errorf("add: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := f.as("").do(t, "GET", "/pub/a.txt"); resp.StatusCode != http.StatusOK {
		t.Errorf("rule not in force: %d", resp.StatusCode)
	}
	_, body := f.as("superadmin").do(t, "GET", rulesPath)
	if !strings.Contains(body, `<td class="name">everyone</td>`) || !strings.Contains(body, "<code>/pub/*</code>") {
		t.Error("rule not listed")
	}
	for form, want := range map[string]int{
		"action=add&" + rule:                              409,
		"action=add&subject=anonymous&path=pub&act=read":  400,
		"action=add&subject=root&path=/x/*&act=read":      400,
		"action=add&subject=anonymous&path=/x/*&act=nuke": 400,
	} {
		if resp, body := post(form); resp.StatusCode != want || !strings.Contains(body, `class="alert error banner"`) {
			t.Errorf("%s: %d, want %d", form, resp.StatusCode, want)
		}
	}
	if _, body := post("action=add&subject=anonymous&path=pub&act=read"); !strings.Contains(html.UnescapeString(body), "Path must be a clean absolute URL path") {
		t.Error("refused path not explained")
	}

	resp, _ = post("action=remove&" + rule)
	expectStatus(t, resp, http.StatusSeeOther)
	if resp, _ := f.as("").do(t, "GET", "/pub/a.txt"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("removed rule still in force: %d", resp.StatusCode)
	}
	if resp, _ := post("action=remove&" + rule); resp.StatusCode != http.StatusNotFound {
		t.Errorf("removing a missing rule: %d", resp.StatusCode)
	}

	// Rules that deny: chosen, or written as in a .gitignore.
	f.write(t, "pub/secret/s.txt", "s")
	f.write(t, "pub/old/o.txt", "o")
	for _, form := range []string{"subject=user&path=/pub/secret/*&act=read&effect=deny", "subject=user&path=!/pub/old/*&act=read&effect=allow"} {
		if resp, _ := post("action=add&" + form); resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%s: %d", form, resp.StatusCode)
		}
	}
	for p, want := range map[string]int{"/pub/a.txt": 200, "/pub/secret/s.txt": 403, "/pub/old/o.txt": 403} {
		if resp, _ := f.as("user").do(t, "GET", p); resp.StatusCode != want {
			t.Errorf("user GET %s: %d, want %d", p, resp.StatusCode, want)
		}
	}
	_, body = f.as("superadmin").do(t, "GET", rulesPath)
	for _, want := range []string{`<span class="deny">may not</span> read`, "<code>/pub/secret/*</code>", `name="path" value="!/pub/secret/*"`, "may then read <code>/pub/old/*</code> if another rule allows it"} {
		if !strings.Contains(html.UnescapeString(body), want) {
			t.Errorf("rules page lacks %s", want)
		}
	}
	if resp, _ := post("action=add&subject=user&path=/pub/x/*&act=read&effect=maybe"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown effect: %d", resp.StatusCode)
	}
	if resp, _ := post("action=remove&subject=user&path=!/pub/secret/*&act=read"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("removing a denial: %d", resp.StatusCode)
	}
	if resp, _ := f.as("user").do(t, "GET", "/pub/secret/s.txt"); resp.StatusCode != http.StatusOK {
		t.Errorf("removed denial still in force: %d", resp.StatusCode)
	}
}
