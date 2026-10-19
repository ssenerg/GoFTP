package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
	"goftp/internal/auth/authtest"
	"goftp/internal/config"
)

type testAuth struct {
	svc    *auth.Service
	store  *authtest.Store
	tokens map[string]string // session tokens by role
}

// userOfRole names the test user holding role.
func userOfRole(role string) string { return "the-" + role }

func testPassword(name string) string { return "password of " + name }

// newTestAuth creates a user with a chosen password for each role.
func newTestAuth(tb testing.TB) *testAuth {
	svc, store := authtest.NewService(time.Hour)
	ta := &testAuth{svc: svc, store: store, tokens: map[string]string{}}
	for _, role := range auth.Roles {
		ta.tokens[role] = ta.addUser(tb, userOfRole(role), role)
	}
	return ta
}

// addUser signs up a user who has already chosen their password and returns
// a session token.
func (ta *testAuth) addUser(tb testing.TB, name, role string) string {
	ctx := context.Background()
	temp, err := ta.svc.CreateUser(ctx, name, role)
	if err == nil {
		var sess *auth.Session
		if sess, err = ta.svc.Login(ctx, name, temp); err == nil {
			if sess, err = ta.svc.ChangePassword(ctx, sess.User, temp, testPassword(name)); err == nil {
				return sess.Token
			}
		}
	}
	if tb == nil {
		panic(err)
	}
	tb.Fatal(err)
	return ""
}

// sharedAuth spares most tests the cost of hashing passwords.
var sharedAuth = sync.OnceValue(func() *testAuth { return newTestAuth(nil) })

// cookieOf returns the value of the named cookie set by resp.
func cookieOf(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func formBody(kv ...string) (io.Reader, string, string) {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return strings.NewReader(v.Encode()), "Content-Type", "application/x-www-form-urlencoded"
}

func TestAnonymousIsDenied(t *testing.T) {
	f := newFixture(t).as("")
	f.write(t, "docs/a.txt", "secret")

	// Existing and missing paths get the same answer.
	for _, target := range []string{"/", "/docs/", "/docs", "/docs/a.txt", "/docs/missing.txt", "/missing/"} {
		for _, method := range []string{"GET", "HEAD"} {
			resp, body := f.do(t, method, target)
			expectStatus(t, resp, 401)
			if resp.Header.Get("WWW-Authenticate") != `Bearer realm="goftp"` || strings.Contains(body, "secret") ||
				resp.Header.Get("ETag") != "" || resp.Header.Get("Content-Disposition") != "" {
				t.Errorf("%s %s: leaked %q %v", method, target, body, resp.Header)
			}
		}
		// Browsers are sent to the login form.
		resp, _ := f.do(t, "GET", target+"?x=1", "Accept", "text/html")
		expectStatus(t, resp, http.StatusSeeOther)
		if got, want := resp.Header.Get("Location"), loginPath+"?next="+url.QueryEscape(target+"?x=1"); got != want {
			t.Errorf("%s: Location %q, want %q", target, got, want)
		}
	}

	for _, h := range []string{"Bearer nope", "Bearer " + strings.Repeat("x", 43)} {
		resp, _ := f.do(t, "GET", "/docs/a.txt", "Authorization", h)
		expectStatus(t, resp, 401)
		if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="goftp", error="invalid_token"` {
			t.Errorf("%q: WWW-Authenticate %q", h, got)
		}
	}
	// Other schemes, e.g. of a reverse proxy, are ignored.
	resp, _ := f.do(t, "GET", "/docs/a.txt", "Authorization", "Basic YTpi")
	expectStatus(t, resp, 401)
	if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="goftp"` {
		t.Errorf("Basic: WWW-Authenticate %q", got)
	}
	resp, _ = f.do(t, "GET", "/docs/a.txt", "Authorization", "bearer "+f.auth.tokens["user"])
	expectStatus(t, resp, 200)
}

func TestLoginForm(t *testing.T) {
	f := newFixture(t).as("")
	name := userOfRole("operator")

	resp, body := f.do(t, "GET", loginPath+"?next=/docs/")
	expectStatus(t, resp, 200)
	for _, want := range []string{`action="/.auth/login"`, `name="username"`, `name="password"`, `name="next" value="/docs/"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %s", want)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("login page may be cached")
	}

	r, k, v := formBody("username", name, "password", "wrong password", "next", "/docs/")
	resp, body = f.send(t, "POST", loginPath, r, k, v)
	expectStatus(t, resp, 401)
	if !strings.Contains(body, "Wrong username or password.") || !strings.Contains(body, `value="`+name+`"`) || cookieOf(resp, cookieName) != nil {
		t.Errorf("failed login: %q", body)
	}

	r, k, v = formBody("username", " "+strings.ToUpper(name)+" ", "password", testPassword(name), "next", "/docs/")
	resp, _ = f.send(t, "POST", loginPath, r, k, v)
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/docs/" {
		t.Errorf("Location %q", got)
	}
	c := cookieOf(resp, cookieName)
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure ||
		c.Expires.Before(time.Now().Add(59*time.Minute)) {
		t.Fatalf("session cookie %+v", c)
	}

	// The cookie signs the visitor in.
	resp, body = f.do(t, "GET", "/", "Cookie", cookieName+"="+c.Value)
	expectStatus(t, resp, 200)
	if !strings.Contains(body, "Signed in as <strong>"+name+`</strong><span class="role">operator</span>`) {
		t.Error("listing does not show the user")
	}
	resp, _ = f.do(t, "GET", loginPath+"?next=/sub/", "Cookie", cookieName+"="+c.Value)
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/sub/" {
		t.Errorf("signed-in login page redirects to %q", got)
	}

	// next never leads to another site.
	for _, next := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example", "evil", "/a\r\nSet-Cookie: x=y"} {
		r, k, v := formBody("username", name, "password", testPassword(name), "next", next)
		resp, _ := f.send(t, "POST", loginPath, r, k, v)
		if got := resp.Header.Get("Location"); got != "/" {
			t.Errorf("next %q: Location %q", next, got)
		}
	}

	// Names that match no user are not logged: people sometimes type their
	// password, e.g. a temporary one, into the name field.
	for _, typed := range []string{"nobody", "IPWOFW7TNK2EK4PBA344NZDOQZ"} {
		r, k, v = formBody("username", typed, "password", "x")
		f.send(t, "POST", loginPath, r, k, v)
		if strings.Contains(strings.ToLower(f.logs.raw()), strings.ToLower(typed)) {
			t.Errorf("unknown name %q logged", typed)
		}
	}
	if e := f.logs.entries("login failed"); len(e) != 3 || e[2]["user"] != "(unknown)" || !strings.HasSuffix(e[2]["error"].(string), ": no such user") {
		t.Errorf("failed logins logged: %v", e)
	}

	resp, _ = f.send(t, "POST", loginPath, strings.NewReader("username=a"), "Content-Type", "text/plain")
	expectStatus(t, resp, http.StatusUnsupportedMediaType)
	r, k, v = formBody("username", name, "password", strings.Repeat("x", maxFormSize))
	resp, _ = f.send(t, "POST", loginPath, r, k, v)
	expectStatus(t, resp, http.StatusRequestEntityTooLarge)
}

func TestLoginJSON(t *testing.T) {
	f := newFixture(t).as("")
	name := userOfRole("user")
	login := func(body string) (*http.Response, map[string]any) {
		resp, raw := f.send(t, "POST", loginPath, strings.NewReader(body), "Content-Type", "application/json")
		var out map[string]any
		_ = json.Unmarshal([]byte(raw), &out)
		return resp, out
	}

	resp, out := login(`{"username":"` + name + `","password":"` + testPassword(name) + `"}`)
	expectStatus(t, resp, 200)
	token, _ := out["token"].(string)
	if len(token) != 43 || out["must_change_password"] != false || cookieOf(resp, cookieName) != nil {
		t.Fatalf("login response %v", out)
	}
	if exp, err := time.Parse(time.RFC3339, out["expires_at"].(string)); err != nil || exp.Before(time.Now().Add(59*time.Minute)) {
		t.Errorf("expires_at %v: %v", out["expires_at"], err)
	}
	if resp, _ := f.do(t, "GET", "/", "Authorization", "Bearer "+token); resp.StatusCode != 200 {
		t.Errorf("token refused: %d", resp.StatusCode)
	}

	for _, body := range []string{`{"username":"` + name + `","password":"nope"}`, `{"username":"nobody","password":"x"}`, `{}`} {
		if resp, _ := login(body); resp.StatusCode != 401 {
			t.Errorf("%s: status %d", body, resp.StatusCode)
		}
	}
	for _, body := range []string{`{"username":1}`, `[`, `null x`} {
		if resp, _ := login(body); resp.StatusCode != 400 {
			t.Errorf("%s: status %d", body, resp.StatusCode)
		}
	}
}

// A new user signs in with the temporary password and has to choose their
// own before doing anything else.
func TestFirstLoginRequiresPasswordChange(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta).as("")
	f.write(t, "a.txt", "a")
	ctx := context.Background()
	temp, err := ta.svc.CreateUser(ctx, "newbie", "user")
	if err != nil {
		t.Fatal(err)
	}

	r, k, v := formBody("username", "newbie", "password", temp, "next", "/a.txt")
	resp, _ := f.send(t, "POST", loginPath, r, k, v)
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != passwordPath+"?next=%2Fa.txt" {
		t.Errorf("Location %q", got)
	}
	cookie := cookieName + "=" + cookieOf(resp, cookieName).Value

	resp, _ = f.do(t, "GET", "/a.txt", "Cookie", cookie, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != passwordPath+"?next=%2Fa.txt" {
		t.Errorf("gate Location %q", got)
	}
	resp, body := f.do(t, "GET", "/a.txt", "Cookie", cookie)
	if resp.StatusCode != 403 || body != "password change required\n" {
		t.Errorf("gate for API clients: %d %q", resp.StatusCode, body)
	}
	resp, _ = f.send(t, "PUT", "/b.txt", strings.NewReader("b"), "Cookie", cookie)
	expectStatus(t, resp, 403)

	resp, body = f.do(t, "GET", passwordPath+"?next=/a.txt", "Cookie", cookie)
	expectStatus(t, resp, 200)
	for _, want := range []string{"You signed in with a temporary password", `name="current_password"`, `name="new_password"`, `name="confirm_password"`, `name="next" value="/a.txt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("password page lacks %s", want)
		}
	}

	change := func(current, next, confirm string) (*http.Response, string) {
		r, k, v := formBody("current_password", current, "new_password", next, "confirm_password", confirm, "next", "/a.txt")
		return f.send(t, "POST", passwordPath, r, k, v, "Cookie", cookie)
	}
	for _, tc := range []struct {
		current, next, confirm string
		status                 int
		msg                    string
	}{
		{temp, "a new password", "another password", 400, "The new passwords do not match."},
		{"wrong", "a new password", "a new password", 403, "The current password is wrong."},
		{temp, "short", "short", 400, "use at least 12 characters"},
		{temp, "NEWBIE", "NEWBIE", 400, "use at least 12 characters"},
		{temp, temp, temp, 400, "must differ from the current one"},
	} {
		resp, body := change(tc.current, tc.next, tc.confirm)
		if resp.StatusCode != tc.status || !strings.Contains(body, tc.msg) {
			t.Errorf("change(%q, %q): %d, body lacks %q", tc.current, tc.next, resp.StatusCode, tc.msg)
		}
	}

	resp, _ = change(temp, "my own password", "my own password")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/a.txt" {
		t.Errorf("Location %q", got)
	}
	// The session is replaced: the old cookie no longer works.
	fresh := cookieOf(resp, cookieName)
	if fresh == nil || cookieName+"="+fresh.Value == cookie {
		t.Fatal("no new session cookie")
	}
	resp, _ = f.do(t, "GET", "/a.txt", "Cookie", cookie)
	expectStatus(t, resp, 401)
	resp, body = f.do(t, "GET", "/a.txt", "Cookie", cookieName+"="+fresh.Value)
	if resp.StatusCode != 200 || body != "a" {
		t.Errorf("after change: %d %q", resp.StatusCode, body)
	}
	if _, err := ta.svc.Login(ctx, "newbie", "my own password"); err != nil {
		t.Errorf("new password: %v", err)
	}
}

func TestChangePasswordJSON(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta).as("user")
	name := userOfRole("user")
	other := ta.tokens["operator"]

	resp, body := f.send(t, "POST", passwordPath, strings.NewReader(`{"current_password":"`+testPassword(name)+`","new_password":"brand new password"}`),
		"Content-Type", "application/json")
	expectStatus(t, resp, 200)
	var out map[string]string
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out["token"]) != 43 || cookieOf(resp, cookieName) != nil {
		t.Fatalf("response %q: %v", body, err)
	}
	if resp, _ := f.do(t, "GET", "/"); resp.StatusCode != 401 {
		t.Errorf("old token still valid: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", "/", "Authorization", "Bearer "+out["token"]); resp.StatusCode != 200 {
		t.Errorf("new token refused: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", "/", "Authorization", "Bearer "+other); resp.StatusCode != 200 {
		t.Errorf("another user's session ended: %d", resp.StatusCode)
	}

	resp, body = f.as("").send(t, "POST", passwordPath, strings.NewReader(`{}`), "Content-Type", "application/json")
	expectStatus(t, resp, 401)
	resp, _ = f.as("").do(t, "GET", passwordPath, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
}

func TestLogout(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)

	resp, _ := f.as("user").do(t, "POST", logoutPath)
	expectStatus(t, resp, http.StatusNoContent)
	if resp, _ := f.as("user").do(t, "GET", "/"); resp.StatusCode != 401 {
		t.Errorf("session survived logout: %d", resp.StatusCode)
	}

	cookie := cookieName + "=" + ta.tokens["operator"]
	resp, _ = f.as("").do(t, "POST", logoutPath, "Cookie", cookie, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	c := cookieOf(resp, cookieName)
	if resp.Header.Get("Location") != loginPath || c == nil || c.Value != "" || c.Expires.After(time.Now()) {
		t.Errorf("logout: %q %+v", resp.Header.Get("Location"), c)
	}
	// An ended session makes the visitor anonymous and clears the cookie.
	resp, _ = f.as("").do(t, "GET", "/", "Cookie", cookie, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if c := cookieOf(resp, cookieName); c == nil || c.Value != "" || !strings.HasPrefix(resp.Header.Get("Location"), loginPath) {
		t.Errorf("stale cookie: %+v %q", c, resp.Header.Get("Location"))
	}
	if n := f.logs.entries("logout"); len(n) != 2 {
		t.Errorf("logout entries: %v", n)
	}
}

func TestExpiredSession(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta).as("")
	u, err := ta.store.UserByName(context.Background(), userOfRole("admin"))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("e", 43)
	sum := sha256.Sum256([]byte(token))
	if err := ta.store.CreateSession(context.Background(), sum[:], u, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, _ := f.do(t, "GET", "/", "Authorization", "Bearer "+token)
	expectStatus(t, resp, 401)
	resp, _ = f.do(t, "GET", "/", "Cookie", cookieName+"="+token)
	expectStatus(t, resp, 401)
}

func TestCrossOriginRequests(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		headers []string
		want    int
	}{
		{nil, 201},
		{[]string{"Sec-Fetch-Site", "same-origin"}, 201},
		{[]string{"Sec-Fetch-Site", "none"}, 201},
		{[]string{"Sec-Fetch-Site", "same-site"}, 403},
		{[]string{"Sec-Fetch-Site", "cross-site"}, 403},
		{[]string{"Sec-Fetch-Site", "cross-site", "Origin", "http://example.com"}, 403},
		{[]string{"Origin", "http://example.com"}, 201},
		{[]string{"Origin", "https://example.com:443"}, 403},
		{[]string{"Origin", "http://evil.example"}, 403},
		{[]string{"Origin", "null"}, 403},
	}
	for i, tc := range tests {
		target := fmt.Sprintf("/x%d.txt", i)
		resp, _ := f.send(t, "PUT", target, strings.NewReader("x"), tc.headers...)
		if resp.StatusCode != tc.want {
			t.Errorf("%v: status %d, want %d", tc.headers, resp.StatusCode, tc.want)
		}
	}
	// Login forms from other sites cannot sign visitors in either.
	name := userOfRole("user")
	r, k, v := formBody("username", name, "password", testPassword(name))
	resp, _ := f.as("").send(t, "POST", loginPath, r, k, v, "Sec-Fetch-Site", "cross-site")
	expectStatus(t, resp, 403)
	// Safe methods are never refused.
	resp, _ = f.do(t, "GET", "/", "Sec-Fetch-Site", "cross-site")
	expectStatus(t, resp, 200)
	if n := len(f.logs.entries("cross-origin request refused")); n != 7 {
		t.Errorf("%d refusals logged", n)
	}
}

func TestSecureCookieBehindProxy(t *testing.T) {
	name := userOfRole("user")
	for setup, mutate := range map[string]func(*config.Config){
		"proxy header": func(c *config.Config) {
			c.Server.ProxyHeader = "X-Forwarded-For"
			c.Server.TrustedProxies = []string{"0.0.0.0"}
		},
		// HTTPS is recognized from a trusted proxy without a proxy header too.
		"trusted proxy only": func(c *config.Config) { c.Server.TrustedProxies = []string{"0.0.0.0"} },
	} {
		f := newFixture(t, mutate).as("")
		r, k, v := formBody("username", name, "password", testPassword(name))
		resp, _ := f.send(t, "POST", loginPath, r, k, v, "X-Forwarded-Proto", "https")
		c := cookieOf(resp, secureCookieName)
		if c == nil || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
			t.Fatalf("%s: cookie %+v", setup, resp.Cookies())
		}
		resp, _ = f.do(t, "GET", "/", "Cookie", secureCookieName+"="+c.Value, "X-Forwarded-Proto", "https")
		expectStatus(t, resp, 200)
		if resp.Header.Get("Strict-Transport-Security") == "" {
			t.Errorf("%s: no HSTS over HTTPS", setup)
		}
		// Over plain HTTP the secure cookie is not honored.
		resp, _ = f.do(t, "GET", "/", "Cookie", secureCookieName+"="+c.Value)
		expectStatus(t, resp, 401)
		if resp.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS over plain HTTP", setup)
		}
	}

	// Without a trusted proxy, clients cannot claim HTTPS.
	f := newFixture(t).as("")
	r, k, v := formBody("username", name, "password", testPassword(name))
	resp, _ := f.send(t, "POST", loginPath, r, k, v, "X-Forwarded-Proto", "https")
	if cookieOf(resp, cookieName) == nil || resp.Header.Get("Strict-Transport-Security") != "" {
		t.Errorf("untrusted X-Forwarded-Proto believed: %v", resp.Header)
	}
	// That is logged, once.
	f.do(t, "GET", "/", "X-Forwarded-For", "203.0.113.9")
	if n := len(f.logs.entries("ignoring proxy headers from an untrusted address; behind a reverse proxy, set server.proxy_header and server.trusted_proxies")); n != 1 {
		t.Errorf("untrusted proxy headers noted %d times", n)
	}
}

func TestLoginLimiter(t *testing.T) {
	limited := func(c *config.Config) { c.Limiter = config.LimiterConfig{MaxFailures: 3, Window: time.Minute} }
	f := newFixture(t, limited).as("")
	name := userOfRole("user")
	login := func(password string) *http.Response {
		r, k, v := formBody("username", name, "password", password)
		resp, _ := f.send(t, "POST", loginPath, r, k, v)
		return resp
	}

	// Successes do not use up the client's budget.
	for i := 0; i < 5; i++ {
		expectStatus(t, login(testPassword(name)), http.StatusSeeOther)
	}
	for i := 0; i < 3; i++ {
		expectStatus(t, login("guess"+strconv.Itoa(i)), 401)
	}
	// The budget is spent: even the right password is refused unchecked.
	resp := login(testPassword(name))
	expectStatus(t, resp, http.StatusTooManyRequests)
	if ra, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || ra < 59 || ra > 60 {
		t.Errorf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
	failed := f.logs.entries("login failed")
	if len(failed) != 3 || failed[0]["user"] != name || !strings.HasSuffix(failed[0]["error"].(string), ": wrong password") {
		t.Errorf("failed logins logged: %v", failed)
	}

	// Wrong current passwords count as well.
	f = newFixture(t, limited).as("user")
	for i := 0; i < 3; i++ {
		resp, _ := f.send(t, "POST", passwordPath, strings.NewReader(`{"current_password":"x","new_password":"yyyyyyyyyyyyy"}`),
			"Content-Type", "application/json")
		expectStatus(t, resp, 403)
	}
	r, k, v := formBody("username", name, "password", testPassword(name))
	resp, _ = f.as("").send(t, "POST", loginPath, r, k, v)
	expectStatus(t, resp, http.StatusTooManyRequests)
}

// Password hashing is costly even for valid credentials, so a user's
// sign-ins are limited too.
func TestSignInLimiter(t *testing.T) {
	defer func(n int) { signInsPerMinute = n }(signInsPerMinute)
	signInsPerMinute = 3
	f := newFixture(t).as("")
	login := func(name string) *http.Response {
		r, k, v := formBody("username", name, "password", testPassword(name))
		resp, _ := f.send(t, "POST", loginPath, r, k, v)
		return resp
	}
	name := userOfRole("admin")
	for i := 0; i < 3; i++ {
		expectStatus(t, login(name), http.StatusSeeOther)
	}
	expectStatus(t, login(name), http.StatusTooManyRequests)
	expectStatus(t, login(userOfRole("operator")), http.StatusSeeOther)
}

// Concurrent guesses must not slip past the budget.
func TestLoginLimiterConcurrentGuesses(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.Limiter = config.LimiterConfig{MaxFailures: 3, Window: time.Minute}
	})
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		counts = map[int]int{}
	)
	for i := 0; i < 50; i++ {
		wg.Go(func() {
			req := httptest.NewRequest("POST", loginPath, strings.NewReader("username=the-user&password=guess"+strconv.Itoa(i)))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := f.srv.App().Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			counts[resp.StatusCode]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if counts[401] != 3 || counts[429] != 47 {
		t.Errorf("status counts %v, want 3×401 and 47×429", counts)
	}
}

// Rules can grant anonymous access and narrow a user's view.
func TestPolicies(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	for _, name := range []string{"public/p.txt", "shared/s.txt", "private/x.txt", "top.txt"} {
		f.write(t, name, name)
	}
	ta.addUser(t, "guest", "user")
	guest := ta.addUser(t, "bob", "user")
	if _, err := ta.svc.Enforcer().DeleteRolesForUser(auth.Subject("bob")); err != nil {
		t.Fatal(err)
	}
	for _, rule := range [][]string{
		{auth.Anonymous, "/public/*", auth.ActRead},
		{auth.Subject("bob"), "/", auth.ActRead},
		{auth.Subject("bob"), "/shared/*", auth.ActRead},
		{auth.Subject("bob"), "/shared/*", auth.ActWrite},
		// Covers /top.txt/ but not the file /top.txt.
		{auth.Subject("bob"), "/top.txt/*", auth.ActRead},
		// Replacing without creating.
		{auth.Subject("bob"), "/public/*", auth.ActOverwrite},
	} {
		if _, err := ta.svc.AddPolicy(rule[0], rule[1], rule[2]); err != nil {
			t.Fatal(err)
		}
	}

	anon := f.as("")
	for target, want := range map[string]int{"/public/": 200, "/public/p.txt": 200, "/public": 301, "/": 401, "/top.txt": 401, "/private/nope": 401} {
		if resp, _ := anon.do(t, "GET", target); resp.StatusCode != want {
			t.Errorf("anonymous GET %s: %d, want %d", target, resp.StatusCode, want)
		}
	}
	_, body := anon.do(t, "GET", "/public/", "Accept", "text/html")
	if !strings.Contains(body, `href="/.auth/login?next=%2fpublic%2f"`) || strings.Contains(body, `name="file"`) {
		t.Error("anonymous listing lacks the sign-in link or offers uploads")
	}

	// bob sees only what he may open, and may upload only into /shared/.
	bob := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: guest}
	_, body = bob.do(t, "GET", "/")
	for name, want := range map[string]bool{`href="/shared/"`: true, `href="/public/"`: true, `href="/private/"`: false, `href="/top.txt"`: false, `name="file"`: false} {
		if strings.Contains(body, name) != want {
			t.Errorf("bob's listing: %s shown = %v", name, !want)
		}
	}
	// The rule for a folder /top.txt/ does not reveal that a file is there.
	for target, want := range map[string]int{"/shared/s.txt": 200, "/private/x.txt": 403, "/private/nope": 403, "/top.txt": 404, "/public/p.txt": 200} {
		if resp, _ := bob.do(t, "GET", target); resp.StatusCode != want {
			t.Errorf("bob GET %s: %d, want %d", target, resp.StatusCode, want)
		}
	}
	for target, want := range map[string]int{"/shared/new.txt": 201, "/shared/s.txt": 403, "/new.txt": 403, "/public/p.txt": 204, "/public/new.txt": 403} {
		if resp, _ := bob.send(t, "PUT", target, strings.NewReader("b")); resp.StatusCode != want {
			t.Errorf("bob PUT %s: %d, want %d", target, resp.StatusCode, want)
		}
	}
}

// Denials apply wherever rights do: listings, downloads, zips, uploads and
// links.
func TestDenials(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "docs/a.txt", "alpha")
	f.write(t, "docs/hr/pay.txt", "pay")
	f.write(t, "docs/hr/handbook/rules.txt", "rules")
	for _, rule := range [][3]string{
		{"user", "!/docs/hr/*", "*"},
		{"user", "/docs/hr/handbook/*", auth.ActRead},
		{"admin", "/docs/hr/*", auth.ActRead},
	} {
		if _, err := ta.svc.AddPolicy(rule[0], rule[1], rule[2]); err != nil {
			t.Fatal(err)
		}
	}

	user := f.as("user")
	_, body := user.do(t, "GET", "/docs/", "Accept", "text/html")
	if !strings.Contains(body, `data-name="a.txt"`) || strings.Contains(body, `data-name="hr"`) {
		t.Error("the listing shows what is denied")
	}
	for p, want := range map[string]int{"/docs/a.txt": 200, "/docs/hr/": 403, "/docs/hr/pay.txt": 403, "/docs/hr/handbook/rules.txt": 200, "/docs/hr/handbook/": 200} {
		if resp, _ := user.do(t, "GET", p); resp.StatusCode != want {
			t.Errorf("user GET %s: %d, want %d", p, resp.StatusCode, want)
		}
	}
	if _, body := user.do(t, "GET", "/docs/?zip"); !strings.Contains(body, "a.txt") || strings.Contains(body, "pay.txt") {
		t.Error("the zip holds what is denied")
	}

	// Denied for every role above, unless a rule as long allows it.
	for role, want := range map[string]int{"operator": 403, "admin": 200, "superadmin": 200} {
		if resp, _ := f.as(role).do(t, "GET", "/docs/hr/pay.txt"); resp.StatusCode != want {
			t.Errorf("%s GET: %d, want %d", role, resp.StatusCode, want)
		}
	}
	for p, want := range map[string]int{"/docs/new.txt": 201, "/docs/hr/new.txt": 403} {
		if resp, _ := f.as("operator").send(t, "PUT", p, strings.NewReader("n")); resp.StatusCode != want {
			t.Errorf("operator PUT %s: %d, want %d", p, resp.StatusCode, want)
		}
	}
	// The admin may read /docs/hr/ but not share it: links stay within
	// what their creator may share.
	if resp, _ := f.as("admin").send(t, "POST", sharesPath, strings.NewReader("action=create&expires=1h&path=/docs/hr/"), "Content-Type", formType); resp.StatusCode != http.StatusNotFound {
		t.Errorf("sharing a denied folder: %d", resp.StatusCode)
	}
	link := sharePrefix + createShare(t, f, "admin", "/docs", "1h", "")
	if _, body := f.as("").do(t, "GET", link+"/", "Accept", "text/html"); !strings.Contains(body, `data-name="a.txt"`) || strings.Contains(body, `data-name="hr"`) {
		t.Error("the link shows what is denied")
	}
	if resp, _ := f.as("").do(t, "GET", link+"/hr/pay.txt"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a denied file through the link: %d", resp.StatusCode)
	}
}

func TestSafeNext(t *testing.T) {
	for next, want := range map[string]string{
		"/":                "/",
		"/docs/a%20b?x=1":  "/docs/a%20b?x=1",
		"":                 "/",
		"docs":             "/",
		"//evil.example":   "/",
		"/\\evil.example":  "/",
		"/a\\b":            "/",
		"https://evil.ex/": "/",
		"/a\nb":            "/",
		"/%zz":             "/",
	} {
		if got := safeNext(next); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", next, got, want)
		}
	}
}
