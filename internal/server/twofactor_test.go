package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"goftp/internal/config"
)

// totpOf is the code of the base32 secret, steps of 30 seconds from now
// (RFC 6238).
func totpOf(t *testing.T, secret string, steps int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(secret, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, time.Now().Unix()/30+steps)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:])&0x7fffffff)%1_000_000)
}

var (
	secretShown   = regexp.MustCompile(`id="totp-secret">([A-Z2-7 ]+)<`)
	recoveryShown = regexp.MustCompile(`<li><code>([a-z2-7]{5}-[a-z2-7]{5})</code></li>`)
	challengeSent = regexp.MustCompile(`name="challenge" value="([A-Za-z0-9_-]{43})"`)
)

// setUpTwoFactor turns two-factor sign-in on for the user of f from the
// page, and returns their secret, recovery codes and new session.
func setUpTwoFactor(t *testing.T, f *fixture) (string, []string, *fixture) {
	t.Helper()
	html := []string{"Accept", "text/html"}
	resp, _ := post(t, f, twoFactorPath, "action=start", html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != twoFactorPath {
		t.Fatalf("start: %d %v", resp.StatusCode, resp.Header)
	}
	_, body := f.do(t, "GET", twoFactorPath, html...)
	m := secretShown.FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, `<svg class="qr" viewBox=`) || !strings.Contains(body, `href="otpauth://totp/example.com:`) {
		t.Fatalf("setup: %s", body)
	}
	secret := strings.ReplaceAll(m[1], " ", "")
	resp, body = post(t, f, twoFactorPath, "action=confirm&code="+otherTOTP(totpOf(t, secret, 0)), html...)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "That is not the code the app shows now") {
		t.Errorf("a wrong code: %d %s", resp.StatusCode, body)
	}
	resp, body = post(t, f, twoFactorPath, "action=confirm&code="+totpOf(t, secret, 0))
	expectStatus(t, resp, http.StatusOK)
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
		Token         string
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.RecoveryCodes) != 10 || len(out.Token) != 43 {
		t.Fatalf("confirmed: %s", body)
	}
	// It signed out everywhere.
	if resp, _ := f.do(t, "GET", "/"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old session: %d", resp.StatusCode)
	}
	return secret, out.RecoveryCodes, f.signedIn(out.Token)
}

func otherTOTP(code string) string { return string('0'+(code[0]-'0'+1)%10) + code[1:] }

func TestTwoFactorSignIn(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	dora := f.signedIn(ta.addUser(t, "dora", "user"))
	html := []string{"Accept", "text/html"}

	if _, body := dora.do(t, "GET", "/", html...); !strings.Contains(body, `<a href="/.auth/two-factor">`) {
		t.Error("no menu entry")
	}
	_, body := dora.do(t, "GET", twoFactorPath, html...)
	if !strings.Contains(body, "Off: your password alone signs you in.") || !strings.Contains(body, `value="start"`) {
		t.Errorf("off: %s", body)
	}
	secret, codes, dora := setUpTwoFactor(t, dora)
	_, body = dora.do(t, "GET", twoFactorPath, html...)
	if !strings.Contains(body, "On: after your password") || !strings.Contains(body, "10 of 10 left.") {
		t.Errorf("on: %s", body)
	}
	if _, body := f.as("superadmin").do(t, "GET", usersPath, html...); !strings.Contains(body, "</svg>two-factor</span>") {
		t.Error("not shown to superadmins")
	}

	// The password first, then a code.
	form := func(kv ...string) (*http.Response, string) {
		t.Helper()
		r, k, v := formBody(kv...)
		return f.as("").send(t, "POST", loginPath, r, k, v)
	}
	resp, body := form("username", "dora", "password", testPassword("dora"), "next", "/docs/")
	m := challengeSent.FindStringSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil || !strings.Contains(body, "<h1>Two-factor sign-in</h1>") || cookieOf(resp, cookieName) != nil {
		t.Fatalf("after the password: %d %s", resp.StatusCode, body)
	}
	resp, body = form("challenge", m[1], "code", "000000", "next", "/docs/")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "Wrong code.") || !strings.Contains(body, m[1]) {
		t.Errorf("a wrong code: %d %s", resp.StatusCode, body)
	}
	resp, _ = form("challenge", m[1], "code", totpOf(t, secret, 1), "next", "/docs/")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/docs/" || cookieOf(resp, cookieName) == nil {
		t.Errorf("with the code: %d %v", resp.StatusCode, resp.Header)
	}
	resp, body = form("challenge", m[1], "code", totpOf(t, secret, 1))
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "sign in again") || challengeSent.MatchString(body) {
		t.Errorf("twice: %d %s", resp.StatusCode, body)
	}
	if e := f.logs.entries("login"); len(e) == 0 || e[len(e)-1]["two_factor"] != true || e[len(e)-1]["recovery_code"] != false {
		t.Errorf("logged: %v", e)
	}

	// Recovery codes, after which the page says how many are left.
	_, body = form("username", "dora", "password", testPassword("dora"))
	m = challengeSent.FindStringSubmatch(body)
	resp, _ = form("challenge", m[1], "code", strings.ToUpper(codes[0]))
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != twoFactorPath+"?recovered=1" {
		t.Fatalf("a recovery code: %d %v", resp.StatusCode, resp.Header)
	}
	_, body = f.as("").do(t, "GET", twoFactorPath+"?recovered=1", "Accept", "text/html", "Cookie", cookieName+"="+cookieOf(resp, cookieName).Value)
	if !strings.Contains(body, "You signed in with a recovery code: 9 are left.") {
		t.Errorf("recovered: %s", body)
	}

	// Scripts, in two steps or one.
	login := func(body string) (*http.Response, map[string]any) {
		t.Helper()
		resp, raw := f.as("").send(t, "POST", loginPath, strings.NewReader(body), "Content-Type", "application/json")
		var out map[string]any
		_ = json.Unmarshal([]byte(raw), &out)
		return resp, out
	}
	resp, out := login(`{"username":"dora","password":"` + testPassword("dora") + `"}`)
	challenge, _ := out["challenge"].(string)
	if resp.StatusCode != http.StatusUnauthorized || out["two_factor"] != true || len(challenge) != 43 {
		t.Fatalf("without a code: %d %v", resp.StatusCode, out)
	}
	if resp, out := login(`{"challenge":"` + challenge + `","code":"` + codes[1] + `"}`); resp.StatusCode != http.StatusOK || len(out["token"].(string)) != 43 {
		t.Errorf("with a code: %d %v", resp.StatusCode, out)
	}
	if resp, _ := login(`{"username":"dora","password":"` + testPassword("dora") + `","code":"` + codes[2] + `"}`); resp.StatusCode != http.StatusOK {
		t.Errorf("in one step: %d", resp.StatusCode)
	}
	if resp, _ := login(`{"username":"dora","password":"` + testPassword("dora") + `","code":"` + codes[2] + `"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a code used again: %d", resp.StatusCode)
	}

	// New recovery codes, and turning it off, take the password.
	resp, body = post(t, dora, twoFactorPath, "action=codes&password=wrong")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("new codes, wrong password: %d %s", resp.StatusCode, body)
	}
	resp, body = post(t, dora, twoFactorPath, "action=codes&password="+testPassword("dora"), html...)
	if resp.StatusCode != http.StatusOK || len(recoveryShown.FindAllString(body, -1)) != 10 || !strings.Contains(body, "the old ones no longer work") {
		t.Errorf("new codes: %d %s", resp.StatusCode, body)
	}
	if resp, _ := post(t, dora, twoFactorPath, "action=off&password=wrong"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("off, wrong password: %d", resp.StatusCode)
	}
	resp, _ = post(t, dora, twoFactorPath, "action=off&password="+testPassword("dora"), html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != twoFactorPath+"?done=off" {
		t.Errorf("off: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := form("username", "dora", "password", testPassword("dora")); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("signing in when off: %d", resp.StatusCode)
	}

	// Superadmins turn it off for those who lost their app.
	_, _, dora = setUpTwoFactor(t, dora)
	resp, _ = post(t, f.as("superadmin"), usersPath, "action=two-factor-off&user=dora", html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != usersPath+"?done=two-factor" {
		t.Errorf("reset: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := form("username", "dora", "password", testPassword("dora")); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("signing in after the reset: %d", resp.StatusCode)
	}
	if e := f.logs.entries("two-factor sign-in turned off"); len(e) != 1 || e[0]["target"] != "dora" {
		t.Errorf("reset logged: %v", e)
	}
}

// Wrong codes count against the client's budget, as wrong passwords do.
func TestTwoFactorLimiter(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, func(c *config.Config) { c.Limiter = config.LimiterConfig{MaxFailures: 3, Window: time.Minute} })
	_, codes, _ := setUpTwoFactor(t, f.signedIn(ta.addUser(t, "dora", "user")))
	form := func(kv ...string) (*http.Response, string) {
		t.Helper()
		r, k, v := formBody(kv...)
		return f.as("").send(t, "POST", loginPath, r, k, v)
	}
	_, body := form("username", "dora", "password", testPassword("dora"))
	m := challengeSent.FindStringSubmatch(body)
	if m == nil {
		t.Fatal(html.UnescapeString(body))
	}
	for range 3 {
		if resp, _ := form("challenge", m[1], "code", "000000"); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("a wrong code: %d", resp.StatusCode)
		}
	}
	if resp, _ := form("challenge", m[1], "code", codes[0]); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("after the budget: %d", resp.StatusCode)
	}
}
