package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
)

// Test requests come from http://example.com.
var testRP = virtualwebauthn.RelyingParty{Name: "goftp", ID: "example.com", Origin: "http://example.com"}

// postJSON posts body as JSON as the client f, and decodes the answer
// into out, if it is JSON.
func postJSON(t *testing.T, f *fixture, uri string, body any, out any) (*http.Response, string) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := f.send(t, "POST", uri, strings.NewReader(string(data)), "Content-Type", "application/json")
	if out != nil && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal([]byte(raw), out); err != nil {
			t.Fatal(err)
		}
	}
	return resp, raw
}

type ceremonyStart struct {
	Options json.RawMessage
	Token   string
}

// addPasskey makes a passkey named name for the user of f, whose password
// is password, on a new authenticator, which it returns with the key.
func addPasskey(t *testing.T, f *fixture, password, name string) (virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
	t.Helper()
	var start ceremonyStart
	resp, body := postJSON(t, f, passkeysPath, map[string]string{"action": "begin", "password": password}, &start)
	if resp.StatusCode != http.StatusOK || start.Token == "" {
		t.Fatalf("begin: %d %s", resp.StatusCode, body)
	}
	opts, err := virtualwebauthn.ParseAttestationOptions(string(start.Options))
	if err != nil {
		t.Fatal(err)
	}
	a := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(opts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	answer := json.RawMessage(virtualwebauthn.CreateAttestationResponse(testRP, a, cred, *opts))
	resp, body = postJSON(t, f, passkeysPath, map[string]any{"action": "finish", "token": start.Token, "name": name, "credential": answer}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("finish: %d %s", resp.StatusCode, body)
	}
	a.AddCredential(cred)
	return a, cred
}

// passkeySignIn signs in anonymously with the passkey cred of a.
func passkeySignIn(t *testing.T, f *fixture, a virtualwebauthn.Authenticator, cred virtualwebauthn.Credential, next string) (*http.Response, string) {
	t.Helper()
	anon := f.as("")
	var start ceremonyStart
	if resp, body := postJSON(t, anon, passkeyLoginPath, map[string]string{"action": "begin"}, &start); resp.StatusCode != http.StatusOK {
		t.Fatalf("begin: %d %s", resp.StatusCode, body)
	}
	opts, err := virtualwebauthn.ParseAssertionOptions(string(start.Options))
	if err != nil {
		t.Fatal(err)
	}
	answer := json.RawMessage(virtualwebauthn.CreateAssertionResponse(testRP, a, cred, *opts))
	return postJSON(t, anon, passkeyLoginPath, map[string]any{"action": "finish", "token": start.Token, "next": next, "credential": answer}, nil)
}

func TestPasskeySignIn(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	dora := f.signedIn(ta.addUser(t, "dora", "user"))
	html := []string{"Accept", "text/html"}

	if _, body := dora.do(t, "GET", "/", html...); !strings.Contains(body, `<a href="/.auth/passkeys">`) {
		t.Error("no menu entry")
	}
	if _, body := f.as("").do(t, "GET", loginPath, html...); !strings.Contains(body, `autocomplete="username webauthn"`) || !strings.Contains(body, `id="passkey-signin"`) {
		t.Errorf("login page: %s", body)
	}
	_, body := dora.do(t, "GET", passkeysPath, html...)
	if !strings.Contains(body, "You have no passkeys.") || !strings.Contains(body, `id="add-passkey"`) {
		t.Errorf("no passkeys: %s", body)
	}

	// Adding one takes the password.
	if resp, body := postJSON(t, dora, passkeysPath, map[string]string{"action": "begin", "password": "wrong"}, nil); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, "The password is wrong.") {
		t.Errorf("wrong password: %d %s", resp.StatusCode, body)
	}
	if resp, _ := post(t, dora, passkeysPath, "action=begin"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("as a form: %d", resp.StatusCode)
	}
	a, cred := addPasskey(t, dora, testPassword("dora"), "laptop")
	_, body = dora.do(t, "GET", passkeysPath, html...)
	if !strings.Contains(body, "<span>laptop</span>") || !strings.Contains(body, `<span class="faint">never</span>`) {
		t.Errorf("listed: %s", body)
	}

	// It signs dora in, without a password, and her browser goes on.
	resp, body := passkeySignIn(t, f, a, cred, "/docs/")
	var done struct{ Next string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &done) != nil || done.Next != "/docs/" {
		t.Fatalf("signed in: %d %s", resp.StatusCode, body)
	}
	cookie := cookieOf(resp, cookieName)
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	if _, body := f.as("").do(t, "GET", "/", "Accept", "text/html", "Cookie", cookieName+"="+cookie.Value); !strings.Contains(body, "Signed in as <strong>dora</strong>") {
		t.Errorf("the session: %s", body)
	}
	if e := f.logs.entries("login"); len(e) == 0 || e[len(e)-1]["passkey"] != true {
		t.Errorf("logged: %v", e)
	}
	if resp, _ := passkeySignIn(t, f, a, cred, "https://evil.example/"); resp.StatusCode != http.StatusOK {
		t.Errorf("signed in again: %d", resp.StatusCode)
	} else if _, body := passkeySignIn(t, f, a, cred, "//evil.example/"); !strings.Contains(body, `"next":"/"`) {
		t.Errorf("next leads elsewhere: %s", body)
	}

	// With two-factor sign-in, no code after it.
	_, _, dora = setUpTwoFactor(t, dora, "dora")
	if resp, _ := passkeySignIn(t, f, a, cred, "/"); resp.StatusCode != http.StatusOK {
		t.Errorf("with two-factor sign-in: %d", resp.StatusCode)
	}

	// Passkeys it does not know, and answers that do not check out, are
	// refused.
	stranger := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	a.AddCredential(stranger)
	if resp, body := passkeySignIn(t, f, a, stranger, "/"); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "does not sign anyone in here") {
		t.Errorf("an unknown passkey: %d %s", resp.StatusCode, body)
	}
	if resp, body := postJSON(t, f.as(""), passkeyLoginPath, map[string]any{"action": "finish", "token": strings.Repeat("x", 43), "credential": map[string]string{}}, nil); resp.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(body, "It took too long") {
		t.Errorf("no such ceremony: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.as("").send(t, "POST", passkeyLoginPath, strings.NewReader("action=begin"), "Content-Type", formType); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("as a form: %d", resp.StatusCode)
	}

	// Deleted, it signs nobody in.
	u, err := ta.svc.UserNamed(t.Context(), "dora")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ta.svc.Passkeys(t.Context(), u)
	if err != nil || len(keys) != 1 {
		t.Fatalf("passkeys: %v, %v", keys, err)
	}
	resp, _ = post(t, dora, passkeysPath, "action=delete&id="+strconv.FormatInt(keys[0].ID, 10), html...)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != passkeysPath+"?done=deleted" {
		t.Errorf("deleted: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := passkeySignIn(t, f, a, cred, "/"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a deleted passkey: %d", resp.StatusCode)
	}
	if resp, _ := post(t, dora, passkeysPath, "action=delete&id="+strconv.FormatInt(keys[0].ID, 10)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleted twice: %d", resp.StatusCode)
	}
}

// Starting passkey sign-ins is limited per client.
func TestPasskeyStartLimit(t *testing.T) {
	defer func(n int) { passkeyStartsPerMinute = n }(passkeyStartsPerMinute)
	passkeyStartsPerMinute = 2
	f := newFixture(t).as("")
	for i := range 3 {
		resp, _ := postJSON(t, f, passkeyLoginPath, map[string]string{"action": "begin"}, nil)
		if want := map[bool]int{true: http.StatusOK, false: http.StatusTooManyRequests}[i < 2]; resp.StatusCode != want {
			t.Errorf("start %d: %d", i, resp.StatusCode)
		}
	}
}
