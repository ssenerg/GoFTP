package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/descope/virtualwebauthn"

	"goftp/internal/auth"
)

var (
	site   = auth.Site{Host: "files.example.com", Origin: "https://files.example.com"}
	siteRP = virtualwebauthn.RelyingParty{Name: "goftp", ID: site.Host, Origin: site.Origin}
)

// makePasskey makes a passkey for u named name on a new authenticator,
// which it returns with the passkey's key.
func makePasskey(t *testing.T, svc *auth.Service, u *auth.User, password, name string) (virtualwebauthn.Authenticator, virtualwebauthn.Credential, *auth.Passkey) {
	t.Helper()
	ctx := context.Background()
	options, token, err := svc.BeginPasskey(ctx, u, password, site)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := virtualwebauthn.ParseAttestationOptions(string(options))
	if err != nil {
		t.Fatal(err)
	}
	a := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(parsed.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	pk, err := svc.FinishPasskey(ctx, u, token, name, []byte(virtualwebauthn.CreateAttestationResponse(siteRP, a, cred, *parsed)))
	if err != nil {
		t.Fatal(err)
	}
	a.AddCredential(cred)
	return a, cred, pk
}

// signInWith signs in with the passkey cred of a, answering as rp.
func signInWith(t *testing.T, svc *auth.Service, a virtualwebauthn.Authenticator, cred virtualwebauthn.Credential, rp virtualwebauthn.RelyingParty) (*auth.Session, error) {
	t.Helper()
	options, token, err := svc.BeginPasskeyLogin(site)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := virtualwebauthn.ParseAssertionOptions(string(options))
	if err != nil {
		t.Fatal(err)
	}
	return svc.PasskeyLogin(context.Background(), token, []byte(virtualwebauthn.CreateAssertionResponse(rp, a, cred, *parsed)))
}

func TestPasskeys(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		password, err := svc.CreateUser(ctx, "dora", "user")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CreateUser(ctx, "erin", "user"); err != nil {
			t.Fatal(err)
		}
		dora, erin := userNamed(t, svc, "dora"), userNamed(t, svc, "erin")

		if _, _, err := svc.BeginPasskey(ctx, dora, "wrong password", site); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("wrong password: %v", err)
		}
		_, token, err := svc.BeginPasskey(ctx, dora, password, site)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"", " ", "a\nb"} {
			if _, err := svc.FinishPasskey(ctx, dora, token, name, []byte("{}")); !errors.Is(err, auth.ErrInvalid) {
				t.Errorf("name %q: %v", name, err)
			}
		}
		if _, err := svc.FinishPasskey(ctx, erin, token, "phone", []byte("{}")); !errors.Is(err, auth.ErrCeremonyGone) {
			t.Errorf("someone else's: %v", err)
		}
		if _, err := svc.FinishPasskey(ctx, dora, token, "phone", []byte("{}")); !errors.Is(err, auth.ErrCeremonyGone) {
			t.Errorf("finished twice: %v", err)
		}

		a, cred, pk := makePasskey(t, svc, dora, password, " laptop ")
		if pk.ID == 0 || pk.Name != "laptop" || pk.UserID != dora.ID || len(pk.CredentialID) == 0 {
			t.Errorf("passkey %+v", pk)
		}
		// An authenticator with one of dora's passkeys makes no other.
		options, _, err := svc.BeginPasskey(ctx, dora, password, site)
		if err != nil {
			t.Fatal(err)
		}
		if parsed, err := virtualwebauthn.ParseAttestationOptions(string(options)); err != nil || len(parsed.ExcludeCredentials) != 1 {
			t.Errorf("excluded: %+v, %v", parsed, err)
		}

		// It signs dora in, whoever she is to the browser.
		sess, err := signInWith(t, svc, a, cred, siteRP)
		if err != nil || sess.User.ID != dora.ID || len(sess.Token) != 43 {
			t.Fatalf("signed in: %+v, %v", sess, err)
		}
		if keys, err := svc.Passkeys(ctx, dora); err != nil || len(keys) != 1 || keys[0].LastUsedAt.IsZero() {
			t.Errorf("used: %+v, %v", keys, err)
		}
		// Not on another site, nor with a passkey it does not know.
		if _, err := signInWith(t, svc, a, cred, virtualwebauthn.RelyingParty{Name: "goftp", ID: site.Host, Origin: "https://evil.example.com"}); !errors.Is(err, auth.ErrPasskeyRefused) {
			t.Errorf("another origin: %v", err)
		}
		if _, err := signInWith(t, svc, a, cred, virtualwebauthn.RelyingParty{Name: "goftp", ID: "evil.example.com", Origin: site.Origin}); !errors.Is(err, auth.ErrPasskeyRefused) {
			t.Errorf("another site: %v", err)
		}
		stranger := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		a.AddCredential(stranger)
		if _, err := signInWith(t, svc, a, stranger, siteRP); !errors.Is(err, auth.ErrPasskeyRefused) {
			t.Errorf("an unknown passkey: %v", err)
		}
		if _, err := svc.PasskeyLogin(ctx, "nope", []byte("{}")); !errors.Is(err, auth.ErrCeremonyGone) {
			t.Errorf("no such ceremony: %v", err)
		}

		// With two-factor sign-in, no code after it: a passkey is one in
		// itself.
		secret, err := svc.StartTwoFactor(ctx, dora)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.ConfirmTwoFactor(ctx, dora, codeOf(t, secret, 0)); err != nil {
			t.Fatal(err)
		}
		if _, err := signInWith(t, svc, a, cred, siteRP); err != nil {
			t.Errorf("with two-factor sign-in on: %v", err)
		}

		// Deleted, it signs nobody in.
		if err := svc.DeletePasskey(ctx, erin, pk.ID); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("deleted by someone else: %v", err)
		}
		if err := svc.DeletePasskey(ctx, dora, pk.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := signInWith(t, svc, a, cred, siteRP); !errors.Is(err, auth.ErrPasskeyRefused) {
			t.Errorf("a deleted passkey: %v", err)
		}

		// A new temporary password ends them, as one does after a break-in.
		a, cred, _ = makePasskey(t, svc, dora, password, "phone")
		if _, err := svc.ResetPassword(ctx, "dora"); err != nil {
			t.Fatal(err)
		}
		if keys, err := svc.Passkeys(ctx, dora); err != nil || len(keys) != 0 {
			t.Errorf("after a reset: %+v, %v", keys, err)
		}
		if _, err := signInWith(t, svc, a, cred, siteRP); !errors.Is(err, auth.ErrPasskeyRefused) {
			t.Errorf("after a reset: %v", err)
		}
	})
}

func TestPasskeyLimit(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		password, err := svc.CreateUser(ctx, "dora", "user")
		if err != nil {
			t.Fatal(err)
		}
		dora := userNamed(t, svc, "dora")
		for range auth.MaxPasskeys {
			makePasskey(t, svc, dora, password, "key")
		}
		if _, _, err := svc.BeginPasskey(ctx, dora, password, site); !errors.Is(err, auth.ErrTooMany) {
			t.Errorf("one too many: %v", err)
		}
	})
}
