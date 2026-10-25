package auth_test

import (
	"context"
	"encoding/base32"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
)

// The test vectors of RFC 6238, appendix B, for SHA-1, to six digits.
func TestTOTPCode(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924",
		2000000000: "279037", 20000000000: "353130"} {
		if got := auth.TOTPCode(secret, unix/30); got != want {
			t.Errorf("at %d: %s, want %s", unix, got, want)
		}
	}
}

// codeOf is the code of the base32 secret, steps from now.
func codeOf(t *testing.T, secret string, steps int64) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return auth.TOTPCode(raw, time.Now().Unix()/30+steps)
}

// otherCode is a code that is not code.
func otherCode(code string) string {
	return string('0'+(code[0]-'0'+1)%10) + code[1:]
}

func TestTwoFactor(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		password, err := svc.CreateUser(ctx, "dora", "user")
		if err != nil {
			t.Fatal(err)
		}
		dora := userNamed(t, svc, "dora")
		before, err := svc.Login(ctx, "dora", password)
		if err != nil {
			t.Fatal(err)
		}

		// Set up: a secret, which is on once a code of it comes.
		if _, _, err := svc.ConfirmTwoFactor(ctx, dora, "123456"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("confirmed nothing: %v", err)
		}
		secret, err := svc.StartTwoFactor(ctx, dora)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[A-Z2-7]{32}$`).MatchString(secret) {
			t.Errorf("secret %q", secret)
		}
		if st, err := svc.TwoFactorOf(ctx, dora); err != nil || st.On || st.Pending != secret {
			t.Errorf("pending: %+v, %v", st, err)
		}
		if _, err := svc.Login(ctx, "dora", password); err != nil {
			t.Errorf("signing in while it is set up: %v", err)
		}
		code := codeOf(t, secret, 0)
		if _, _, err := svc.ConfirmTwoFactor(ctx, dora, otherCode(code)); !errors.Is(err, auth.ErrWrongCode) {
			t.Errorf("a wrong code: %v", err)
		}
		codes, sess, err := svc.ConfirmTwoFactor(ctx, dora, code)
		if err != nil {
			t.Fatal(err)
		}
		if len(codes) != 10 || !regexp.MustCompile(`^[a-z2-7]{5}-[a-z2-7]{5}$`).MatchString(codes[0]) || codes[0] == codes[1] {
			t.Errorf("recovery codes %q", codes)
		}
		if !sess.User.TwoFactor {
			t.Error("the new session's user")
		}
		// It signs out everywhere else.
		if _, err := svc.Authenticate(ctx, before.Token); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("an older session: %v", err)
		}
		if u, err := svc.Authenticate(ctx, sess.Token); err != nil || !u.TwoFactor {
			t.Errorf("the new session: %+v, %v", u, err)
		}
		if st, err := svc.TwoFactorOf(ctx, dora); err != nil || !st.On || st.Pending != "" || st.RecoveryCodes != 10 {
			t.Errorf("on: %+v, %v", st, err)
		}
		if _, err := svc.StartTwoFactor(ctx, dora); !errors.Is(err, auth.ErrInvalid) {
			t.Errorf("set up again: %v", err)
		}
		dora = userNamed(t, svc, "dora")

		// Signing in now takes a code, after the password.
		if _, err := svc.LoginWithCode(ctx, "dora", "wrong password", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("a wrong password: %v", err)
		}
		_, err = svc.Login(ctx, "dora", password)
		var needed *auth.CodeNeeded
		if !errors.As(err, &needed) || len(needed.Challenge) != 43 {
			t.Fatalf("without a code: %v", err)
		}
		// The code used to set it up was used.
		if _, err := svc.ContinueLogin(ctx, needed.Challenge, code); !errors.Is(err, auth.ErrWrongCode) {
			t.Errorf("a code used before: %v", err)
		}
		next := codeOf(t, secret, 1)
		sess, err = svc.ContinueLogin(ctx, needed.Challenge, " "+next[:3]+" "+next[3:])
		if err != nil || sess.RecoveryCode || sess.User.ID != dora.ID {
			t.Fatalf("with a code: %+v, %v", sess, err)
		}
		if _, err := svc.ContinueLogin(ctx, needed.Challenge, next); !errors.Is(err, auth.ErrChallengeGone) {
			t.Errorf("signed in twice: %v", err)
		}
		if _, err := svc.LoginWithCode(ctx, "dora", password, next); !errors.Is(err, auth.ErrWrongCode) {
			t.Errorf("a code used again: %v", err)
		}
		for _, bad := range []string{"12345", "1234567", "abcdef", "aaaaa-aaaaa", "x"} {
			if _, err := svc.LoginWithCode(ctx, "dora", password, bad); !errors.Is(err, auth.ErrWrongCode) {
				t.Errorf("code %q: %v", bad, err)
			}
		}

		// Recovery codes work once each, as typed.
		sess, err = svc.LoginWithCode(ctx, "dora", password, codes[0])
		if err != nil || !sess.RecoveryCode {
			t.Errorf("a recovery code: %+v, %v", sess, err)
		}
		if _, err := svc.LoginWithCode(ctx, "dora", password, codes[0]); !errors.Is(err, auth.ErrWrongCode) {
			t.Errorf("a recovery code used again: %v", err)
		}
		if _, err := svc.LoginWithCode(ctx, "dora", password, strings.ToUpper(strings.ReplaceAll(codes[1], "-", " "))); err != nil {
			t.Errorf("a recovery code as typed: %v", err)
		}
		if st, err := svc.TwoFactorOf(ctx, dora); err != nil || st.RecoveryCodes != 8 {
			t.Errorf("left: %+v, %v", st, err)
		}

		// A sign-in waits for a code a few tries long.
		_, err = svc.Login(ctx, "dora", password)
		if !errors.As(err, &needed) {
			t.Fatal(err)
		}
		for i := range 5 {
			if _, err := svc.ContinueLogin(ctx, needed.Challenge, "000000"); !errors.Is(err, auth.ErrWrongCode) && !(i == 4 && err == nil) {
				t.Errorf("try %d: %v", i, err)
			}
		}
		if _, err := svc.ContinueLogin(ctx, needed.Challenge, codes[2]); !errors.Is(err, auth.ErrChallengeGone) {
			t.Errorf("after five tries: %v", err)
		}
		if _, err := svc.ContinueLogin(ctx, "nope", codes[2]); !errors.Is(err, auth.ErrChallengeGone) {
			t.Errorf("no such sign-in: %v", err)
		}

		// New recovery codes, and turning it off, take the password.
		if _, err := svc.NewRecoveryCodes(ctx, dora, "wrong password"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("new codes, wrong password: %v", err)
		}
		fresh, err := svc.NewRecoveryCodes(ctx, dora, password)
		if err != nil || len(fresh) != 10 {
			t.Fatalf("new codes: %v, %v", fresh, err)
		}
		if _, err := svc.LoginWithCode(ctx, "dora", password, codes[3]); !errors.Is(err, auth.ErrWrongCode) {
			t.Errorf("an old recovery code: %v", err)
		}
		if _, err := svc.LoginWithCode(ctx, "dora", password, fresh[0]); err != nil {
			t.Errorf("a new recovery code: %v", err)
		}
		if err := svc.DisableTwoFactor(ctx, dora, "wrong password"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("off, wrong password: %v", err)
		}
		if err := svc.DisableTwoFactor(ctx, dora, password); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Login(ctx, "dora", password); err != nil {
			t.Errorf("off: %v", err)
		}
		if st, err := svc.TwoFactorOf(ctx, dora); err != nil || st.On || st.RecoveryCodes != 0 {
			t.Errorf("off: %+v, %v", st, err)
		}
		if _, err := svc.NewRecoveryCodes(ctx, dora, password); !errors.Is(err, auth.ErrInvalid) {
			t.Errorf("new codes while off: %v", err)
		}

		// Administrators turn it off for those who lost their app.
		secret, err = svc.StartTwoFactor(ctx, dora)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.ConfirmTwoFactor(ctx, dora, codeOf(t, secret, 0)); err != nil {
			t.Fatal(err)
		}
		if on, err := svc.ResetTwoFactor(ctx, "Dora"); err != nil || !on {
			t.Errorf("reset: %v, %v", on, err)
		}
		if on, err := svc.ResetTwoFactor(ctx, "dora"); err != nil || on {
			t.Errorf("reset again: %v, %v", on, err)
		}
		if _, err := svc.ResetTwoFactor(ctx, "nobody"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("reset nobody: %v", err)
		}
		if _, err := svc.Login(ctx, "dora", password); err != nil {
			t.Errorf("after the reset: %v", err)
		}
	})
}

func TestOTPAuthURI(t *testing.T) {
	got := auth.OTPAuthURI("files.example.com", "dora", "ABCDEF")
	want := "otpauth://totp/files.example.com:dora?algorithm=SHA1&digits=6&issuer=files.example.com&period=30&secret=ABCDEF"
	if got != want {
		t.Errorf("%s, want %s", got, want)
	}
}
