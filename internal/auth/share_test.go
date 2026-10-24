package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
	"goftp/internal/auth/authtest"
)

func userNamed(t *testing.T, svc *auth.Service, name string) *auth.User {
	t.Helper()
	users, err := svc.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Username == name {
			return &u.User
		}
	}
	t.Fatalf("no user %s", name)
	return nil
}

func TestShares(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		for _, name := range []string{"ann", "ben"} {
			if _, err := svc.CreateUser(ctx, name, "admin"); err != nil {
				t.Fatal(err)
			}
		}
		ann, ben := userNamed(t, svc, "ann"), userNamed(t, svc, "ben")

		token, sh, err := svc.CreateShare(ctx, ann, "/docs", true, auth.ShareOptions{TTL: time.Hour})
		if err != nil || sh.ID == 0 || !auth.ValidToken(token) {
			t.Fatalf("CreateShare: %q %+v %v", token, sh, err)
		}
		got, err := svc.ShareByToken(ctx, token)
		if err != nil || got.Path != "/docs" || !got.IsDir || got.Creator != "ann" || got.CreatedBy != ann.ID ||
			got.PasswordHash != "" || time.Until(got.ExpiresAt) > time.Hour || time.Until(got.ExpiresAt) < 59*time.Minute {
			t.Fatalf("ShareByToken: %+v %v", got, err)
		}
		for _, bad := range []string{"", "x", token[:42], token + "x", strings.Repeat("A", 43), token[:42] + "."} {
			if _, err := svc.ShareByToken(ctx, bad); !errors.Is(err, auth.ErrNotFound) {
				t.Errorf("ShareByToken(%q): %v", bad, err)
			}
		}
		expired, _, err := svc.CreateShare(ctx, ann, "/old.txt", false, auth.ShareOptions{TTL: -time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ShareByToken(ctx, expired); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("expired link: %v", err)
		}

		// Passwords: short ones are refused, only a hash is kept.
		for _, pw := range []string{"short", "seven 7", strings.Repeat("x", 257)} {
			if _, _, err := svc.CreateShare(ctx, ann, "/x.txt", false, auth.ShareOptions{TTL: time.Hour, Password: pw}); !errors.Is(err, auth.ErrWeakPassword) {
				t.Errorf("password %q: %v", pw, err)
			}
		}
		locked, _, err := svc.CreateShare(ctx, ann, "/x.txt", false, auth.ShareOptions{TTL: time.Hour, Password: "correct horse"})
		if err != nil {
			t.Fatal(err)
		}
		lsh, err := svc.ShareByToken(ctx, locked)
		if err != nil || lsh.PasswordHash == "" || strings.Contains(lsh.PasswordHash, "correct") {
			t.Fatalf("protected link: %+v %v", lsh, err)
		}
		for pw, want := range map[string]bool{"correct horse": true, "correct horse ": false, "wrong": false, "": false} {
			if ok, err := svc.CheckSharePassword(ctx, lsh, pw); ok != want || err != nil {
				t.Errorf("CheckSharePassword(%q) = %v, %v", pw, ok, err)
			}
		}
		if ok, _ := svc.CheckSharePassword(ctx, got, ""); !ok {
			t.Error("a link without a password needs one")
		}

		// Proof of the password, for a cookie.
		now := time.Now()
		proof := auth.UnlockShare(lsh, locked, now.Add(time.Hour))
		if !auth.ShareUnlocked(lsh, locked, proof, now) {
			t.Error("fresh proof refused")
		}
		exp, mac, _ := strings.Cut(proof, ".")
		other := *lsh
		other.PasswordHash = "$argon2id$other"
		for name, ok := range map[string]bool{
			"expired":      auth.ShareUnlocked(lsh, locked, proof, now.Add(time.Hour)),
			"other token":  auth.ShareUnlocked(lsh, token, proof, now),
			"other link":   auth.ShareUnlocked(&other, locked, proof, now),
			"extended":     auth.ShareUnlocked(lsh, locked, "9"+exp+"."+mac, now),
			"no expiry":    auth.ShareUnlocked(lsh, locked, mac, now),
			"empty":        auth.ShareUnlocked(lsh, locked, "", now),
			"no proof":     auth.ShareUnlocked(lsh, locked, exp+".", now),
			"forged proof": auth.ShareUnlocked(lsh, locked, exp+"."+strings.Repeat("A", len(mac)), now),
			"no password":  auth.ShareUnlocked(got, token, auth.UnlockShare(got, token, now.Add(time.Hour)), now),
		} {
			if ok {
				t.Errorf("%s: accepted", name)
			}
		}

		// Listing and revoking: users see and revoke their own links.
		mine, err := svc.Shares(ctx, ann, false)
		if err != nil || len(mine) != 2 || mine[0].Path != "/x.txt" || mine[1].Path != "/docs" || mine[1].Creator != "ann" {
			t.Errorf("ann's links: %+v %v", mine, err)
		}
		if theirs, _ := svc.Shares(ctx, ben, false); len(theirs) != 0 {
			t.Errorf("ben's links: %+v", theirs)
		}
		if all, _ := svc.Shares(ctx, ben, true); len(all) != 2 {
			t.Errorf("all links: %+v", all)
		}
		if err := svc.RevokeShare(ctx, ben, sh.ID, false); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("revoking another's link: %v", err)
		}
		if err := svc.RevokeShare(ctx, ben, sh.ID, true); err != nil {
			t.Errorf("revoking as an administrator: %v", err)
		}
		if _, err := svc.ShareByToken(ctx, token); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("revoked link: %v", err)
		}
		if err := svc.RevokeShare(ctx, ann, sh.ID, false); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("revoking twice: %v", err)
		}

		// Choosing a password keeps a user's links; a reset by an
		// administrator ends them, and so does deleting the user.
		temp, err := svc.ResetPassword(ctx, "ben")
		if err != nil {
			t.Fatal(err)
		}
		sess, err := svc.Login(ctx, "ben", temp)
		if err != nil {
			t.Fatal(err)
		}
		bens, _, err := svc.CreateShare(ctx, sess.User, "/b/", true, auth.ShareOptions{TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ChangePassword(ctx, sess.User, temp, "a long new password"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ShareByToken(ctx, bens); err != nil {
			t.Errorf("a password change ended a link: %v", err)
		}
		if _, err := svc.ResetPassword(ctx, "ann"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ShareByToken(ctx, locked); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("a link survived a password reset: %v", err)
		}
		if err := svc.DeleteUser(ctx, "ben"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ShareByToken(ctx, bens); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("a link survived its creator: %v", err)
		}
		if _, _, err := svc.CreateShare(ctx, ben, "/b/", true, auth.ShareOptions{TTL: time.Hour}); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("a deleted user created a link: %v", err)
		}
	})
}

// Links can be upload links, limited in uses, and know when they were
// last used.
func TestShareUses(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		if _, err := svc.CreateUser(ctx, "ann", "admin"); err != nil {
			t.Fatal(err)
		}
		ann := userNamed(t, svc, "ann")
		for _, opts := range []auth.ShareOptions{{TTL: time.Hour, Upload: true}, {TTL: time.Hour, MaxUses: -1}, {TTL: time.Hour, MaxUses: auth.MaxShareUses + 1}} {
			if _, _, err := svc.CreateShare(ctx, ann, "/f.txt", false, opts); !errors.Is(err, auth.ErrInvalid) {
				t.Errorf("%+v: %v", opts, err)
			}
		}
		token, sh, err := svc.CreateShare(ctx, ann, "/inbox", true, auth.ShareOptions{TTL: time.Hour, Upload: true, MaxUses: 2})
		if err != nil {
			t.Fatal(err)
		}
		got, err := svc.ShareByToken(ctx, token)
		if err != nil || !got.Upload || got.MaxUses != 2 || got.Uses != 0 || !got.LastUsedAt.IsZero() || got.UsedUp() {
			t.Fatalf("ShareByToken: %+v %v", got, err)
		}
		if err := svc.TouchShare(ctx, got); err != nil {
			t.Fatal(err)
		}
		if byID, err := svc.ShareByID(ctx, sh.ID); err != nil || byID.Path != "/inbox" || byID.Creator != "ann" || time.Since(byID.LastUsedAt) > time.Minute {
			t.Errorf("ShareByID: %+v %v", byID, err)
		}
		for i, want := range []bool{true, true, false} {
			if ok, err := svc.UseShare(ctx, got); ok != want || err != nil {
				t.Errorf("use %d: %v %v", i+1, ok, err)
			}
		}
		if got, _ = svc.ShareByToken(ctx, token); got.Uses != 2 || !got.UsedUp() {
			t.Errorf("after its uses: %+v", got)
		}
		// Without a limit, uses are just counted.
		free, _, err := svc.CreateShare(ctx, ann, "/f.txt", false, auth.ShareOptions{TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		fsh, _ := svc.ShareByToken(ctx, free)
		for range 3 {
			if ok, err := svc.UseShare(ctx, fsh); !ok || err != nil {
				t.Fatalf("use: %v %v", ok, err)
			}
		}
		if fsh, _ = svc.ShareByToken(ctx, free); fsh.Uses != 3 || fsh.UsedUp() {
			t.Errorf("unlimited link: %+v", fsh)
		}
		if err := svc.RevokeShare(ctx, ann, fsh.ID, false); err != nil {
			t.Fatal(err)
		}
		if ok, err := svc.UseShare(ctx, fsh); ok || err != nil {
			t.Errorf("using a revoked link: %v %v", ok, err)
		}
		if _, err := svc.ShareByID(ctx, fsh.ID); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("ShareByID of a revoked link: %v", err)
		}
	})
}

func TestShareLimit(t *testing.T) {
	svc, _ := authtest.NewService(time.Hour)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, "ann", "admin"); err != nil {
		t.Fatal(err)
	}
	ann := userNamed(t, svc, "ann")
	if _, _, err := svc.CreateShare(ctx, ann, "/gone", false, auth.ShareOptions{TTL: -time.Second}); err != nil {
		t.Fatal(err)
	}
	for i := range auth.MaxShares {
		if _, _, err := svc.CreateShare(ctx, ann, "/f", false, auth.ShareOptions{TTL: time.Hour}); err != nil {
			t.Fatalf("link %d: %v", i, err)
		}
	}
	if _, _, err := svc.CreateShare(ctx, ann, "/f", false, auth.ShareOptions{TTL: time.Hour}); !errors.Is(err, auth.ErrTooMany) {
		t.Errorf("one link too many: %v", err)
	}
}

func TestMayShare(t *testing.T) {
	svc, _ := authtest.NewService(time.Hour)
	ctx := context.Background()
	for name, role := range map[string]string{"sam": "superadmin", "ada": "admin", "oli": "operator", "uma": "user"} {
		if _, err := svc.CreateUser(ctx, name, role); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]bool{"sam": true, "ada": true, "oli": false, "uma": false, "nobody": false} {
		if got := svc.MayShare(name); got != want {
			t.Errorf("MayShare(%s) = %v", name, got)
		}
	}
	if _, err := svc.AddPolicy("user:uma", "/uma/*", auth.ActShare); err != nil {
		t.Fatal(err)
	}
	if !svc.MayShare("uma") || svc.MayShare("oli") {
		t.Error("a rule of one's own does not count")
	}
	if _, err := svc.AddPolicy(auth.Anonymous, "/pub/*", "*"); err != nil {
		t.Fatal(err)
	}
	if !svc.MayShare("oli") {
		t.Error("what everyone may do does not count")
	}
}
