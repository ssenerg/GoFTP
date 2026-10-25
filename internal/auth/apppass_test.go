package auth_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
)

func TestAppPasswords(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		temp, err := svc.CreateUser(ctx, "dora", "user")
		if err != nil {
			t.Fatal(err)
		}
		erinTemp, err := svc.CreateUser(ctx, "erin", "user")
		if err != nil {
			t.Fatal(err)
		}
		dora, erin := userNamed(t, svc, "dora"), userNamed(t, svc, "erin")

		for _, name := range []string{"", "  ", strings.Repeat("x", 65), "a\nb"} {
			if _, _, err := svc.CreateAppPassword(ctx, dora, name, temp); !errors.Is(err, auth.ErrInvalid) {
				t.Errorf("CreateAppPassword(%q): %v", name, err)
			}
		}
		// It takes the password: a stolen session alone makes none.
		for _, wrong := range []string{"", "wrong password", erinTemp} {
			if _, _, err := svc.CreateAppPassword(ctx, dora, "laptop", wrong); !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Errorf("password %q: %v", wrong, err)
			}
		}
		password, ap, err := svc.CreateAppPassword(ctx, dora, "  rclone on my laptop ", temp)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[a-z2-7]{4}(-[a-z2-7]{4}){5}$`).MatchString(password) {
			t.Errorf("password %q", password)
		}
		if ap.ID == 0 || ap.Name != "rclone on my laptop" || ap.CreatedAt.IsZero() || !ap.LastUsedAt.IsZero() {
			t.Errorf("app password %+v", ap)
		}

		// It signs in as dora, written as people may copy it.
		for _, tc := range []struct{ username, password string }{
			{"dora", password},
			{"Dora", strings.ToUpper(password)},
			{"dora", strings.ReplaceAll(password, "-", "")},
			{"dora", " " + password + "\n"},
		} {
			u, err := svc.AppPasswordUser(ctx, tc.username, tc.password)
			if err != nil || u.ID != dora.ID {
				t.Errorf("AppPasswordUser(%q, %q): %v, %v", tc.username, tc.password, u, err)
			}
		}
		other, _, err := svc.CreateAppPassword(ctx, erin, "phone", erinTemp)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ username, password string }{
			{"erin", password}, // someone else's
			{"dora", other},    // and the other way round
			{"dora", temp},     // the account's password
			{"dora", password[:len(password)-1] + "1"}, // not base32
			{"dora", password + "a"},
			{"nobody", password},
			{"dora", ""},
		} {
			if _, err := svc.AppPasswordUser(ctx, tc.username, tc.password); !errors.Is(err, auth.ErrNotFound) {
				t.Errorf("AppPasswordUser(%q, %q): %v", tc.username, tc.password, err)
			}
		}

		// Listed newest first, with when they were last used.
		phone, _, err := svc.CreateAppPassword(ctx, dora, "phone", temp)
		if err != nil {
			t.Fatal(err)
		}
		apps, err := svc.AppPasswords(ctx, dora)
		if err != nil {
			t.Fatal(err)
		}
		if len(apps) != 2 || apps[0].Name != "phone" || apps[1].ID != ap.ID || time.Since(apps[1].LastUsedAt) > time.Minute ||
			!apps[0].LastUsedAt.IsZero() {
			t.Errorf("listed %+v", apps)
		}

		// Revoked, one stops working and the others do not.
		if err := svc.RevokeAppPassword(ctx, erin, ap.ID); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("revoked by someone else: %v", err)
		}
		if err := svc.RevokeAppPassword(ctx, dora, ap.ID); err != nil {
			t.Fatal(err)
		}
		if err := svc.RevokeAppPassword(ctx, dora, ap.ID); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("revoked twice: %v", err)
		}
		if _, err := svc.AppPasswordUser(ctx, "dora", password); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("revoked app password: %v", err)
		}
		if _, err := svc.AppPasswordUser(ctx, "dora", phone); err != nil {
			t.Errorf("the other app password: %v", err)
		}

		// A user has only so many.
		for i := 1; i < auth.MaxAppPasswords; i++ {
			if _, _, err := svc.CreateAppPassword(ctx, dora, "app", temp); err != nil {
				t.Fatal(i, err)
			}
		}
		if _, _, err := svc.CreateAppPassword(ctx, dora, "one too many", temp); !errors.Is(err, auth.ErrTooMany) {
			t.Errorf("over the limit: %v", err)
		}

		// A new password ends them all: they may have been made by
		// whoever learned the old one.
		sess, err := svc.Login(ctx, "dora", temp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ChangePassword(ctx, sess.User, temp, "a long new password"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.AppPasswordUser(ctx, "dora", phone); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("after a password change: %v", err)
		}
		if apps, err := svc.AppPasswords(ctx, dora); err != nil || len(apps) != 0 {
			t.Errorf("after a password change: %v, %v", apps, err)
		}
		if _, err := svc.AppPasswordUser(ctx, "erin", other); err != nil {
			t.Errorf("another user's: %v", err)
		}
		// So does a reset by an administrator, and deleting the user.
		if _, err := svc.ResetPassword(ctx, "erin"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.AppPasswordUser(ctx, "erin", other); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("after a reset: %v", err)
		}
		// The password checked must still be the password when it is made.
		if _, _, err := svc.CreateAppPassword(ctx, dora, "stale", temp); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("with the password before the change: %v", err)
		}
		dora = userNamed(t, svc, "dora")
		last, _, err := svc.CreateAppPassword(ctx, dora, "last", "a long new password")
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteUser(ctx, "dora"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.AppPasswordUser(ctx, "dora", last); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("of a deleted user: %v", err)
		}
	})
}
