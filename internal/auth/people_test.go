package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"goftp/internal/auth"
)

func TestFolderShares(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		svc.SetHomes("/home")
		for _, name := range []string{"dora", "erin", "finn"} {
			if _, err := svc.CreateUser(ctx, name, "user"); err != nil {
				t.Fatal(err)
			}
		}
		dora, erin, finn := userNamed(t, svc, "dora"), userNamed(t, svc, "erin"), userNamed(t, svc, "finn")

		for _, tc := range []struct {
			path, user string
			want       error
		}{
			{"/home/erin/docs", "erin", auth.ErrInvalid}, // not dora's
			{"/home/doras", "erin", auth.ErrInvalid},
			{"/public", "erin", auth.ErrInvalid},
			{"/home/dora/../erin", "erin", auth.ErrInvalid},
			{"/home/dora/docs", "dora", auth.ErrInvalid}, // dora's already
			{"/home/dora/docs", "nobody", auth.ErrNotFound},
		} {
			if _, err := svc.ShareFolder(ctx, dora, tc.path, tc.user, false); !errors.Is(err, tc.want) {
				t.Errorf("ShareFolder(%q, %q): %v", tc.path, tc.user, err)
			}
		}
		fs, err := svc.ShareFolder(ctx, dora, "/home/dora/docs", "Erin", false)
		if err != nil {
			t.Fatal(err)
		}
		if fs.ID == 0 || fs.UserID != erin.ID || fs.User != "erin" || fs.Write || fs.CreatedAt.IsZero() {
			t.Errorf("share %+v", fs)
		}

		allowed := func(u *auth.User, obj, act string) bool {
			t.Helper()
			rules, err := svc.RulesFor(ctx, u)
			if err != nil {
				t.Fatal(err)
			}
			return rules.Allow(obj, act)
		}
		type check struct {
			who      *auth.User
			obj, act string
			want     bool
		}
		checks := func(cs []check) {
			t.Helper()
			for _, c := range cs {
				if got := allowed(c.who, c.obj, c.act); got != c.want {
					t.Errorf("%s may %s %s: %v", c.who.Username, c.act, c.obj, got)
				}
			}
		}
		checks([]check{
			{erin, "/home/dora/docs/", auth.ActRead, true},
			{erin, "/home/dora/docs/a.txt", auth.ActRead, true},
			{erin, "/home/dora/docs/a.txt", auth.ActWrite, false},
			{erin, "/home/dora/", auth.ActRead, false},
			{erin, "/home/dora/other/", auth.ActRead, false},
			{erin, "/home/dora/docs/", auth.ActShare, false},
			{finn, "/home/dora/docs/a.txt", auth.ActRead, false},
		})

		// Sharing it again changes how.
		again, err := svc.ShareFolder(ctx, dora, "/home/dora/docs", "erin", true)
		if err != nil || again.ID != fs.ID || !again.Write {
			t.Fatalf("shared again: %+v, %v", again, err)
		}
		checks([]check{
			{erin, "/home/dora/docs/a.txt", auth.ActWrite, true},
			{erin, "/home/dora/docs/a.txt", auth.ActOverwrite, true},
			{erin, "/home/dora/docs/sub/", auth.ActDelete, true},
			{erin, "/home/dora/docs/", auth.ActDelete, false},
			{erin, "/home/dora/docs/", auth.ActShare, false},
			{erin, "/home/dora/", auth.ActWrite, false},
		})

		// Only as far as its owner may go and share, and administrators'
		// rules for the same paths come first.
		for _, rule := range [][3]string{
			{"user:dora", "!/home/dora/docs/secret/*", "*"},
			{"user:dora", "!/home/dora/docs/mine/*", auth.ActShare},
			{"user:erin", "!/home/dora/docs/*", auth.ActDelete},
		} {
			if ok, err := svc.AddPolicy(rule[0], rule[1], rule[2]); !ok || err != nil {
				t.Fatalf("AddPolicy(%q) = %v, %v", rule, ok, err)
			}
		}
		checks([]check{
			{erin, "/home/dora/docs/secret/a.txt", auth.ActRead, false},
			{erin, "/home/dora/docs/mine/a.txt", auth.ActRead, false},
			{dora, "/home/dora/docs/mine/a.txt", auth.ActRead, true},
			{erin, "/home/dora/docs/sub/", auth.ActDelete, false},
			{erin, "/home/dora/docs/a.txt", auth.ActRead, true},
		})

		lists := func(u *auth.User, all bool, want ...string) {
			t.Helper()
			shares, err := svc.FolderShares(ctx, u, all)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, fs := range shares {
				got = append(got, fs.Owner+":"+fs.Path+">"+fs.User)
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("FolderShares(%s, %v) = %v, want %v", u.Username, all, got, want)
			}
		}
		sharedWith := func(u *auth.User, want ...string) {
			t.Helper()
			shares, err := svc.SharedWith(ctx, u)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, fs := range shares {
				got = append(got, fs.Path)
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("SharedWith(%s) = %v, want %v", u.Username, got, want)
			}
		}
		if _, err := svc.ShareFolder(ctx, dora, "/home/dora/docs/team", "finn", false); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ShareFolder(ctx, erin, "/home/erin", "dora", false); err != nil {
			t.Fatal(err)
		}
		lists(dora, false, "dora:/home/dora/docs/team>finn", "dora:/home/dora/docs>erin")
		lists(dora, true, "erin:/home/erin>dora", "dora:/home/dora/docs/team>finn", "dora:/home/dora/docs>erin")
		sharedWith(erin, "/home/dora/docs")
		sharedWith(dora, "/home/erin")
		checks([]check{{dora, "/home/erin/x/a.txt", auth.ActRead, true}})

		// Shares follow their folders within the home, and end once they
		// leave it.
		moves := []struct{ from, to string }{
			{"/home/dora/docs", "/home/dora/a/papers"},
			{"/home/dora/a/papers/team", "/home/dora/team"},
		}
		for _, m := range moves {
			if err := svc.MoveFolderShares(ctx, m.from, m.to); err != nil {
				t.Fatal(err)
			}
		}
		sharedWith(erin, "/home/dora/a/papers")
		sharedWith(finn, "/home/dora/team")
		checks([]check{
			{erin, "/home/dora/a/papers/x.txt", auth.ActRead, true},
			{erin, "/home/dora/docs/x.txt", auth.ActRead, false},
		})
		if err := svc.MoveFolderShares(ctx, "/home/dora/team", "/home/erin/team"); err != nil {
			t.Fatal(err)
		}
		sharedWith(finn)
		if err := svc.MoveFolderShares(ctx, "/home/dora/a", ""); err != nil {
			t.Fatal(err)
		}
		sharedWith(erin)
		// Unrelated moves leave them be; shares left where a folder moves to
		// are of a folder that is gone.
		for _, p := range []string{"/home/dora/p", "/home/dora/q", "/home/dora/qq"} {
			if _, err := svc.ShareFolder(ctx, dora, p, "erin", false); err != nil {
				t.Fatal(err)
			}
		}
		if err := svc.MoveFolderShares(ctx, "/home/dora/p", "/home/dora/q"); err != nil {
			t.Fatal(err)
		}
		sharedWith(erin, "/home/dora/q", "/home/dora/qq")
		if err := svc.MoveFolderShares(ctx, "/home/dora/z", "/home/dora/qq"); err != nil {
			t.Fatal(err)
		}
		sharedWith(erin, "/home/dora/q")

		// Their owner stops them, or their user leaves; nobody else may.
		shares, err := svc.SharedWith(ctx, erin)
		if err != nil {
			t.Fatal(err)
		}
		q := shares[0].ID
		if _, err := svc.UnshareFolder(ctx, finn, q, false); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("finn ended a share: %v", err)
		}
		gone, err := svc.UnshareFolder(ctx, erin, q, false)
		if err != nil || gone.Path != "/home/dora/q" || gone.OwnerID != dora.ID || gone.UserID != erin.ID {
			t.Errorf("erin left: %+v, %v", gone, err)
		}
		if _, err := svc.UnshareFolder(ctx, dora, q, false); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("ended twice: %v", err)
		}
		fs, err = svc.ShareFolder(ctx, dora, "/home/dora", "finn", false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.UnshareFolder(ctx, erin, fs.ID, true); err != nil {
			t.Errorf("ended by a superadmin: %v", err)
		}

		// Users' shares go with them.
		if _, err := svc.ShareFolder(ctx, dora, "/home/dora/x", "erin", false); err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteUser(ctx, "erin"); err != nil {
			t.Fatal(err)
		}
		lists(dora, true)

		// Homes that moved leave their shares behind.
		if _, err := svc.ShareFolder(ctx, dora, "/home/dora/x", "finn", true); err != nil {
			t.Fatal(err)
		}
		svc.SetHomes("/users")
		sharedWith(finn)
		checks([]check{{finn, "/home/dora/x/a.txt", auth.ActWrite, false}})
		svc.SetHomes("")
		sharedWith(finn)
	})
}

func TestFolderShareLimit(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		svc.SetHomes("/home")
		for _, name := range []string{"dora", "erin"} {
			if _, err := svc.CreateUser(ctx, name, "user"); err != nil {
				t.Fatal(err)
			}
		}
		dora := userNamed(t, svc, "dora")
		for i := range auth.MaxFolderShares {
			if _, err := svc.ShareFolder(ctx, dora, fmt.Sprintf("/home/dora/%d", i), "erin", false); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := svc.ShareFolder(ctx, dora, "/home/dora/more", "erin", false); !errors.Is(err, auth.ErrTooMany) {
			t.Errorf("one too many: %v", err)
		}
		// Changing how one is shared is not one more.
		if _, err := svc.ShareFolder(ctx, dora, "/home/dora/0", "erin", true); err != nil {
			t.Errorf("shared again: %v", err)
		}
	})
}

// Where names are found whatever their case, the folder spelled otherwise
// is the same folder.
func TestFolderSharesFolded(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		svc.SetHomes("/home")
		svc.SetFold(strings.ToLower)
		for _, name := range []string{"dora", "erin"} {
			if _, err := svc.CreateUser(ctx, name, "user"); err != nil {
				t.Fatal(err)
			}
		}
		dora, erin := userNamed(t, svc, "dora"), userNamed(t, svc, "erin")
		first, err := svc.ShareFolder(ctx, dora, "/home/dora/Docs", "erin", false)
		if err != nil {
			t.Fatal(err)
		}
		again, err := svc.ShareFolder(ctx, dora, "/home/dora/DOCS", "erin", true)
		if err != nil || again.ID != first.ID || again.Path != "/home/dora/Docs" {
			t.Errorf("shared again: %+v, %v", again, err)
		}
		if err := svc.MoveFolderShares(ctx, "/home/dora/docs", "/home/dora/Papers"); err != nil {
			t.Fatal(err)
		}
		shares, err := svc.SharedWith(ctx, erin)
		if err != nil || len(shares) != 1 || shares[0].Path != "/home/dora/Papers" {
			t.Errorf("moved: %+v, %v", shares, err)
		}
		rules, err := svc.RulesFor(ctx, erin)
		if err != nil {
			t.Fatal(err)
		}
		if !rules.Allow("/home/dora/PAPERS/a.txt", auth.ActWrite) {
			t.Error("the folder spelled otherwise is not shared")
		}
	})
}
