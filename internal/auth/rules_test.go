package auth_test

import (
	"context"
	"strings"
	"testing"

	"goftp/internal/auth"
)

func TestDenyRules(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		for name, role := range map[string]string{"alice": "user", "olga": "operator", "adam": "admin", "sam": "superadmin", "bob": "user", "carl": "user"} {
			if _, err := svc.Enforcer().AddRoleForUser(auth.Subject(name), role); err != nil {
				t.Fatal(err)
			}
		}
		for _, rule := range [][3]string{
			// Users may not open /hr/, admins may, and users may read the
			// handbook in it.
			{"user", "!/hr/*", "*"},
			{"admin", "/hr/*", "*"},
			{"user", "/hr/handbook/*", "read"},
			// bob may open /bob/ only, and list the top folder.
			{"user:bob", "!/*", "*"},
			{"user:bob", "/bob/*", "*"},
			{"user:bob", "/", "read"},
			// Everyone may read /public/, but its drafts.
			{"anonymous", "/public/*", "read"},
			{"anonymous", "!/public/drafts/*", "read"},
			// Which signing in cannot take away.
			{"user:alice", "!/public/*", "read"},
			// One action only.
			{"user:olga", "!/docs/*", "write"},
			// The same path both ways: denied.
			{"user:carl", "/tie/*", "read"},
			{"user:carl", "!/tie/*", "read"},
			// An exact path before the same path with "*".
			{"user:carl", "!/list/*", "read"},
			{"user:carl", "/list/", "read"},
		} {
			if ok, err := svc.AddPolicy(rule[0], rule[1], rule[2]); !ok || err != nil {
				t.Fatalf("AddPolicy(%q) = %v, %v", rule, ok, err)
			}
		}
		for _, c := range []struct {
			who, obj, act string
			want          bool
		}{
			{"alice", "/docs/a", "read", true},
			{"alice", "/hr/", "read", false},
			{"alice", "/hr/pay.pdf", "read", false},
			{"alice", "/hr/handbook/", "read", true},
			{"alice", "/hr/handbook/a.pdf", "read", true},
			{"alice", "/hrx/a", "read", true},
			{"alice", "/public/a", "read", true},
			{"alice", "/public/drafts/a", "read", false},
			{"olga", "/hr/a", "read", false},
			{"olga", "/hr/a", "write", false},
			{"olga", "/docs/a", "read", true},
			{"olga", "/docs/a", "write", false},
			{"olga", "/other/a", "write", true},
			{"adam", "/hr/a", "read", true},
			{"adam", "/hr/a", "delete", true},
			{"sam", "/hr/a", "share", true},
			{"sam", "/docs/a", "anything", true},
			{"bob", "/", "read", true},
			{"bob", "/", "write", false},
			{"bob", "/docs/", "read", false},
			{"bob", "/docs/a", "read", false},
			{"bob", "/bob/", "read", true},
			{"bob", "/bob/a", "write", true},
			{"bob", "/bob/a", "delete", true},
			{"bob", "/bobby/a", "read", false},
			{"bob", "/hr/handbook/a.pdf", "read", true},
			{"bob", "/public/a", "read", true},
			{"carl", "/tie/a", "read", false},
			{"carl", "/list/", "read", true},
			{"carl", "/list/a", "read", false},
			{"", "/public/a", "read", true},
			{"", "/public/drafts/a", "read", false},
			{"", "/docs/a", "read", false},
		} {
			var u *auth.User
			if c.who != "" {
				u = &auth.User{Username: c.who}
			}
			if got, err := svc.Allowed(u, c.obj, c.act); got != c.want || err != nil {
				t.Errorf("%s %s %s = %v, %v; want %v", c.who, c.act, c.obj, got, err, c.want)
			}
		}

		// Rules are checked as the request found them.
		rules, err := svc.RulesFor(context.Background(), &auth.User{Username: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.RemovePolicy("user", "!/hr/*", "*"); err != nil {
			t.Fatal(err)
		}
		if rules.Allow("/hr/a", "read") {
			t.Error("gathered rules changed")
		}
		if ok, _ := svc.Allowed(&auth.User{Username: "alice"}, "/hr/a", "read"); !ok {
			t.Error("removing the denial did not open /hr/")
		}

		for _, obj := range []string{"!", "!!/a", "!a", "! /a", "!/a/../b", "!/pub*", "/!/a/*/b"} {
			if _, err := svc.AddPolicy("user", obj, "read"); err == nil {
				t.Errorf("AddPolicy(%q) accepted", obj)
			}
		}
		if ok, err := svc.AddPolicy("user", "/!draft/*", "read"); !ok || err != nil {
			t.Errorf("a path with ! inside: %v, %v", ok, err)
		}
	})
}

// Everyone may do anything in their own home and nobody may open the
// others, unless rules for those paths say otherwise.
func TestHomeRules(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		for name, role := range map[string]string{"alice": "user", "adam": "admin", "sam": "superadmin", "olga": "operator"} {
			if _, err := svc.Enforcer().AddRoleForUser(auth.Subject(name), role); err != nil {
				t.Fatal(err)
			}
		}
		check := func(cases []struct {
			who, obj, act string
			want          bool
		}) {
			t.Helper()
			for _, c := range cases {
				var u *auth.User
				if c.who != "" {
					u = &auth.User{Username: c.who}
				}
				if got, err := svc.Allowed(u, c.obj, c.act); got != c.want || err != nil {
					t.Errorf("%q %s %s = %v, %v; want %v", c.who, c.act, c.obj, got, err, c.want)
				}
			}
		}
		svc.SetHomes("/home")
		if svc.HomeOf("alice") != "/home/alice" || svc.Homes() != "/home" {
			t.Errorf("HomeOf %q, Homes %q", svc.HomeOf("alice"), svc.Homes())
		}
		check([]struct {
			who, obj, act string
			want          bool
		}{
			{"alice", "/home/alice/", "read", true},
			{"alice", "/home/alice/a.txt", "write", true},
			{"alice", "/home/alice/sub/", "delete", true},
			{"alice", "/home/alice/", "delete", false},
			{"alice", "/home/alice/a.txt", "share", true},
			{"alice", "/home/alice/a.txt", "overwrite", true},
			{"alice", "/home/olga/a.txt", "read", false},
			{"alice", "/home/", "read", false},
			{"alice", "/homes/a.txt", "read", true},
			{"alice", "/docs/a.txt", "read", true},
			{"alice", "/docs/a.txt", "write", false},
			{"adam", "/home/alice/a.txt", "read", false},
			{"sam", "/home/alice/a.txt", "read", false},
			{"sam", "/home/sam/a.txt", "write", true},
			{"", "/home/alice/a.txt", "read", false},
		})
		if !svc.MayWrite("alice") || !svc.MayShare("alice") || !svc.MayDelete("alice") || svc.MayWrite("") {
			t.Error("users with a home may not write, share and delete somewhere")
		}

		// Rules decide over the built-in ones, also for the same paths.
		for _, rule := range [][3]string{
			{"admin", "/home/*", "read"},
			{"user:alice", "!/home/alice/locked/*", "*"},
			{"user:olga", "!/home/olga/*", "delete"},
		} {
			if _, err := svc.AddPolicy(rule[0], rule[1], rule[2]); err != nil {
				t.Fatal(err)
			}
		}
		check([]struct {
			who, obj, act string
			want          bool
		}{
			{"adam", "/home/alice/a.txt", "read", true},
			{"adam", "/home/alice/a.txt", "write", false},
			{"sam", "/home/alice/a.txt", "read", true},
			{"alice", "/home/alice/locked/a.txt", "read", false},
			{"alice", "/home/alice/a.txt", "read", true},
			{"olga", "/home/olga/a.txt", "delete", false},
			{"olga", "/home/olga/a.txt", "write", true},
		})

		// Without homes, the roles decide.
		svc.SetHomes("")
		check([]struct {
			who, obj, act string
			want          bool
		}{
			{"alice", "/home/olga/a.txt", "read", true},
			{"alice", "/home/alice/a.txt", "write", false},
		})
		if svc.HomeOf("alice") != "" || svc.MayWrite("alice") {
			t.Error("homes are still on")
		}
	})
}

// With a fold, rules meet paths however they are spelled.
func TestFoldedRules(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		if _, err := svc.Enforcer().AddRoleForUser(auth.Subject("olga"), "operator"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.AddPolicy("operator", "!/Docs/Secret/*", auth.ActRead); err != nil {
			t.Fatal(err)
		}
		svc.SetHomes("/home")
		olga, alice := &auth.User{Username: "olga"}, &auth.User{Username: "alice"}
		allowed := func(u *auth.User, obj string) bool {
			t.Helper()
			ok, err := svc.Allowed(u, obj, auth.ActRead)
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		if !allowed(olga, "/HOME/alice/x") || !allowed(olga, "/docs/secret/x") {
			t.Fatal("without a fold, paths are compared as spelled")
		}
		svc.SetFold(strings.ToLower)
		defer svc.SetFold(nil)
		for _, obj := range []string{"/HOME/alice/x", "/Home/ALICE/", "/docs/secret/x", "/DOCS/SECRET/x"} {
			if allowed(olga, obj) {
				t.Errorf("olga reads %s", obj)
			}
		}
		if !allowed(alice, "/HOME/Alice/x") || !allowed(olga, "/docs/other") {
			t.Error("folded rules allow too little")
		}
	})
}
