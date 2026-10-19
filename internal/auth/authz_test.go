package auth_test

import (
	"testing"
	"time"

	"goftp/internal/auth"
	"goftp/internal/auth/authtest"
)

func TestDefaultPolicy(t *testing.T) {
	svc, _ := authtest.NewService(time.Hour)
	for _, tc := range []struct {
		role string
		acts map[string]bool
	}{
		{"user", map[string]bool{auth.ActRead: true, auth.ActWrite: false, auth.ActOverwrite: false, auth.ActDelete: false}},
		{"operator", map[string]bool{auth.ActRead: true, auth.ActWrite: true, auth.ActOverwrite: false, auth.ActDelete: false}},
		{"admin", map[string]bool{auth.ActRead: true, auth.ActWrite: true, auth.ActOverwrite: true, auth.ActDelete: true}},
		{"superadmin", map[string]bool{auth.ActRead: true, auth.ActWrite: true, auth.ActOverwrite: true, auth.ActDelete: true, "anything": true}},
		{auth.Anonymous, map[string]bool{auth.ActRead: false}},
	} {
		u := &auth.User{Username: "u-" + tc.role}
		if tc.role == auth.Anonymous {
			u = nil
		} else if _, err := svc.Enforcer().AddRoleForUser(auth.Subject(u.Username), tc.role); err != nil {
			t.Fatal(err)
		}
		for act, want := range tc.acts {
			for _, obj := range []string{"/", "/a.txt", "/deep/dir/"} {
				if got, err := svc.Allowed(u, obj, act); got != want || err != nil {
					t.Errorf("%s %s %s = %v, %v", tc.role, act, obj, got, err)
				}
			}
		}
	}
	// A user named like a role does not hold it.
	if ok, _ := svc.Allowed(&auth.User{Username: "admin"}, "/", auth.ActRead); ok {
		t.Error("user admin holds the admin role")
	}
}

func TestPathPatterns(t *testing.T) {
	svc, _ := authtest.NewService(time.Hour)
	for _, obj := range []string{"/docs/*", "/list/"} {
		if _, err := svc.AddPolicy("user:bob", obj, auth.ActRead); err != nil {
			t.Fatal(err)
		}
	}
	bob := &auth.User{Username: "bob"}
	for obj, want := range map[string]bool{
		"/docs/": true, "/docs/a.txt": true, "/docs/sub/b": true, "/docs": false, "/docsx": false, "/": false,
		"/list/": true, "/list/a.txt": false,
	} {
		if got, _ := svc.Allowed(bob, obj, auth.ActRead); got != want {
			t.Errorf("%s: %v, want %v", obj, got, want)
		}
	}
}
