package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"goftp/internal/db/dbtest"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Execute(context.Background(), args, &out, &out)
	return out.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run(t, args...)
	if err != nil {
		t.Fatalf("goftp %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

var tempPassword = regexp.MustCompile(`(?m)^temporary password: (\S{26})$`)

func TestUserCommands(t *testing.T) {
	_, url := dbtest.Open(t)
	t.Setenv("GOFTP_DATABASE_URL", url)

	out := mustRun(t, "user", "add", "Alice", "--role", "operator")
	if !strings.Contains(out, "created user alice with role operator") || !tempPassword.MatchString(out) {
		t.Errorf("user add: %q", out)
	}
	mustRun(t, "user", "add", "bob")
	for _, args := range [][]string{
		{"user", "add", "alice"},
		{"user", "add", "carol", "--role", "king"},
		{"user", "add", "X Y"},
		{"user", "role", "nobody", "admin"},
		{"user", "passwd", "nobody"},
		{"user", "delete", "nobody"},
		{"user", "add"},
	} {
		if out, err := run(t, args...); err == nil {
			t.Errorf("goftp %s succeeded: %q", strings.Join(args, " "), out)
		}
	}

	for _, args := range [][]string{{"user", "quota", "nobody", "1GiB"}, {"user", "quota", "bob", "lots"}} {
		if out, err := run(t, args...); err == nil {
			t.Errorf("goftp %s succeeded: %q", strings.Join(args, " "), out)
		}
	}
	if out := mustRun(t, "user", "quota", "bob", "10GiB"); !strings.Contains(out, "the home of bob may hold 10GiB") {
		t.Errorf("user quota: %q", out)
	}
	if out := mustRun(t, "user", "list"); !strings.Contains(out, "HOME QUOTA") || !regexp.MustCompile(`bob +\S+ +temporary +10GiB`).MatchString(out) {
		t.Errorf("user list: %q", out)
	}
	if out := mustRun(t, "user", "quota", "bob", "none"); !strings.Contains(out, "may hold any amount") {
		t.Errorf("user quota none: %q", out)
	}
	if out := mustRun(t, "user", "quota", "bob", "default"); !strings.Contains(out, "as much as homes.quota says") {
		t.Errorf("user quota default: %q", out)
	}

	mustRun(t, "user", "role", "bob", "admin")
	out = mustRun(t, "user", "passwd", "bob")
	if !tempPassword.MatchString(out) {
		t.Errorf("user passwd: %q", out)
	}
	out = mustRun(t, "user", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !regexp.MustCompile(`^alice\s+operator\s+temporary\s`).MatchString(lines[1]) ||
		!regexp.MustCompile(`^bob\s+admin\s+temporary\s`).MatchString(lines[2]) {
		t.Errorf("user list:\n%s", out)
	}
	// Their home goes to the trash.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "home", "bob"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "home", "bob", "notes.txt"), []byte("bob's"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOFTP_DIR", dir)
	if out := mustRun(t, "user", "delete", "bob"); !strings.Contains(out, "moved their home to the trash") {
		t.Errorf("user delete: %q", out)
	}
	if out := mustRun(t, "user", "list"); strings.Contains(out, "bob") {
		t.Errorf("deleted user listed:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "home", "bob")); !os.IsNotExist(err) {
		t.Errorf("the home stayed: %v", err)
	}
	trashed, _ := filepath.Glob(filepath.Join(dir, ".goftp-trash", "*", "bob", "notes.txt"))
	if len(trashed) != 1 {
		t.Errorf("not in the trash: %v", trashed)
	}
	// Users without a home are deleted all the same.
	if out := mustRun(t, "user", "delete", "alice"); strings.Contains(out, "home") {
		t.Errorf("user delete without a home: %q", out)
	}
}

func TestPolicyCommands(t *testing.T) {
	_, url := dbtest.Open(t)
	t.Setenv("GOFTP_DATABASE_URL", url)

	mustRun(t, "policy", "add", "anonymous", "/public/*", "read")
	if _, err := run(t, "policy", "add", "anonymous", "/public/*", "read"); err == nil {
		t.Error("duplicate rule added")
	}
	if _, err := run(t, "policy", "add", "anonymous", "public", "read"); err == nil {
		t.Error("invalid rule added")
	}
	out := mustRun(t, "policy", "list")
	for _, want := range []string{`anonymous\s+/public/\*\s+read`, `superadmin\s+/\*\s+\*`, `operator\s+user`} {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Errorf("policy list lacks %s:\n%s", want, out)
		}
	}
	mustRun(t, "policy", "remove", "anonymous", "/public/*", "read")
	if _, err := run(t, "policy", "remove", "anonymous", "/public/*", "read"); err == nil {
		t.Error("removed a missing rule")
	}
	if out := mustRun(t, "migrate"); !strings.Contains(out, "up to date") {
		t.Errorf("migrate: %q", out)
	}
}

func TestUsageErrors(t *testing.T) {
	t.Setenv("GOFTP_DATABASE_URL", "")
	for _, args := range [][]string{{"usr"}, {"serve", "extra"}, {"--nope"}, {"user", "delet", "bob"}, {"policy", "rm"}} {
		if _, err := run(t, args...); err == nil {
			t.Errorf("goftp %s succeeded", strings.Join(args, " "))
		}
	}
	if _, err := run(t, "user", "list"); err == nil || !strings.Contains(err.Error(), "database.url is required") {
		t.Errorf("missing database URL: %v", err)
	}
	if out := mustRun(t, "--help"); !strings.Contains(out, "user") || !strings.Contains(out, "policy") {
		t.Errorf("help: %q", out)
	}
	if out := mustRun(t, "user"); !strings.Contains(out, "passwd") {
		t.Errorf("user help: %q", out)
	}
}

// Without a command, goftp serves until its context ends.
func TestServe(t *testing.T) {
	_, url := dbtest.Open(t)
	t.Setenv("GOFTP_DATABASE_URL", url)
	t.Setenv("GOFTP_LOG_LEVEL", "error")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("served"), 0o644); err != nil {
		t.Fatal(err)
	}
	temp := tempPassword.FindStringSubmatch(mustRun(t, "user", "add", "sam"))[1]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Execute(ctx, []string{"--dir", dir, "--addr", addr}, io.Discard, io.Discard) }()

	base := "http://" + addr
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(base + "/a.txt")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("anonymous download: %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp, err := http.Post(base+"/.auth/login", "application/json", strings.NewReader(`{"username":"sam","password":"`+temp+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"must_change_password":true`) {
		t.Errorf("login: %d %s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}
}
