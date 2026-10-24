package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goftp/internal/config"
)

func withTrash(cfg *config.Config) { cfg.Trash.Keep = 30 * 24 * time.Hour }

// trashed returns the entries of the trash folder on disk.
func trashedOnDisk(t *testing.T, f *fixture) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.dir, trashDir))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func trashForm(t *testing.T, f *fixture, form string, headers ...string) (*http.Response, string) {
	t.Helper()
	return f.send(t, "POST", trashPath, strings.NewReader(form), append([]string{"Content-Type", formType}, headers...)...)
}

func TestTrash(t *testing.T) {
	f := newFixture(t, withTrash)
	f.write(t, "docs/a.txt", "alpha")
	f.write(t, "docs/sub/b.txt", "beta")
	admin := f.as("admin")

	// A deletion goes to the trash, which says where to restore it from.
	resp, _ := admin.do(t, "DELETE", "/docs/a.txt")
	expectStatus(t, resp, http.StatusNoContent)
	id := resp.Header.Get(trashIDsHeader)
	if !validTrashID(id) {
		t.Fatalf("trash ID %q", id)
	}
	if exists(filepath.Join(f.dir, "docs", "a.txt")) {
		t.Error("still in its folder")
	}
	if b, err := os.ReadFile(filepath.Join(f.dir, trashDir, id, "a.txt")); err != nil || string(b) != "alpha" {
		t.Errorf("in the trash: %q, %v", b, err)
	}
	var note trashNote
	if b, err := os.ReadFile(filepath.Join(f.dir, trashDir, id, trashInfo)); err != nil || json.Unmarshal(b, &note) != nil {
		t.Fatalf("note: %s, %v", b, err)
	}
	if note.Path != "/docs/a.txt" || note.Dir || note.By != userOfRole("admin") || time.Since(note.At) > time.Minute {
		t.Errorf("note %+v", note)
	}
	if e := f.logs.entries("delete"); len(e) != 1 || e[0]["trash"] != true {
		t.Errorf("logged %v", e)
	}
	// The trash is never served as a folder.
	for _, p := range []string{"/" + trashDir + "/", "/" + trashDir + "/" + id + "/a.txt"} {
		if resp, _ := f.do(t, "GET", p); resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}

	// The folder's page offers to undo it.
	_, body := admin.do(t, "GET", "/docs/?deleted=1&undo="+id)
	if !strings.Contains(body, "Moved <strong>a.txt</strong> to the trash.") || !strings.Contains(body, `name="id" value="`+id+`"`) {
		t.Errorf("no undo: %s", body)
	}
	for q, want := range map[string]string{
		"deleted=1&undo=" + strings.Repeat("A", 26): "Moved it to the",
		"deleted=3&trashed=1":                       "Moved 3 items to the",
		"deleted=2":                                 "Deleted 2 items.",
	} {
		if _, body := admin.do(t, "GET", "/docs/?"+q); !strings.Contains(body, want) {
			t.Errorf("?%s: no %q", q, want)
		}
	}

	// The trash lists it with who deleted it, and restores it.
	_, body = admin.do(t, "GET", trashPath)
	if !strings.Contains(body, "<span>a.txt</span>") || !strings.Contains(body, `href="/docs/"`) || !strings.Contains(body, "by "+userOfRole("admin")) {
		t.Errorf("not listed: %s", body)
	}
	resp, _ = trashForm(t, admin, "action=restore&id="+id, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/docs/?restored=a.txt" {
		t.Errorf("Location %q", got)
	}
	if b, err := os.ReadFile(filepath.Join(f.dir, "docs", "a.txt")); err != nil || string(b) != "alpha" {
		t.Errorf("restored: %q, %v", b, err)
	}
	if got := trashedOnDisk(t, f); len(got) != 0 {
		t.Errorf("left in the trash: %v", got)
	}
	if _, body := admin.do(t, "GET", "/docs/?restored=a.txt"); !strings.Contains(body, `id="restored"`) {
		t.Error("restoring not confirmed")
	}

	// Folders go with everything in them, and come back so.
	resp, _ = admin.send(t, "POST", "/docs/", strings.NewReader("delete=sub"), "Content-Type", formType, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	loc := resp.Header.Get("Location")
	subID, ok := strings.CutPrefix(loc, "/docs/?deleted=1&undo=")
	if !ok || !validTrashID(subID) {
		t.Fatalf("Location %q", loc)
	}
	resp, _ = trashForm(t, admin, "action=restore&id="+subID)
	expectStatus(t, resp, http.StatusCreated)
	if got := resp.Header.Get("Location"); got != "/docs/sub" {
		t.Errorf("Location %q", got)
	}
	if b, err := os.ReadFile(filepath.Join(f.dir, "docs", "sub", "b.txt")); err != nil || string(b) != "beta" {
		t.Errorf("restored folder: %q, %v", b, err)
	}

	// Restoring needs the name free, and the folder still there.
	resp, _ = admin.do(t, "DELETE", "/docs/a.txt")
	id = resp.Header.Get(trashIDsHeader)
	f.write(t, "docs/a.txt", "newer")
	resp, body = trashForm(t, admin, "action=restore&id="+id)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "Something named a.txt is there now") {
		t.Errorf("restore over a file: %d %q", resp.StatusCode, body)
	}
	if b, _ := os.ReadFile(filepath.Join(f.dir, "docs", "a.txt")); string(b) != "newer" {
		t.Error("restoring replaced a file")
	}
	resp, body = trashForm(t, admin, "action=restore&id="+id, "Accept", "text/html")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "Something named a.txt is there now") || !strings.Contains(body, "<span>a.txt</span>") {
		t.Errorf("browsers see why on the trash page: %d %s", resp.StatusCode, body)
	}
	f.write(t, "gone/c.txt", "c")
	resp, _ = admin.do(t, "DELETE", "/gone/c.txt")
	cID := resp.Header.Get(trashIDsHeader)
	if resp, _ := admin.do(t, "DELETE", "/gone/?permanent"); resp.StatusCode != http.StatusNoContent || resp.Header.Get(trashIDsHeader) != "" {
		t.Errorf("permanent deletion: %d %q", resp.StatusCode, resp.Header.Get(trashIDsHeader))
	}
	if exists(filepath.Join(f.dir, "gone")) {
		t.Error("not deleted for good")
	}
	resp, body = trashForm(t, admin, "action=restore&id="+cID)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "The folder it was in, /gone, is gone") {
		t.Errorf("restore into a deleted folder: %d %q", resp.StatusCode, body)
	}

	// Deleting for good, one at a time or all at once.
	resp, _ = trashForm(t, admin, "action=purge&id="+cID, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != trashPath+"?done=purged" {
		t.Errorf("Location %q", got)
	}
	if resp, _ := trashForm(t, admin, "action=purge&id="+cID); resp.StatusCode != http.StatusNotFound {
		t.Errorf("purged twice: %d", resp.StatusCode)
	}
	resp, body = trashForm(t, admin, "action=empty")
	expectStatus(t, resp, http.StatusOK)
	if body != `{"deleted":1}` {
		t.Errorf("emptied %s", body)
	}
	if got := trashedOnDisk(t, f); len(got) != 0 {
		t.Errorf("left in the trash: %v", got)
	}
	if e := f.logs.entries("purge"); len(e) != 2 {
		t.Errorf("%d purges logged", len(e))
	}
	for form, want := range map[string]int{
		"action=restore&id=nope":                       404,
		"action=restore&id=" + strings.Repeat("A", 26): 404,
		"action=purge":                                 404,
		"action=shred&id=" + id:                        400,
	} {
		if resp, _ := trashForm(t, admin, form); resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", form, resp.StatusCode, want)
		}
	}
}

// What the trash shows and lets visitors do follows the rules where the
// entries were.
func TestTrashRights(t *testing.T) {
	f := newFixture(t, withTrash)
	f.write(t, "docs/a.txt", "a")
	resp, _ := f.as("admin").do(t, "DELETE", "/docs/a.txt")
	id := resp.Header.Get(trashIDsHeader)

	if resp, _ := f.as("").do(t, "GET", trashPath); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", resp.StatusCode)
	}
	if resp, _ := trashForm(t, f.as(""), "action=restore&id="+id); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous restore: %d", resp.StatusCode)
	}
	// Users who may only read see nothing to do, and may not restore.
	_, body := f.as("user").do(t, "GET", trashPath)
	if strings.Contains(body, "a.txt") || !strings.Contains(body, "The trash is empty.") || strings.Contains(body, `href="/.trash/"`) {
		t.Errorf("user sees: %s", body)
	}
	if resp, _ := trashForm(t, f.as("user"), "action=restore&id="+id); resp.StatusCode != http.StatusForbidden {
		t.Errorf("user restore: %d", resp.StatusCode)
	}
	// Operators may restore, which creates it again, but not delete it.
	_, body = f.as("operator").do(t, "GET", trashPath)
	if !strings.Contains(body, "a.txt") || !strings.Contains(body, "Restore") || strings.Contains(body, "Delete for good") || strings.Contains(body, "Empty trash") {
		t.Errorf("operator sees: %s", body)
	}
	if resp, _ := trashForm(t, f.as("operator"), "action=purge&id="+id); resp.StatusCode != http.StatusForbidden {
		t.Errorf("operator purge: %d", resp.StatusCode)
	}
	if resp, body := trashForm(t, f.as("operator"), "action=empty"); resp.StatusCode != http.StatusOK || body != `{"deleted":0}` {
		t.Errorf("operator empties: %d %s", resp.StatusCode, body)
	}
	resp, _ = trashForm(t, f.as("operator"), "action=restore&id="+id)
	expectStatus(t, resp, http.StatusCreated)
	// The tab shows to those who may delete.
	if _, body := f.as("admin").do(t, "GET", "/"); !strings.Contains(body, `href="/.trash/"`) {
		t.Error("no trash tab for admins")
	}
	if _, body := f.as("operator").do(t, "GET", "/"); strings.Contains(body, `href="/.trash/"`) {
		t.Error("trash tab for operators")
	}
}

func TestTrashOff(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "a")
	resp, _ := f.do(t, "DELETE", "/a.txt")
	expectStatus(t, resp, http.StatusNoContent)
	if resp.Header.Get(trashIDsHeader) != "" || trashedOnDisk(t, f) != nil {
		t.Error("went to the trash, which is off")
	}
	if _, body := f.do(t, "GET", "/"); strings.Contains(body, `href="/.trash/"`) {
		t.Error("trash tab while it is off")
	}
}

func TestExpireTrash(t *testing.T) {
	f := newFixture(t, withTrash)
	for _, name := range []string{"old.txt", "new.txt"} {
		f.write(t, name, name)
	}
	resp, _ := f.do(t, "DELETE", "/old.txt")
	oldID := resp.Header.Get(trashIDsHeader)
	resp, _ = f.do(t, "DELETE", "/new.txt")
	newID := resp.Header.Get(trashIDsHeader)
	// Backdate one deletion.
	note := trashNote{Path: "/old.txt", By: "x", At: time.Now().Add(-31 * 24 * time.Hour)}
	b, _ := json.Marshal(note)
	if err := os.WriteFile(filepath.Join(f.dir, trashDir, oldID, trashInfo), b, 0o600); err != nil {
		t.Fatal(err)
	}
	// What removals and deletions cut off left behind.
	for _, d := range []string{goneMark + "AAAAAAAAAAAAAAAAAAAAAAAAAA/x", "BBBBBBBBBBBBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCCCCCCCCCCC"} {
		if err := os.MkdirAll(filepath.Join(f.dir, trashDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(f.dir, trashDir, "BBBBBBBBBBBBBBBBBBBBBBBBBB"), old, old); err != nil {
		t.Fatal(err)
	}

	if n := f.srv.expireTrash(time.Now().Add(-30 * 24 * time.Hour)); n != 2 {
		t.Errorf("expired %d", n)
	}
	got := trashedOnDisk(t, f)
	if strings.Join(got, " ") != strings.Join([]string{"CCCCCCCCCCCCCCCCCCCCCCCCCC", newID}, " ") &&
		strings.Join(got, " ") != strings.Join([]string{newID, "CCCCCCCCCCCCCCCCCCCCCCCCCC"}, " ") {
		t.Errorf("left %v", got)
	}
	// Turned off, the trash is emptied.
	f.srv.expireTrash(time.Now())
	if got := trashedOnDisk(t, f); len(got) != 1 || got[0] != "CCCCCCCCCCCCCCCCCCCCCCCCCC" {
		t.Errorf("left %v", got)
	}
}

func TestKeepText(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * 24 * time.Hour: "30 days", 24 * time.Hour: "1 day", 36 * time.Hour: "36 hours", 90 * time.Minute: "1h30m0s"} {
		if got := keepText(d); got != want {
			t.Errorf("keepText(%v) = %q, want %q", d, got, want)
		}
	}
}
