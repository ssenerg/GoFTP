package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
	"goftp/internal/config"
)

// tus sends a tus request as f's user; a PATCH always has a body.
func tus(t *testing.T, f *fixture, method, uri, body string, headers ...string) (*http.Response, string) {
	t.Helper()
	var r io.Reader
	if body != "" || method == "PATCH" {
		r = strings.NewReader(body)
	}
	return f.send(t, method, uri, r, append([]string{"Tus-Resumable", tusVersion}, headers...)...)
}

func metadata(name string, extra ...string) string {
	m := "filename " + base64.StdEncoding.EncodeToString([]byte(name))
	for _, e := range extra {
		k, v, _ := strings.Cut(e, "=")
		m += "," + k + " " + base64.StdEncoding.EncodeToString([]byte(v))
	}
	return m
}

// startResumable starts an upload of length bytes as dir/name and returns
// its URL.
func startResumable(t *testing.T, f *fixture, dir, name string, length int, meta ...string) string {
	t.Helper()
	resp, body := tus(t, f, "POST", dir, "", "Upload-Length", strconv.Itoa(length), "Upload-Metadata", metadata(name, meta...))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST %s: %d %s", dir, resp.StatusCode, body)
	}
	loc, absolute := strings.CutPrefix(resp.Header.Get("Location"), "http://example.com")
	if !absolute || !strings.HasPrefix(loc, uploadsPrefix) || !auth.ValidToken(strings.TrimPrefix(loc, uploadsPrefix)) ||
		resp.Header.Get("Tus-Resumable") != tusVersion || resp.Header.Get("Upload-Expires") == "" {
		t.Fatalf("creation answer: %v", resp.Header)
	}
	return loc
}

func patchAt(t *testing.T, f *fixture, loc string, offset int, data string) *http.Response {
	t.Helper()
	resp, _ := tus(t, f, "PATCH", loc, data, "Upload-Offset", strconv.Itoa(offset), "Content-Type", "application/offset+octet-stream")
	return resp
}

// offsetOf asks how much of an upload arrived, or -1 if it is gone.
func offsetOf(t *testing.T, f *fixture, loc string) int {
	t.Helper()
	resp, _ := tus(t, f, "HEAD", loc, "")
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	n, err := strconv.Atoi(resp.Header.Get("Upload-Offset"))
	if err != nil || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("HEAD: %v", resp.Header)
	}
	return n
}

func partials(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && validPartial(d.Name()) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestResumableUpload(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta).as("operator")
	f.write(t, "dir/keep.txt", "k")
	data := strings.Repeat("0123456789", 1000)
	loc := startResumable(t, f, "/dir/", "big.bin", len(data))

	resp, _ := tus(t, f, "HEAD", loc, "")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Upload-Offset") != "0" || resp.Header.Get("Upload-Length") != strconv.Itoa(len(data)) {
		t.Fatalf("HEAD: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := patchAt(t, f, loc, 0, data[:4000]); resp.StatusCode != http.StatusNoContent || resp.Header.Get("Upload-Offset") != "4000" {
		t.Fatalf("first PATCH: %d %v", resp.StatusCode, resp.Header)
	}
	// Until it is complete, nothing shows.
	if _, body := f.do(t, "GET", "/dir/"); strings.Contains(body, `data-name="big.bin"`) || strings.Contains(body, `data-name="`+tempPrefix) {
		t.Error("an unfinished upload is listed")
	}
	if resp, _ := f.do(t, "GET", "/dir/big.bin"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unfinished upload downloadable: %d", resp.StatusCode)
	}
	if p := partials(f.dir); len(p) != 1 {
		t.Fatalf("partial files %v", p)
	} else if resp, _ := f.do(t, "GET", "/dir/"+filepath.Base(p[0])); resp.StatusCode != http.StatusForbidden {
		t.Errorf("partial file served: %d", resp.StatusCode)
	}
	// Data goes where the received data ends, and no further than the end.
	for offset, want := range map[int]int{0: 409, 3999: 409, 4001: 409} {
		if resp := patchAt(t, f, loc, offset, "x"); resp.StatusCode != want || resp.Header.Get("Upload-Offset") != "4000" {
			t.Errorf("PATCH at %d: %d %q", offset, resp.StatusCode, resp.Header.Get("Upload-Offset"))
		}
	}
	if resp := patchAt(t, f, loc, 4000, data[4000:]+"x"); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("PATCH past the end: %d", resp.StatusCode)
	}
	resp, _ = tus(t, f, "PATCH", loc, "x", "Upload-Offset", "4000", "Content-Type", "text/plain")
	expectStatus(t, resp, http.StatusUnsupportedMediaType)

	if resp := patchAt(t, f, loc, 4000, data[4000:]); resp.StatusCode != http.StatusNoContent || resp.Header.Get("Upload-Offset") != strconv.Itoa(len(data)) {
		t.Fatalf("last PATCH: %d %v", resp.StatusCode, resp.Header)
	}
	if readFile(t, f.dir, "dir/big.bin") != data {
		t.Error("stored content differs")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftovers %v", l)
	}
	if offsetOf(t, f, loc) != -1 {
		t.Error("a finished upload can still be asked about")
	}
	if e := f.logs.entries("upload"); len(e) != 1 || e[0]["bytes"] != float64(len(data)) || e[0]["path"] != "/dir/big.bin" || e[0]["user"] != userOfRole("operator") {
		t.Errorf("logged %v", e)
	}
	// Tokens stay out of the logs.
	if strings.Contains(f.logs.raw(), strings.TrimPrefix(loc, uploadsPrefix)) {
		t.Error("an upload's token was logged")
	}
	if e := requestEntry(t, f, uploadsPrefix+"***"); e["method"] != "HEAD" && e["method"] != "PATCH" {
		t.Errorf("access log %v", e)
	}
}

func TestResumableCreation(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, func(c *config.Config) { c.Upload.MaxSize = 1000 })
	f.write(t, "dir/old.txt", "old")
	f.write(t, "dir/sub/x", "x")
	f.write(t, "dir/"+lockName("busy.txt"), "another tool's lock")
	post := func(role, dir string, headers ...string) int {
		resp, _ := f.as(role).send(t, "POST", dir, nil, headers...)
		return resp.StatusCode
	}
	tusHeaders := func(length, meta string) []string {
		return []string{"Tus-Resumable", tusVersion, "Upload-Length", length, "Upload-Metadata", meta}
	}
	for name, c := range map[string]struct {
		role, dir string
		headers   []string
		want      int
	}{
		"old version":      {"operator", "/dir/", []string{"Tus-Resumable", "0.2.2", "Upload-Length", "1", "Upload-Metadata", metadata("a")}, 412},
		"no length":        {"operator", "/dir/", tusHeaders("", metadata("a")), 400},
		"negative length":  {"operator", "/dir/", tusHeaders("-1", metadata("a")), 400},
		"too large":        {"operator", "/dir/", tusHeaders("1001", metadata("a")), 413},
		"no name":          {"operator", "/dir/", tusHeaders("1", ""), 400},
		"bad metadata":     {"operator", "/dir/", tusHeaders("1", "filename !!"), 400},
		"hidden name":      {"operator", "/dir/", tusHeaders("1", metadata(".env")), 400},
		"slash in name":    {"operator", "/dir/", tusHeaders("1", metadata("a/b")), 400},
		"anonymous":        {"", "/dir/", tusHeaders("1", metadata("a")), 401},
		"read only":        {"user", "/dir/", tusHeaders("1", metadata("a")), 403},
		"no folder":        {"operator", "/nope/", tusHeaders("1", metadata("a")), 404},
		"hidden folder":    {"operator", "/.git/", tusHeaders("1", metadata("a")), 403},
		"a folder's name":  {"admin", "/dir/", tusHeaders("1", metadata("sub")), 409},
		"exists":           {"admin", "/dir/", tusHeaders("1", metadata("old.txt")), 409},
		"replace, may not": {"operator", "/dir/", tusHeaders("1", metadata("old.txt", "replace=1")), 403},
		"busy":             {"operator", "/dir/", tusHeaders("1", metadata("busy.txt")), 409},
		"replace":          {"admin", "/dir/", tusHeaders("3", metadata("old.txt", "replace=1")), 201},
		"new":              {"operator", "/dir/", tusHeaders("1000", metadata("new.bin")), 201},
		"version":          {"operator", "/dir/", append(tusHeaders("1", metadata("a")), "Tus-Resumable", "1.0.0"), 201},
	} {
		if got := post(c.role, c.dir, c.headers...); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	resp, _ := f.as("operator").send(t, "POST", "/dir/", strings.NewReader("data"), "Tus-Resumable", tusVersion, "Upload-Length", "4", "Upload-Metadata", metadata("a"))
	expectStatus(t, resp, http.StatusBadRequest)
	resp, _ = f.as("operator").send(t, "POST", "/dir/", nil, "Tus-Resumable", "2.0.0")
	if resp.StatusCode != http.StatusPreconditionFailed || resp.Header.Get("Tus-Version") != tusVersion {
		t.Errorf("unknown version: %d %v", resp.StatusCode, resp.Header)
	}

	// Empty files are complete at once.
	loc := startResumable(t, f.as("operator"), "/dir/", "empty.txt", 0)
	if readFile(t, f.dir, "dir/empty.txt") != "" || offsetOf(t, f.as("operator"), loc) != -1 {
		t.Error("empty upload not stored")
	}
	if p := partials(f.dir); len(p) != 3 {
		t.Errorf("partial files %v", p)
	}
}

// Uploads belong to whoever started them.
func TestResumableOwnership(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	if _, err := ta.svc.AddPolicy(auth.Anonymous, "/drop/*", auth.ActWrite); err != nil {
		t.Fatal(err)
	}
	f.write(t, "drop/x", "x")
	mine := startResumable(t, f.as("operator"), "/drop/", "mine.bin", 10)
	theirs := startResumable(t, f.as(""), "/drop/", "theirs.bin", 10)
	for _, c := range []struct {
		role, loc string
		want      int
	}{
		{"operator", mine, 0}, {"admin", mine, -1}, {"", mine, -1},
		{"", theirs, 0}, {"operator", theirs, -1},
	} {
		if got := offsetOf(t, f.as(c.role), c.loc); got != c.want {
			t.Errorf("%q asking about %s: %d", c.role, c.loc, got)
		}
	}
	if resp := patchAt(t, f.as("admin"), mine, 0, "0123456789"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another's PATCH: %d", resp.StatusCode)
	}
	if resp, _ := tus(t, f.as("admin"), "DELETE", mine, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another's DELETE: %d", resp.StatusCode)
	}
	for _, loc := range []string{uploadsPrefix + strings.Repeat("A", 43), uploadsPrefix + "x", uploadsPrefix} {
		if got := offsetOf(t, f.as("operator"), loc); got != -1 {
			t.Errorf("%s: %d", loc, got)
		}
	}
	// Who may no longer upload there cannot go on.
	if _, err := ta.svc.RemovePolicy(auth.Anonymous, "/drop/*", auth.ActWrite); err != nil {
		t.Fatal(err)
	}
	if resp := patchAt(t, f.as(""), theirs, 0, "0123456789"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("PATCH without the right: %d", resp.StatusCode)
	}
}

func TestResumableCancel(t *testing.T) {
	f := newFixture(t).as("operator")
	loc := startResumable(t, f, "/", "big.bin", 10)
	expectStatus(t, patchAt(t, f, loc, 0, "01234"), http.StatusNoContent)
	resp, _ := tus(t, f, "DELETE", loc, "")
	expectStatus(t, resp, http.StatusNoContent)
	if offsetOf(t, f, loc) != -1 || len(partials(f.dir)) != 0 || exists(filepath.Join(f.dir, "big.bin")) {
		t.Error("cancelled upload left something behind")
	}
	if len(f.logs.entries("upload cancelled")) != 1 {
		t.Error("cancel not logged")
	}
}

// Once all data is there, the file is stored as other uploads are.
func TestResumableCompletion(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	admin := f.as("admin")

	// Someone else stored the name meanwhile: the upload cannot be stored.
	loc := startResumable(t, admin, "/", "a.txt", 3)
	f.write(t, "a.txt", "theirs")
	if resp := patchAt(t, admin, loc, 0, "new"); resp.StatusCode != http.StatusConflict {
		t.Errorf("name taken meanwhile: %d", resp.StatusCode)
	}
	if readFile(t, f.dir, "a.txt") != "theirs" || offsetOf(t, admin, loc) != -1 || len(partials(f.dir)) != 0 {
		t.Error("the failed upload was not dropped cleanly")
	}

	// Asked to replace, it does.
	loc = startResumable(t, admin, "/", "a.txt", 3, "replace=1")
	expectStatus(t, patchAt(t, admin, loc, 0, "new"), http.StatusNoContent)
	if readFile(t, f.dir, "a.txt") != "new" {
		t.Error("not replaced")
	}

	// Rights are checked again at the end: replacing a file that appeared
	// meanwhile needs the right to replace.
	op := f.as("operator")
	loc = startResumable(t, op, "/", "c.txt", 3, "replace=1")
	f.write(t, "c.txt", "theirs")
	if resp := patchAt(t, op, loc, 0, "new"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("replacing without the right: %d", resp.StatusCode)
	}
	if readFile(t, f.dir, "c.txt") != "theirs" {
		t.Error("replaced without the right")
	}

	// While another upload stores the name, the last PATCH waits; an empty
	// one finishes later.
	loc = startResumable(t, admin, "/", "b.txt", 3)
	release, err := f.srv.acquireLock(mustRoot(t, f), "b.txt", tempPrefix+"X"+tempSuffix)
	if err != nil {
		t.Fatal(err)
	}
	resp := patchAt(t, admin, loc, 0, "bbb")
	if resp.StatusCode != http.StatusLocked || resp.Header.Get("Retry-After") == "" || offsetOf(t, admin, loc) != 3 {
		t.Errorf("name busy: %d", resp.StatusCode)
	}
	release()
	expectStatus(t, patchAt(t, admin, loc, 3, ""), http.StatusNoContent)
	if readFile(t, f.dir, "b.txt") != "bbb" {
		t.Error("not stored after the name was free")
	}
}

// An upload whose folder went away cannot go on, and is forgotten.
func TestResumableFolderGone(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta).as("operator")
	for _, ask := range []string{"HEAD", "PATCH"} {
		f.write(t, "box/a.txt", "a")
		loc := startResumable(t, f, "/box/", "big.bin", 10)
		expectStatus(t, patchAt(t, f, loc, 0, "01234"), http.StatusNoContent)
		if err := os.RemoveAll(filepath.Join(f.dir, "box")); err != nil {
			t.Fatal(err)
		}
		if ask == "PATCH" {
			if resp := patchAt(t, f, loc, 5, "56789"); resp.StatusCode != http.StatusNotFound {
				t.Errorf("PATCH: %d", resp.StatusCode)
			}
		} else if offsetOf(t, f, loc) != -1 {
			t.Error("the upload goes on")
		}
		if _, err := ta.svc.UploadByToken(context.Background(), strings.TrimPrefix(loc, uploadsPrefix)); err == nil {
			t.Errorf("%s: the upload is still known", ask)
		}
	}
}

func mustRoot(t *testing.T, f *fixture) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// A request that is cut off keeps what arrived, so the upload goes on from
// there. Meanwhile, another request cannot write.
func TestResumableAfterCutOff(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Server.ReadTimeout = 300 * time.Millisecond })
	op := f.as("operator")
	addr, _ := startServer(t, op)
	data := bytes.Repeat([]byte("0123456789"), 100_000)
	half := len(data) / 2
	loc := startResumable(t, op, "/", "big.bin", len(data))

	sendPart := func(offset, n int, part []byte) net.Conn {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		fmt.Fprintf(conn, "PATCH %s HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer %s\r\nTus-Resumable: 1.0.0\r\n"+
			"Upload-Offset: %d\r\nContent-Type: application/offset+octet-stream\r\nContent-Length: %d\r\n\r\n", loc, op.token, offset, n)
		if _, err := conn.Write(part); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	partSize := func() int64 {
		p := partials(f.dir)
		if len(p) != 1 {
			return -1
		}
		info, err := os.Stat(p[0])
		if err != nil {
			return -1
		}
		return info.Size()
	}

	conn := sendPart(0, len(data), data[:half])
	waitFor(t, "half on disk", func() bool { return partSize() == int64(half) })
	if resp := patchAt(t, op, loc, half, string(data[half:])); resp.StatusCode != http.StatusLocked || resp.Header.Get("Retry-After") != "5" {
		t.Errorf("second writer: %d", resp.StatusCode)
	}
	_ = conn.Close()
	waitFor(t, "the cut-off request to end", func() bool {
		for _, e := range f.logs.entries("request") {
			if e["method"] == "PATCH" && e["status"] == float64(http.StatusBadRequest) {
				return true
			}
		}
		return false
	})
	if got := offsetOf(t, op, loc); got != half {
		t.Fatalf("offset after the cut-off: %d", got)
	}

	// A stalled request times out the same way.
	quarter := half / 2
	stalled := sendPart(half, len(data)-half, data[half:half+quarter])
	waitFor(t, "a quarter more on disk", func() bool { return partSize() == int64(half+quarter) })
	resp, err := http.ReadResponse(bufio.NewReader(stalled), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	expectStatus(t, resp, http.StatusRequestTimeout)

	var last *http.Response
	waitFor(t, "the claim to be free", func() bool {
		last = patchAt(t, op, loc, half+quarter, string(data[half+quarter:]))
		return last.StatusCode != http.StatusLocked
	})
	expectStatus(t, last, http.StatusNoContent)
	if readFile(t, f.dir, "big.bin") != string(data) {
		t.Error("stored content differs")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftovers %v", l)
	}
}

// A request that loses its claim stops writing: another may write then.
func TestResumableLostClaim(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta).as("operator")
	addr, _ := startServer(t, f)
	defer func(d time.Duration) { claimRenew = d }(claimRenew)
	claimRenew = 20 * time.Millisecond
	data := bytes.Repeat([]byte("x"), 1<<20)
	loc := startResumable(t, f, "/", "big.bin", len(data))
	up, err := ta.svc.UploadByToken(context.Background(), strings.TrimPrefix(loc, uploadsPrefix))
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PATCH %s HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer %s\r\nTus-Resumable: 1.0.0\r\n"+
		"Upload-Offset: 0\r\nContent-Type: application/offset+octet-stream\r\nContent-Length: %d\r\n\r\n", loc, f.token, len(data))
	// fasthttp reads the first 8 KiB before the handler runs.
	const sent = 64 << 10
	if _, err := conn.Write(data[:sent]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "data on disk", func() bool {
		p := partials(f.dir)
		if len(p) != 1 {
			return false
		}
		info, err := os.Stat(p[0])
		return err == nil && info.Size() == sent
	})
	ta.store.SetUploadWriter(up.ID, "another")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	expectStatus(t, resp, http.StatusLocked)
	if len(f.logs.entries("upload claim lost")) != 1 {
		t.Error("lost claim not logged")
	}
}

func TestResumableExpiry(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta).as("operator")
	loc := startResumable(t, f, "/", "big.bin", 10)
	expectStatus(t, patchAt(t, f, loc, 0, "01234"), http.StatusNoContent)
	up, err := ta.svc.UploadByToken(context.Background(), strings.TrimPrefix(loc, uploadsPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(up.ExpiresAt) < 59*time.Minute {
		t.Errorf("expires %v", up.ExpiresAt)
	}
	ta.store.ExpireUpload(up.ID)
	if offsetOf(t, f, loc) != -1 {
		t.Error("an expired upload goes on")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.srv.purgeUploads(ctx)
	if len(partials(f.dir)) != 0 {
		t.Error("expired upload's data not removed")
	}
	if len(f.logs.entries("removed expired uploads")) != 1 {
		t.Error("purge not logged")
	}
}

// Data whose upload was forgotten, as when its folder moved, goes once old.
func TestRemoveLeftoverPartials(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a/"+tempPrefix+"OLD"+partialSuffix, "old")
	f.write(t, "a/"+tempPrefix+"NEW"+partialSuffix, "new")
	old := time.Now().Add(-f.srv.cfg.Upload.ResumeWindow - 2*time.Hour)
	if err := os.Chtimes(filepath.Join(f.dir, "a", tempPrefix+"OLD"+partialSuffix), old, old); err != nil {
		t.Fatal(err)
	}
	if n := f.srv.removeLeftovers(context.Background()); n != 1 {
		t.Errorf("removed %d", n)
	}
	if p := partials(f.dir); len(p) != 1 || !strings.Contains(p[0], "NEW") {
		t.Errorf("left %v", p)
	}
}

// Deleting a folder deletes unfinished uploads into it.
func TestDeleteFolderWithUnfinishedUpload(t *testing.T) {
	f := newFixture(t).as("admin")
	f.write(t, "box/a.txt", "a")
	loc := startResumable(t, f, "/box/", "big.bin", 10)
	resp, _ := f.do(t, "DELETE", "/box")
	expectStatus(t, resp, http.StatusNoContent)
	if offsetOf(t, f, loc) != -1 || exists(filepath.Join(f.dir, "box")) {
		t.Error("folder or upload left")
	}
}

func TestTusMetadata(t *testing.T) {
	for h, want := range map[string]map[string]string{
		"":                                   {},
		"filename YS50eHQ=":                  {"filename": "a.txt"},
		"filename YS50eHQ=, replace MQ==":    {"filename": "a.txt", "replace": "1"},
		"filename YS50eHQ=,flag":             {"filename": "a.txt", "flag": ""},
		"filename YS50eHQ=,filename Yi50eHQ": nil,
		"filename !!":                        nil,
		",":                                  nil,
	} {
		got, ok := tusMetadata(h)
		if ok != (want != nil) || len(got) != len(want) {
			t.Errorf("tusMetadata(%q) = %v, %v", h, got, ok)
			continue
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("tusMetadata(%q)[%s] = %q", h, k, got[k])
			}
		}
	}
}
