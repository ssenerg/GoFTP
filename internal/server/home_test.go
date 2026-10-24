package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"goftp/internal/auth"
	"goftp/internal/config"
)

func withHomes(cfg *config.Config) {
	cfg.Homes.Path = "/home"
	cfg.Trash.Keep = 30 * 24 * time.Hour
}

// homeOwnerOf reads whose home on disk the home of name is, 0 for nobody.
func homeOwnerOf(t *testing.T, f *fixture, name string) int64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "home", name, homeOwner))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func idOf(t *testing.T, ta *testAuth, name string) int64 {
	t.Helper()
	u, err := ta.svc.UserNamed(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestHomes(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	f.write(t, "docs/a.txt", "shared")
	user, admin := f.as("user"), f.as("admin")
	mine := "/home/" + userOfRole("user")

	// Everyone gets a home, which only they may open, as My files.
	_, body := user.do(t, "GET", "/")
	if !strings.Contains(body, `<a href="`+mine+`/"><svg class="i" aria-hidden="true"><use href="#i-home"/></svg>My files</a>`) ||
		strings.Contains(body, `data-name="home"`) {
		t.Errorf("Files: %s", body)
	}
	if homeOwnerOf(t, f, userOfRole("user")) != idOf(t, ta, userOfRole("user")) {
		t.Error("the home is not noted as theirs")
	}
	resp, body := user.do(t, "GET", mine+"/")
	expectStatus(t, resp, http.StatusOK)
	if !strings.Contains(body, "<h1>My files") || !strings.Contains(body, `aria-current="true"><svg class="i" aria-hidden="true"><use href="#i-home"/></svg>My files`) ||
		!strings.Contains(body, `<a href="`+mine+`/" aria-current="page"><svg class="i" aria-hidden="true"><use href="#i-home"/>`) {
		t.Errorf("My files: %s", body)
	}
	// Users who may only read elsewhere may do anything there, but delete
	// it.
	for _, req := range []struct {
		method, uri, form string
		want              int
	}{
		{"PUT", mine + "/notes.txt", "mine", 201},
		{"PUT", mine + "/notes.txt", "mine again", 204},
		{"POST", mine + "/", "folder=sub", 201},
		{"PUT", mine + "/sub/deep.txt", "deep", 201},
		{"POST", mine + "/", "copy=deep.txt&into=" + mine, 404},
		{"POST", mine + "/sub/", "copy=deep.txt&into=" + mine, 201},
		{"DELETE", mine + "/deep.txt", "", 204},
		{"DELETE", mine, "", 403},
		{"POST", "/home/", "delete=" + userOfRole("user"), 403},
		{"PUT", "/docs/b.txt", "no", 403},
	} {
		var resp *http.Response
		if req.method == "POST" {
			resp, _ = post(t, user, req.uri, req.form)
		} else {
			resp, _ = user.send(t, req.method, req.uri, strings.NewReader(req.form))
		}
		if resp.StatusCode != req.want {
			t.Errorf("%s %s %s: %d, want %d", req.method, req.uri, req.form, resp.StatusCode, req.want)
		}
	}
	_, body = user.do(t, "GET", mine+"/sub/")
	if !strings.Contains(body, `<a href="`+mine+`/" `) || strings.Contains(body, `href="/home/"`) || !strings.Contains(body, `<a href="`+mine+`/">Parent folder`) &&
		!strings.Contains(body, `<tr class="up"><td class="pick"></td><td class="name" colspan="4"><a href="`+mine+`/">`) {
		t.Errorf("crumbs in the home: %s", body)
	}
	_, body = user.do(t, "GET", mine+"/notes.txt?view")
	if !strings.Contains(body, `href="`+mine+`/"`) || strings.Contains(body, `href="/home/"`) {
		t.Errorf("viewer in the home: %s", body)
	}

	// Nobody else may open it, nor the folder of homes.
	for _, who := range []string{"operator", "admin", "superadmin", ""} {
		for _, p := range []string{mine + "/notes.txt", mine + "/", "/home/"} {
			if resp, _ := f.as(who).do(t, "GET", p); resp.StatusCode < 400 {
				t.Errorf("%q GET %s: %d", who, p, resp.StatusCode)
			}
		}
	}
	_, body = admin.do(t, "GET", "/")
	if strings.Contains(body, `data-name="home"`) {
		t.Error("the folder of homes is listed")
	}
	if _, body := admin.do(t, "GET", searchPath+"?q=notes", "Accept", "application/json"); strings.Contains(body, "notes.txt") {
		t.Errorf("search finds another's home: %s", body)
	}
	if _, body := user.do(t, "GET", searchPath+"?q=notes&in="+mine, "Accept", "text/html"); !strings.Contains(body, mine+"/notes.txt") ||
		!strings.Contains(body, ">My files</a>") {
		t.Errorf("search in the home: %s", body)
	}
	// What they delete there only they see in the trash.
	resp, _ = user.do(t, "DELETE", mine+"/notes.txt")
	expectStatus(t, resp, http.StatusNoContent)
	if _, body := user.do(t, "GET", trashPath); !strings.Contains(body, "<span>notes.txt</span>") {
		t.Error("the trash does not show it to its owner")
	}
	if _, body := f.as("superadmin").do(t, "GET", trashPath); strings.Contains(body, "notes.txt") {
		t.Error("the trash shows it to others")
	}
	// They may share what is in it, as links.
	createLink(t, user, map[string][]string{"path": {mine + "/sub"}})
}

func TestHomeOfDeletedUser(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	super := f.as("superadmin")
	dora := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "dora", "user")}
	resp, _ := dora.send(t, "PUT", "/home/dora/secret.txt", strings.NewReader("dora's"))
	expectStatus(t, resp, http.StatusCreated)

	// Deleting her moves her home to the trash, which superadmins see,
	// but not what is in it.
	resp, _ = post(t, super, usersPath, "action=delete&user=dora", "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != usersPath+"?done=deleted-home" {
		t.Errorf("Location %q", got)
	}
	if exists(filepath.Join(f.dir, "home", "dora")) {
		t.Error("her home stayed")
	}
	_, body := super.do(t, "GET", trashPath)
	if !strings.Contains(body, `<span>dora</span><span class="chip"`) || !strings.Contains(body, "Restore") {
		t.Errorf("trash: %s", body)
	}
	var id string
	for _, e := range trashedOnDisk(t, f) {
		id = e
	}
	if resp, _ := super.do(t, "GET", "/home/dora/secret.txt"); resp.StatusCode < 400 {
		t.Error("a superadmin opens a home")
	}
	// It goes back to a user of her name only, replacing an empty home.
	resp, body = trashForm(t, super, "action=restore&id="+id)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "Add the user dora again first") {
		t.Errorf("restore without dora: %d %q", resp.StatusCode, body)
	}
	dora.token = ta.addUser(t, "dora", "user")
	if resp, _ := dora.do(t, "GET", "/home/dora/secret.txt"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("the new dora reads the old one's file: %d", resp.StatusCode)
	}
	resp, _ = trashForm(t, super, "action=restore&id="+id, "Accept", "text/html")
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != trashPath+"?done=restored" {
		t.Errorf("Location %q", got)
	}
	if resp, body := dora.do(t, "GET", "/home/dora/secret.txt"); resp.StatusCode != http.StatusOK || body != "dora's" {
		t.Errorf("restored home: %d %q", resp.StatusCode, body)
	}
	if homeOwnerOf(t, f, "dora") != idOf(t, ta, "dora") {
		t.Error("the restored home is not noted as hers")
	}

	// A home that a user deleted elsewhere (the command line, another
	// server) left behind goes to the trash before a new one gets in.
	f.write(t, "home/erin/old.txt", "the old erin's")
	f.write(t, "home/erin/"+homeOwner, "999999\n")
	erin := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "erin", "user")}
	if resp, _ := erin.do(t, "GET", "/home/erin/old.txt"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a new user reads what an old one left: %d", resp.StatusCode)
	}
	if homeOwnerOf(t, f, "erin") != idOf(t, ta, "erin") || exists(filepath.Join(f.dir, "home", "erin", "old.txt")) {
		t.Error("the old home stayed")
	}
	var note trashNote
	found := false
	for _, e := range trashedOnDisk(t, f) {
		b, err := os.ReadFile(filepath.Join(f.dir, trashDir, e, trashInfo))
		if err == nil && json.Unmarshal(b, &note) == nil && note.Path == "/home/erin" {
			found = note.Home && note.By == "goftp"
		}
	}
	if !found {
		t.Errorf("the old home is not in the trash: %+v", note)
	}
	// A home made by hand, before its user, becomes theirs.
	f.write(t, "home/fred/welcome.txt", "hello")
	fred := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "fred", "user")}
	if resp, body := fred.do(t, "GET", "/home/fred/welcome.txt"); resp.StatusCode != http.StatusOK || body != "hello" {
		t.Errorf("a home made by hand: %d %q", resp.StatusCode, body)
	}

	// Superadmins may delete a home in the trash for good.
	var erinID string
	for _, e := range trashedOnDisk(t, f) {
		erinID = e
	}
	if resp, _ := trashForm(t, super, "action=purge&id="+erinID); resp.StatusCode != http.StatusNoContent {
		t.Errorf("purging a home: %d", resp.StatusCode)
	}
	if resp, _ := trashForm(t, f.as("admin"), "action=empty"); resp.StatusCode != http.StatusOK {
		t.Errorf("an admin empties the trash: %d", resp.StatusCode)
	}
}

func TestHomesSetting(t *testing.T) {
	// The folder of homes is made when the server starts, and may not be a
	// file.
	f := newFixture(t, withHomes)
	if info, err := os.Stat(filepath.Join(f.dir, "home")); err != nil || !info.IsDir() {
		t.Errorf("folder of homes: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "home"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Dir: dir, Homes: config.HomesConfig{Path: "/home"}}
	if _, err := New(cfg, nil, sharedAuth().svc); err == nil || !strings.Contains(err.Error(), "must be a folder") {
		t.Errorf("a file as the folder of homes: %v", err)
	}
	// Without homes, nobody gets one.
	f = newFixture(t)
	if _, body := f.as("user").do(t, "GET", "/"); strings.Contains(body, "My files") || exists(filepath.Join(f.dir, "home")) {
		t.Error("homes while they are off")
	}
	sharedAuth().svc.SetHomes("")
}

func TestInHome(t *testing.T) {
	for _, tc := range []struct{ home, p, want string }{
		{"/home/bob", "/home/bob", "/"},
		{"/home/bob", "/home/bob/a/b", "/a/b"},
		{"/home/bob", "/home/bobby", ""},
		{"/home/bob", "/home", ""},
		{"", "/home/bob", ""},
	} {
		if got := inHome(tc.home, tc.p); got != tc.want {
			t.Errorf("inHome(%q, %q) = %q, want %q", tc.home, tc.p, got, tc.want)
		}
	}
}

// What a deleted user deleted from their home is not a new user's of the
// same name, until a superadmin gives the old home back.
func TestTrashOfReusedName(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	super := f.as("superadmin")
	dora := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "dora", "user")}
	resp, _ := dora.send(t, "PUT", "/home/dora/diary.txt", strings.NewReader("old dora's diary"))
	expectStatus(t, resp, http.StatusCreated)
	resp, _ = dora.do(t, "DELETE", "/home/dora/diary.txt")
	expectStatus(t, resp, http.StatusNoContent)
	diary := resp.Header.Get(trashIDsHeader)
	resp, _ = post(t, super, usersPath, "action=delete&user=dora")
	expectStatus(t, resp, http.StatusSeeOther)

	dora.token = ta.addUser(t, "dora", "user")
	if _, body := dora.do(t, "GET", trashPath); strings.Contains(body, "diary.txt") || strings.Contains(body, `<span>dora</span>`) {
		t.Errorf("the new dora sees the old one's trash: %s", body)
	}
	for _, form := range []string{"action=restore&id=" + diary, "action=purge&id=" + diary} {
		if resp, _ := trashForm(t, dora, form); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", form, resp.StatusCode)
		}
	}
	if !exists(filepath.Join(f.dir, trashDir, diary)) {
		t.Fatal("the old diary is gone")
	}
	if _, body := super.do(t, "GET", trashPath); strings.Contains(body, "diary.txt") {
		t.Error("superadmins see what was in a home")
	}

	// Once the old home is back, so is what she deleted from it.
	var home string
	for _, e := range trashedOnDisk(t, f) {
		if e != diary {
			home = e
		}
	}
	resp, _ = trashForm(t, super, "action=restore&id="+home)
	expectStatus(t, resp, http.StatusCreated)
	if _, body := dora.do(t, "GET", trashPath); !strings.Contains(body, "diary.txt") {
		t.Error("her trash did not come back with her home")
	}
	resp, _ = trashForm(t, dora, "action=restore&id="+diary)
	expectStatus(t, resp, http.StatusCreated)
	if resp, body := dora.do(t, "GET", "/home/dora/diary.txt"); resp.StatusCode != http.StatusOK || body != "old dora's diary" {
		t.Errorf("restored diary: %d %q", resp.StatusCode, body)
	}
}

// A home that cannot be moved away keeps its new user out of it, and out
// of nothing else.
func TestHomeThatCannotBeSettled(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	f.write(t, "docs/a.txt", "a")
	f.write(t, "home/gus/old.txt", "the old gus's")
	f.write(t, "home/gus/"+homeOwner, "999999\n")
	f.write(t, trashDir, "not a folder")
	gus := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "gus", "user")}
	if resp, body := gus.do(t, "GET", "/docs/a.txt"); resp.StatusCode != http.StatusOK || body != "a" {
		t.Errorf("elsewhere: %d %q", resp.StatusCode, body)
	}
	for _, uri := range []string{"/home/gus/old.txt", "/HOME/Gus/old.txt"} {
		if resp, _ := gus.do(t, "GET", uri); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
			t.Errorf("the old home, as %s: %d", uri, resp.StatusCode)
		}
	}
	if len(f.logs.entries("claim home")) == 0 {
		t.Error("not logged")
	}
}

// Rules for a deleted user's home go with them: a new user of that name
// starts with a private home.
func TestHomeRulesGoWithUser(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	ta.addUser(t, "dora", "user")
	for _, obj := range []string{"/home/dora/*", "!/home/dora/x", "/home/dorab/*", "/home/*"} {
		if _, err := ta.svc.AddPolicy("user:"+userOfRole("user"), obj, auth.ActRead); err != nil {
			t.Fatal(err)
		}
	}
	resp, _ := post(t, f.as("superadmin"), usersPath, "action=delete&user=dora")
	expectStatus(t, resp, http.StatusSeeOther)
	perms, _, err := ta.svc.Policies()
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, p := range perms {
		if strings.HasPrefix(strings.TrimPrefix(p[1], auth.DenyPrefix), "/home/") {
			left = append(left, p[1])
		}
	}
	slices.Sort(left)
	if strings.Join(left, " ") != "/home/* /home/dorab/*" {
		t.Errorf("rules left: %v", left)
	}
}

// Superadmins may revoke any link, without learning what is in others'
// homes.
func TestSharesPageHidesHomes(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	dora := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "dora", "user")}
	resp, _ := dora.send(t, "PUT", "/home/dora/tax-return.pdf", strings.NewReader("%PDF"))
	expectStatus(t, resp, http.StatusCreated)
	createLink(t, dora, url.Values{"path": {"/home/dora/tax-return.pdf"}})
	_, body := f.as("superadmin").do(t, "GET", sharesPath, "Accept", "text/html")
	if strings.Contains(body, "tax-return") || !strings.Contains(body, "Private file") || !strings.Contains(body, "Revoke") {
		t.Errorf("shares page: %s", body)
	}
	if _, body := dora.do(t, "GET", sharesPath, "Accept", "text/html"); !strings.Contains(body, "tax-return.pdf") {
		t.Error("the owner does not see her own link")
	}
}

// With the trash off, deleting a user deletes their home, and says so.
func TestDeleteUserWithTrashOff(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes, func(cfg *config.Config) { cfg.Trash.Keep = 0 })
	super := f.as("superadmin")
	dora := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "dora", "user")}
	resp, _ := dora.send(t, "PUT", "/home/dora/a.txt", strings.NewReader("a"))
	expectStatus(t, resp, http.StatusCreated)
	if _, body := super.do(t, "GET", usersPath); !strings.Contains(body, "Their home and everything in it go too.") {
		t.Error("the confirmation does not say the home goes for good")
	}
	resp, _ = post(t, super, usersPath, "action=delete&user=dora", "Accept", "text/html")
	if got := resp.Header.Get("Location"); got != usersPath+"?done=deleted-all" {
		t.Errorf("Location %q", got)
	}
	if exists(filepath.Join(f.dir, "home", "dora")) {
		t.Error("her home stayed")
	}
}

// Restoring a home lets an empty new one give way, but never what arrived
// in it meanwhile.
func TestClearEmptyHome(t *testing.T) {
	dir, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := dir.Mkdir("ann", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeOwner(dir, "ann", 7); err != nil {
		t.Fatal(err)
	}
	if err := clearEmptyHome(dir, "ann"); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.Lstat("ann"); !os.IsNotExist(err) {
		t.Error("an empty home stayed")
	}
	if err := dir.Mkdir("bob", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeOwner(dir, "bob", 8); err != nil {
		t.Fatal(err)
	}
	if err := dir.WriteFile("bob/new.txt", []byte("just in"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := clearEmptyHome(dir, "bob"); err != nil {
		t.Fatal(err)
	}
	if id, _, _ := readOwner(dir, "bob"); id != 8 {
		t.Errorf("owner %d", id)
	}
}

// Where the file system finds names whatever their case, other spellings
// of a path meet the rules of its real one.
func TestSpelledOtherwise(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta, withHomes)
	if !exists(filepath.Join(f.dir, "HOME")) {
		t.Skip("names are found only as spelled here")
	}
	if _, err := ta.svc.AddPolicy("operator", "!/Docs/Secret/*", auth.ActRead); err != nil {
		t.Fatal(err)
	}
	f.write(t, "docs/secret/plan.txt", "plan")
	victim := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: ta.addUser(t, "victim", "user")}
	resp, _ := victim.send(t, "PUT", "/home/victim/private.txt", strings.NewReader("secret"))
	expectStatus(t, resp, http.StatusCreated)
	op, admin := f.as("operator"), f.as("admin")
	for _, req := range []struct {
		who         *fixture
		method, uri string
	}{
		{op, "GET", "/HOME/victim/private.txt"},
		{op, "GET", "/Home/victim/"},
		{op, "GET", "/home/VICTIM/private.txt?inline"},
		{op, "PUT", "/HOME/victim/planted.txt"},
		{admin, "DELETE", "/HOME/victim/private.txt"},
		{op, "GET", "/docs/secret/plan.txt"},
		{op, "GET", "/DOCS/SECRET/plan.txt"},
	} {
		if resp, _ := req.who.send(t, req.method, req.uri, strings.NewReader("x")); resp.StatusCode < 400 {
			t.Errorf("%s %s: %d", req.method, req.uri, resp.StatusCode)
		}
	}
	if _, body := op.do(t, "GET", "/.search/?in=/HOME&q=private"); strings.Contains(body, "private.txt") {
		t.Error("search finds what is in a home")
	}
	if resp, _ := post(t, admin, "/Home/", "copy=victim&into=/docs"); resp.StatusCode < 400 {
		t.Errorf("copying a home: %d", resp.StatusCode)
	}
	if readFile(t, f.dir, "home/victim/private.txt") != "secret" || exists(filepath.Join(f.dir, "home", "victim", "planted.txt")) {
		t.Error("the home changed")
	}
	// Its owner may still spell it as she likes.
	if resp, body := victim.do(t, "GET", "/HOME/Victim/private.txt"); resp.StatusCode != http.StatusOK || body != "secret" {
		t.Errorf("the owner: %d %q", resp.StatusCode, body)
	}
}

// Rules fold paths as the file system folds names, if it does.
func TestCheckNames(t *testing.T) {
	f := newFixture(t)
	fold, err := f.srv.checkNames()
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, "probe.txt", "")
	caseless := f.srv.sameEntry("probe.txt", "PROBE.TXT")
	if (fold != nil && fold("/A") == "/a") != caseless {
		t.Errorf("caseless %v, but fold %v", caseless, fold != nil)
	}
	if got := swapCase("Ab-Ç1é"); got != "aB-ç1É" {
		t.Errorf("swapCase: %q", got)
	}
	if !f.srv.sameEntry("probe.txt", "probe.txt") || f.srv.sameEntry("probe.txt", "other.txt") {
		t.Error("sameEntry")
	}
}

// With homes off, homes left from before are ordinary folders: goftp says
// so at startup.
func TestOldHomesWarning(t *testing.T) {
	f := newFixture(t)
	f.write(t, "home/ann/"+homeOwner, "7\n")
	g := newFixtureWith(t, f.auth, func(cfg *config.Config) { cfg.Dir = f.dir })
	if len(g.logs.entries("homes are off, but /home holds homes from before: whoever the rules let in may open them now")) != 1 {
		t.Error("no warning")
	}
}
