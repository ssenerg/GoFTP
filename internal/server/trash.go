package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// Deleted files and folders go to the trash, a hidden folder at the top of
// the served folder, and stay there for trash.keep; until then they can be
// restored. Each waits in a folder of its own, under its name, next to a
// note of where it was:
//
//	.goftp-trash/ID/NAME   what was deleted
//	.goftp-trash/ID/.info  JSON: its URL path, who deleted it and when
//
// Deleting and restoring are renames, so they take no time and no space.
// What is on another file system than the trash cannot go there.
const (
	trashDir  = ".goftp-trash"
	trashInfo = ".info"
	trashPath = "/.trash/"
	// goneMark marks a trashed entry being removed for good.
	goneMark = "gone-"
	// trashIDsHeader names the trash entries a deletion made, for scripts
	// that want to restore them.
	trashIDsHeader = "Goftp-Trash-Ids"
)

// trashNote is what the trash knows of an entry.
type trashNote struct {
	Path string    `json:"path"` // URL path where it really was (see resolve)
	Dir  bool      `json:"dir"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	// Home is set for the home of a user who was deleted (see home.go).
	Home bool `json:"home,omitempty"`
	// Owner is the ID of the user whose home it was in, or was.
	Owner int64 `json:"owner,omitempty"`
}

// trashed is an entry in the trash.
type trashed struct {
	ID string
	trashNote
	size int64
}

var errOtherDisk = errors.New("on another file system than the trash")

// validTrashID reports whether id could name an entry in the trash.
func validTrashID(id string) bool {
	if len(id) != 26 {
		return false
	}
	for _, c := range []byte(id) {
		if !('A' <= c && c <= 'Z' || '2' <= c && c <= '7') {
			return false
		}
	}
	return true
}

// openTrash opens the trash, which is created if create is set.
func (s *Server) openTrash(create bool) (*os.Root, error) {
	if create {
		if err := s.root.Mkdir(trashDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	// Only goftp makes dot entries here; still, a symlink is not followed.
	if info, err := s.root.Lstat(trashDir); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, fs.ErrNotExist
	}
	return s.root.OpenRoot(trashDir)
}

// toTrash moves the entry name of dir, which really lives at realPath, to
// the trash, and returns its ID there. The caller checked that it may be
// deleted.
func (s *Server) toTrash(c fiber.Ctx, dir *os.Root, name, realPath string, info fs.FileInfo) (string, error) {
	note := trashNote{Path: realPath, Dir: info.IsDir(), By: visitor(c), At: time.Now().UTC()}
	if home, ok := s.homeName(realPath); ok {
		note.Owner, _, _ = s.ownerNow(home)
	}
	return s.moveToTrash(dir, name, note)
}

// moveToTrash moves the entry name of dir to the trash with note, and
// returns its ID there. It waits there under the name it had at note.Path.
func (s *Server) moveToTrash(dir *os.Root, name string, note trashNote) (string, error) {
	trash, err := s.openTrash(true)
	if err != nil {
		return "", err
	}
	defer trash.Close()
	id := rand.Text()
	if err := trash.Mkdir(id, 0o700); err != nil {
		return "", err
	}
	box, err := trash.OpenRoot(id)
	if err == nil {
		defer box.Close()
		err = writeNote(box, note)
	}
	if err == nil {
		err = renameBetween(dir, name, box, path.Base(note.Path))
	}
	if err != nil {
		_ = trash.RemoveAll(id)
		if errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EBUSY) {
			err = errOtherDisk
		}
		return "", err
	}
	syncDir(box)
	return id, nil
}

func writeNote(box *os.Root, note trashNote) error {
	data, err := json.Marshal(note)
	if err != nil {
		return err
	}
	f, err := box.OpenFile(trashInfo, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// rewriteNote replaces the note of the trash entry box.
func rewriteNote(box *os.Root, note trashNote) error {
	data, err := json.Marshal(note)
	if err != nil {
		return err
	}
	tmp := tempPrefix + rand.Text() + tempSuffix
	f, err := box.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = box.Rename(tmp, trashInfo)
	}
	if err != nil {
		_ = box.Remove(tmp)
	}
	return err
}

func readNote(box *os.Root) (trashNote, error) {
	var note trashNote
	f, err := box.Open(trashInfo)
	if err != nil {
		return note, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<10))
	if err != nil {
		return note, err
	}
	if err := json.Unmarshal(data, &note); err != nil || !strings.HasPrefix(note.Path, "/") || note.Path == "/" {
		return note, fs.ErrNotExist
	}
	return note, nil
}

// trashEntry opens the entry id of the trash, with its note and what
// Lstat says of it.
func (s *Server) trashEntry(id string) (trash, box *os.Root, note trashNote, info fs.FileInfo, err error) {
	if !validTrashID(id) {
		return nil, nil, note, nil, fiber.ErrNotFound
	}
	if trash, err = s.openTrash(false); err != nil {
		return nil, nil, note, nil, s.openError(err)
	}
	if box, err = trash.OpenRoot(id); err == nil {
		if note, err = readNote(box); err == nil {
			info, err = box.Lstat(path.Base(note.Path))
		}
		if err != nil {
			_ = box.Close()
		}
	}
	if err != nil {
		_ = trash.Close()
		return nil, nil, note, nil, s.openError(err)
	}
	return trash, box, note, info, nil
}

// trashItems lists what is in the trash, newest first.
func (s *Server) trashItems() ([]trashed, error) {
	trash, err := s.openTrash(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer trash.Close()
	d, err := trash.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return nil, err
	}
	var items []trashed
	for _, e := range entries {
		if !e.IsDir() || !validTrashID(e.Name()) {
			continue
		}
		box, err := trash.OpenRoot(e.Name())
		if err != nil {
			continue
		}
		note, err := readNote(box)
		var info fs.FileInfo
		if err == nil {
			info, err = box.Lstat(path.Base(note.Path))
		}
		_ = box.Close()
		if err != nil {
			continue
		}
		it := trashed{ID: e.Name(), trashNote: note}
		if info.Mode().IsRegular() {
			it.size = info.Size()
		}
		items = append(items, it)
	}
	slices.SortFunc(items, func(a, b trashed) int { return b.At.Compare(a.At) })
	return items, nil
}

// mayRestore reports whether the visitor may see the trashed entry, and
// restore it or delete it for good: they need to read it where it was,
// and to create it there or delete it.
func mayRestore(allow allowFunc, note trashNote) (restore, purge bool, err error) {
	if ok, err := mayBoth(allow, auth.ActRead, note.Path, note.Path, note.Dir); err != nil || !ok {
		return false, false, err
	}
	if restore, err = mayBoth(allow, auth.ActWrite, note.Path, note.Path, note.Dir); err != nil {
		return false, false, err
	}
	purge, err = mayBoth(allow, auth.ActDelete, note.Path, note.Path, note.Dir)
	return restore, purge, err
}

// trashRights is mayRestore for the visitor of c. The home of a deleted
// user is for superadmins only: they may restore it, for a user of that
// name, and delete it for good, without seeing what is in it; home is set
// then. What a deleted user deleted from their home is nobody's (see
// stillTheirs).
func (s *Server) trashRights(c fiber.Ctx, note trashNote) (restore, purge, home bool, err error) {
	if note.Home {
		su := s.auth.IsSuperadmin(visitorName(c))
		return su, su, su, nil
	}
	if !s.stillTheirs(note) {
		return false, false, false, nil
	}
	restore, purge, err = mayRestore(s.visitorRules(c), note)
	return restore, purge, false, err
}

// trashSeen reports whether the visitor of c is told that the trashed
// entry exists, when they may not restore or delete it: if they may read
// it where it was.
func (s *Server) trashSeen(c fiber.Ctx, note trashNote) bool {
	if note.Home || !s.stillTheirs(note) {
		return false
	}
	may, _ := mayBoth(s.visitorRules(c), auth.ActRead, note.Path, note.Path, note.Dir)
	return may
}

// restore puts the trashed entry id back where it was, and returns that
// URL path. The folder it was in has to be there, and nothing of its name.
// A home goes back to the user of its name, whose new home gives way if it
// is empty.
func (s *Server) restore(c fiber.Ctx, id string) (string, error) {
	s.trashMu.Lock()
	defer s.trashMu.Unlock()
	trash, box, note, info, err := s.trashEntry(id)
	if err != nil {
		return "", err
	}
	defer trash.Close()
	defer box.Close()
	ok, _, home, err := s.trashRights(c, note)
	if err != nil {
		return "", err
	} else if !ok {
		if !s.trashSeen(c, note) {
			return "", fiber.ErrNotFound
		}
		return "", s.deny(c)
	}
	dirPath, name := path.Split(note.Path)
	var owner *auth.User
	if home {
		ctx, cancel := dbContext(c)
		owner, err = s.auth.UserNamed(ctx, name)
		cancel()
		if errors.Is(err, auth.ErrNotFound) {
			return "", explain(fiber.ErrConflict, "Add the user "+name+" again first: a home goes back to its user.")
		}
		if err != nil {
			return "", err
		}
	}
	dir, realDir, err := s.uploadDir(dirPath)
	if errors.Is(err, fiber.ErrNotFound) {
		return "", explain(fiber.ErrConflict, "The folder it was in, "+path.Clean(dirPath)+", is gone: restore or create that first.")
	}
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if ok, err := s.mayAt(c, auth.ActWrite, note.Path, path.Join(realDir, name), note.Dir); err != nil {
		return "", err
	} else if !ok && !home {
		return "", s.deny(c)
	}
	// The lock keeps uploads of the name out meanwhile.
	release, err := s.acquireLock(dir, name, tempPrefix+rand.Text()+tempSuffix)
	if err != nil {
		return "", err
	}
	defer release()
	if home {
		s.homeMu.Lock()
		defer s.homeMu.Unlock()
		if err := clearEmptyHome(dir, name); err != nil {
			return "", err
		}
	}
	if err := moveNoReplace(box, name, dir, name, info); errors.Is(err, errExists) && home {
		return "", explain(fiber.ErrConflict, name+" has a home with files in it already, so the old one stays in the trash.")
	} else if errors.Is(err, errExists) {
		return "", explain(fiber.ErrConflict, "Something named "+name+" is there now: rename or delete it first.")
	} else if err != nil {
		return "", s.openError(err)
	}
	syncDir(dir)
	if home {
		if err := writeOwner(dir, name, owner.ID); err != nil {
			return "", err
		}
		s.homesChecked.Delete(owner.ID)
		s.reownTrash(trash, note, owner.ID)
	}
	_ = trash.RemoveAll(id)
	s.log.Info("restore", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", note.Path),
		zap.Bool("folder", note.Dir))
	return note.Path, nil
}

// purge removes the trashed entry id for good, if the visitor may delete
// it and, for a folder, everything in it, where it was.
func (s *Server) purge(c fiber.Ctx, id string) error {
	s.trashMu.Lock()
	trash, box, note, info, err := s.trashEntry(id)
	if err != nil {
		s.trashMu.Unlock()
		return err
	}
	defer trash.Close()
	err = func() error {
		defer box.Close()
		_, ok, home, err := s.trashRights(c, note)
		if err != nil {
			return err
		} else if !ok {
			if !s.trashSeen(c, note) {
				return fiber.ErrNotFound
			}
			return s.deny(c)
		}
		// A home is deleted as a whole, by a superadmin.
		acts := []string{auth.ActDelete}
		if home {
			acts = nil
		}
		if info.IsDir() {
			switch _, err := s.checkTree(c, box, path.Base(note.Path), note.Path, note.Path, acts...); {
			case errors.Is(err, errDenied):
				return explain(fiber.ErrForbidden, "You may not delete everything in this folder.")
			case errors.Is(err, errMounted):
				return explain(fiber.ErrConflict, "Another disk is mounted in this folder: deleting it would empty that disk too.")
			case err != nil && !errors.Is(err, errBusy):
				return s.openError(err)
			}
		}
		// Claimed under the lock, so that it cannot be restored while it
		// is removed.
		return trash.Rename(id, goneMark+id)
	}()
	s.trashMu.Unlock()
	if err != nil {
		return err
	}
	if err := trash.RemoveAll(goneMark + id); err != nil {
		return err
	}
	s.homeChanged(note.Path)
	s.log.Info("purge", zap.String("ip", c.IP()), zap.String("user", visitor(c)), zap.String("path", note.Path),
		zap.Bool("folder", note.Dir))
	return nil
}

// reownTrash gives what the user of the restored home (noted in home) had
// deleted from it to its new owner id: the user of that name again.
func (s *Server) reownTrash(trash *os.Root, home trashNote, id int64) {
	if home.Owner <= 0 {
		return
	}
	d, err := trash.Open(".")
	if err != nil {
		return
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !validTrashID(e.Name()) {
			continue
		}
		box, err := trash.OpenRoot(e.Name())
		if err != nil {
			continue
		}
		if note, err := readNote(box); err == nil && !note.Home && note.Owner == home.Owner && inHome(home.Path, note.Path) != "" {
			note.Owner = id
			if err := rewriteNote(box, note); err != nil {
				s.log.Warn("give back trashed entry", zap.String("id", e.Name()), zap.Error(err))
			}
		}
		_ = box.Close()
	}
}

// clearEmptyHome removes the home name of the folder of homes dir if it
// holds nothing but its owner note, so that an old one can take its place.
// The note goes first; the folder only goes if nothing else came meanwhile,
// such as an upload of its user, and the note comes back if it stays.
func clearEmptyHome(dir *os.Root, name string) error {
	d, err := dir.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.Name() != homeOwner {
			return nil
		}
	}
	owner, _, err := readOwner(dir, name)
	if err != nil {
		return err
	}
	if err := dir.Remove(path.Join(name, homeOwner)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := dir.Remove(name); err != nil {
		if owner > 0 {
			return writeOwner(dir, name, owner)
		}
		return nil
	}
	return nil
}

// moveNoReplace moves the entry name of from to newName in to, unless
// newName exists there. Files are hard-linked first, which makes "only if
// absent" atomic even against writers that ignore lock files.
func moveNoReplace(from *os.Root, name string, to *os.Root, newName string, info fs.FileInfo) error {
	if _, err := to.Lstat(newName); err == nil {
		return errExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if info.Mode().IsRegular() {
		err := linkBetween(from, name, to, newName)
		switch {
		case err == nil:
			if err := from.Remove(name); err != nil {
				_ = to.Remove(newName)
				return err
			}
			return nil
		case errors.Is(err, fs.ErrExist):
			return errExists
		}
		// No hard links here: rename, as checked above.
	}
	return renameExclBetween(from, name, to, newName)
}

// purgeTrash removes what was deleted more than trash.keep ago, every
// purgeEvery until ctx ends, along with what removals cut off left behind.
func (s *Server) purgeTrash(ctx context.Context) {
	for {
		if n := s.expireTrash(time.Now().Add(-s.cfg.Trash.Keep)); n > 0 {
			s.log.Info("emptied the trash", zap.Int("entries", n))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(purgeEvery):
		}
	}
}

// expireTrash removes the trash entries deleted before cutoff and returns
// how many.
func (s *Server) expireTrash(cutoff time.Time) int {
	trash, err := s.openTrash(false)
	if err != nil {
		return 0
	}
	defer trash.Close()
	d, err := trash.Open(".")
	if err != nil {
		return 0
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, goneMark) && validTrashID(strings.TrimPrefix(name, goneMark)):
			_ = trash.RemoveAll(name)
		case e.IsDir() && validTrashID(name):
			if s.expired(trash, e, cutoff) && s.claim(trash, name) {
				if trash.RemoveAll(goneMark+name) == nil {
					removed++
				}
			}
		}
	}
	if removed > 0 {
		s.recountAll()
	}
	return removed
}

// expired reports whether the trash entry e was deleted before cutoff. One
// without a note, which a deletion cut off left behind, counts once it is
// an hour old.
func (s *Server) expired(trash *os.Root, e fs.DirEntry, cutoff time.Time) bool {
	box, err := trash.OpenRoot(e.Name())
	if err != nil {
		return false
	}
	defer box.Close()
	note, err := readNote(box)
	if err != nil {
		return olderThan(e, time.Hour)
	}
	return note.At.Before(cutoff)
}

// claim marks the trash entry id as being removed, unless it was restored
// meanwhile.
func (s *Server) claim(trash *os.Root, id string) bool {
	s.trashMu.Lock()
	defer s.trashMu.Unlock()
	return trash.Rename(id, goneMark+id) == nil
}

// trashData is the trash page.
type trashData struct {
	page
	Keep   string
	Items  []trashItem
	Purge  bool // something here may be deleted for good
	Notice string
	Error  string
}

type trashItem struct {
	ID                  string
	Name, Folder        string
	FolderHref          string
	Kind, Size          string
	By                  string
	Deleted, DeletedISO string
	Gone, GoneISO       string // when it is removed for good
	CanRestore          bool
	CanPurge            bool
	Home                bool // of a deleted user
}

var trashNotices = map[string]string{"purged": "Deleted for good.", "emptied": "The trash was emptied.",
	"restored": "Restored: it is back where it was."}

func (s *Server) trashPage(c fiber.Ctx) error {
	if userOf(c) == nil {
		return s.deny(c)
	}
	return s.renderTrash(c, fiber.StatusOK, trashNotices[c.Query("done")], "")
}

// keepText says how long the trash keeps things, e.g. "30 days".
func keepText(d time.Duration) string {
	if days := d / (24 * time.Hour); d%(24*time.Hour) == 0 {
		return plural(int(days), "day")
	}
	if d%time.Hour == 0 {
		return plural(int(d/time.Hour), "hour")
	}
	return d.String()
}

func (s *Server) renderTrash(c fiber.Ctx, status int, notice, failure string) error {
	items, err := s.trashItems()
	if err != nil {
		return err
	}
	data := trashData{page: s.page(c, "Trash"), Keep: keepText(s.cfg.Trash.Keep), Notice: notice, Error: failure}
	for _, it := range items {
		restore, purge, _, err := s.trashRights(c, it.trashNote)
		if err != nil {
			return err
		}
		if !restore && !purge {
			continue
		}
		folder := path.Dir(it.Path)
		gone := it.At.Add(s.cfg.Trash.Keep)
		ti := trashItem{ID: it.ID, Name: path.Base(it.Path), Folder: folder, FolderHref: escapePath(object(folder, true)),
			Kind: kindOf(it.Path), Size: formatSize(it.size), By: it.By,
			Deleted: shownTime(it.At), DeletedISO: isoTime(it.At),
			Gone: shownTime(gone), GoneISO: isoTime(gone),
			CanRestore: restore, CanPurge: purge, Home: it.Home}
		if it.Dir {
			ti.Kind, ti.Size = "folder", "—"
		}
		data.Items = append(data.Items, ti)
		data.Purge = data.Purge || purge
	}
	return s.render(c, status, "trash", data)
}

// trashAction restores entries from the trash and deletes them for good:
//
//	action=restore&id=ID  puts the entry ID back where it was
//	action=purge&id=ID    deletes it for good
//	action=empty          deletes everything the visitor may for good
//
// e.g. curl -d action=restore -d id=ID https://host/.trash/
func (s *Server) trashAction(c fiber.Ctx) error {
	if userOf(c) == nil {
		return s.deny(c)
	}
	form, _, err := s.readForm(c)
	if err != nil {
		return err
	}
	html := strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML)
	switch form["action"] {
	case "restore":
		p, err := s.restore(c, form["id"])
		if err != nil {
			return s.trashError(c, err)
		}
		if html {
			// Back to its folder, if the visitor may open it.
			if ok, err := s.allowed(c, object(path.Dir(p), true), auth.ActRead); err != nil || !ok {
				return s.redirect(c, trashPath+"?done=restored")
			}
			return s.redirect(c, escapePath(object(path.Dir(p), true))+"?restored="+url.QueryEscape(path.Base(p)))
		}
		c.Location(escapePath(p))
		return c.SendStatus(fiber.StatusCreated)
	case "purge":
		if err := s.purge(c, form["id"]); err != nil {
			return s.trashError(c, err)
		}
		if html {
			return s.redirect(c, trashPath+"?done=purged")
		}
		return c.SendStatus(fiber.StatusNoContent)
	case "empty":
		n, err := s.emptyTrash(c)
		if err != nil {
			return err
		}
		if html {
			return s.redirect(c, trashPath+"?done=emptied")
		}
		return c.JSON(fiber.Map{"deleted": n})
	}
	return fiber.ErrBadRequest
}

// trashError shows why a trash entry could not be restored or deleted on
// the trash page; other clients get the error.
func (s *Server) trashError(c fiber.Ctx, err error) error {
	var fe *fiber.Error
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) || !errors.As(err, &fe) {
		return err
	}
	msg := map[int]string{
		fiber.StatusForbidden: "You may not do that.",
		fiber.StatusNotFound:  "It is no longer in the trash.",
		fiber.StatusConflict:  "It is being changed right now. Try again.",
	}[fe.Code]
	var ex *explained
	if errors.As(err, &ex) {
		msg = ex.detail
	}
	if msg == "" {
		return err
	}
	return s.renderTrash(c, fe.Code, "", msg)
}

// emptyTrash deletes for good what the visitor may delete of the trash,
// and returns how many entries.
func (s *Server) emptyTrash(c fiber.Ctx) (int, error) {
	items, err := s.trashItems()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if _, purge, _, err := s.trashRights(c, it.trashNote); err != nil {
			return n, err
		} else if !purge {
			continue
		}
		var fe *fiber.Error
		switch err := s.purge(c, it.ID); {
		case err == nil:
			n++
		case !errors.As(err, &fe):
			return n, err
		}
	}
	return n, nil
}

// trashIDs formats the IDs of trash entries for trashIDsHeader.
func trashIDs(ids []string) string { return strings.Join(ids, ", ") }

// deletedQuery confirms a deletion of n entries on the folder's page:
// undo names the one trash entry it made, if it made one.
func deletedQuery(n int, ids []string) string {
	q := "deleted=" + strconv.Itoa(n)
	switch {
	case len(ids) == 1:
		q += "&undo=" + ids[0]
	case len(ids) > 1:
		q += "&trashed=1"
	}
	return q
}
