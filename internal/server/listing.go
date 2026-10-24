package server

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

// appJS enhances the pages, which also work without it.
//
//go:embed templates/app.js
var appJS string

// scriptHash admits appJS, and no other script, in the CSP.
var scriptHash = func() string {
	sum := sha256.Sum256([]byte(appJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"script":  func() template.HTML { return template.HTML("<script>" + appJS + "</script>") },
	"initial": func(s string) string { return strings.ToUpper(s[:min(1, len(s))]) },
	// actionName describes a rule's action for people.
	"actionName": func(act string) string {
		return map[string]string{
			auth.ActRead: "read", auth.ActWrite: "add files and folders", auth.ActOverwrite: "replace files",
			auth.ActDelete: "delete and rename", auth.ActShare: "share links", "*": "do anything",
		}[act]
	},
	"expiryOptions": func() []shareTTL { return shareTTLs },
}).ParseFS(templateFS, "templates/*.html"))

// page holds what every page shows.
type page struct {
	Title     string
	User      string
	Role      string
	Admin     bool   // may administer users and rules
	Shares    bool   // may share links, or administers them
	Trash     bool   // may delete, so the trash is of use
	Section   string // the top bar's tab for the page: "files", "shared" or ""
	Here      string
	MinLength int
	// Shared is set on pages reached through a share link, which show
	// nothing of the visitor's account; Share describes the link if it
	// works.
	Shared bool
	Share  *shareView
}

func (s *Server) page(c fiber.Ctx, title string) page {
	p := page{Title: title, Here: c.OriginalURL(), MinLength: auth.MinPasswordLength}
	if u := userOf(c); u != nil {
		p.User = u.Username
		p.Role = s.auth.Role(u.Username)
		p.Admin = s.auth.IsSuperadmin(u.Username)
		p.Shares = p.Admin || s.auth.MayShare(u.Username)
		p.Trash = s.cfg.Trash.Keep > 0 && (p.Admin || s.auth.MayDelete(u.Username))
	}
	switch {
	case strings.HasPrefix(c.Path(), sharesPath):
		p.Section = "shared"
	case strings.HasPrefix(c.Path(), trashPath):
		p.Section = "trash"
	case strings.HasPrefix(c.Path(), searchPath):
		p.Section = "files"
	case !strings.HasPrefix(c.Path(), "/."):
		p.Section = "files"
	}
	return p
}

func (s *Server) render(c fiber.Ctx, status int, name string, data any) error {
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Status(status).Send(buf.Bytes())
}

type listing struct {
	page
	Path     string
	Action   string // where this folder's forms post to
	Home     string // where the first crumb leads
	Crumbs   []crumb
	Parent   string
	Items    []listItem
	Upload   *uploadForm
	Mkdir    bool
	Sort     string
	Desc     bool
	Summary  string
	Uploaded int
	Created  *listItem
	Renamed  *listItem
	Restored *listItem
	Deleted  int  // entries just deleted
	Trashed  bool // they went to the trash
	Undo     *undo
	Moved    *moved // entries just moved or copied elsewhere
	// TrashKeep says how long deleted entries stay in the trash; "" if
	// they are deleted at once.
	TrashKeep string
	// Copy is set when the visitor may add files somewhere, so copying
	// entries elsewhere is of use.
	Copy      bool
	DeleteAny bool      // some entry may be deleted
	Manage    bool      // some entry may be renamed, moved, copied, deleted or shared
	Selected  *listItem // its forms are shown
	// ShareHere is set when the visitor may share this folder.
	ShareHere bool
}

// undo restores the one entry a deletion moved to the trash.
type undo struct{ ID, Name string }

// moved confirms that N entries were moved or copied to a folder.
type moved struct {
	Verb       string // Moved or Copied
	N          int
	Name, Href string // the folder
}

// itemForms is what the rename, share and delete forms of an entry show.
type itemForms struct {
	Action                         string
	Folder                         string // URL path of the folder, ending in "/"
	Name, Path                     string
	IsDir                          bool
	CanRename, CanDelete, CanShare bool
	CanCopy                        bool
	TrashKeep                      string
}

// Forms describes the forms for it; nil gives the blank ones the page's
// script fills in.
func (l listing) Forms(it *listItem) itemForms {
	f := itemForms{Action: l.Action, Folder: object(l.Path, true), CanCopy: l.Copy, TrashKeep: l.TrashKeep}
	if it != nil {
		f.Name, f.Path, f.IsDir = it.Name, it.Path, it.IsDir
		f.CanRename, f.CanDelete, f.CanShare = it.CanRename, it.CanDelete, it.CanShare
	}
	return f
}

type crumb struct {
	Name, Href string
	Current    bool
}

type uploadForm struct {
	Action  string
	Replace bool
}

type listItem struct {
	Name    string
	Path    string // URL path
	Key     string // lower-case name, for sorting and filtering
	Href    string
	Kind    string // icon: folder, image, video, ...
	Size    string
	ModTime string
	ModISO  string
	IsDir   bool
	Preview string // how ?view shows it: image, video, audio or pdf; "" if not
	Thumb   bool   // a thumbnail of it may be shown
	New     bool   // just created or renamed
	// CanDelete, CanRename and CanShare tell the visitor's rights on the
	// entry.
	CanDelete, CanRename, CanShare bool
	Selected                       bool // its forms are shown
	size                           int64
	mod                            time.Time
	real                           string // URL path where it really lives (see resolve)
}

// ActionsLabel names what the visitor may do with the entry, for the
// button of its menu: e.g. "Rename, share or delete a.txt". copy says
// whether they may copy it elsewhere.
func (it listItem) ActionsLabel(copy bool) string {
	var acts []string
	for _, a := range []struct {
		ok   bool
		name string
	}{{it.CanRename, "rename"}, {it.CanDelete && copy, "move"}, {copy, "copy"}, {it.CanShare, "share"}, {it.CanDelete, "delete"}} {
		if a.ok {
			acts = append(acts, a.name)
		}
	}
	if len(acts) == 0 {
		return "Actions for " + it.Name
	}
	label := acts[len(acts)-1]
	if n := len(acts); n > 1 {
		label = strings.Join(acts[:n-1], ", ") + " or " + label
	}
	return strings.ToUpper(label[:1]) + label[1:] + " " + it.Name
}

// Folder is the listing's folder as a path to type, ending in "/".
func (l listing) Folder() string { return object(l.Path, true) }

// PickHint says what entries can be ticked for, e.g. "download, copy or
// delete".
func (l listing) PickHint() string {
	acts := []string{"download"}
	if l.Copy && l.DeleteAny {
		acts = append(acts, "move")
	}
	if l.Copy {
		acts = append(acts, "copy")
	}
	if l.DeleteAny {
		acts = append(acts, "delete")
	}
	if n := len(acts); n > 1 {
		return strings.Join(acts[:n-1], ", ") + " or " + acts[n-1]
	}
	return acts[0]
}

// SortHref links a column header: a second click reverses the order.
func (l listing) SortHref(col string) string {
	if l.Sort == col && !l.Desc {
		return "?sort=" + col + "&order=desc"
	}
	return "?sort=" + col
}

// SortState is a column's aria-sort value.
func (l listing) SortState(col string) string {
	switch {
	case l.Sort != col:
		return "none"
	case l.Desc:
		return "descending"
	default:
		return "ascending"
	}
}

func (s *Server) serveDir(c fiber.Ctx, dir *os.File, urlPath, realPath string, wantDir bool) error {
	if !wantDir && urlPath != "/" {
		// Not cached: whether the folder may be seen depends on the visitor.
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.Redirect().Status(fiber.StatusMovedPermanently).To(escapePath(urlPath + "/"))
	}
	if c.Request().URI().QueryArgs().Has("zip") {
		return s.serveZip(c, urlPath, realPath, zipName(urlPath), s.visitorRules(c))
	}

	items, err := s.folderItems(dir, urlPath, realPath, s.visitorRules(c))
	if err != nil {
		return err
	}
	data := listing{page: s.page(c, "All files"), Path: urlPath, Action: escapePath(object(urlPath, true)),
		Home: "/", Crumbs: crumbs("", urlPath), Items: items, Summary: summaryOf(items)}
	create, replace, err := s.uploadRightsAt(c, object(urlPath, true), object(realPath, true))
	if err != nil {
		return err
	}
	for i := range data.Items {
		item := &data.Items[i]
		if item.CanDelete, err = s.mayAt(c, auth.ActDelete, item.Path, path.Join(realPath, item.Name), item.IsDir); err != nil {
			return err
		}
		// Renaming creates an entry, so it needs the right to create here.
		item.CanRename = item.CanDelete && create
		// Links let others read it, so where it really lives counts too.
		if item.CanShare, err = s.mayAt(c, auth.ActShare, item.Path, item.real, item.IsDir); err != nil {
			return err
		}
		data.Manage = data.Manage || item.CanDelete || item.CanShare
		data.DeleteAny = data.DeleteAny || item.CanDelete
	}
	data.Copy = len(data.Items) > 0 && s.auth.MayWrite(visitorName(c))
	data.Manage = data.Manage || data.Copy
	if data.ShareHere, err = s.mayAt(c, auth.ActShare, urlPath, realPath, true); err != nil {
		return err
	}
	data.Sort, data.Desc = sortOrder(c)
	sortItems(data.Items, data.Sort, data.Desc)

	if urlPath != "/" {
		data.Title = path.Base(urlPath)
		data.Parent = escapePath(object(path.Dir(urlPath), true))
	}
	if n, err := strconv.Atoi(c.Query("uploaded")); err == nil && n > 0 {
		data.Uploaded = n
	}
	// Only entries that are listed are confirmed, so links cannot be used to
	// show made-up text.
	created, renamed, restored, selected := c.Query("created"), c.Query("renamed"), c.Query("restored"), c.Query("item")
	for i := range data.Items {
		switch it := &data.Items[i]; it.Name {
		case created:
			if it.IsDir {
				it.New, data.Created = true, it
			}
		case renamed:
			it.New, data.Renamed = true, it
		case restored:
			it.New, data.Restored = true, it
		case selected:
			if it.CanDelete || it.CanShare || data.Copy {
				it.Selected, data.Selected = true, it
			}
		}
	}
	if s.cfg.Trash.Keep > 0 {
		data.TrashKeep = keepText(s.cfg.Trash.Keep)
	}
	if err := s.deletedBanner(c, &data); err != nil {
		return err
	}
	data.Moved = s.movedBanner(c)
	if create || replace {
		data.Upload = &uploadForm{Action: data.Action, Replace: replace}
	}
	data.Mkdir = create
	return s.render(c, fiber.StatusOK, "listing", data)
}

// deletedBanner confirms a deletion (see deletedQuery). Undo is offered if
// the visitor may restore what went to the trash.
func (s *Server) deletedBanner(c fiber.Ctx, data *listing) error {
	n, err := strconv.Atoi(c.Query("deleted"))
	if err != nil || n <= 0 {
		return nil
	}
	data.Deleted, data.Trashed = n, c.Query("trashed") == "1"
	id := c.Query("undo")
	if id == "" || n != 1 {
		return nil
	}
	data.Trashed = true
	trash, box, note, _, err := s.trashEntry(id)
	if errors.Is(err, fiber.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_ = box.Close()
	_ = trash.Close()
	if ok, _, err := mayRestore(s.visitorRules(c), note); err != nil || !ok {
		return err
	}
	data.Undo = &undo{ID: id, Name: path.Base(note.Path)}
	return nil
}

// movedBanner confirms entries moved or copied to another folder (see
// relocate), if the visitor may open that folder: links cannot make it
// name folders that are not there.
func (s *Server) movedBanner(c fiber.Ctx) *moved {
	m := &moved{Verb: "Moved"}
	n, err := strconv.Atoi(c.Query("moved"))
	if err != nil {
		m.Verb = "Copied"
		n, err = strconv.Atoi(c.Query("copied"))
	}
	dest, ok := formPath(c.Query("to"))
	if err != nil || n <= 0 || !ok || hidden(dest) {
		return nil
	}
	f, info, _, err := s.lookup(dest, s.visitorRules(c))
	if err != nil {
		return nil
	}
	_ = f.Close()
	if !info.IsDir() {
		return nil
	}
	m.N, m.Name, m.Href = n, dest, escapePath(object(dest, true))
	return m
}

// folderItems lists the entries of the folder dir at urlPath, which really
// lives at realPath, that allow lets the reader open. Entries being
// uploaded are left out.
func (s *Server) folderItems(dir *os.File, urlPath, realPath string, allow allowFunc) ([]listItem, error) {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	// Entries with a live lock file are still being uploaded.
	locked := make(map[string]bool)
	for _, e := range entries {
		if target, ok := lockTarget(e.Name()); ok && s.locked(rootName(urlPath), target) {
			locked[target] = true
		}
	}
	items := make([]listItem, 0, len(entries))
	for _, e := range entries {
		if locked[e.Name()] {
			continue
		}
		item, ok := s.listItem(urlPath, realPath, e)
		if !ok {
			continue
		}
		// Only what the reader may open is listed.
		if ok, err := mayBoth(allow, auth.ActRead, item.Path, item.real, item.IsDir); err != nil {
			return nil, err
		} else if !ok {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

// sortOrder is the order a listing was asked for: a column and whether it
// is reversed.
func sortOrder(c fiber.Ctx) (string, bool) {
	col := c.Query("sort")
	switch col {
	case "size", "modified":
	default:
		col = "name"
	}
	return col, c.Query("order") == "desc"
}

// sortItems puts directories first, then orders by col, then by name.
func sortItems(items []listItem, col string, desc bool) {
	slices.SortFunc(items, func(a, b listItem) int {
		if a.IsDir != b.IsDir {
			if a.IsDir {
				return -1
			}
			return 1
		}
		n := 0
		switch col {
		case "size":
			n = cmp.Compare(a.size, b.size)
		case "modified":
			n = a.mod.Compare(b.mod)
		}
		if n == 0 {
			n = cmp.Or(strings.Compare(a.Key, b.Key), strings.Compare(a.Name, b.Name))
		}
		if desc {
			return -n
		}
		return n
	})
}

// summaryOf describes a listing of items, e.g. "3 folders · 10 files ·
// 56.9 MiB".
func summaryOf(items []listItem) string {
	var (
		dirs, files int
		total       int64
	)
	for _, it := range items {
		if it.IsDir {
			dirs++
		} else {
			files++
			total += it.size
		}
	}
	return summary(dirs, files, total)
}

func summary(dirs, files int, total int64) string {
	var parts []string
	if dirs > 0 {
		parts = append(parts, plural(dirs, "folder"))
	}
	if files > 0 {
		parts = append(parts, plural(files, "file"), formatSize(total))
	}
	if len(parts) == 0 {
		return "Empty folder"
	}
	return strings.Join(parts, " · ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// crumbs links every directory on the way to urlPath, below base.
func crumbs(base, urlPath string) []crumb {
	var out []crumb
	p := base
	for _, name := range strings.Split(strings.Trim(urlPath, "/"), "/") {
		if name == "" {
			continue
		}
		p += "/" + name
		out = append(out, crumb{Name: name, Href: escapePath(p + "/")})
	}
	if len(out) > 0 {
		out[len(out)-1].Current = true
	}
	return out
}

// listItem describes the entry e of the directory at dirPath, which really
// lives at realDir. It hides dotfiles, non-regular files and symlinks that
// do not resolve inside the root, or lead to entries that may not be shown.
func (s *Server) listItem(dirPath, realDir string, e fs.DirEntry) (listItem, bool) {
	name := e.Name()
	if hidden(name) {
		return listItem{}, false
	}
	var (
		info fs.FileInfo
		err  error
		real = path.Join(realDir, name)
	)
	if e.Type()&fs.ModeSymlink != 0 {
		target := rootName(path.Join(dirPath, name))
		var ok bool
		if real, ok = s.resolve(target, nil); !ok {
			return listItem{}, false
		}
		info, err = s.root.Stat(target)
	} else {
		info, err = e.Info()
	}
	if err != nil {
		return listItem{}, false
	}

	mod := info.ModTime().UTC()
	item := listItem{
		Name:    name,
		Path:    path.Join(dirPath, name),
		Key:     strings.ToLower(name),
		Href:    escapePath(path.Join(dirPath, name)),
		ModTime: mod.Format("Jan 2, 2006 15:04") + " UTC",
		ModISO:  mod.Format(time.RFC3339),
		mod:     mod,
		real:    real,
	}
	switch {
	case info.IsDir():
		item.IsDir = true
		item.Href += "/"
		item.Kind = "folder"
		item.Size = "—"
	case info.Mode().IsRegular():
		item.Kind = kindOf(name)
		item.size = info.Size()
		item.Size = formatSize(item.size)
		item.Preview = previewKind(name)
		item.Thumb = thumbExts[strings.ToLower(path.Ext(name))]
	default:
		return listItem{}, false
	}
	return item, true
}

var fileKinds = func() map[string]string {
	m := make(map[string]string)
	for kind, exts := range map[string]string{
		"image":   "jpg jpeg png gif webp svg bmp tif tiff heic heif avif ico",
		"video":   "mp4 m4v mkv mov avi webm wmv flv mpg mpeg",
		"audio":   "mp3 flac wav ogg oga opus m4a aac wma",
		"archive": "zip rar 7z tar gz tgz bz2 xz zst iso dmg deb rpm apk",
		"doc":     "pdf doc docx odt rtf epub",
		"sheet":   "xls xlsx ods csv tsv",
		"slides":  "ppt pptx odp key",
		"code":    "go js ts py rb rs c h cpp hpp java kt swift sh php html css json yaml yml toml xml sql",
		"text":    "txt md log ini conf cfg",
	} {
		for _, ext := range strings.Fields(exts) {
			m["."+ext] = kind
		}
	}
	return m
}()

// kindOf picks the icon for a file name.
func kindOf(name string) string {
	return cmp.Or(fileKinds[strings.ToLower(path.Ext(name))], "file")
}

// escapePath percent-encodes a URL path so names containing '#', '?', '%'
// and the like produce working links.
func escapePath(p string) string {
	return (&url.URL{Path: p}).EscapedPath()
}

func formatSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
