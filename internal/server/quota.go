package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"goftp/internal/auth"
)

// A home may hold up to a quota, homes.quota or what is set for its user
// (auth.User.HomeQuota), along with what its user deleted from it that
// waits in the trash: deleting makes room only once the trash is emptied.
// What a home holds is counted by walking it, at most once every usageAge
// unless something left it meanwhile; what is written in between is added
// as it arrives.
const usageAge = time.Minute

// errQuota stops a write that would take a home past its quota. Like a full
// disk, it answers 507.
var errQuota = fmt.Errorf("over the home's quota: %w", syscall.ENOSPC)

// homeUse is what one home holds.
type homeUse struct {
	mu      sync.Mutex
	quota   int64 // 0 for no limit
	used    int64 // in the home and in the trash, as counted, plus what was written since
	trashed int64 // of used, in the trash
	counted time.Time
}

// homeUse returns what the home name holds, counted again if that is due.
// Its lock is held; the caller unlocks it.
func (s *Server) homeUse(name string) (*homeUse, error) {
	v, _ := s.uses.LoadOrStore(name, &homeUse{})
	u := v.(*homeUse)
	u.mu.Lock()
	if time.Since(u.counted) < usageAge {
		return u, nil
	}
	if err := s.countHome(name, u); err != nil {
		u.mu.Unlock()
		return nil, err
	}
	return u, nil
}

// countHome counts what the home name holds into u, and reads its quota.
func (s *Server) countHome(name string, u *homeUse) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	user, err := s.auth.UserNamed(ctx, name)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		user = nil
	case err != nil:
		return err
	}
	u.quota, u.used, u.trashed = int64(s.cfg.Homes.Quota), 0, 0
	if user != nil && user.HomeQuota != nil {
		u.quota = *user.HomeQuota
	}
	if dir, err := s.root.OpenRoot(rootName(path.Join(s.cfg.Homes.Path, name))); err == nil {
		u.used = treeBytes(dir)
		_ = dir.Close()
	}
	if user != nil {
		u.trashed = s.trashedBytes(name, user.ID)
		u.used += u.trashed
	}
	u.counted = time.Now()
	return nil
}

// treeBytes adds up the files in the folder dir and the folders in it,
// hidden ones too, such as unfinished uploads: they take space as well, but
// for goftp's notes (whose a home is, what a trash entry is) and locks. A
// file with more names counts once.
func treeBytes(dir *os.Root) int64 {
	var n int64
	seen := map[[2]uint64]bool{}
	_ = fs.WalkDir(dir.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || p == homeOwner || p == trashInfo {
			return nil
		}
		if _, lock := lockTarget(d.Name()); lock {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if id, ok := fileID(info); ok {
			if seen[id] {
				return nil
			}
			seen[id] = true
		}
		n += info.Size()
		return nil
	})
	return n
}

// trashedBytes adds up what the user id deleted from their home, name,
// that is in the trash.
func (s *Server) trashedBytes(name string, id int64) int64 {
	trash, err := s.openTrash(false)
	if err != nil {
		return 0
	}
	defer trash.Close()
	d, err := trash.Open(".")
	if err != nil {
		return 0
	}
	entries, _ := d.ReadDir(-1)
	_ = d.Close()
	var n int64
	for _, e := range entries {
		if !e.IsDir() || !validTrashID(e.Name()) {
			continue
		}
		box, err := trash.OpenRoot(e.Name())
		if err != nil {
			continue
		}
		if note, err := readNote(box); err == nil && !note.Home && note.Owner == id {
			if home, ok := s.homeName(note.Path); ok && home == name {
				n += treeBytes(box)
			}
		}
		_ = box.Close()
	}
	return n
}

// homeUsage reports what the home name holds, how much of it is in the
// trash, and its quota (0 for none).
func (s *Server) homeUsage(name string) (used, trashed, quota int64, err error) {
	u, err := s.homeUse(name)
	if err != nil {
		return 0, 0, 0, err
	}
	defer u.mu.Unlock()
	return u.used, u.trashed, u.quota, nil
}

// homeRoom checks that n more bytes fit in the home name, if it is one.
func (s *Server) homeRoom(name string, n int64) error {
	if name == "" || s.cfg.Homes.Path == "" {
		return nil
	}
	u, err := s.homeUse(name)
	if err != nil {
		return err
	}
	defer u.mu.Unlock()
	if u.quota > 0 && u.used+n > u.quota {
		return errQuota
	}
	return nil
}

// homeAt returns the name of the home that the folder dir is in, if any.
func (s *Server) homeAt(dir *os.Root) string {
	if s.cfg.Homes.Path == "" {
		return ""
	}
	p, ok := s.dirPath(dir)
	if !ok {
		return ""
	}
	name, _ := s.homeName(p)
	return name
}

// dirPath returns the URL path where the folder dir really lives.
func (s *Server) dirPath(dir *os.Root) (string, bool) {
	f, err := dir.Open(".")
	if err != nil {
		return "", false
	}
	defer f.Close()
	p, ok := fdPath(f)
	if !ok {
		if p, err = filepath.EvalSymlinks(dir.Name()); err != nil {
			return "", false
		}
	}
	rel, err := filepath.Rel(s.rootPath, p)
	if err != nil || rel == ".." || len(rel) > 2 && rel[:3] == ".."+string(filepath.Separator) {
		return "", false
	}
	return path.Clean("/" + filepath.ToSlash(rel)), true
}

// writeGuard wraps w, which writes into the folder dir, to stop short of
// the disk's last upload.min_free bytes (see spaceGuard) and of the quota
// of the home dir is in, if any, where what is written replaces credit
// bytes. With w nil, setWriter gives it its writer later: the home's usage
// is read before the file is made.
func (s *Server) writeGuard(dir *os.Root, w io.Writer, credit int64) (io.Writer, error) {
	g := &guardWriter{w: w, space: s.spaceGuard(dir), credit: credit}
	if name := s.homeAt(dir); name != "" {
		u, err := s.homeUse(name)
		if err != nil {
			return nil, err
		}
		if u.quota > 0 {
			g.use = u
		}
		u.mu.Unlock()
	}
	return g, nil
}

// setWriter gives the writer of writeGuard where to write.
func setWriter(g io.Writer, w io.Writer) { g.(*guardWriter).w = w }

type guardWriter struct {
	w      io.Writer
	space  *spaceWriter // nil without a floor of free space
	use    *homeUse     // the home's usage, nil without a quota
	credit int64        // bytes of the file it replaces, freed once it is in place
}

func (g *guardWriter) Write(p []byte) (int, error) {
	if g.space != nil {
		if err := g.space.check(len(p)); err != nil {
			return 0, err
		}
	}
	if u := g.use; u != nil {
		u.mu.Lock()
		if u.quota > 0 && u.used+int64(len(p))-g.credit > u.quota {
			u.mu.Unlock()
			return 0, errQuota
		}
		u.used += int64(len(p))
		u.mu.Unlock()
	}
	return g.w.Write(p)
}

// homeChanged has what the home that urlPath is in, or is, holds counted
// again before its next write: something left it, or may have.
func (s *Server) homeChanged(urlPath string) {
	if name, ok := s.homeName(urlPath); ok {
		s.recount(name)
	}
}

// recount has what the home name, if not "", holds counted again before
// its next write.
func (s *Server) recount(name string) {
	if v, ok := s.uses.Load(name); ok && name != "" {
		u := v.(*homeUse)
		u.mu.Lock()
		u.counted = time.Time{}
		u.mu.Unlock()
	}
}

// recountAll has what every home holds counted again before its next write.
func (s *Server) recountAll() {
	s.uses.Range(func(k, _ any) bool {
		s.recount(k.(string))
		return true
	})
}
