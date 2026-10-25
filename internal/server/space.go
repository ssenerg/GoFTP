package server

import (
	"fmt"
	"os"
	"syscall"
)

// errLowSpace stops writing short of the disk's last upload.min_free bytes,
// which are kept for the database and everything else on it, and of its
// last inodes (see inodeReserve). Like a full disk, it answers 507.
var errLowSpace = fmt.Errorf("the disk is down to its last upload.min_free bytes or inodes: %w", syscall.ENOSPC)

// spaceCheckEvery is how much is written between looks at the free space.
const spaceCheckEvery = 8 << 20

// With upload.min_free, the last 1/inodeReserve of a disk's inodes are
// kept too, where it counts them: each file and folder takes one, and
// empty ones take no bytes.
const inodeReserve = 100

// roomFor reports whether n more bytes, and a file or folder, fit in the
// folder dir above upload.min_free; true where the free space cannot be
// known.
func (s *Server) roomFor(dir *os.Root, n int64) bool {
	min := int64(s.cfg.Upload.MinFree)
	if min <= 0 {
		return true
	}
	free, fewInodes, ok := diskSpace(dir)
	return !ok || free-n >= min && !fewInodes
}

// spaceGuard returns what checks, for writes into the folder dir, that the
// disk is not down to upload.min_free; nil if nothing does.
func (s *Server) spaceGuard(dir *os.Root) *spaceWriter {
	if s.cfg.Upload.MinFree <= 0 {
		return nil
	}
	return &spaceWriter{s: s, dir: dir, unchecked: spaceCheckEvery}
}

type spaceWriter struct {
	s         *Server
	dir       *os.Root
	unchecked int64 // written since the last look
}

// check fails with errLowSpace if writing n more bytes would take the disk
// below upload.min_free. It looks every spaceCheckEvery bytes.
func (g *spaceWriter) check(n int) error {
	if g.unchecked >= spaceCheckEvery {
		if !g.s.roomFor(g.dir, int64(n)) {
			return errLowSpace
		}
		g.unchecked = 0
	}
	g.unchecked += int64(n)
	return nil
}
