package server

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// errLowSpace stops writing short of the disk's last upload.min_free bytes,
// which are kept for the database and everything else on it. Like a full
// disk, it answers 507.
var errLowSpace = fmt.Errorf("less than upload.min_free left on the disk: %w", syscall.ENOSPC)

// spaceCheckEvery is how much is written between looks at the free space.
const spaceCheckEvery = 8 << 20

// roomFor reports whether n more bytes fit in the folder dir above
// upload.min_free; true where the free space cannot be known.
func (s *Server) roomFor(dir *os.Root, n int64) bool {
	min := int64(s.cfg.Upload.MinFree)
	if min <= 0 {
		return true
	}
	free, ok := freeSpace(dir)
	return !ok || free-n >= min
}

// spaceGuard wraps w, which writes into the folder dir, to fail with
// errLowSpace once the disk is down to upload.min_free.
func (s *Server) spaceGuard(dir *os.Root, w io.Writer) io.Writer {
	if s.cfg.Upload.MinFree <= 0 {
		return w
	}
	return &spaceWriter{s: s, dir: dir, w: w, unchecked: spaceCheckEvery}
}

type spaceWriter struct {
	s         *Server
	dir       *os.Root
	w         io.Writer
	unchecked int64 // written since the last look
}

func (g *spaceWriter) Write(p []byte) (int, error) {
	if g.unchecked >= spaceCheckEvery {
		if !g.s.roomFor(g.dir, int64(len(p))) {
			return 0, errLowSpace
		}
		g.unchecked = 0
	}
	g.unchecked += int64(len(p))
	return g.w.Write(p)
}
