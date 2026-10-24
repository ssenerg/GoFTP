package server

import (
	"os"
	"strconv"
)

// fdPath returns the current path of an open file as the kernel sees it.
func fdPath(f *os.File) (string, bool) {
	conn, err := f.SyscallConn()
	if err != nil {
		return "", false
	}
	var (
		p    string
		rerr error
	)
	if err := conn.Control(func(fd uintptr) {
		p, rerr = os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10))
	}); err != nil || rerr != nil {
		return "", false
	}
	return p, true
}

// pathByOpening is whether resolve opens an entry to learn its path.
const pathByOpening = false
