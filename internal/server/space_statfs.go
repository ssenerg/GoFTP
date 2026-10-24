//go:build linux || darwin || freebsd

package server

import (
	"os"

	"golang.org/x/sys/unix"
)

// freeSpace returns the bytes that unprivileged writers can still add to
// the file system of the folder dir.
func freeSpace(dir *os.Root) (int64, bool) {
	f, err := dir.Open(".")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
