//go:build linux || darwin || freebsd

package server

import (
	"os"

	"golang.org/x/sys/unix"
)

// freeSpace returns the bytes that unprivileged writers can still add to
// the file system of the folder dir.
func freeSpace(dir *os.Root) (int64, bool) {
	free, _, ok := diskSpace(dir)
	return free, ok
}

// diskSpace returns freeSpace, and whether the file system's inodes, if it
// counts them, are down to their last 1/inodeReserve.
func diskSpace(dir *os.Root) (free int64, fewInodes, ok bool) {
	f, err := dir.Open(".")
	if err != nil {
		return 0, false, false
	}
	defer f.Close()
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, false, false
	}
	files, left := int64(st.Files), int64(st.Ffree)
	return int64(st.Bavail) * int64(st.Bsize), files > 0 && left < files/inodeReserve, true
}
