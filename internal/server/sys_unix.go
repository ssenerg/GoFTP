//go:build unix

package server

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openFileLimit returns the process's limit on open file descriptors, which
// Go raises to the hard limit at startup. "Unlimited" comes out huge.
func openFileLimit() (uint64, bool) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	return uint64(lim.Cur), true
}

// sameDevice reports whether two entries live on the same file system.
func sameDevice(a, b fs.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	return !okA || !okB || sa.Dev == sb.Dev
}

// renameBetween renames the entry name of the folder from to newName in the
// folder to. Both stay pinned by their open roots, so symlink swaps on the
// way to them cannot redirect the rename.
func renameBetween(from *os.Root, name string, to *os.Root, newName string) error {
	return betweenDirs(from, to, "renameat", name, newName, func(fromFd, toFd int) error {
		return unix.Renameat(fromFd, name, toFd, newName)
	})
}

// renameExclBetween is renameBetween, unless newName exists (errExists).
func renameExclBetween(from *os.Root, name string, to *os.Root, newName string) error {
	err := betweenDirs(from, to, "renameat", name, newName, func(fromFd, toFd int) error {
		return renameExcl(fromFd, name, toFd, newName)
	})
	if errors.Is(err, unix.EEXIST) {
		return errExists
	}
	return err
}

// renameChecked renames unless newName exists (EEXIST), as checked just
// before: for systems that cannot tell atomically.
func renameChecked(fromFd int, name string, toFd int, newName string) error {
	var st unix.Stat_t
	switch err := unix.Fstatat(toFd, newName, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		return unix.EEXIST
	case err != unix.ENOENT:
		return err
	}
	return unix.Renameat(fromFd, name, toFd, newName)
}

// linkBetween hard-links the file name of the folder from as newName in the
// folder to, like renameBetween; it fails if newName exists.
func linkBetween(from *os.Root, name string, to *os.Root, newName string) error {
	return betweenDirs(from, to, "linkat", name, newName, func(fromFd, toFd int) error {
		return unix.Linkat(fromFd, name, toFd, newName, 0)
	})
}

func betweenDirs(from, to *os.Root, op, name, newName string, do func(fromFd, toFd int) error) error {
	a, err := from.Open(".")
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := to.Open(".")
	if err != nil {
		return err
	}
	defer b.Close()
	ac, err := a.SyscallConn()
	if err != nil {
		return err
	}
	bc, err := b.SyscallConn()
	if err != nil {
		return err
	}
	var opErr, innerErr error
	err = ac.Control(func(fa uintptr) {
		innerErr = bc.Control(func(fb uintptr) { opErr = do(int(fa), int(fb)) })
	})
	if err == nil {
		err = innerErr
	}
	if err != nil {
		return err
	}
	if opErr != nil {
		return &os.LinkError{Op: op, Old: name, New: newName, Err: opErr}
	}
	return nil
}
