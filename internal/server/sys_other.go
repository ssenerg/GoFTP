//go:build !unix

package server

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func openFileLimit() (uint64, bool) { return 0, false }

func sameDevice(a, b fs.FileInfo) bool { return true }

func fileID(fs.FileInfo) ([2]uint64, bool) { return [2]uint64{}, false }

// renameBetween renames the entry name of the folder from to newName in the
// folder to. Here, the folders are found by name again.
func renameBetween(from *os.Root, name string, to *os.Root, newName string) error {
	return os.Rename(filepath.Join(from.Name(), name), filepath.Join(to.Name(), newName))
}

// linkBetween hard-links the file name of the folder from as newName in the
// folder to; it fails if newName exists.
func linkBetween(from *os.Root, name string, to *os.Root, newName string) error {
	return os.Link(filepath.Join(from.Name(), name), filepath.Join(to.Name(), newName))
}

// renameExclBetween is renameBetween, unless newName exists (errExists), as
// checked just before.
func renameExclBetween(from *os.Root, name string, to *os.Root, newName string) error {
	if _, err := to.Lstat(newName); err == nil {
		return errExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return renameBetween(from, name, to, newName)
}
