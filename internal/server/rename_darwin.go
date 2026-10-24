package server

import "golang.org/x/sys/unix"

// renameExcl renames, failing with EEXIST if newName exists; on file
// systems that cannot tell, it checks just before.
func renameExcl(fromFd int, name string, toFd int, newName string) error {
	err := unix.RenameatxNp(fromFd, name, toFd, newName, unix.RENAME_EXCL)
	if err == unix.EINVAL || err == unix.ENOTSUP {
		return renameChecked(fromFd, name, toFd, newName)
	}
	return err
}
