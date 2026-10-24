package server

import "golang.org/x/sys/unix"

// renameExcl renames, failing with EEXIST if newName exists; on file
// systems that cannot tell, it checks just before.
func renameExcl(fromFd int, name string, toFd int, newName string) error {
	err := unix.Renameat2(fromFd, name, toFd, newName, unix.RENAME_NOREPLACE)
	if err == unix.EINVAL || err == unix.ENOSYS {
		return renameChecked(fromFd, name, toFd, newName)
	}
	return err
}
