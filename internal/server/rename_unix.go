//go:build unix && !linux && !darwin

package server

// renameExcl renames, failing with EEXIST if newName exists, as checked
// just before.
func renameExcl(fromFd int, name string, toFd int, newName string) error {
	return renameChecked(fromFd, name, toFd, newName)
}
