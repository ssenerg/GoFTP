package server

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fdPath returns the current path of an open file as the kernel sees it:
// spelled as it is stored, also where the file system ignores case or
// Unicode normalization in names, which rules do not.
func fdPath(f *os.File) (string, bool) {
	conn, err := f.SyscallConn()
	if err != nil {
		return "", false
	}
	buf := make([]byte, unix.PathMax)
	var errno syscall.Errno
	if err := conn.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0])))
	}); err != nil || errno != 0 {
		return "", false
	}
	n := bytes.IndexByte(buf, 0)
	if n <= 0 {
		return "", false
	}
	return string(buf[:n]), true
}

// pathByOpening is whether resolve opens an entry to learn its path: here
// a name may be spelled otherwise than it is stored.
const pathByOpening = true
