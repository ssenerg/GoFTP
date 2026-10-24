//go:build !(linux || darwin || freebsd)

package server

import "os"

func freeSpace(*os.Root) (int64, bool) { return 0, false }
