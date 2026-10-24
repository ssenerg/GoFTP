//go:build !linux && !darwin

package server

import "os"

// fdPath is unsupported here; callers fall back to resolving the name.
func fdPath(*os.File) (string, bool) { return "", false }

// pathByOpening is whether resolve opens an entry to learn its path.
const pathByOpening = false
