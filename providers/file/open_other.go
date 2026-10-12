//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package file

import (
	"os"
	"path/filepath"
	"strings"
)

func openAllowedFile(path string, roots []string) (*os.File, error) {
	if _, _, ok := containingRoot(path, roots); !ok {
		return nil, os.ErrPermission
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrPermission
	}
	return os.Open(path) // #nosec G304 -- the path is constrained by host-owned roots.
}

func containingRoot(path string, roots []string) (string, string, bool) {
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return root, relative, true
		}
	}
	return "", "", false
}
