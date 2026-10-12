//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package file

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openAllowedFile(path string, roots []string) (*os.File, error) {
	root, relative, ok := containingRoot(path, roots)
	if !ok || relative == "." {
		return nil, os.ErrPermission
	}
	directory, err := openDirectoryNoFollow(root)
	if err != nil {
		return nil, err
	}
	current := directory
	defer func() { _ = unix.Close(current) }()
	parts := strings.Split(relative, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, os.ErrPermission
			}
			return nil, openErr
		}
		_ = unix.Close(current)
		current = next
	}
	fd, err := unix.Openat(current, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, os.ErrPermission
		}
		return nil, err
	}
	handle := os.NewFile(uintptr(fd), filepath.Base(path))
	if handle == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open secret file")
	}
	return handle, nil
}

func openDirectoryNoFollow(path string) (int, error) {
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.SplitSeq(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	for part := range parts {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			_ = unix.Close(current)
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return -1, os.ErrPermission
			}
			return -1, openErr
		}
		_ = unix.Close(current)
		current = next
	}
	return current, nil
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
