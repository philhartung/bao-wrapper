//go:build linux

package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	secretFileMode = 0600
	oPath          = 0x200000 // Linux O_PATH ABI value.
)

// writeSecretFile writes data to an exclusively-created temporary file and
// atomically installs it at path. All path traversal and mutation uses a
// directory descriptor, so concurrently replacing a path component with a
// symlink cannot redirect the write.
func writeSecretFile(path, data string) error {
	dirFD, name, err := openSecretParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(dirFD) }()

	targetFD, err := syscall.Openat(dirFD, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		var stat syscall.Stat_t
		statErr := syscall.Fstat(targetFD, &stat)
		_ = syscall.Close(targetFD)
		if statErr != nil {
			return fmt.Errorf("inspect outfile %q: %w", path, statErr)
		}
		if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return fmt.Errorf("outfile %q is not a regular file", path)
		}
	}
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("inspect outfile %q: %w", path, err)
	}

	tmpName, file, err := createSecretTemp(dirFD)
	if err != nil {
		return fmt.Errorf("create temporary outfile for %q: %w", path, err)
	}
	installed := false
	defer func() {
		_ = file.Close()
		if !installed {
			_ = syscall.Unlinkat(dirFD, tmpName)
		}
	}()

	// Enforce the mode on the descriptor as well as at creation time. This is
	// independent of the process umask and remains tied to the opened inode.
	if err := file.Chmod(secretFileMode); err != nil {
		return fmt.Errorf("chmod temporary outfile: %w", err)
	}
	if _, err := file.WriteString(data); err != nil {
		return fmt.Errorf("write temporary outfile: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary outfile: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary outfile: %w", err)
	}
	if err := syscall.Renameat(dirFD, tmpName, dirFD, name); err != nil {
		return fmt.Errorf("install outfile %q: %w", path, err)
	}
	installed = true
	if err := syscall.Fsync(dirFD); err != nil {
		return fmt.Errorf("sync outfile directory for %q: %w", path, err)
	}
	return nil
}

func openSecretParent(path string) (int, string, error) {
	clean, err := filepath.Abs(path)
	if err != nil {
		return -1, "", fmt.Errorf("resolve outfile path %q: %w", path, err)
	}
	name := filepath.Base(clean)
	if name == "." || name == string(filepath.Separator) {
		return -1, "", fmt.Errorf("invalid outfile path %q", path)
	}

	dir := strings.TrimPrefix(filepath.Dir(clean), string(filepath.Separator))

	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	dirFD, err := syscall.Open(string(filepath.Separator), flags, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open outfile root: %w", err)
	}

	for _, component := range strings.Split(dir, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		nextFD, openErr := syscall.Openat(dirFD, component, flags, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			if mkdirErr := syscall.Mkdirat(dirFD, component, 0750); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				_ = syscall.Close(dirFD)
				return -1, "", fmt.Errorf("create outfile directory %q: %w", component, mkdirErr)
			}
			nextFD, openErr = syscall.Openat(dirFD, component, flags, 0)
		}
		if openErr != nil {
			_ = syscall.Close(dirFD)
			return -1, "", fmt.Errorf("open outfile directory %q without following symlinks: %w", component, openErr)
		}
		_ = syscall.Close(dirFD)
		dirFD = nextFD
	}
	return dirFD, name, nil
}

func createSecretTemp(dirFD int) (string, *os.File, error) {
	for range 100 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := ".bao-wrapper-" + hex.EncodeToString(random[:]) + ".tmp"
		fd, err := syscall.Openat(dirFD, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, secretFileMode)
		if err == nil {
			return name, os.NewFile(uintptr(fd), name), nil
		}
		if !errors.Is(err, syscall.EEXIST) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("could not allocate a unique temporary file")
}
