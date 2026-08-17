//go:build !linux

package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const secretFileMode = 0600

// writeSecretFile uses an os.Root to keep temporary-file creation and rename
// anchored to the same directory on non-Linux platforms.
func writeSecretFile(path, data string) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return fmt.Errorf("invalid outfile path %q", path)
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create outfile directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open outfile directory: %w", err)
	}
	defer root.Close()

	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("outfile %q is not a regular file", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect outfile %q: %w", path, err)
	}

	tmpName, tmp, err := createRootedSecretTemp(root)
	if err != nil {
		return fmt.Errorf("create temporary outfile: %w", err)
	}
	installed := false
	defer func() {
		_ = tmp.Close()
		if !installed {
			_ = root.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(secretFileMode); err != nil {
		return fmt.Errorf("chmod temporary outfile: %w", err)
	}
	if _, err := tmp.WriteString(data); err != nil {
		return fmt.Errorf("write temporary outfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary outfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary outfile: %w", err)
	}
	if err := root.Rename(tmpName, name); err != nil {
		return fmt.Errorf("install outfile %q: %w", path, err)
	}
	installed = true
	return nil
}

func createRootedSecretTemp(root *os.Root) (string, *os.File, error) {
	for range 100 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := ".bao-wrapper-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, secretFileMode)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("could not allocate a unique temporary file")
}
