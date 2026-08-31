//go:build !linux

package runner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const secretFileMode = 0600

// writeSecretFile uses an os.Root to keep temporary-file creation and rename
// anchored to the same directory on non-Linux platforms. The parent is opened
// one component at a time so OpenRoot never receives an unchecked path that
// could contain a symbolic link.
func writeSecretFile(path, data string) error {
	root, name, err := openSecretParentRoot(path)
	if err != nil {
		return err
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

// openSecretParentRoot resolves path from the filesystem (or Windows volume)
// root without accepting a symbolic link in any parent component. OpenRoot
// follows a link passed as its argument, so each component is first inspected
// and the opened directory handle is then checked with SameFile. If an attacker
// swaps a component between those operations, the identity check fails; if it
// is swapped afterwards, the returned Root remains attached to the opened
// directory.
func openSecretParentRoot(path string) (*os.Root, string, error) {
	clean, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("resolve outfile path %q: %w", path, err)
	}
	name := filepath.Base(clean)
	if name == "." || name == string(filepath.Separator) {
		return nil, "", fmt.Errorf("invalid outfile path %q", path)
	}

	anchor := string(filepath.Separator)
	if volume := filepath.VolumeName(clean); volume != "" {
		anchor = volume + string(filepath.Separator)
	}
	dir := filepath.Dir(clean)
	relDir, err := filepath.Rel(anchor, dir)
	if err != nil {
		return nil, "", fmt.Errorf("resolve outfile directory %q: %w", dir, err)
	}
	parentPrefix := ".." + string(filepath.Separator)
	if relDir == ".." || filepath.IsAbs(relDir) || strings.HasPrefix(relDir, parentPrefix) {
		return nil, "", fmt.Errorf("invalid outfile path %q", path)
	}

	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, "", fmt.Errorf("open outfile root %q: %w", anchor, err)
	}
	if relDir == "." {
		return root, name, nil
	}

	for _, component := range strings.Split(relDir, string(filepath.Separator)) {
		info, statErr := root.Lstat(component)
		if os.IsNotExist(statErr) {
			if mkdirErr := root.Mkdir(component, 0750); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				_ = root.Close()
				return nil, "", fmt.Errorf("create outfile directory %q: %w", component, mkdirErr)
			}
			info, statErr = root.Lstat(component)
		}
		if statErr != nil {
			_ = root.Close()
			return nil, "", fmt.Errorf("inspect outfile directory %q: %w", component, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return nil, "", fmt.Errorf("open outfile directory %q without following symbolic links: symbolic link not allowed", component)
		}
		if !info.IsDir() {
			_ = root.Close()
			return nil, "", fmt.Errorf("outfile parent %q is not a directory", component)
		}

		next, openErr := root.OpenRoot(component)
		if openErr != nil {
			_ = root.Close()
			return nil, "", fmt.Errorf("open outfile directory %q: %w", component, openErr)
		}
		openedInfo, openedStatErr := next.Stat(".")
		if openedStatErr != nil || !os.SameFile(info, openedInfo) {
			_ = next.Close()
			_ = root.Close()
			if openedStatErr != nil {
				return nil, "", fmt.Errorf("verify outfile directory %q: %w", component, openedStatErr)
			}
			return nil, "", fmt.Errorf("verify outfile directory %q: path changed during traversal", component)
		}
		_ = root.Close()
		root = next
	}
	return root, name, nil
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
