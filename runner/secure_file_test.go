package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteSecretFileCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "secret")
	if err := writeSecretFile(path, "new-secret"); err != nil {
		t.Fatalf("writeSecretFile() error = %v", err)
	}

	assertFileContent(t, path, "new-secret")
	assertPrivateMode(t, path)
}

func TestWriteSecretFileReplacesExistingFileWithPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}

	if err := writeSecretFile(path, "new-secret"); err != nil {
		t.Fatalf("writeSecretFile() error = %v", err)
	}

	assertFileContent(t, path, "new-secret")
	assertPrivateMode(t, path)
}

func TestWriteSecretFileRejectsOutfileSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("must-not-change"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}

	err := writeSecretFile(path, "new-secret")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("writeSecretFile() error = %v, want non-regular-file error", err)
	}
	assertFileContent(t, target, "must-not-change")
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("outfile symlink was changed: info=%v err=%v", info, err)
	}
}

func TestWriteSecretFileRejectsNonRegularOutfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}

	err := writeSecretFile(path, "new-secret")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("writeSecretFile() error = %v, want non-regular-file error", err)
	}
}

func TestWriteSecretFileRejectsSymlinkInParentPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("descriptor-based no-follow path traversal is Linux-specific")
	}
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	err := writeSecretFile(filepath.Join(linkDir, "secret"), "new-secret")
	if err == nil {
		t.Fatal("writeSecretFile() succeeded through a parent symlink")
	}
	if _, err := os.Stat(filepath.Join(realDir, "secret")); !os.IsNotExist(err) {
		t.Fatalf("secret was written through parent symlink: %v", err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
}

func assertPrivateMode(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != secretFileMode {
		t.Fatalf("mode = %04o, want %04o", got, secretFileMode)
	}
}
