//go:build ignore

// Install the pinned, checksum-verified OpenBao executable for the current host.
// Usage: go run ./integration/tools/install-openbao.go DESTINATION_DIRECTORY
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

const version = "2.6.2"

// SHA-256 digests from the upstream v2.6.2 release assets. Updating OpenBao
// requires reviewing and updating these pins together with the Compose image.
var digests = map[string]string{
	"linux_amd64":   "8dc11cc5fca0b539a9e352727dacb4e2d304daffcf9a66e0718ac325a20d05aa",
	"linux_arm64":   "1b408e01f3565ac0cbcb88d637dca271d0515148fb72efdeff4473a34fa50c4e",
	"darwin_amd64":  "64fdf1ce8f410bbc1531d2f0ea142d21b4e755b986542025a00294999a8cfaa5",
	"darwin_arm64":  "4e495376174accc0e014d31e9901f518a974f966850c839f626347eaac05fd52",
	"windows_amd64": "12e8d40c71fe5a0aa23062c6c36a77a96717005980e30d0d42acdea3268d3fa2",
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./integration/tools/install-openbao.go DESTINATION_DIRECTORY")
		os.Exit(1)
	}
	if err := install(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func install(destination string) error {
	platform := runtime.GOOS + "_" + runtime.GOARCH
	digest, ok := digests[platform]
	if !ok {
		return fmt.Errorf("no pinned OpenBao archive for %s", platform)
	}
	ext, executable := ".tar.gz", "bao"
	if runtime.GOOS == "windows" {
		ext, executable = ".zip", "bao.exe"
	}
	url := fmt.Sprintf("https://github.com/openbao/openbao/releases/download/v%s/openbao_%s_%s%s", version, version, platform, ext)
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download OpenBao: HTTP %d", resp.StatusCode)
	}
	archive, err := os.CreateTemp("", "openbao-download-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(archive.Name()) }()
	defer func() { _ = archive.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(resp.Body, 512<<20)); err != nil {
		return err
	}
	if got := fmt.Sprintf("%x", hash.Sum(nil)); got != digest {
		return fmt.Errorf("OpenBao checksum mismatch: got %s, want %s", got, digest)
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0755); err != nil {
		return err
	}
	output := filepath.Join(destination, executable)
	if ext == ".zip" {
		info, err := archive.Stat()
		if err != nil {
			return err
		}
		reader, err := zip.NewReader(archive, info.Size())
		if err != nil {
			return err
		}
		for _, file := range reader.File {
			if path.Base(file.Name) != executable || !file.Mode().IsRegular() {
				continue
			}
			contents, err := file.Open()
			if err != nil {
				return err
			}
			defer func() { _ = contents.Close() }()
			return writeExecutable(output, contents)
		}
	} else {
		reader, err := gzip.NewReader(archive)
		if err != nil {
			return err
		}
		defer func() { _ = reader.Close() }()
		files := tar.NewReader(reader)
		for {
			header, err := files.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if path.Base(header.Name) == executable && header.Typeflag == tar.TypeReg {
				return writeExecutable(output, files)
			}
		}
	}
	return fmt.Errorf("verified OpenBao archive did not contain %s", executable)
}

func writeExecutable(destination string, contents io.Reader) error {
	// Extract only the executable, to a fixed destination; never use archive
	// paths as filesystem destinations.
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, contents)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return closeErr
	}
	fmt.Printf("Installed OpenBao %s: %s\n", version, destination)
	return nil
}
