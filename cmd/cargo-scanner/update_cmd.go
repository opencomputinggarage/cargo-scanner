package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type updateRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []updateAsset `json:"assets"`
}

type updateAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func runUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", "opencomputinggarage/cargo-scanner", "GitHub repo to update from")
	versionFlag := fs.String("version", "latest", "version to install, or latest")
	checkOnly := fs.Bool("check", false, "check for an update without installing")
	force := fs.Bool("force", false, "install even when the selected version matches the current version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "update does not accept positional arguments")
		return 2
	}

	progress := (*operationProgress)(nil)
	if shouldStartOperationProgress(stderr) && !*checkOnly {
		progress = startOperationProgress(stderr, "Update Cargo Scanner", 1)
		defer func() {
			if err := progress.Stop(); err != nil {
				_, _ = fmt.Fprintf(stderr, "close progress ui: %v\n", err)
			}
		}()
	}
	if progress != nil {
		progress.Step(1, 1, "Checking release", *versionFlag)
	}

	release, err := fetchUpdateRelease(ctx, *repo, *versionFlag)
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintf(stderr, "check update: %v\n", err)
		return 1
	}
	current := displayVersion()
	if !*force && current != "" && current != "dev" && strings.TrimPrefix(release.TagName, "v") == strings.TrimPrefix(current, "v") {
		if progress != nil {
			progress.Complete(true, "Already up to date")
		}
		_, _ = fmt.Fprintf(stdout, "cargo-scanner is up to date (%s)\n", current)
		return 0
	}
	if *checkOnly {
		if current == "" || current == "dev" {
			_, _ = fmt.Fprintf(stdout, "latest cargo-scanner is %s (current: %s)\n", release.TagName, current)
		} else {
			_, _ = fmt.Fprintf(stdout, "update available: %s -> %s\n", current, release.TagName)
		}
		return 0
	}

	if progress != nil {
		progress.Stage("Resolving executable", "")
	}
	exe, err := os.Executable()
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintf(stderr, "resolve executable: %v\n", err)
		return 1
	}
	exe, _ = filepath.EvalSymlinks(exe)
	archiveName, err := updateArchiveName(release.TagName)
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	archiveURL, err := release.assetURL(archiveName)
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	checksumURL, err := release.assetURL("checksums.txt")
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	if progress != nil {
		progress.Stage("Downloading archive", archiveName)
	}
	archiveBytes, err := downloadUpdateAsset(ctx, client, archiveURL)
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintf(stderr, "download archive: %v\n", err)
		return 1
	}
	if progress != nil {
		progress.Stage("Downloading checksums", "checksums.txt")
	}
	checksumBytes, err := downloadUpdateAsset(ctx, client, checksumURL)
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintf(stderr, "download checksums: %v\n", err)
		return 1
	}
	if progress != nil {
		progress.Stage("Verifying checksum", archiveName)
	}
	expected, err := checksumLine(string(checksumBytes), archiveName)
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if got := sha256HexBytes(archiveBytes); got != expected {
		if progress != nil {
			progress.Complete(false, "checksum mismatch")
		}
		_, _ = fmt.Fprintf(stderr, "checksum mismatch for %s: got %s want %s\n", archiveName, got, expected)
		return 1
	}
	if progress != nil {
		progress.Stage("Extracting binary", archiveName)
	}
	binary, err := extractUpdateBinary(archiveName, archiveBytes)
	if err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintf(stderr, "extract binary: %v\n", err)
		return 1
	}
	if progress != nil {
		progress.Stage("Installing", exe)
	}
	if err := replaceExecutable(exe, binary); err != nil {
		if progress != nil {
			progress.Complete(false, err.Error())
		}
		_, _ = fmt.Fprintf(stderr, "install update: %v\n", err)
		_, _ = fmt.Fprintf(stderr, "hint: if %s is owned by root, rerun with sudo or reinstall with scripts/install.sh\n", exe)
		return 1
	}
	if progress != nil {
		progress.Complete(true, "Installed "+release.TagName)
	}
	_, _ = fmt.Fprintf(stdout, "updated cargo-scanner %s -> %s at %s\n", current, release.TagName, exe)
	return 0
}

func fetchUpdateRelease(ctx context.Context, repo, version string) (updateRelease, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return updateRelease{}, errors.New("repo is required")
	}
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	if strings.TrimSpace(version) != "" && version != "latest" {
		tag := version
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		url = "https://api.github.com/repos/" + repo + "/releases/tags/" + tag
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return updateRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return updateRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return updateRelease{}, fmt.Errorf("github release API status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var release updateRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return updateRelease{}, err
	}
	if release.TagName == "" {
		return updateRelease{}, errors.New("release missing tag")
	}
	return release, nil
}

func (r updateRelease) assetURL(name string) (string, error) {
	for _, asset := range r.Assets {
		if asset.Name == name {
			return asset.URL, nil
		}
	}
	return "", fmt.Errorf("release asset %q not found", name)
}

func updateArchiveName(tag string) (string, error) {
	version := strings.TrimPrefix(tag, "v")
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("unsupported architecture %q", goarch)
	}
	switch goos {
	case "darwin", "linux":
		return fmt.Sprintf("cargo-scanner_%s_%s_%s.tar.gz", version, goos, goarch), nil
	case "windows":
		return fmt.Sprintf("cargo-scanner_%s_%s_%s.zip", version, goos, goarch), nil
	default:
		return "", fmt.Errorf("unsupported OS %q", goos)
	}
}

func downloadUpdateAsset(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("download status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(resp.Body)
}

func checksumLine(contents, archiveName string) (string, error) {
	for _, line := range strings.Split(contents, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == archiveName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found", archiveName)
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func extractUpdateBinary(archiveName string, data []byte) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		return extractUpdateBinaryZip(data)
	}
	return extractUpdateBinaryTarGZ(data)
}

func extractUpdateBinaryTarGZ(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag == tar.TypeReg && filepath.Base(header.Name) == "cargo-scanner" {
			return io.ReadAll(tr)
		}
	}
	return nil, errors.New("cargo-scanner binary not found in archive")
}

func extractUpdateBinaryZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, file := range zr.File {
		if filepath.Base(file.Name) != "cargo-scanner.exe" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, errors.New("cargo-scanner.exe binary not found in archive")
}

func replaceExecutable(path string, binary []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, binary, info.Mode().Perm()|0o700); err != nil {
		return err
	}
	backup := path + ".old"
	_ = os.Remove(backup)
	if err := os.Rename(path, backup); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Rename(backup, path)
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(backup)
	return nil
}
