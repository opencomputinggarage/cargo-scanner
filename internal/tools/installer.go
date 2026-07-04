package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Tool struct {
	Name string
	Repo string
}

var supported = map[string]Tool{
	"grype": {Name: "grype", Repo: "anchore/grype"},
	"syft":  {Name: "syft", Repo: "anchore/syft"},
	"trivy": {Name: "trivy", Repo: "aquasecurity/trivy"},
}

type Installer struct {
	HTTP   *http.Client
	BinDir string
}

type InstallResult struct {
	Name    string
	Version string
	Path    string
}

type Manifest struct {
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	Repository    string    `json:"repository"`
	Archive       string    `json:"archive"`
	ArchiveURL    string    `json:"archive_url"`
	ChecksumURL   string    `json:"checksum_url"`
	SHA256        string    `json:"sha256"`
	BinarySHA256  string    `json:"binary_sha256"`
	InstalledPath string    `json:"installed_path"`
	InstalledAt   time.Time `json:"installed_at"`
}

func SupportedNames() []string {
	return []string{"grype", "trivy", "syft"}
}

func (i Installer) Install(ctx context.Context, name string) (InstallResult, error) {
	toolName, requestedVersion := splitToolSpec(name)
	tool, ok := supported[strings.ToLower(strings.TrimSpace(toolName))]
	if !ok {
		return InstallResult{}, fmt.Errorf("unsupported tool %q", name)
	}
	if i.BinDir == "" {
		return InstallResult{}, errors.New("managed bin dir is required")
	}
	if err := os.MkdirAll(i.BinDir, 0o700); err != nil {
		return InstallResult{}, err
	}
	release, err := i.release(ctx, tool.Repo, requestedVersion)
	if err != nil {
		return InstallResult{}, err
	}
	version := strings.TrimPrefix(release.TagName, "v")
	archiveName, err := archiveName(tool.Name, version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return InstallResult{}, err
	}
	checksumName := fmt.Sprintf("%s_%s_checksums.txt", tool.Name, version)
	archiveURL, err := release.assetURL(archiveName)
	if err != nil {
		return InstallResult{}, err
	}
	checksumURL, err := release.assetURL(checksumName)
	if err != nil {
		return InstallResult{}, err
	}
	archiveBytes, err := i.download(ctx, archiveURL)
	if err != nil {
		return InstallResult{}, err
	}
	checksumBytes, err := i.download(ctx, checksumURL)
	if err != nil {
		return InstallResult{}, err
	}
	expected, err := checksumFor(string(checksumBytes), archiveName)
	if err != nil {
		return InstallResult{}, err
	}
	if got := sha256Hex(archiveBytes); got != expected {
		return InstallResult{}, fmt.Errorf("checksum mismatch for %s: got %s want %s", archiveName, got, expected)
	}
	binary, err := extractBinary(archiveBytes, tool.Name)
	if err != nil {
		return InstallResult{}, err
	}
	dst := filepath.Join(i.BinDir, tool.Name)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, binary, 0o700); err != nil {
		return InstallResult{}, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return InstallResult{}, err
	}
	manifest := Manifest{
		Name:          tool.Name,
		Version:       version,
		Repository:    tool.Repo,
		Archive:       archiveName,
		ArchiveURL:    archiveURL,
		ChecksumURL:   checksumURL,
		SHA256:        expected,
		BinarySHA256:  sha256Hex(binary),
		InstalledPath: dst,
		InstalledAt:   time.Now().UTC(),
	}
	if err := writeManifest(dst+".json", manifest); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Name: tool.Name, Version: version, Path: dst}, nil
}

func splitToolSpec(spec string) (string, string) {
	name, version, ok := strings.Cut(strings.TrimSpace(spec), "@")
	if !ok {
		return name, ""
	}
	return name, strings.TrimPrefix(strings.TrimSpace(version), "v")
}

func ReadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func writeManifest(path string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

type releaseDoc struct {
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func (r releaseDoc) assetURL(name string) (string, error) {
	for _, asset := range r.Assets {
		if asset.Name == name {
			return asset.URL, nil
		}
	}
	return "", fmt.Errorf("release asset %q not found", name)
}

func (i Installer) release(ctx context.Context, repo string, version string) (releaseDoc, error) {
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	if version != "" {
		url = "https://api.github.com/repos/" + repo + "/releases/tags/v" + version
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return releaseDoc{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := i.http().Do(req)
	if err != nil {
		return releaseDoc{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return releaseDoc{}, fmt.Errorf("github release API status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var release releaseDoc
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return releaseDoc{}, err
	}
	if release.TagName == "" {
		return releaseDoc{}, errors.New("latest release missing tag")
	}
	return release, nil
}

func (i Installer) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := i.http().Do(req)
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

func (i Installer) http() *http.Client {
	if i.HTTP != nil {
		return i.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func archiveName(tool, version, goos, goarch string) (string, error) {
	switch tool {
	case "grype", "syft":
		return fmt.Sprintf("%s_%s_%s_%s.tar.gz", tool, version, goos, goarch), nil
	case "trivy":
		osPart, err := trivyOS(goos)
		if err != nil {
			return "", err
		}
		archPart, err := trivyArch(goarch)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("trivy_%s_%s-%s.tar.gz", version, osPart, archPart), nil
	default:
		return "", fmt.Errorf("unsupported tool %q", tool)
	}
}

func trivyOS(goos string) (string, error) {
	switch goos {
	case "darwin":
		return "macOS", nil
	case "linux":
		return "Linux", nil
	case "freebsd":
		return "FreeBSD", nil
	default:
		return "", fmt.Errorf("unsupported OS %q", goos)
	}
}

func trivyArch(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "64bit", nil
	case "arm64":
		return "ARM64", nil
	case "arm":
		return "ARM", nil
	case "386":
		return "32bit", nil
	default:
		return "", fmt.Errorf("unsupported arch %q", goarch)
	}
}

func checksumFor(text, filename string) (string, error) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[len(fields)-1] == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found", filename)
}

func extractBinary(archive []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
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
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(header.Name) != name {
			continue
		}
		return io.ReadAll(tr)
	}
	return nil, fmt.Errorf("binary %q not found in archive", name)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
