package tools

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestArchiveNameAnchore(t *testing.T) {
	got, err := archiveName("grype", "0.115.0", "darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	want := "grype_0.115.0_darwin_arm64.tar.gz"
	if got != want {
		t.Fatalf("archiveName = %q, want %q", got, want)
	}
}

func TestArchiveNameTrivy(t *testing.T) {
	got, err := archiveName("trivy", "0.72.0", "darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	want := "trivy_0.72.0_macOS-ARM64.tar.gz"
	if got != want {
		t.Fatalf("archiveName = %q, want %q", got, want)
	}
}

func TestArchiveNameAnchoreWindows(t *testing.T) {
	got, err := archiveName("syft", "1.46.0", "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := "syft_1.46.0_windows_amd64.zip"
	if got != want {
		t.Fatalf("archiveName = %q, want %q", got, want)
	}
}

func TestArchiveNameTrivyWindows(t *testing.T) {
	got, err := archiveName("trivy", "0.72.0", "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := "trivy_0.72.0_windows-64bit.zip"
	if got != want {
		t.Fatalf("archiveName = %q, want %q", got, want)
	}
}

func TestArchiveNameWindowsARM64Fallback(t *testing.T) {
	got, err := archiveName("grype", "0.115.0", "windows", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	want := "grype_0.115.0_windows_amd64.zip"
	if got != want {
		t.Fatalf("archiveName = %q, want %q", got, want)
	}

	got, err = archiveName("syft", "1.46.0", "windows", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	want = "syft_1.46.0_windows_arm64.zip"
	if got != want {
		t.Fatalf("archiveName = %q, want %q", got, want)
	}
}

func TestChecksumFor(t *testing.T) {
	text := "abc123  grype_0.115.0_darwin_arm64.tar.gz\n"
	got, err := checksumFor(text, "grype_0.115.0_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc123" {
		t.Fatalf("checksum = %q, want abc123", got)
	}
}

func TestExtractBinaryZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("nested/grype.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("binary")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := extractBinary(buf.Bytes(), "grype")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary" {
		t.Fatalf("binary = %q, want binary", string(got))
	}
}

func TestSplitToolSpec(t *testing.T) {
	name, version := splitToolSpec("grype@v0.115.0")
	if name != "grype" || version != "0.115.0" {
		t.Fatalf("splitToolSpec = %q %q", name, version)
	}
}
