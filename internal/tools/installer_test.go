package tools

import "testing"

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

func TestSplitToolSpec(t *testing.T) {
	name, version := splitToolSpec("grype@v0.115.0")
	if name != "grype" || version != "0.115.0" {
		t.Fatalf("splitToolSpec = %q %q", name, version)
	}
}
