package managed

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestToolPathUsesWindowsExecutableSuffix(t *testing.T) {
	rt := New(filepath.Join("tmp", "cargo-scanner"))
	got := filepath.Base(rt.ToolPath("grype"))
	want := "grype"
	if runtime.GOOS == "windows" {
		want = "grype.exe"
	}
	if got != want {
		t.Fatalf("ToolPath base = %q, want %q", got, want)
	}
}
