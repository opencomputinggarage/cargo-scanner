package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverTargetsWithFilters(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.jar"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := DiscoverTargetsWithFilters(dir, true, []string{"*.jar"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || filepath.Base(targets[0].Path) != "a.jar" {
		t.Fatalf("targets = %+v, want a.jar only", targets)
	}
}
