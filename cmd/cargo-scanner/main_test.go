package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeScanArgsAllowsFlagsAfterTarget(t *testing.T) {
	args, err := normalizeScanArgs([]string{"README.md", "--json", "--scanner", "grype"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--json", "--scanner", "grype", "README.md"}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %#v, want %#v", args, want)
		}
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if stdout.String() == "" {
		t.Fatal("expected version output")
	}
}

func TestRunInitWritesConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, ".cargo-scanner.yaml")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"init", "--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("runtime: managed")) {
		t.Fatalf("expected managed default, got %s", string(data))
	}
}

func TestRunCompletionZsh(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"completion", "zsh"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("#compdef cargo-scanner")) {
		t.Fatalf("expected zsh completion, got %s", stdout.String())
	}
}

func TestRunScanMissingTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"scan"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

func TestRunToolsPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CARGO_SCANNER_HOME", tmp)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"tools", "path"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	want := filepath.Join(tmp, "tools", "bin") + "\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestRunToolsList(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CARGO_SCANNER_HOME", tmp)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"tools", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("Managed tools path:")) {
		t.Fatalf("expected tools path, got %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("- grype: missing")) {
		t.Fatalf("expected grype status, got %s", stdout.String())
	}
}

func TestRunScanWritesMissingScannerJSON(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CARGO_SCANNER_HOME", filepath.Join(tmp, "home"))
	target := filepath.Join(tmp, "artifact.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"scan", target, "--scanner", "trivy", "--runtime", "managed", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"status": "failed"`)) {
		t.Fatalf("expected failed JSON, got %s", stdout.String())
	}
}
