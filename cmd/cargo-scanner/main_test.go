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

func TestNormalizeScanArgsAllowsTUIFlagAfterTarget(t *testing.T) {
	args, err := normalizeScanArgs([]string{"README.md", "--tui=false"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--tui=false", "README.md"}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %#v, want %#v", args, want)
		}
	}
}

func TestNormalizeScanArgsAllowsShortFlagsAfterTarget(t *testing.T) {
	args, err := normalizeScanArgs([]string{"README.md", "-R", "-s", "trivy", "-f=json", "-o", "report.json"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-R", "-s", "trivy", "-f=json", "-o", "report.json", "README.md"}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %#v, want %#v", args, want)
		}
	}
}

func TestScanWizardOptionsSBOMArgs(t *testing.T) {
	args := scanWizardOptions{
		Target:     "~/Downloads",
		Recursive:  true,
		Scanner:    "syft",
		Runtime:    "auto",
		Format:     "text",
		SBOMOutput: "sbom.cdx.json",
	}.sbomArgs()
	want := []string{"--scanner", "syft", "--runtime", "auto", "--format", "text", "--recursive", "--sbom-output", "sbom.cdx.json", expandHome("~/Downloads")}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %#v, want %#v", args, want)
		}
	}
}

func TestScanWizardOptionsVulnerabilityArgs(t *testing.T) {
	args := scanWizardOptions{
		Target:  ".",
		Scanner: "trivy",
		Runtime: "auto",
		Format:  "sarif",
		FailOn:  "high",
		Output:  "results.sarif",
	}.args()
	want := []string{"--scanner", "trivy", "--runtime", "auto", "--format", "sarif", "--fail-on", "high", "--output", "results.sarif", "."}
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

func TestRunVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("cargo-scanner")) {
		t.Fatalf("expected version output, got %s", stdout.String())
	}
}

func TestShouldScanImplicitly(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "artifact.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !shouldScanImplicitly(target) {
		t.Fatal("expected existing file to scan implicitly")
	}
	if shouldScanImplicitly("scna") {
		t.Fatal("expected unknown command typo not to scan implicitly")
	}
	if !shouldScanImplicitly("--json") {
		t.Fatal("expected scan option to scan implicitly")
	}
}

func TestSuggestCommand(t *testing.T) {
	if got := suggestCommand("scna"); got != "scan" {
		t.Fatalf("suggestCommand = %q, want scan", got)
	}
	if got := suggestCommand("totallyunknown"); got != "" {
		t.Fatalf("suggestCommand = %q, want empty", got)
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
	if !bytes.Contains(stdout.Bytes(), []byte("update:update cargo-scanner")) {
		t.Fatalf("expected update completion, got %s", stdout.String())
	}
}

func TestRunTUIPrint(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CARGO_SCANNER_HOME", tmp)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"tui", "--print"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("Cargo Scanner")) {
		t.Fatalf("expected dashboard title, got %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("Scan Downloads")) {
		t.Fatalf("expected action list, got %s", stdout.String())
	}
}

func TestRunScanMissingTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"scan"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("example:")) {
		t.Fatalf("expected example hint, got %s", stderr.String())
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
	if !bytes.Contains(stdout.Bytes(), []byte("grype")) || !bytes.Contains(stdout.Bytes(), []byte("missing")) {
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

func TestSuggestCommandUpdate(t *testing.T) {
	if got := suggestCommand("updat"); got != "update" {
		t.Fatalf("suggestCommand = %q, want update", got)
	}
}

func TestUpdateChecksumLine(t *testing.T) {
	got, err := checksumLine("abc123  cargo-scanner_0.1.11_darwin_arm64.tar.gz\n", "cargo-scanner_0.1.11_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc123" {
		t.Fatalf("checksum = %q, want abc123", got)
	}
}
