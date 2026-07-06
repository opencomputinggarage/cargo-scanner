package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bubbletable "github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
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
		Target:     "~/artifact.jar",
		Recursive:  true,
		Scanner:    "syft",
		Runtime:    "auto",
		Format:     "text",
		SBOMOutput: "sbom.cdx.json",
	}.sbomArgs()
	want := []string{"--scanner", "syft", "--runtime", "auto", "--format", "text", "--recursive", "--sbom-output", "sbom.cdx.json", expandHome("~/artifact.jar")}
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

func TestSBOMTextViewShowsSummaryNotRawJSON(t *testing.T) {
	report := core.Report{
		Target:    core.Target{Path: "artifact.jar"},
		Scanner:   core.ScannerInfo{Name: "syft", Version: "1.0.0", Runtime: "managed"},
		Status:    core.StatusCompleted,
		StartedAt: mustParseTime(t, "2026-01-01T00:00:00Z"),
		EndedAt:   mustParseTime(t, "2026-01-01T00:00:02Z"),
		SBOM: &core.SBOM{
			Format:        "cyclonedx-json",
			ContentDigest: "sha256:abc123",
			ContentJSON: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"metadata": {"component": {"type": "file", "name": "artifact.jar"}},
				"components": [
					{"type": "library", "name": "demo-lib", "version": "1.2.3", "purl": "pkg:maven/demo/demo-lib@1.2.3"}
				],
				"dependencies": [{"ref": "artifact.jar", "dependsOn": ["demo-lib"]}]
			}`,
		},
	}
	view := sbomTextView(report, 100)
	for _, want := range []string{"SBOM", "Summary", "Components", "demo-lib", "CycloneDX 1.6"} {
		if !strings.Contains(view, want) {
			t.Fatalf("SBOM view missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, `"components"`) || strings.Contains(view, `"bomFormat"`) {
		t.Fatalf("SBOM view should not print raw JSON:\n%s", view)
	}
}

func TestSBOMViewerShowsComponentDetails(t *testing.T) {
	report := sampleSBOMReport(t)
	summary, err := parseCycloneDXSummary(report.SBOM.ContentJSON)
	if err != nil {
		t.Fatal(err)
	}
	model := newSBOMViewerModel(report, summary)
	model.width = 72
	model.height = 24
	model.refresh()
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(sbomViewerModel)

	view := model.View()
	for _, want := range []string{"Components", "Component details", "demo-lib", "pkg:maven/demo/demo-lib@1.2.3"} {
		if !strings.Contains(view, want) {
			t.Fatalf("SBOM viewer missing %q:\n%s", want, view)
		}
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > model.width {
			t.Fatalf("line width = %d, want <= %d:\n%s", lipgloss.Width(line), model.width, view)
		}
	}
}

func sampleSBOMReport(t *testing.T) core.Report {
	t.Helper()
	return core.Report{
		Target:    core.Target{Path: "artifact.jar"},
		Scanner:   core.ScannerInfo{Name: "syft", Version: "1.0.0", Runtime: "managed"},
		Status:    core.StatusCompleted,
		StartedAt: mustParseTime(t, "2026-01-01T00:00:00Z"),
		EndedAt:   mustParseTime(t, "2026-01-01T00:00:02Z"),
		SBOM: &core.SBOM{
			Format:        "cyclonedx-json",
			ContentDigest: "sha256:abc123",
			ContentJSON: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"metadata": {"component": {"type": "file", "name": "artifact.jar"}},
				"components": [
					{"type": "library", "name": "demo-lib", "version": "1.2.3", "purl": "pkg:maven/demo/demo-lib@1.2.3", "bom-ref": "pkg:maven/demo/demo-lib@1.2.3"}
				],
				"dependencies": [{"ref": "artifact.jar", "dependsOn": ["demo-lib"]}]
			}`,
		},
	}
}

func TestPathSuggestionsCompletesFilesAndDirectories(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "artifact.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tmp, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(tmp)

	suggestions := pathSuggestions("art")
	for _, want := range []string{"artifact.jar", "artifacts" + string(os.PathSeparator)} {
		if !containsString(suggestions, want) {
			t.Fatalf("suggestions missing %q: %#v", want, suggestions)
		}
	}

	suggestions = pathSuggestions(".")
	for _, want := range []string{"." + string(os.PathSeparator) + "artifact.jar", "." + string(os.PathSeparator) + "artifacts" + string(os.PathSeparator)} {
		if !containsString(suggestions, want) {
			t.Fatalf("dot suggestions missing %q: %#v", want, suggestions)
		}
	}
}

func TestPathInputTabCompletesSuggestion(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "artifact.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(tmp)

	model := newPathInputModel("art")
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	model = updated.(pathInputModel)
	if got := model.input.Value(); got != "artifact.jar" {
		t.Fatalf("input value = %q, want artifact.jar", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestResultViewerSummaryAndDetailsContent(t *testing.T) {
	t.Setenv("CARGO_SCANNER_PLAIN", "1")
	reports := []core.Report{{
		Target:  core.Target{Path: "artifact.jar"},
		Scanner: core.ScannerInfo{Name: "grype", Runtime: "managed"},
		Status:  core.StatusCompleted,
		Summary: core.Summary{Total: 1, High: 1},
		Findings: []core.Finding{{
			ID:             "CVE-2026-0001",
			Severity:       core.SeverityHigh,
			PackageName:    "demo",
			PackageVersion: "1.0.0",
			FixedVersions:  []string{"1.0.1"},
			URL:            "https://example.test/CVE-2026-0001",
		}},
	}}

	summary := resultSummaryContent(reports, 100)
	for _, want := range []string{"Targets", "Top risks", "Vulnerability", "Findings", "artifact.jar", "HIGH"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}

	details := resultDetailsContent(reports, 100)
	for _, want := range []string{"Findings", "sorted by severity", "Vulnerability", "CVE-2026-0001", "demo 1.0.0"} {
		if !strings.Contains(details, want) {
			t.Fatalf("details missing %q:\n%s", want, details)
		}
	}
	label := resultFindingLabel(reports[0].Findings[0])
	if label != "CVE-2026-0001" {
		t.Fatalf("finding label = %s", label)
	}
	rows, links := resultFindingRows(allFindings(reports))
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if links["CVE-2026-0001"] != "https://example.test/CVE-2026-0001" {
		t.Fatalf("finding link missing URL: %#v", links)
	}
}

func TestResultTableFitsWidth(t *testing.T) {
	rows := []bubbletable.Row{{
		"HIGH",
		"CVE-2026-0001",
		"very-long-package-name-with-version 1.2.3",
		"1.2.4",
		"/very/long/path/to/artifact.jar",
	}}
	cols := []bubbletable.Column{
		{Title: "Severity", Width: 10},
		{Title: "Vulnerability", Width: 24},
		{Title: "Package", Width: 30},
		{Title: "Fixed", Width: 16},
		{Title: "Target", Width: 24},
	}
	view := resultTable(cols, rows, 72)
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > 72 {
			t.Fatalf("line width = %d, want <= 72:\n%s", lipgloss.Width(line), view)
		}
	}
}

func TestResultTableWithLinksKeepsRowsSingleLine(t *testing.T) {
	t.Setenv("CARGO_SCANNER_PLAIN", "1")
	rows := []bubbletable.Row{{
		"HIGH",
		"CVE-2026-0001",
		"very-long-package-name-with-version 1.2.3",
		"1.2.4",
		"/very/long/path/to/artifact.jar",
	}}
	cols := resultFindingColumns(72)
	view := resultTableWithLinks(cols, rows, 72, map[string]string{
		"CVE-2026-0001": "https://example.test/a/very/long/path/for/CVE-2026-0001",
	})
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > 72 {
			t.Fatalf("line width = %d, want <= 72:\n%s", lipgloss.Width(line), view)
		}
	}
}

func TestResultSummaryFitsWidth(t *testing.T) {
	reports := []core.Report{{
		Target:  core.Target{Path: "artifact.jar"},
		Scanner: core.ScannerInfo{Name: "grype", Runtime: "managed"},
		Status:  core.StatusCompleted,
		Summary: core.Summary{Total: 0},
	}}
	view := resultSummaryContent(reports, 72)
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > 72 {
			t.Fatalf("line width = %d, want <= 72:\n%s", lipgloss.Width(line), view)
		}
	}
}

func TestResultFindingDetailFitsWidth(t *testing.T) {
	view := resultFindingDetailView(findingWithTarget{
		target: "/very/long/path/to/artifacts/releases/artifact-with-a-long-name.jar",
		finding: core.Finding{
			ID:             "CVE-2026-0001",
			Severity:       core.SeverityHigh,
			Source:         "grype",
			PackageName:    "very-long-package-name-with-version",
			PackageVersion: "1.2.3",
			PackageType:    "java-archive",
			FixedVersions:  []string{"1.2.4", "1.2.5"},
			Location:       "/very/long/location/inside/archive/path/to/library.jar",
			URL:            "https://example.test/a/very/long/path/for/CVE-2026-0001/with/details",
		},
	}, 72)
	if strings.Contains(view, "╭") || strings.Contains(view, "╰") {
		t.Fatalf("detail view should not use rounded border:\n%s", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > 72 {
			t.Fatalf("line width = %d, want <= 72:\n%s", lipgloss.Width(line), view)
		}
	}
}

func TestResultViewerDetailsFitsTerminalWidth(t *testing.T) {
	report := core.Report{
		Target:  core.Target{Path: "/very/long/path/to/artifacts/releases/artifact-with-a-long-name.jar"},
		Scanner: core.ScannerInfo{Name: "grype", Runtime: "managed"},
		Status:  core.StatusCompleted,
		Summary: core.Summary{Total: 1, High: 1},
		Findings: []core.Finding{{
			ID:             "CVE-2026-0001",
			Severity:       core.SeverityHigh,
			Source:         "grype",
			PackageName:    "very-long-package-name-with-version",
			PackageVersion: "1.2.3",
			PackageType:    "java-archive",
			FixedVersions:  []string{"1.2.4", "1.2.5"},
			Location:       "/very/long/location/inside/archive/path/to/library.jar",
			URL:            "https://example.test/a/very/long/path/for/CVE-2026-0001/with/details",
		}},
	}
	model := newResultViewerModel([]core.Report{report})
	model.width = 72
	model.height = 24
	model.view.Width = resultContentWidth(model.width)
	model.view.Height = 12
	model.mode = resultDetailsMode
	model.refresh()
	finding := model.detailsFindings[0]
	model.selectedFinding = &finding

	view := model.View()
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > model.width {
			t.Fatalf("line width = %d, want <= %d:\n%s", lipgloss.Width(line), model.width, view)
		}
	}
}

func TestResultViewerDefaultShowsSummaryFindingsAndDetails(t *testing.T) {
	report := core.Report{
		Target:  core.Target{Path: "artifact.jar"},
		Scanner: core.ScannerInfo{Name: "grype", Version: "1.0.0", Runtime: "managed"},
		Status:  core.StatusCompleted,
		Summary: core.Summary{Total: 1, High: 1},
		Findings: []core.Finding{{
			ID:             "CVE-2026-0001",
			Severity:       core.SeverityHigh,
			Source:         "grype",
			PackageName:    "demo",
			PackageVersion: "1.0.0",
			FixedVersions:  []string{"1.0.1"},
			URL:            "https://example.test/CVE-2026-0001",
		}},
	}
	model := newResultViewerModel([]core.Report{report})
	model.width = 72
	model.height = 24
	model.view.Width = resultContentWidth(model.width)
	model.view.Height = 12
	model.refresh()

	view := model.View()
	for _, want := range []string{"Vulnerabilities", "Summary", "Findings", "CVE-2026"} {
		if !strings.Contains(view, want) {
			t.Fatalf("result viewer missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Summary Details") {
		t.Fatalf("result viewer should not show summary/details tabs:\n%s", view)
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(resultViewerModel)
	view = model.View()
	if !strings.Contains(view, "Finding details") || !strings.Contains(view, "CVE-2026-0001") {
		t.Fatalf("result viewer should open finding details:\n%s", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > model.width {
			t.Fatalf("line width = %d, want <= %d:\n%s", lipgloss.Width(line), model.width, view)
		}
	}
}

func TestResultFindingColumnsExpandWithWidth(t *testing.T) {
	narrow := resultFindingColumns(72)
	wide := resultFindingColumns(160)
	if wide[2].Width <= narrow[2].Width {
		t.Fatalf("package column did not expand: narrow=%d wide=%d", narrow[2].Width, wide[2].Width)
	}
	if wide[4].Width <= narrow[4].Width {
		t.Fatalf("target column did not expand: narrow=%d wide=%d", narrow[4].Width, wide[4].Width)
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
	if !bytes.Contains(stdout.Bytes(), []byte("Scan Current Folder")) {
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
