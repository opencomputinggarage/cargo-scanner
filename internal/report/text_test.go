package report

import (
	"bytes"
	"testing"
	"time"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

func TestWriteTextIncludesBubblesReportAndLinks(t *testing.T) {
	t.Setenv("CARGO_SCANNER_PLAIN", "1")
	started := time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC)
	report := core.Report{
		Target: core.Target{Path: "artifact.jar"},
		Scanner: core.ScannerInfo{
			Name:    "grype",
			Version: "1.0.0",
			Runtime: "managed",
		},
		Status: core.StatusCompleted,
		Findings: []core.Finding{{
			ID:             "CVE-2026-0001",
			Type:           core.FindingVulnerability,
			Severity:       core.SeverityHigh,
			PackageName:    "demo",
			PackageVersion: "1.0.0",
			FixedVersions:  []string{"1.0.1"},
			URL:            "https://example.test/CVE-2026-0001",
		}},
		Summary:   core.Summary{Total: 1, High: 1},
		StartedAt: started,
		EndedAt:   started.Add(2 * time.Second),
	}

	var buf bytes.Buffer
	if err := WriteText(&buf, report); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Cargo Scanner",
		"Findings",
		"Top findings",
		"Severity",
		"CVE-2026-0001",
		"Details",
		"https://example.test/CVE-2026-0001",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}
