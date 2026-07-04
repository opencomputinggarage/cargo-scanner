package report

import (
	"bytes"
	"testing"

	"github.com/byeonggi/cargo-scanner/internal/core"
)

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSARIF(&buf, []core.Report{{
		Target:  core.Target{Path: "artifact.jar"},
		Scanner: core.ScannerInfo{Name: "grype", Version: "1.0.0"},
		Findings: []core.Finding{{
			ID:          "CVE-2024-0001",
			Type:        core.FindingVulnerability,
			Severity:    core.SeverityHigh,
			PackageName: "demo",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"version": "2.1.0"`)) {
		t.Fatalf("missing SARIF version: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"ruleId": "CVE-2024-0001"`)) {
		t.Fatalf("missing result: %s", buf.String())
	}
}
