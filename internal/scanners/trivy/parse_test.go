package trivy

import (
	"os"
	"testing"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

func TestParse(t *testing.T) {
	data := []byte(`{
	  "Results": [{
	    "Target": "package-lock.json",
	    "Type": "npm",
	    "Vulnerabilities": [{
	      "VulnerabilityID": "CVE-2024-0002",
	      "PkgName": "demo",
	      "InstalledVersion": "1.0.0",
	      "FixedVersion": "1.0.1, 1.0.2",
	      "Severity": "CRITICAL",
	      "PrimaryURL": "https://example.test/CVE-2024-0002",
	      "DataSource": {"ID": "ghsa", "URL": "https://github.com/advisories"}
	    }]
	  }]
	}`)
	findings, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.ID != "CVE-2024-0002" || f.Severity != core.SeverityCritical || len(f.FixedVersions) != 2 {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].ID != "CVE-2024-2000" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}
