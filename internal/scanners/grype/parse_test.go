package grype

import (
	"os"
	"testing"

	"github.com/byeonggi/cargo-scanner/internal/core"
)

func TestParse(t *testing.T) {
	data := []byte(`{
	  "matches": [
	    {
	      "vulnerability": {
	        "id": "CVE-2024-0001",
	        "severity": "High",
	        "dataSource": "https://example.test",
	        "urls": ["https://example.test/CVE-2024-0001"],
	        "fix": {"versions": ["1.2.3"]}
	      },
	      "artifact": {
	        "name": "demo",
	        "version": "1.0.0",
	        "type": "java-archive",
	        "locations": [{"path": "/artifact.jar"}]
	      }
	    }
	  ]
	}`)
	findings, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.ID != "CVE-2024-0001" || f.Severity != core.SeverityHigh || f.PackageName != "demo" {
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
	if findings[0].ID != "CVE-2024-1000" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}
