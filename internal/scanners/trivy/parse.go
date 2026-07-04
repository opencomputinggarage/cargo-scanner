package trivy

import (
	"encoding/json"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

type document struct {
	Results []result `json:"Results"`
}

type result struct {
	Target          string          `json:"Target"`
	Type            string          `json:"Type"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
}

type vulnerability struct {
	VulnerabilityID  string  `json:"VulnerabilityID"`
	PkgName          string  `json:"PkgName"`
	InstalledVersion string  `json:"InstalledVersion"`
	FixedVersion     string  `json:"FixedVersion"`
	Severity         string  `json:"Severity"`
	PrimaryURL       string  `json:"PrimaryURL"`
	DataSource       *source `json:"DataSource"`
}

type source struct {
	ID  string `json:"ID"`
	URL string `json:"URL"`
}

func Parse(data []byte) ([]core.Finding, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var findings []core.Finding
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			f := core.Finding{
				ID:             v.VulnerabilityID,
				Type:           core.FindingVulnerability,
				Severity:       core.ParseSeverity(v.Severity),
				PackageName:    v.PkgName,
				PackageVersion: v.InstalledVersion,
				PackageType:    r.Type,
				FixedVersions:  splitFixedVersions(v.FixedVersion),
				URL:            v.PrimaryURL,
				Location:       r.Target,
			}
			if v.DataSource != nil {
				f.Source = v.DataSource.ID
				if f.URL == "" {
					f.URL = v.DataSource.URL
				}
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func splitFixedVersions(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range []rune(s) {
		_ = part
	}
	start := 0
	for i, r := range s {
		if r == ',' {
			if v := trimVersion(s[start:i]); v != "" {
				out = append(out, v)
			}
			start = i + 1
		}
	}
	if v := trimVersion(s[start:]); v != "" {
		out = append(out, v)
	}
	return out
}

func trimVersion(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
