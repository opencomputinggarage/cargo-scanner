package grype

import (
	"encoding/json"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

type document struct {
	Matches []match `json:"matches"`
}

type match struct {
	Vulnerability vulnerability `json:"vulnerability"`
	Artifact      artifact      `json:"artifact"`
	Details       []detail      `json:"matchDetails"`
}

type vulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	DataSource  string   `json:"dataSource"`
	URLs        []string `json:"urls"`
	Fix         fix      `json:"fix"`
	Description string   `json:"description"`
}

type fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type artifact struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Type      string     `json:"type"`
	PURL      string     `json:"purl"`
	Locations []location `json:"locations"`
}

type location struct {
	Path string `json:"path"`
}

type detail struct {
	Type string `json:"type"`
}

func Parse(data []byte) ([]core.Finding, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	findings := make([]core.Finding, 0, len(doc.Matches))
	for _, m := range doc.Matches {
		f := core.Finding{
			ID:             m.Vulnerability.ID,
			Type:           core.FindingVulnerability,
			Severity:       core.ParseSeverity(m.Vulnerability.Severity),
			PackageName:    m.Artifact.Name,
			PackageVersion: m.Artifact.Version,
			PackageType:    m.Artifact.Type,
			FixedVersions:  m.Vulnerability.Fix.Versions,
			Source:         m.Vulnerability.DataSource,
		}
		if len(m.Vulnerability.URLs) > 0 {
			f.URL = m.Vulnerability.URLs[0]
		}
		if len(m.Artifact.Locations) > 0 {
			f.Location = m.Artifact.Locations[0].Path
		}
		findings = append(findings, f)
	}
	return findings, nil
}
