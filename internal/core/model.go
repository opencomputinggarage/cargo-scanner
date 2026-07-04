package core

import (
	"fmt"
	"strings"
	"time"
)

type Severity string

const (
	SeverityUnknown    Severity = "unknown"
	SeverityNegligible Severity = "negligible"
	SeverityLow        Severity = "low"
	SeverityMedium     Severity = "medium"
	SeverityHigh       Severity = "high"
	SeverityCritical   Severity = "critical"
)

func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "negligible":
		return SeverityNegligible
	default:
		return SeverityUnknown
	}
}

func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityNegligible:
		return 1
	default:
		return 0
	}
}

func ParseFailSeverity(s string) (Severity, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	sev := ParseSeverity(s)
	if sev == SeverityUnknown && !strings.EqualFold(s, string(SeverityUnknown)) {
		return "", fmt.Errorf("unknown severity %q", s)
	}
	return sev, nil
}

type Target struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

type ScannerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Runtime string `json:"runtime"`
}

type Status string

const (
	StatusCompleted     Status = "completed"
	StatusFailed        Status = "failed"
	StatusNotApplicable Status = "not_applicable"
)

type FindingType string

const (
	FindingVulnerability FindingType = "vulnerability"
	FindingSecret        FindingType = "secret"
	FindingMisconfig     FindingType = "misconfiguration"
	FindingLicense       FindingType = "license"
)

type Finding struct {
	ID             string      `json:"id"`
	Type           FindingType `json:"type"`
	Severity       Severity    `json:"severity"`
	PackageName    string      `json:"package_name,omitempty"`
	PackageVersion string      `json:"package_version,omitempty"`
	PackageType    string      `json:"package_type,omitempty"`
	FixedVersions  []string    `json:"fixed_versions,omitempty"`
	Source         string      `json:"source,omitempty"`
	URL            string      `json:"url,omitempty"`
	Location       string      `json:"location,omitempty"`
}

type Summary struct {
	Total      int `json:"total"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
}

func (s Summary) MaxSeverity() Severity {
	switch {
	case s.Critical > 0:
		return SeverityCritical
	case s.High > 0:
		return SeverityHigh
	case s.Medium > 0:
		return SeverityMedium
	case s.Low > 0:
		return SeverityLow
	case s.Negligible > 0:
		return SeverityNegligible
	default:
		return SeverityUnknown
	}
}

type RawOutput struct {
	Tool    string `json:"tool"`
	Format  string `json:"format"`
	Path    string `json:"path,omitempty"`
	Content string `json:"content,omitempty"`
}

type SBOM struct {
	Format           string    `json:"format"`
	Generator        string    `json:"generator"`
	GeneratorVersion string    `json:"generator_version,omitempty"`
	ContentDigest    string    `json:"content_digest,omitempty"`
	ContentJSON      string    `json:"content_json,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type Report struct {
	Target    Target      `json:"target"`
	Scanner   ScannerInfo `json:"scanner"`
	Status    Status      `json:"status"`
	Summary   Summary     `json:"summary"`
	Findings  []Finding   `json:"findings,omitempty"`
	SBOM      *SBOM       `json:"sbom,omitempty"`
	Raw       []RawOutput `json:"raw,omitempty"`
	Error     string      `json:"error,omitempty"`
	StartedAt time.Time   `json:"started_at"`
	EndedAt   time.Time   `json:"ended_at"`
}

func Summarize(findings []Finding) Summary {
	out := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			out.Critical++
		case SeverityHigh:
			out.High++
		case SeverityMedium:
			out.Medium++
		case SeverityLow:
			out.Low++
		case SeverityNegligible:
			out.Negligible++
		default:
			out.Unknown++
		}
	}
	return out
}
