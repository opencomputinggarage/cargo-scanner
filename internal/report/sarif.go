package report

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/byeonggi/cargo-scanner/internal/core"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifText         `json:"shortDescription,omitempty"`
	Properties       sarifRuleProperty `json:"properties"`
	HelpURI          string            `json:"helpUri,omitempty"`
}

type sarifRuleProperty struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func WriteSARIF(w io.Writer, reports []core.Report) error {
	rulesByID := map[string]sarifRule{}
	var results []sarifResult
	scannerName := "cargo-scanner"
	scannerVersion := ""
	for _, report := range reports {
		if report.Scanner.Name != "" {
			scannerName = "cargo-scanner/" + report.Scanner.Name
		}
		if report.Scanner.Version != "" {
			scannerVersion = report.Scanner.Version
		}
		for _, finding := range report.Findings {
			rulesByID[finding.ID] = sarifRule{
				ID:               finding.ID,
				Name:             finding.ID,
				ShortDescription: sarifText{Text: finding.ID},
				Properties: sarifRuleProperty{
					SecuritySeverity: sarifSecuritySeverity(finding.Severity),
					Tags:             []string{"security", string(finding.Type), string(finding.Severity)},
				},
				HelpURI: finding.URL,
			}
			results = append(results, sarifResult{
				RuleID:  finding.ID,
				Level:   sarifLevel(finding.Severity),
				Message: sarifText{Text: sarifMessage(finding)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: sarifURI(report, finding)},
					},
				}},
			})
		}
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, rule := range rulesByID {
		rules = append(rules, rule)
	}
	if results == nil {
		results = []sarifResult{}
	}
	doc := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           scannerName,
				Version:        scannerVersion,
				InformationURI: "https://github.com/byeonggi/cargo-scanner",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifSecuritySeverity(sev core.Severity) string {
	switch sev {
	case core.SeverityCritical:
		return "9.0"
	case core.SeverityHigh:
		return "7.0"
	case core.SeverityMedium:
		return "5.0"
	case core.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func sarifLevel(sev core.Severity) string {
	switch sev {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium, core.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

func sarifMessage(f core.Finding) string {
	parts := []string{f.ID}
	if f.PackageName != "" {
		parts = append(parts, "in "+f.PackageName)
	}
	if f.PackageVersion != "" {
		parts = append(parts, f.PackageVersion)
	}
	if len(f.FixedVersions) > 0 {
		parts = append(parts, "fixed in "+strings.Join(f.FixedVersions, ", "))
	}
	return strings.Join(parts, " ")
}

func sarifURI(report core.Report, finding core.Finding) string {
	if finding.Location != "" {
		return finding.Location
	}
	return report.Target.Path
}
