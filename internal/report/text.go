package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
	"github.com/opencomputinggarage/cargo-scanner/internal/ui"
)

var (
	reportPanelStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
	reportLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	reportValueStyle = lipgloss.NewStyle().Bold(true)
)

func WriteText(w io.Writer, r core.Report) error {
	if _, err := fmt.Fprintln(w, reportHeader(r)); err != nil {
		return err
	}
	if r.Status == core.StatusFailed {
		_, err := fmt.Fprintf(w, "%s: %s\n", ui.Status("error"), r.Error)
		return err
	}
	s := r.Summary
	if _, err := fmt.Fprintf(w, "%s: %d total\n", ui.Section("Findings"), s.Total); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, summaryTable(s)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, ui.Status("OK")+" No findings.")
		return err
	}
	findings := append([]core.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return core.SeverityRank(findings[i].Severity) > core.SeverityRank(findings[j].Severity)
	})
	limit := 10
	if len(findings) < limit {
		limit = len(findings)
	}
	if _, err := fmt.Fprintln(w, ui.Section("Top findings")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, findingsTable(findings[:limit])); err != nil {
		return err
	}
	return nil
}

func reportHeader(r core.Report) string {
	scanner := r.Scanner.Name
	if r.Scanner.Version != "" {
		scanner += " " + r.Scanner.Version
	}
	lines := []string{
		ui.Title("Cargo Scanner"),
		"",
		reportLine("Target", ui.Code(r.Target.Path)),
		reportLine("Scanner", scanner),
		reportLine("Runtime", r.Scanner.Runtime),
		reportLine("Status", ui.Status(string(r.Status))),
		reportLine("Started", r.StartedAt.Format("2006-01-02 15:04:05 UTC")),
		reportLine("Duration", r.EndedAt.Sub(r.StartedAt).String()),
	}
	return reportPanelStyle.Render(strings.Join(lines, "\n"))
}

func reportLine(label, value string) string {
	return reportLabelStyle.Render(label+": ") + reportValueStyle.Render(value)
}

func summaryTable(s core.Summary) string {
	return table.New().
		Headers("Severity", "Count").
		Rows(
			[]string{ui.Severity("Critical"), strconv.Itoa(s.Critical)},
			[]string{ui.Severity("High"), strconv.Itoa(s.High)},
			[]string{ui.Severity("Medium"), strconv.Itoa(s.Medium)},
			[]string{ui.Severity("Low"), strconv.Itoa(s.Low)},
			[]string{ui.Severity("Negligible"), strconv.Itoa(s.Negligible)},
			[]string{"Unknown", strconv.Itoa(s.Unknown)},
		).
		Render()
}

func findingsTable(findings []core.Finding) string {
	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		fixed := ""
		if len(f.FixedVersions) > 0 {
			fixed = f.FixedVersions[0]
		}
		pkg := strings.TrimSpace(f.PackageName + " " + f.PackageVersion)
		rows = append(rows, []string{
			ui.Severity(string(f.Severity)),
			f.ID,
			pkg,
			fixed,
		})
	}
	return table.New().
		Headers("Severity", "ID", "Package", "Fixed").
		Rows(rows...).
		Render()
}

func WriteTextList(w io.Writer, reports []core.Report) error {
	for i, r := range reports {
		if i > 0 {
			if _, err := fmt.Fprintln(w, "\n---"); err != nil {
				return err
			}
		}
		if err := WriteText(w, r); err != nil {
			return err
		}
	}
	return nil
}
