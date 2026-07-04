package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/charmbracelet/lipgloss/table"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
	"github.com/opencomputinggarage/cargo-scanner/internal/ui"
)

func WriteText(w io.Writer, r core.Report) error {
	_, err := fmt.Fprintf(w, "%s\n\nTarget:  %s\nScanner: %s", ui.Title("Cargo Scanner"), ui.Code(r.Target.Path), r.Scanner.Name)
	if err != nil {
		return err
	}
	if r.Scanner.Version != "" {
		if _, err := fmt.Fprintf(w, " %s", r.Scanner.Version); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, " (%s)\nStatus:  %s\n\n", r.Scanner.Runtime, ui.Status(string(r.Status))); err != nil {
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
	if _, err := fmt.Fprintln(w, ui.Section("Top findings")+":"); err != nil {
		return err
	}
	for _, f := range findings[:limit] {
		fixed := ""
		if len(f.FixedVersions) > 0 {
			fixed = " fixed in " + f.FixedVersions[0]
		}
		if _, err := fmt.Fprintf(w, "- %-8s %-18s %s %s%s\n", ui.Severity(string(f.Severity)), f.ID, f.PackageName, f.PackageVersion, fixed); err != nil {
			return err
		}
	}
	return nil
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
