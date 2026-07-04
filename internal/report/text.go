package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

func WriteText(w io.Writer, r core.Report) error {
	_, err := fmt.Fprintf(w, "Cargo Scanner\n\nTarget:  %s\nScanner: %s", r.Target.Path, r.Scanner.Name)
	if err != nil {
		return err
	}
	if r.Scanner.Version != "" {
		if _, err := fmt.Fprintf(w, " %s", r.Scanner.Version); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, " (%s)\nStatus:  %s\n\n", r.Scanner.Runtime, r.Status); err != nil {
		return err
	}
	if r.Status == core.StatusFailed {
		_, err := fmt.Fprintf(w, "Error: %s\n", r.Error)
		return err
	}
	s := r.Summary
	if _, err := fmt.Fprintf(w, "Findings: %d total\n", s.Total); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Critical:   %d\n  High:       %d\n  Medium:     %d\n  Low:        %d\n  Negligible: %d\n  Unknown:    %d\n\n", s.Critical, s.High, s.Medium, s.Low, s.Negligible, s.Unknown); err != nil {
		return err
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
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
	if _, err := fmt.Fprintln(w, "Top findings:"); err != nil {
		return err
	}
	for _, f := range findings[:limit] {
		fixed := ""
		if len(f.FixedVersions) > 0 {
			fixed = " fixed in " + f.FixedVersions[0]
		}
		if _, err := fmt.Fprintf(w, "- %-8s %-18s %s %s%s\n", f.Severity, f.ID, f.PackageName, f.PackageVersion, fixed); err != nil {
			return err
		}
	}
	return nil
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
