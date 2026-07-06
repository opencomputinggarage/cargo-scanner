package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	bubbletable "github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/config"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

func runSBOM(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", ".cargo-scanner.yaml", "config file path")
	scannerName := fs.String("scanner", "", "SBOM scanner to use")
	runtimeName := fs.String("runtime", "", "runtime to use: auto, docker, native")
	dockerImage := fs.String("docker-image", "", "scanner runtime Docker image")
	format := fs.String("format", "text", "output format: text, json, sarif")
	jsonOut := fs.Bool("json", false, "write normalized JSON")
	outputPath := fs.String("output", "", "write normalized report to file")
	sbomOutputPath := fs.String("sbom-output", "", "write raw SBOM content to file")
	timeout := fs.Duration("timeout", 15*time.Minute, "scan timeout")
	recursive := fs.Bool("recursive", false, "scan files under a directory")
	includeRaw := fs.String("include", "", "comma-separated include globs")
	excludeRaw := fs.String("exclude", "", "comma-separated exclude globs")
	fs.StringVar(scannerName, "s", *scannerName, "alias for --scanner")
	fs.StringVar(runtimeName, "u", *runtimeName, "alias for --runtime")
	fs.StringVar(format, "f", *format, "alias for --format")
	fs.BoolVar(jsonOut, "j", *jsonOut, "alias for --json")
	fs.StringVar(outputPath, "o", *outputPath, "alias for --output")
	fs.StringVar(sbomOutputPath, "b", *sbomOutputPath, "alias for --sbom-output")
	fs.DurationVar(timeout, "t", *timeout, "alias for --timeout")
	fs.BoolVar(recursive, "R", *recursive, "alias for --recursive")
	fs.StringVar(includeRaw, "i", *includeRaw, "alias for --include")
	fs.StringVar(excludeRaw, "x", *excludeRaw, "alias for --exclude")
	normalizedArgs, err := normalizeScanArgs(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := fs.Parse(normalizedArgs); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "sbom requires exactly one target path")
		_, _ = fmt.Fprintln(stderr, "example: cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json")
		return 2
	}
	cfg, err := config.LoadLayered(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	applyDefaults(scannerName, runtimeName, format, timeout, &cfg, "syft")
	include := mergeList(cfg.Include, splitCSV(*includeRaw))
	exclude := mergeList(cfg.Exclude, splitCSV(*excludeRaw))
	targets, err := core.DiscoverTargetsWithFilters(fs.Arg(0), *recursive, include, exclude)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "inspect target: %v\n", err)
		return 1
	}
	scanner, err := scannerByName(*scannerName)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	generator, ok := scanner.(core.SBOMGenerator)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "scanner %q does not support SBOM generation\n", scanner.Name())
		return 2
	}
	rt, err := runtimeByName(ctx, *runtimeName, *dockerImage, scanner.Name())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if scanner.Name() == "trivy" {
		_, _ = fmt.Fprintln(stderr, "Trivy may download or update its vulnerability database on first use.")
	}
	scanCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var reports []core.Report
	exitCode := 0
	for _, target := range targets {
		result, err := generator.GenerateSBOM(scanCtx, rt, target, core.ScanOptions{})
		reports = append(reports, result)
		if err != nil {
			exitCode = 1
			if result.Error != "" {
				_, _ = fmt.Fprintf(stderr, "%s\n", result.Error)
			} else {
				_, _ = fmt.Fprintf(stderr, "sbom failed: %v\n", err)
			}
			printFailureHint(stderr, err)
		}
	}
	if *jsonOut {
		*format = "json"
	}
	if strings.EqualFold(strings.TrimSpace(*format), "text") && (*outputPath != "" || len(reports) != 1) {
		if err := writeSBOMTextReports(*outputPath, stdout, reports); err != nil {
			_, _ = fmt.Fprintf(stderr, "write report: %v\n", err)
			return 1
		}
		return exitCode
	}
	if *outputPath != "" || *format != "text" || len(reports) != 1 {
		if err := writeReports(*outputPath, stdout, reports, *format); err != nil {
			_, _ = fmt.Fprintf(stderr, "write report: %v\n", err)
			return 1
		}
		return exitCode
	}
	if len(reports) == 1 && reports[0].SBOM != nil {
		if *sbomOutputPath != "" {
			if err := os.WriteFile(*sbomOutputPath, []byte(reports[0].SBOM.ContentJSON), 0o600); err != nil {
				_, _ = fmt.Fprintf(stderr, "write sbom: %v\n", err)
				return 1
			}
		} else {
			if shouldShowSBOMViewer(stdout, os.Stdin, *sbomOutputPath, *format) {
				if err := showSBOMViewer(stdout, reports[0]); err != nil {
					_, _ = fmt.Fprintf(stderr, "show sbom: %v\n", err)
					return 1
				}
			} else {
				_, _ = fmt.Fprintln(stdout, sbomTextView(reports[0], 100))
			}
		}
	}
	return exitCode
}

func shouldShowSBOMViewer(stdout io.Writer, stdin *os.File, sbomOutputPath, format string) bool {
	return strings.TrimSpace(sbomOutputPath) == "" &&
		strings.EqualFold(strings.TrimSpace(format), "text") &&
		isInteractiveTerminal(stdout) &&
		isattyFile(stdin)
}

func writeSBOMTextReports(path string, stdout io.Writer, reports []core.Report) error {
	var w io.Writer = stdout
	if path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		w = file
	}
	for i, report := range reports {
		if i > 0 {
			if _, err := fmt.Fprintln(w, "\n---"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, sbomTextView(report, 100)); err != nil {
			return err
		}
	}
	return nil
}

type cyclonedxSummary struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	SerialNumber string                `json:"serialNumber"`
	Metadata     cyclonedxMetadata     `json:"metadata"`
	Components   []cyclonedxComponent  `json:"components"`
	Dependencies []cyclonedxDependency `json:"dependencies"`
}

type cyclonedxMetadata struct {
	Component cyclonedxComponent `json:"component"`
}

type cyclonedxComponent struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	PURL       string `json:"purl"`
	BOMRef     string `json:"bom-ref"`
	Publisher  string `json:"publisher"`
	Scope      string `json:"scope"`
	PackageURL string `json:"packageUrl"`
}

type cyclonedxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func sbomTextView(r core.Report, width int) string {
	contentWidth := maxInt(40, width-resultFrameStyle.GetHorizontalFrameSize())
	sections := []string{sbomHero(r, contentWidth), sbomMeta(r, contentWidth)}
	if r.Status == core.StatusFailed {
		sections = append(sections, resultBadStyle.Render("Error")+"\n"+emptyDisplay(r.Error))
		return resultFrameStyle.Width(width).Render(strings.Join(sections, "\n\n"))
	}
	if r.SBOM == nil {
		sections = append(sections, resultMutedStyle.Render("No SBOM content."))
		return resultFrameStyle.Width(width).Render(strings.Join(sections, "\n\n"))
	}
	summary, err := parseCycloneDXSummary(r.SBOM.ContentJSON)
	if err != nil {
		sections = append(sections, resultWarnStyle.Render("SBOM created, but summary parsing failed."), err.Error())
		return resultFrameStyle.Width(width).Render(strings.Join(sections, "\n\n"))
	}
	sections = append(sections, sbomSummarySection(r, summary, contentWidth), sbomComponentsSection(summary.Components, contentWidth))
	return resultFrameStyle.Width(width).Render(strings.Join(sections, "\n\n"))
}

func sbomHero(r core.Report, width int) string {
	status := resultGoodStyle.Render(strings.ToUpper(string(r.Status)))
	if r.Status == core.StatusFailed {
		status = resultBadStyle.Render(strings.ToUpper(string(r.Status)))
	}
	left := lipgloss.NewStyle().Width(maxInt(12, width-lipgloss.Width(status)-2)).Render(resultTitleStyle.Render("SBOM") + "\n" + resultMutedStyle.Render(r.Target.Path))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, status)
}

func sbomMeta(r core.Report, width int) string {
	scanner := strings.TrimSpace(r.Scanner.Name + " " + r.Scanner.Version)
	if scanner == "" {
		scanner = "-"
	}
	duration := r.EndedAt.Sub(r.StartedAt).String()
	if r.EndedAt.IsZero() || r.StartedAt.IsZero() {
		duration = "-"
	}
	cardWidth := maxInt(12, (width-2)/3)
	return lipgloss.JoinHorizontal(lipgloss.Top,
		resultMetric("Scanner", scanner, cardWidth),
		resultMetric("Runtime", emptyDisplay(r.Scanner.Runtime), cardWidth),
		resultMetric("Duration", duration, cardWidth),
	)
}

func sbomSummarySection(r core.Report, summary cyclonedxSummary, width int) string {
	format := emptyDisplay(summary.BOMFormat)
	if summary.SpecVersion != "" {
		format += " " + summary.SpecVersion
	}
	root := summary.Metadata.Component.Name
	if root == "" {
		root = r.Target.Path
	}
	digest := "-"
	if r.SBOM != nil {
		digest = strings.TrimPrefix(r.SBOM.ContentDigest, "sha256:")
	}
	rows := []bubbletable.Row{
		{"Format", format},
		{"Root", emptyDisplay(root)},
		{"Components", strconv.Itoa(len(summary.Components))},
		{"Dependencies", strconv.Itoa(len(summary.Dependencies))},
		{"Digest", digest},
	}
	cols := []bubbletable.Column{
		{Title: "Field", Width: 14},
		{Title: "Value", Width: maxInt(20, width-18)},
	}
	return resultTitleStyle.Render("Summary") + "\n" + resultTable(cols, rows, width)
}

func sbomComponentsSection(components []cyclonedxComponent, width int) string {
	if len(components) == 0 {
		return resultTitleStyle.Render("Components") + "\n" + resultMutedStyle.Render("No components listed.")
	}
	components = append([]cyclonedxComponent(nil), components...)
	sort.SliceStable(components, func(i, j int) bool {
		if components[i].Type != components[j].Type {
			return components[i].Type < components[j].Type
		}
		return components[i].Name < components[j].Name
	})
	limit := minInt(10, len(components))
	rows := make([]bubbletable.Row, 0, limit)
	for _, component := range components[:limit] {
		version := component.Version
		if version == "" {
			version = "-"
		}
		purl := component.PURL
		if purl == "" {
			purl = component.PackageURL
		}
		rows = append(rows, bubbletable.Row{
			emptyDisplay(component.Type),
			emptyDisplay(component.Name),
			version,
			emptyDisplay(purl),
		})
	}
	cols := []bubbletable.Column{
		{Title: "Type", Width: 12},
		{Title: "Name", Width: maxInt(18, width/3)},
		{Title: "Version", Width: 16},
		{Title: "PURL", Width: maxInt(18, width-width/3-36)},
	}
	note := ""
	if len(components) > limit {
		note = "\n" + resultMutedStyle.Render(fmt.Sprintf("Showing top %d of %d components. Save SBOM for the full CycloneDX document.", limit, len(components)))
	}
	return resultTitleStyle.Render("Components") + "\n" + resultTable(cols, rows, width) + note
}

func parseCycloneDXSummary(content string) (cyclonedxSummary, error) {
	var summary cyclonedxSummary
	if err := json.Unmarshal([]byte(content), &summary); err != nil {
		return summary, err
	}
	return summary, nil
}
