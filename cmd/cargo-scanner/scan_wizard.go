package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/opencomputinggarage/cargo-scanner/internal/ui"
)

type scanWizardOptions struct {
	Target     string
	Recursive  bool
	Scanner    string
	Runtime    string
	Format     string
	FailOn     string
	Output     string
	SBOMOutput string
}

func shouldRunScanWizard(stdout, stderr io.Writer) bool {
	return isInteractiveTerminal(stderr) && isInteractiveTerminal(stdout) && isInteractiveTerminal(os.Stdin)
}

func runScanWizard(ctx context.Context, stdout, stderr io.Writer) int {
	targetChoice := "current"
	opts := scanWizardOptions{
		Target:  ".",
		Scanner: "grype",
		Runtime: "auto",
		Format:  "text",
		FailOn:  "",
	}

	_, _ = fmt.Fprintln(stderr, ui.Title("Cargo Scanner"))
	_, _ = fmt.Fprintln(stderr, ui.Muted("I will ask only what is needed, then start the scan."))
	_, _ = fmt.Fprintln(stderr)

	targetOptions := []huh.Option[string]{
		huh.NewOption("Current folder (.)", "current"),
		huh.NewOption("Enter another path", "custom"),
	}

	var err error
	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("What should be scanned?").
			Description("Choose a common target or enter a path.").
			Options(targetOptions...).
			Value(&targetChoice),
	); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}
	switch targetChoice {
	case "current":
		opts.Target = "."
	case "custom":
		opts.Target = "~/Downloads"
		if err := runScanWizardStep(
			huh.NewInput().
				Title("Enter the file or folder path").
				Description("Use an absolute path, relative path, or ~/Downloads.").
				Value(&opts.Target).
				Validate(func(value string) error {
					value = strings.TrimSpace(value)
					if value == "" {
						return fmt.Errorf("target path is required")
					}
					if _, err := os.Stat(expandHome(value)); err != nil {
						return err
					}
					return nil
				}),
		); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
	}

	targetInfo, err := os.Stat(expandHome(strings.TrimSpace(opts.Target)))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("error"), err)
		return 1
	}
	if targetInfo.IsDir() {
		_, _ = fmt.Fprintf(stderr, "%s %s\n\n", ui.Section("Folder detected"), ui.Muted("Recursive scan uses -R / --recursive."))
		opts.Recursive = true
		if err := runScanWizardStep(
			huh.NewConfirm().
				Title("Scan recursively?").
				Description("Recursive scan uses -R / --recursive and scans files inside this folder.").
				Affirmative("Yes, scan files inside this folder").
				Negative("No, folder only").
				Value(&opts.Recursive),
		); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
	} else {
		_, _ = fmt.Fprintf(stderr, "%s %s\n\n", ui.Section("File detected"), ui.Muted("Recursive scan is not needed."))
	}

	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("What kind of result do you need?").
			Description("Vulnerability scanners produce findings. Syft produces a CycloneDX SBOM.").
			Options(
				huh.NewOption("Grype - vulnerabilities", "grype"),
				huh.NewOption("Trivy - vulnerabilities", "trivy"),
				huh.NewOption("Syft - SBOM inventory", "syft"),
			).
			Value(&opts.Scanner),
	); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}

	if opts.Scanner == "syft" {
		return runSBOMWizard(ctx, opts, stdout, stderr)
	}
	return runVulnerabilityWizard(ctx, opts, stdout, stderr)
}

func runVulnerabilityWizard(ctx context.Context, opts scanWizardOptions, stdout, stderr io.Writer) int {
	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("Should the scan fail on severity?").
			Description("Useful for CI or release checks. You can leave this disabled for local review.").
			Options(
				huh.NewOption("Do not fail automatically", ""),
				huh.NewOption("Fail on high or critical", "high"),
				huh.NewOption("Fail on critical only", "critical"),
				huh.NewOption("Fail on medium or higher", "medium"),
			).
			Value(&opts.FailOn),
	); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}

	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("How should results be shown?").
			Options(
				huh.NewOption("Show readable report here", "text"),
				huh.NewOption("Save JSON report", "json"),
				huh.NewOption("Save SARIF report", "sarif"),
			).
			Value(&opts.Format),
	); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}

	if opts.Format != "text" {
		opts.Output = defaultReportPath(opts.Format)
		if err := runScanWizardStep(
			huh.NewInput().
				Title("Where should the report be saved?").
				Description("Press Enter to use the suggested file name.").
				Value(&opts.Output).
				Validate(func(value string) error {
					if strings.TrimSpace(value) == "" {
						return fmt.Errorf("report file is required")
					}
					return nil
				}),
		); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
	}

	args := opts.args()
	_, _ = fmt.Fprintf(stderr, "\n%s %s\n\n", ui.Section("Running"), ui.Code("cargo-scanner scan "+strings.Join(shellQuoteArgs(args), " ")))
	return runScan(ctx, args, stdout, stderr)
}

func runSBOMWizard(ctx context.Context, opts scanWizardOptions, stdout, stderr io.Writer) int {
	outputChoice := "print"
	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("How should the SBOM be produced?").
			Description("Syft creates package inventory. Use JSON report only when automation needs Cargo Scanner metadata.").
			Options(
				huh.NewOption("Print CycloneDX SBOM here", "print"),
				huh.NewOption("Save CycloneDX SBOM file", "sbom"),
				huh.NewOption("Save normalized JSON report", "json"),
			).
			Value(&outputChoice),
	); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}

	switch outputChoice {
	case "sbom":
		opts.SBOMOutput = "sbom.cdx.json"
		if err := runScanWizardStep(
			huh.NewInput().
				Title("Where should the SBOM be saved?").
				Description("This writes the raw CycloneDX JSON document.").
				Value(&opts.SBOMOutput).
				Validate(func(value string) error {
					if strings.TrimSpace(value) == "" {
						return fmt.Errorf("SBOM file is required")
					}
					return nil
				}),
		); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
	case "json":
		opts.Format = "json"
		opts.Output = defaultReportPath("json")
		if err := runScanWizardStep(
			huh.NewInput().
				Title("Where should the normalized report be saved?").
				Description("This writes Cargo Scanner metadata around the SBOM operation.").
				Value(&opts.Output).
				Validate(func(value string) error {
					if strings.TrimSpace(value) == "" {
						return fmt.Errorf("report file is required")
					}
					return nil
				}),
		); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
	default:
		opts.Format = "text"
	}

	args := opts.sbomArgs()
	_, _ = fmt.Fprintf(stderr, "\n%s %s\n\n", ui.Section("Running"), ui.Code("cargo-scanner sbom "+strings.Join(shellQuoteArgs(args), " ")))
	return runSBOM(ctx, args, stdout, stderr)
}

func runScanWizardStep(field huh.Field) error {
	return field.
		WithTheme(huh.ThemeCharm()).
		WithWidth(72).
		Run()
}

func defaultReportPath(format string) string {
	switch format {
	case "sarif":
		return "cargo-scanner.sarif"
	case "json":
		return "cargo-scanner.json"
	default:
		return ""
	}
}

func (o scanWizardOptions) args() []string {
	args := []string{
		"--scanner", o.Scanner,
		"--runtime", o.Runtime,
		"--format", o.Format,
	}
	if o.Recursive {
		args = append(args, "--recursive")
	}
	if o.FailOn != "" {
		args = append(args, "--fail-on", o.FailOn)
	}
	if strings.TrimSpace(o.Output) != "" {
		args = append(args, "--output", strings.TrimSpace(o.Output))
	}
	return append(args, expandHome(strings.TrimSpace(o.Target)))
}

func (o scanWizardOptions) sbomArgs() []string {
	args := []string{
		"--scanner", o.Scanner,
		"--runtime", o.Runtime,
		"--format", o.Format,
	}
	if o.Recursive {
		args = append(args, "--recursive")
	}
	if strings.TrimSpace(o.Output) != "" {
		args = append(args, "--output", strings.TrimSpace(o.Output))
	}
	if strings.TrimSpace(o.SBOMOutput) != "" {
		args = append(args, "--sbom-output", strings.TrimSpace(o.SBOMOutput))
	}
	return append(args, expandHome(strings.TrimSpace(o.Target)))
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + path[1:]
		}
	}
	return path
}

func expandHomeArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i, arg := range out {
		out[i] = expandHome(arg)
	}
	return out
}

func shellQuoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = shellQuote(arg)
	}
	return out
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if strings.IndexFunc(arg, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '=' || r == '~' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) == -1 {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}
