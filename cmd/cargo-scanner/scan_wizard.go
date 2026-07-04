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
	Target    string
	Recursive bool
	Scanner   string
	Runtime   string
	Format    string
	FailOn    string
	Output    string
}

func shouldRunScanWizard(stdout, stderr io.Writer) bool {
	return isInteractiveTerminal(stderr) && isInteractiveTerminal(stdout) && isInteractiveTerminal(os.Stdin)
}

func runScanWizard(ctx context.Context, stdout, stderr io.Writer) int {
	downloads := defaultDownloadsPath()
	targetChoice := "current"
	if downloads != "" {
		targetChoice = "downloads"
	}
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
	}
	if downloads != "" {
		targetOptions = append([]huh.Option[string]{
			huh.NewOption("Downloads folder ("+displayScanPath(downloads)+")", "downloads"),
		}, targetOptions...)
	}
	targetOptions = append(targetOptions, huh.NewOption("Enter another path", "custom"))

	if err := runScanWizardStep(stderr,
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
	case "downloads":
		opts.Target = downloads
	case "current":
		opts.Target = "."
	case "custom":
		if err := runScanWizardStep(stderr,
			huh.NewInput().
				Title("Enter the file or folder path").
				Placeholder("~/Downloads").
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
		recursiveChoice := "recursive"
		if err := runScanWizardStep(stderr,
			huh.NewSelect[string]().
				Title("How should this folder be scanned?").
				Options(
					huh.NewOption("Recursive scan (-R): include files inside this folder", "recursive"),
					huh.NewOption("Folder only: do not walk into files", "single"),
				).
				Value(&recursiveChoice),
		); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
		opts.Recursive = recursiveChoice == "recursive"
	} else {
		_, _ = fmt.Fprintf(stderr, "%s %s\n\n", ui.Section("File detected"), ui.Muted("Recursive scan is not needed."))
	}

	if err := runScanWizardStep(stderr,
		huh.NewSelect[string]().
			Title("Which scanner should be used?").
			Description("Grype is the default vulnerability scanner. Syft is best for SBOM inventory.").
			Options(
				huh.NewOption("Grype - vulnerabilities", "grype"),
				huh.NewOption("Trivy - vulnerabilities", "trivy"),
				huh.NewOption("Syft - package inventory", "syft"),
			).
			Value(&opts.Scanner),
	); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}

	if err := runScanWizardStep(stderr,
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
		if err := runScanWizardStep(stderr,
			huh.NewInput().
				Title("Where should the report be saved?").
				Placeholder(opts.Output).
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

func runScanWizardStep(stderr io.Writer, field huh.Field) error {
	return huh.NewForm(huh.NewGroup(field)).
		WithTheme(huh.ThemeCharm()).
		WithWidth(72).
		WithInput(os.Stdin).
		WithOutput(stderr).
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

func defaultDownloadsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := home + "/Downloads"
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return path
	}
	return ""
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
