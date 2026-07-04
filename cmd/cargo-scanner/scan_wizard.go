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
	opts := scanWizardOptions{
		Target:  ".",
		Scanner: "grype",
		Runtime: "auto",
		Format:  "text",
		FailOn:  "",
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Cargo Scanner").
				Description("Build a scan command interactively. The scan will start after confirmation."),
			huh.NewInput().
				Title("Target path").
				Description("File or directory to scan. Use recursive mode for folders.").
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
			huh.NewConfirm().
				Title("Scan directories recursively?").
				Description("Recommended for Downloads, extracted archives, and project folders.").
				Value(&opts.Recursive),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Scanner").
				Options(
					huh.NewOption("Grype - vulnerability scan", "grype"),
					huh.NewOption("Trivy - vulnerability scan", "trivy"),
					huh.NewOption("Syft - SBOM inventory", "syft"),
				).
				Value(&opts.Scanner),
			huh.NewSelect[string]().
				Title("Runtime").
				Options(
					huh.NewOption("Auto - choose best available", "auto"),
					huh.NewOption("Managed - bundled tools", "managed"),
					huh.NewOption("Docker - isolated runtime", "docker"),
					huh.NewOption("Native - system PATH", "native"),
				).
				Value(&opts.Runtime),
			huh.NewSelect[string]().
				Title("Report format").
				Options(
					huh.NewOption("Text - human readable", "text"),
					huh.NewOption("JSON - automation", "json"),
					huh.NewOption("SARIF - code scanning", "sarif"),
				).
				Value(&opts.Format),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Fail threshold").
				Description("Choose when the command should exit non-zero.").
				Options(
					huh.NewOption("Do not fail on severity", ""),
					huh.NewOption("Critical", "critical"),
					huh.NewOption("High or above", "high"),
					huh.NewOption("Medium or above", "medium"),
					huh.NewOption("Low or above", "low"),
				).
				Value(&opts.FailOn),
			huh.NewInput().
				Title("Write report to file").
				Description("Optional. Leave empty to print to the terminal.").
				Placeholder("report.json").
				Value(&opts.Output),
			huh.NewConfirm().
				Title("Start scan now?").
				Affirmative("Start").
				Negative("Cancel").
				Validate(func(confirmed bool) error {
					if !confirmed {
						return fmt.Errorf("scan cancelled")
					}
					return nil
				}),
		),
	).
		WithTheme(huh.ThemeCharm()).
		WithWidth(78).
		WithInput(os.Stdin).
		WithOutput(stderr)
	if err := form.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}
	args := opts.args()
	_, _ = fmt.Fprintf(stderr, "\n%s %s\n\n", ui.Section("Running"), ui.Code("cargo-scanner scan "+strings.Join(shellQuoteArgs(args), " ")))
	return runScan(ctx, args, stdout, stderr)
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
