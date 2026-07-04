package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

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

type wizardChoice struct {
	Label string
	Value string
}

func shouldRunScanWizard(stdout, stderr io.Writer) bool {
	return isInteractiveTerminal(stderr) && isInteractiveTerminal(stdout) && isInteractiveTerminal(os.Stdin)
}

func runScanWizard(ctx context.Context, stdout, stderr io.Writer) int {
	reader := bufio.NewReader(os.Stdin)
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

	targetOptions := []wizardChoice{
		{Label: "Current folder (.)", Value: "current"},
	}
	if downloads != "" {
		targetOptions = append([]wizardChoice{
			{Label: "Downloads folder (" + displayScanPath(downloads) + ")", Value: "downloads"},
		}, targetOptions...)
	}
	targetOptions = append(targetOptions, wizardChoice{Label: "Enter another path", Value: "custom"})

	var err error
	targetChoice, err = askWizardChoice(stderr, reader, "What should be scanned?", "Choose a common target or enter a path.", targetOptions, targetChoice)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}
	switch targetChoice {
	case "downloads":
		opts.Target = downloads
	case "current":
		opts.Target = "."
	case "custom":
		opts.Target, err = askWizardInput(stderr, reader, "Enter the file or folder path", "Use an absolute path, relative path, or ~/Downloads.", "~/Downloads", func(value string) error {
			value = strings.TrimSpace(value)
			if value == "" {
				return fmt.Errorf("target path is required")
			}
			if _, err := os.Stat(expandHome(value)); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
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
		recursiveChoice, err = askWizardChoice(stderr, reader, "How should this folder be scanned?", "", []wizardChoice{
			{Label: "Recursive scan (-R): scan files inside this folder", Value: "recursive"},
			{Label: "Folder only: do not walk into files", Value: "single"},
		}, recursiveChoice)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
		opts.Recursive = recursiveChoice == "recursive"
	} else {
		_, _ = fmt.Fprintf(stderr, "%s %s\n\n", ui.Section("File detected"), ui.Muted("Recursive scan is not needed."))
	}

	opts.Scanner, err = askWizardChoice(stderr, reader, "Which scanner should be used?", "Grype is the default vulnerability scanner. Syft is best for SBOM inventory.", []wizardChoice{
		{Label: "Grype - vulnerabilities", Value: "grype"},
		{Label: "Trivy - vulnerabilities", Value: "trivy"},
		{Label: "Syft - package inventory", Value: "syft"},
	}, opts.Scanner)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}

	opts.Format, err = askWizardChoice(stderr, reader, "How should results be shown?", "", []wizardChoice{
		{Label: "Show readable report here", Value: "text"},
		{Label: "Save JSON report", Value: "json"},
		{Label: "Save SARIF report", Value: "sarif"},
	}, opts.Format)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}

	if opts.Format != "text" {
		opts.Output = defaultReportPath(opts.Format)
		opts.Output, err = askWizardInput(stderr, reader, "Where should the report be saved?", "Press Enter to use the suggested file name.", opts.Output, func(value string) error {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("report file is required")
			}
			return nil
		})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
	}

	args := opts.args()
	_, _ = fmt.Fprintf(stderr, "\n%s %s\n\n", ui.Section("Running"), ui.Code("cargo-scanner scan "+strings.Join(shellQuoteArgs(args), " ")))
	return runScan(ctx, args, stdout, stderr)
}

func askWizardChoice(stderr io.Writer, reader *bufio.Reader, title, description string, choices []wizardChoice, defaultValue string) (string, error) {
	if len(choices) == 0 {
		return "", fmt.Errorf("no choices available")
	}
	defaultIndex := 0
	for i, choice := range choices {
		if choice.Value == defaultValue {
			defaultIndex = i
			break
		}
	}
	for {
		_, _ = fmt.Fprintln(stderr, ui.Section(title))
		if strings.TrimSpace(description) != "" {
			_, _ = fmt.Fprintln(stderr, ui.Muted(description))
		}
		for i, choice := range choices {
			marker := " "
			if i == defaultIndex {
				marker = "*"
			}
			_, _ = fmt.Fprintf(stderr, "%s %d) %s\n", marker, i+1, choice.Label)
		}
		_, _ = fmt.Fprintf(stderr, "Select [%d]: ", defaultIndex+1)
		line, err := readWizardLine(reader)
		if err != nil {
			return "", err
		}
		selection := strings.TrimSpace(line)
		if selection == "" {
			_, _ = fmt.Fprintln(stderr)
			return choices[defaultIndex].Value, nil
		}
		index, err := strconv.Atoi(selection)
		if err != nil || index < 1 || index > len(choices) {
			_, _ = fmt.Fprintf(stderr, "%s Choose a number from 1 to %d.\n\n", ui.Status("error"), len(choices))
			continue
		}
		_, _ = fmt.Fprintln(stderr)
		return choices[index-1].Value, nil
	}
}

func askWizardInput(stderr io.Writer, reader *bufio.Reader, title, description, defaultValue string, validate func(string) error) (string, error) {
	for {
		_, _ = fmt.Fprintln(stderr, ui.Section(title))
		if strings.TrimSpace(description) != "" {
			_, _ = fmt.Fprintln(stderr, ui.Muted(description))
		}
		if defaultValue != "" {
			_, _ = fmt.Fprintf(stderr, "> [%s]: ", defaultValue)
		} else {
			_, _ = fmt.Fprint(stderr, "> ")
		}
		line, err := readWizardLine(reader)
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(line)
		if value == "" {
			value = defaultValue
		}
		if validate != nil {
			if err := validate(value); err != nil {
				_, _ = fmt.Fprintf(stderr, "%s %v\n\n", ui.Status("error"), err)
				continue
			}
		}
		_, _ = fmt.Fprintln(stderr)
		return value, nil
	}
}

func readWizardLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err == nil {
		return line, nil
	}
	if errors.Is(err, io.EOF) && line != "" {
		return line, nil
	}
	return "", err
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
