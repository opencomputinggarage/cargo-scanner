package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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
	_, _ = fmt.Fprintln(stderr, ui.Muted("Set target and output."))
	_, _ = fmt.Fprintln(stderr)

	targetOptions := []huh.Option[string]{
		huh.NewOption("Current folder (.)", "current"),
		huh.NewOption("Choose file or folder", "custom"),
	}

	var err error
	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("Target").
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
		opts.Target = "."
		if err := runScanWizardPathStep(stderr, &opts.Target); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
		opts.Target = strings.TrimSpace(opts.Target)
	}

	targetInfo, err := os.Stat(expandHome(strings.TrimSpace(opts.Target)))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("error"), err)
		return 1
	}
	if targetInfo.IsDir() {
		if err := runScanWizardStep(
			huh.NewConfirm().
				Title("Scan recursively?").
				Affirmative("Yes").
				Negative("No").
				Value(&opts.Recursive),
		); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
			return 2
		}
	}

	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("Result").
			Options(
				huh.NewOption("Vulnerabilities with Grype", "grype"),
				huh.NewOption("Vulnerabilities with Trivy", "trivy"),
				huh.NewOption("SBOM with Syft", "syft"),
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

type pathInputModel struct {
	input     textinput.Model
	err       error
	cancelled bool
	done      bool
}

func newPathInputModel(value string) pathInputModel {
	input := textinput.New()
	input.SetValue(value)
	input.CursorEnd()
	input.Focus()
	input.ShowSuggestions = true
	input.SetSuggestions(pathSuggestions(value))
	return pathInputModel{input: input}
}

func (m pathInputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m pathInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.cancelled = true
			return m, tea.Quit
		case "enter":
			value := strings.TrimSpace(m.input.Value())
			if err := validateTargetPath(value); err != nil {
				m.err = err
				return m, nil
			}
			m.input.SetValue(value)
			m.done = true
			return m, tea.Quit
		}
	}

	m.input.SetSuggestions(pathSuggestions(m.input.Value()))
	m.input, cmd = m.input.Update(msg)
	m.input.SetSuggestions(pathSuggestions(m.input.Value()))
	m.err = nil
	return m, cmd
}

func (m pathInputModel) View() string {
	var b strings.Builder
	b.WriteString("Target path\n")
	b.WriteString("Type a file or folder path.\n\n")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")
	b.WriteString("tab complete | enter next | esc cancel")
	if m.err != nil {
		b.WriteString("\n")
		b.WriteString(ui.Status("error"))
		b.WriteString(" ")
		b.WriteString(m.err.Error())
	}
	b.WriteString("\n")
	return b.String()
}

func runScanWizardPathStep(output io.Writer, target *string) error {
	model := newPathInputModel(*target)
	finalModel, err := tea.NewProgram(model, tea.WithInput(os.Stdin), tea.WithOutput(output)).Run()
	if err != nil {
		return err
	}
	model, ok := finalModel.(pathInputModel)
	if !ok {
		return fmt.Errorf("path input failed")
	}
	if model.cancelled {
		return fmt.Errorf("cancelled")
	}
	if !model.done {
		return fmt.Errorf("path input was not completed")
	}
	*target = strings.TrimSpace(model.input.Value())
	return nil
}

func validateTargetPath(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("target path is required")
	}
	if _, err := os.Stat(expandHome(value)); err != nil {
		return err
	}
	return nil
}

func pathSuggestions(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		input = "."
	}

	dirText, displayPrefix, match := splitPathInput(input)
	entries, err := os.ReadDir(expandHome(dirText))
	if err != nil {
		return nil
	}

	match = strings.ToLower(match)
	suggestions := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if match != "" && !strings.HasPrefix(strings.ToLower(name), match) {
			continue
		}
		suggestion := displayPrefix + name
		if entry.IsDir() {
			suggestion += string(os.PathSeparator)
		}
		suggestions = append(suggestions, suggestion)
	}
	sort.Strings(suggestions)
	if len(suggestions) > 20 {
		return suggestions[:20]
	}
	return suggestions
}

func splitPathInput(input string) (dirText string, displayPrefix string, match string) {
	if input == "." || input == ".." || input == "~" {
		return input, input + string(os.PathSeparator), ""
	}
	if strings.HasSuffix(input, string(os.PathSeparator)) {
		return strings.TrimSuffix(input, string(os.PathSeparator)), input, ""
	}
	separator := strings.LastIndex(input, string(os.PathSeparator))
	if separator < 0 {
		return ".", "", input
	}
	dirText = input[:separator]
	if dirText == "" {
		dirText = string(os.PathSeparator)
	}
	return dirText, input[:separator+1], input[separator+1:]
}

func runVulnerabilityWizard(ctx context.Context, opts scanWizardOptions, stdout, stderr io.Writer) int {
	if err := runScanWizardStep(
		huh.NewSelect[string]().
			Title("Fail threshold").
			Options(
				huh.NewOption("None", ""),
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
			Title("Output").
			Options(
				huh.NewOption("Show in terminal", "text"),
				huh.NewOption("Save JSON", "json"),
				huh.NewOption("Save SARIF", "sarif"),
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
				Title("Report path").
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
			Title("Output").
			Options(
				huh.NewOption("Show in terminal", "print"),
				huh.NewOption("Save SBOM", "sbom"),
				huh.NewOption("Save JSON", "json"),
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
				Title("SBOM path").
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
				Title("Report path").
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
