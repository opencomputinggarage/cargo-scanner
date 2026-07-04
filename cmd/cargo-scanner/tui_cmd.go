package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/docker"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/managed"
)

type tuiAction struct {
	Name    string
	Detail  string
	Command string
	Args    []string
}

func (a tuiAction) FilterValue() string {
	return a.Name + " " + a.Detail + " " + a.Command
}

func (a tuiAction) Title() string {
	return a.Name
}

func (a tuiAction) Description() string {
	return a.Detail + "\n" + tuiCommandStyle.Render(a.Command)
}

type tuiModel struct {
	version       string
	status        string
	actions       list.Model
	selectedFinal string
	selectedArgs  []string
	width         int
}

var (
	tuiTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	tuiBoxStyle     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(1, 2)
	tuiFocusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	tuiMutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	tuiCommandStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	tuiBadgeStyle   = lipgloss.NewStyle().Bold(true).Padding(0, 1).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("63"))
	tuiStatusStyle  = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
)

func runTUI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	printOnly := fs.Bool("print", false, "print the TUI dashboard without entering interactive mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "tui does not accept positional arguments")
		return 2
	}
	model := newTUIModel(ctx)
	if *printOnly {
		_, _ = fmt.Fprint(stdout, model.View())
		return 0
	}
	program := tea.NewProgram(model, tea.WithOutput(stdout), tea.WithInput(os.Stdin))
	finalModel, err := program.Run()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "open tui: %v\n", err)
		return 1
	}
	if model, ok := finalModel.(tuiModel); ok && model.selectedFinal != "" {
		_, _ = fmt.Fprintf(stderr, "\n%s %s\n\n", tuiFocusStyle.Render("Running"), tuiCommandStyle.Render(model.selectedFinal))
		return run(ctx, expandHomeArgs(model.selectedArgs), stdout, stderr)
	}
	return 0
}

func newTUIModel(ctx context.Context) tuiModel {
	actions := []list.Item{
		tuiAction{Name: "Guided Scan", Detail: "Pick target, scanner, runtime, format, and fail threshold", Command: "cargo-scanner scan", Args: []string{"scan"}},
		tuiAction{Name: "Scan Downloads", Detail: "Recursive scan for personal inbound files", Command: "cargo-scanner scan ~/Downloads --recursive", Args: []string{"scan", "~/Downloads", "--recursive"}},
		tuiAction{Name: "Scan Current Directory", Detail: "Quick scan of this project or extracted folder", Command: "cargo-scanner scan . --recursive", Args: []string{"scan", ".", "--recursive"}},
		tuiAction{Name: "Fix Environment", Detail: "Install managed scanners and prepare Docker image", Command: "cargo-scanner doctor --fix", Args: []string{"doctor", "--fix"}},
		tuiAction{Name: "Generate SBOM", Detail: "Create CycloneDX JSON for one artifact", Command: "cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json", Args: []string{"sbom", "./artifact.jar", "--sbom-output", "sbom.cdx.json"}},
		tuiAction{Name: "JSON Report", Detail: "Machine-readable vulnerability report", Command: "cargo-scanner ./artifact.jar --json --output report.json", Args: []string{"./artifact.jar", "--json", "--output", "report.json"}},
	}
	delegate := list.NewDefaultDelegate()
	delegate.SetHeight(3)
	delegate.SetSpacing(1)
	delegate.Styles.SelectedTitle = tuiFocusStyle.Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(lipgloss.Color("39")).PaddingLeft(1)
	delegate.Styles.SelectedDesc = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(lipgloss.Color("39")).PaddingLeft(1)
	delegate.Styles.NormalTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Bold(true).PaddingLeft(2)
	delegate.Styles.NormalDesc = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).PaddingLeft(2)
	actionList := list.New(actions, delegate, 62, 17)
	actionList.Title = "Actions"
	actionList.SetShowStatusBar(false)
	actionList.SetFilteringEnabled(true)
	actionList.Styles.Title = tuiBadgeStyle
	actionList.Styles.PaginationStyle = tuiMutedStyle
	actionList.Styles.HelpStyle = tuiMutedStyle
	return tuiModel{
		version: displayVersion(),
		status:  tuiStatus(ctx),
		actions: actionList,
		width:   72,
	}
}

func tuiStatus(ctx context.Context) string {
	rt := managed.New("")
	ready := 0
	total := 0
	for _, name := range []string{"grype", "trivy", "syft"} {
		total++
		scanner, _ := scannerByName(name)
		if scanner.Detect(ctx, rt).Detected {
			ready++
		}
	}
	dockerStatus := "Docker image not pulled"
	dockerRuntime := docker.New(docker.DefaultImage("grype"))
	if err := dockerRuntime.ImageAvailable(ctx); err == nil {
		dockerStatus = "Docker image ready"
	} else if err := dockerRuntime.Available(ctx); err != nil {
		dockerStatus = "Docker unavailable"
	}
	return fmt.Sprintf("Managed tools %d/%d ready - %s", ready, total, dockerStatus)
}

func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.actions.SetSize(maxInt(48, minInt(msg.Width-8, 96)), maxInt(10, msg.Height-10))
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter":
			if selected, ok := m.actions.SelectedItem().(tuiAction); ok {
				m.selectedFinal = selected.Command
				m.selectedArgs = selected.Args
			}
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.actions, cmd = m.actions.Update(msg)
	return m, cmd
}

func (m tuiModel) View() string {
	var b strings.Builder
	contentWidth := maxInt(48, minInt(m.width-14, 82))
	b.WriteString(tuiTitleStyle.Render("Cargo Scanner"))
	b.WriteString(" ")
	b.WriteString(tuiBadgeStyle.Render("workspace safety"))
	b.WriteString(" ")
	b.WriteString(tuiMutedStyle.Render(m.version))
	b.WriteString("\n")
	b.WriteString(tuiStatusStyle.Width(contentWidth).Render(m.status))
	b.WriteString("\n")
	b.WriteString(m.actions.View())
	return tuiBoxStyle.Width(maxInt(56, minInt(m.width-6, 96))).Render(b.String()) + "\n"
}
