package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/docker"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/managed"
)

type tuiAction struct {
	Title       string
	Description string
	Command     string
}

type tuiModel struct {
	version       string
	status        string
	selected      int
	actions       []tuiAction
	selectedFinal string
}

var (
	tuiTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Padding(0, 1)
	tuiBoxStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
	tuiFocusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	tuiMutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
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
		_, _ = fmt.Fprintf(stdout, "\nRun: %s\n", model.selectedFinal)
	}
	return 0
}

func newTUIModel(ctx context.Context) tuiModel {
	return tuiModel{
		version: displayVersion(),
		status:  tuiStatus(ctx),
		actions: []tuiAction{
			{Title: "Scan Downloads", Description: "Recursive managed scan for personal inbound files", Command: "cargo-scanner scan ~/Downloads --recursive"},
			{Title: "Scan Current Directory", Description: "Quick scan of this project or extracted folder", Command: "cargo-scanner scan . --recursive"},
			{Title: "Fix Environment", Description: "Install managed scanners and prepare Docker image", Command: "cargo-scanner doctor --fix"},
			{Title: "Generate SBOM", Description: "Create CycloneDX JSON for one artifact", Command: "cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json"},
			{Title: "JSON Report", Description: "Machine-readable vulnerability report", Command: "cargo-scanner ./artifact.jar --json --output report.json"},
		},
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
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.selected < len(m.actions)-1 {
				m.selected++
			}
		case "enter":
			if len(m.actions) > 0 {
				m.selectedFinal = m.actions[m.selected].Command
			}
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m tuiModel) View() string {
	var b strings.Builder
	b.WriteString(tuiTitleStyle.Render("Cargo Scanner"))
	b.WriteString(" ")
	b.WriteString(tuiMutedStyle.Render(m.version))
	b.WriteString("\n")
	b.WriteString(tuiMutedStyle.Render(m.status))
	b.WriteString("\n\n")
	for i, action := range m.actions {
		cursor := "  "
		title := action.Title
		command := action.Command
		if i == m.selected {
			cursor = "> "
			title = tuiFocusStyle.Render(title)
			command = tuiFocusStyle.Render(command)
		}
		b.WriteString(cursor)
		b.WriteString(title)
		b.WriteString("\n    ")
		b.WriteString(tuiMutedStyle.Render(action.Description))
		b.WriteString("\n    ")
		b.WriteString(command)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(tuiMutedStyle.Render("up/down or j/k to move - enter to choose - q to quit"))
	b.WriteString("\n")
	return tuiBoxStyle.Render(b.String()) + "\n"
}
