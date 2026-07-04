package ui

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	sectionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("75"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	mutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	codeStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
)

func Title(s string) string {
	return render(titleStyle, s)
}

func Section(s string) string {
	return render(sectionStyle, s)
}

func Status(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ok", "completed", "installed", "available":
		return render(successStyle, s)
	case "missing", "not pulled", "skipped":
		return render(warnStyle, s)
	case "failed", "error":
		return render(errorStyle, s)
	default:
		return s
	}
}

func Severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high":
		return render(errorStyle.Bold(true), s)
	case "medium":
		return render(warnStyle, s)
	case "low", "negligible":
		return render(successStyle, s)
	default:
		return s
	}
}

func Muted(s string) string {
	return render(mutedStyle, s)
}

func Code(s string) string {
	return render(codeStyle, s)
}

func render(style lipgloss.Style, s string) string {
	if plainOutput() {
		return s
	}
	return style.Render(s)
}

func plainOutput() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("CARGO_SCANNER_PLAIN") != ""
}
