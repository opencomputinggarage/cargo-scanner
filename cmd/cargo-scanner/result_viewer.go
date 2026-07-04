package main

import (
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

type resultViewMode int

const (
	resultSummaryMode resultViewMode = iota
	resultDetailsMode
)

type resultViewerModel struct {
	reports []core.Report
	mode    resultViewMode
	width   int
	height  int
	view    viewport.Model
}

var (
	resultFrameStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(1, 2)
	resultTitleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	resultMutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	resultGoodStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	resultWarnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	resultBadStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	resultMetricStyle = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(lipgloss.Color("62")).PaddingLeft(1)
	resultTabStyle    = lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("244"))
	resultActiveTab   = lipgloss.NewStyle().Padding(0, 1).Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62"))
)

func shouldShowResultViewer(stdout io.Writer, stdin *os.File, outputPath, format string) bool {
	return outputPath == "" &&
		strings.EqualFold(strings.TrimSpace(format), "text") &&
		isInteractiveTerminal(stdout) &&
		isattyFile(stdin)
}

func isattyFile(file *os.File) bool {
	return file != nil && isInteractiveTerminal(file)
}

func showResultViewer(stdout io.Writer, reports []core.Report) error {
	model := newResultViewerModel(reports)
	_, err := tea.NewProgram(model, tea.WithOutput(stdout), tea.WithInput(os.Stdin)).Run()
	return err
}

func newResultViewerModel(reports []core.Report) resultViewerModel {
	width := 100
	height := 26
	vp := viewport.New(width-6, height-8)
	model := resultViewerModel{
		reports: reports,
		width:   width,
		height:  height,
		view:    vp,
	}
	model.refresh()
	return model
}

func (m resultViewerModel) Init() tea.Cmd {
	return nil
}

func (m resultViewerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = maxInt(72, minInt(msg.Width, 120))
		m.height = maxInt(18, msg.Height)
		m.view.Width = maxInt(40, m.width-6)
		m.view.Height = maxInt(8, m.height-8)
		m.refresh()
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "tab":
			if m.mode == resultSummaryMode {
				m.mode = resultDetailsMode
			} else {
				m.mode = resultSummaryMode
			}
			m.view.GotoTop()
			m.refresh()
		}
	}
	m.view, cmd = m.view.Update(msg)
	return m, cmd
}

func (m resultViewerModel) View() string {
	innerWidth := maxInt(40, m.width-6)
	header := lipgloss.JoinHorizontal(lipgloss.Top,
		resultTitleStyle.Render("Scan Results"),
		"  ",
		resultTabs(m.mode),
	)
	help := resultMutedStyle.Render("tab: summary/details  ↑/↓: scroll  q/esc: quit")
	body := lipgloss.JoinVertical(lipgloss.Left, header, "", m.view.View(), "", help)
	return resultFrameStyle.Width(innerWidth).Render(body) + "\n"
}

func (m *resultViewerModel) refresh() {
	if m.mode == resultDetailsMode {
		m.view.SetContent(resultDetailsContent(m.reports, m.view.Width))
		return
	}
	m.view.SetContent(resultSummaryContent(m.reports, m.view.Width))
}

func resultTabs(mode resultViewMode) string {
	summary := resultTabStyle.Render("Summary")
	details := resultTabStyle.Render("Details")
	if mode == resultSummaryMode {
		summary = resultActiveTab.Render("Summary")
	} else {
		details = resultActiveTab.Render("Details")
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, summary, details)
}

func resultSummaryContent(reports []core.Report, width int) string {
	summary := aggregateResultSummary(reports)
	cardWidth := maxInt(12, (width-5)/5)
	cards := lipgloss.JoinHorizontal(lipgloss.Top,
		resultMetric("Targets", strconv.Itoa(len(reports)), cardWidth),
		resultMetric("Failed", severityCount(summary.failed, summary.failed > 0), cardWidth),
		resultMetric("Findings", strconv.Itoa(summary.total), cardWidth),
		resultMetric("Max", severityValue(summary.maxSeverity), cardWidth),
		resultMetric("Status", resultStatusValue(summary.failed == 0), cardWidth),
	)
	var b strings.Builder
	b.WriteString(cards)
	b.WriteString("\n\n")
	b.WriteString(resultTitleStyle.Render("Severity"))
	b.WriteString("\n")
	b.WriteString(resultSeverityBar(summary, maxInt(24, width-2)))
	b.WriteString("\n\n")
	b.WriteString(resultTargetTable(reports, width))
	return b.String()
}

func resultDetailsContent(reports []core.Report, width int) string {
	findings := allFindings(reports)
	if len(findings) == 0 {
		return resultGoodStyle.Render("No findings.") + "\n\n" + resultMutedStyle.Render("Press q to close.")
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return core.SeverityRank(findings[i].finding.Severity) > core.SeverityRank(findings[j].finding.Severity)
	})
	rows := make([]table.Row, 0, len(findings))
	for _, item := range findings {
		f := item.finding
		fixed := ""
		if len(f.FixedVersions) > 0 {
			fixed = f.FixedVersions[0]
		}
		pkg := strings.TrimSpace(f.PackageName + " " + f.PackageVersion)
		rows = append(rows, table.Row{
			strings.ToUpper(string(f.Severity)),
			f.ID,
			pkg,
			fixed,
			item.target,
		})
	}
	cols := []table.Column{
		{Title: "Severity", Width: 10},
		{Title: "ID", Width: 18},
		{Title: "Package", Width: maxInt(18, width-76)},
		{Title: "Fixed", Width: 16},
		{Title: "Target", Width: 24},
	}
	out := resultTitleStyle.Render("All findings") + "\n" + resultTable(cols, rows, width)
	links := resultFindingLinks(findings)
	if links != "" {
		out += "\n\n" + resultTitleStyle.Render("Links") + "\n" + links
	}
	return out
}

func resultMetric(label, value string, width int) string {
	return resultMetricStyle.Width(width).Render(resultMutedStyle.Render(label) + "\n" + value)
}

func resultStatusValue(ok bool) string {
	if ok {
		return resultGoodStyle.Render("OK")
	}
	return resultBadStyle.Render("FAILED")
}

func severityCount(value int, bad bool) string {
	if bad {
		return resultBadStyle.Render(strconv.Itoa(value))
	}
	return resultGoodStyle.Render(strconv.Itoa(value))
}

func severityValue(severity core.Severity) string {
	switch {
	case core.SeverityRank(severity) >= core.SeverityRank(core.SeverityHigh):
		return resultBadStyle.Render(strings.ToUpper(string(severity)))
	case core.SeverityRank(severity) >= core.SeverityRank(core.SeverityMedium):
		return resultWarnStyle.Render(strings.ToUpper(string(severity)))
	case severity == core.SeverityUnknown:
		return resultMutedStyle.Render("NONE")
	default:
		return resultGoodStyle.Render(strings.ToUpper(string(severity)))
	}
}

type resultSummary struct {
	total       int
	failed      int
	critical    int
	high        int
	medium      int
	low         int
	negligible  int
	unknown     int
	maxSeverity core.Severity
}

func aggregateResultSummary(reports []core.Report) resultSummary {
	var out resultSummary
	for _, r := range reports {
		if r.Status == core.StatusFailed {
			out.failed++
		}
		out.total += r.Summary.Total
		out.critical += r.Summary.Critical
		out.high += r.Summary.High
		out.medium += r.Summary.Medium
		out.low += r.Summary.Low
		out.negligible += r.Summary.Negligible
		out.unknown += r.Summary.Unknown
		if core.SeverityRank(r.Summary.MaxSeverity()) > core.SeverityRank(out.maxSeverity) {
			out.maxSeverity = r.Summary.MaxSeverity()
		}
	}
	return out
}

func resultSeverityBar(s resultSummary, width int) string {
	if s.total == 0 {
		return resultGoodStyle.Render(strings.Repeat("█", minInt(width, 30))) + resultMutedStyle.Render(" clean")
	}
	segments := []struct {
		count int
		style lipgloss.Style
	}{
		{s.critical, resultBadStyle},
		{s.high, resultBadStyle},
		{s.medium, resultWarnStyle},
		{s.low + s.negligible, resultGoodStyle},
		{s.unknown, resultMutedStyle},
	}
	var b strings.Builder
	used := 0
	for _, segment := range segments {
		if segment.count == 0 {
			continue
		}
		size := maxInt(1, segment.count*width/s.total)
		if used+size > width {
			size = width - used
		}
		if size <= 0 {
			continue
		}
		b.WriteString(segment.style.Render(strings.Repeat("█", size)))
		used += size
	}
	if used < width {
		b.WriteString(resultMutedStyle.Render(strings.Repeat("░", width-used)))
	}
	return b.String()
}

func resultTargetTable(reports []core.Report, width int) string {
	rows := make([]table.Row, 0, len(reports))
	for _, r := range reports {
		rows = append(rows, table.Row{
			string(r.Status),
			r.Target.Path,
			strconv.Itoa(r.Summary.Total),
			string(r.Summary.MaxSeverity()),
		})
	}
	cols := []table.Column{
		{Title: "Status", Width: 14},
		{Title: "Target", Width: maxInt(24, width-48)},
		{Title: "Findings", Width: 10},
		{Title: "Max", Width: 10},
	}
	return resultTitleStyle.Render("Targets") + "\n" + resultTable(cols, rows, width)
}

func resultTable(cols []table.Column, rows []table.Row, width int) string {
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true).Foreground(lipgloss.Color("75")).Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(lipgloss.Color("238"))
	styles.Cell = styles.Cell.Foreground(lipgloss.Color("252"))
	styles.Selected = styles.Cell
	t := table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithHeight(len(rows)+1),
		table.WithWidth(width),
		table.WithStyles(styles),
	)
	return t.View()
}

type findingWithTarget struct {
	target  string
	finding core.Finding
}

func allFindings(reports []core.Report) []findingWithTarget {
	var out []findingWithTarget
	for _, r := range reports {
		for _, f := range r.Findings {
			out = append(out, findingWithTarget{target: r.Target.Path, finding: f})
		}
	}
	return out
}

func resultFindingLinks(findings []findingWithTarget) string {
	var lines []string
	for _, item := range findings {
		f := item.finding
		if strings.TrimSpace(f.URL) == "" {
			continue
		}
		label := f.ID
		if label == "" {
			label = f.URL
		}
		lines = append(lines, resultMutedStyle.Render("open ")+resultHyperlink(label, f.URL))
	}
	return strings.Join(lines, "\n")
}

func resultHyperlink(label, rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	label = strings.TrimSpace(label)
	if label == "" {
		label = rawURL
	}
	if rawURL == "" || !(strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://")) {
		return label
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("CARGO_SCANNER_PLAIN") != "" {
		return label + " " + resultMutedStyle.Render(rawURL)
	}
	return "\x1b]8;;" + rawURL + "\x1b\\" + label + "\x1b]8;;\x1b\\"
}
