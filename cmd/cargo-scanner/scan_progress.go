package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

type scanProgress struct {
	program *tea.Program
	done    chan struct{}
	mu      sync.Mutex
	err     error
}

type scanProgressMsg struct {
	Kind    string
	Stage   string
	Target  core.Target
	Index   int
	Total   int
	Report  core.Report
	Error   string
	Scanner string
	Runtime string
	Root    string
}

type scanProgressModel struct {
	spinner  spinner.Model
	progress progress.Model
	logs     viewport.Model

	stage      string
	root       string
	scanner    string
	runtime    string
	current    string
	total      int
	active     int
	completed  int
	failed     int
	findings   int
	maxSev     core.Severity
	events     []string
	finished   bool
	width      int
	startedAt  time.Time
	finishedAt time.Time
}

var (
	scanPanelStyle     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(1, 2)
	scanTitleStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	scanSubtitleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	scanLabelStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	scanCurrentStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	scanGoodStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	scanWarnStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	scanBadStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	scanBadgeStyle     = lipgloss.NewStyle().Bold(true).Padding(0, 1).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("63"))
	scanMetricStyle    = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
	scanMetricName     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	scanMetricValue    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230"))
	scanTargetBoxStyle = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("31")).Padding(0, 1)
)

func startScanProgress(w io.Writer, root, scannerName, runtimeName string, total int) *scanProgress {
	model := newScanProgressModel(root, scannerName, runtimeName, total)
	program := tea.NewProgram(model, tea.WithOutput(w), tea.WithInput(nil), tea.WithAltScreen())
	sp := &scanProgress{program: program, done: make(chan struct{})}
	go func() {
		_, err := program.Run()
		sp.mu.Lock()
		sp.err = err
		sp.mu.Unlock()
		close(sp.done)
	}()
	return sp
}

func shouldStartScanProgress(w io.Writer, enabled bool) bool {
	if !enabled || os.Getenv("CARGO_SCANNER_PLAIN") != "" {
		return false
	}
	return isInteractiveTerminal(w)
}

func (s *scanProgress) Stage(stage string) {
	if s != nil {
		s.program.Send(scanProgressMsg{Kind: "stage", Stage: stage})
	}
}

func (s *scanProgress) StartTarget(index, total int, target core.Target) {
	if s != nil {
		s.program.Send(scanProgressMsg{Kind: "start", Index: index, Total: total, Target: target})
	}
}

func (s *scanProgress) FinishTarget(index, total int, report core.Report, err error) {
	if s == nil {
		return
	}
	msg := scanProgressMsg{Kind: "finish", Index: index, Total: total, Report: report}
	if err != nil {
		msg.Error = err.Error()
	}
	s.program.Send(msg)
}

func (s *scanProgress) Stop() error {
	if s == nil {
		return nil
	}
	s.program.Send(scanProgressMsg{Kind: "done"})
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func newScanProgressModel(root, scannerName, runtimeName string, total int) scanProgressModel {
	spin := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("39"))))
	bar := progress.New(
		progress.WithWidth(48),
		progress.WithScaledGradient("#1FA88B", "#D19A2A"),
	)
	logs := viewport.New(68, 6)
	m := scanProgressModel{
		spinner:   spin,
		progress:  bar,
		logs:      logs,
		stage:     "Preparing scan",
		root:      root,
		scanner:   scannerName,
		runtime:   runtimeName,
		total:     total,
		events:    []string{fmt.Sprintf("discovered %d target(s)", total)},
		width:     80,
		startedAt: time.Now(),
	}
	m.refreshLogs()
	return m
}

func (m scanProgressModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m scanProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		contentWidth := maxInt(44, minInt(msg.Width-8, 96))
		m.progress.Width = maxInt(24, contentWidth-18)
		m.logs.Width = contentWidth
		m.logs.Height = 6
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	case progress.FrameMsg:
		model, cmd := m.progress.Update(msg)
		if updated, ok := model.(progress.Model); ok {
			m.progress = updated
		}
		cmds = append(cmds, cmd)
	case scanProgressMsg:
		cmd := m.handleScanProgressMsg(msg)
		cmds = append(cmds, cmd)
		if msg.Kind == "done" {
			return m, tea.Quit
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		}
	}
	return m, tea.Batch(cmds...)
}

func (m *scanProgressModel) handleScanProgressMsg(msg scanProgressMsg) tea.Cmd {
	switch msg.Kind {
	case "stage":
		m.stage = msg.Stage
		m.addEvent(msg.Stage)
	case "start":
		m.stage = "Scanning target"
		m.active = msg.Index
		m.total = msg.Total
		m.current = displayScanPath(msg.Target.Path)
		m.addEvent(fmt.Sprintf("scan started: %s", m.current))
	case "finish":
		m.completed++
		m.active = msg.Index
		m.total = msg.Total
		if msg.Report.Target.Path != "" {
			m.current = displayScanPath(msg.Report.Target.Path)
		}
		if msg.Error != "" || msg.Report.Status == core.StatusFailed {
			m.failed++
			m.addEvent(fmt.Sprintf("scan failed: %s", m.current))
		} else {
			m.addEvent(fmt.Sprintf("scan completed: %s", m.current))
		}
		m.findings += msg.Report.Summary.Total
		if core.SeverityRank(msg.Report.Summary.MaxSeverity()) > core.SeverityRank(m.maxSev) {
			m.maxSev = msg.Report.Summary.MaxSeverity()
		}
		return m.progress.SetPercent(m.percent())
	case "done":
		m.stage = "Scan finished"
		m.finished = true
		m.finishedAt = time.Now()
		m.addEvent("report generation finished")
		return m.progress.SetPercent(1)
	}
	return nil
}

func (m scanProgressModel) View() string {
	var b strings.Builder
	contentWidth := maxInt(56, minInt(m.width-8, 100))
	icon := m.spinner.View()
	if m.finished {
		icon = scanGoodStyle.Render("✓")
	}
	if m.failed > 0 && m.finished {
		icon = scanWarnStyle.Render("!")
	}
	title := lipgloss.JoinHorizontal(
		lipgloss.Top,
		scanTitleStyle.Render("Cargo Scanner"),
		" ",
		scanBadge(m.stage, m.finished, m.failed),
	)
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(scanSubtitleStyle.Render(fmt.Sprintf("%s %s on %s", icon, m.scanner, m.runtime)))
	b.WriteString("\n")
	b.WriteString(scanTargetBoxStyle.Width(contentWidth).Render(m.targetView()))
	b.WriteString("\n\n")
	b.WriteString(m.progress.View())
	b.WriteString("\n\n")
	b.WriteString(m.metricRow(contentWidth))
	b.WriteString("\n\n")
	b.WriteString(scanLabelStyle.Render("activity"))
	b.WriteString("\n")
	b.WriteString(m.logs.View())
	if m.finished {
		b.WriteString("\n")
		b.WriteString(m.glamourSummary(contentWidth))
	}
	return scanPanelStyle.Width(maxInt(60, minInt(m.width-4, 108))).Render(b.String()) + "\n"
}

func (m *scanProgressModel) addEvent(event string) {
	if strings.TrimSpace(event) == "" {
		return
	}
	m.events = append(m.events, fmt.Sprintf("%s  %s", time.Now().Format("15:04:05"), event))
	if len(m.events) > 200 {
		m.events = m.events[len(m.events)-200:]
	}
	m.refreshLogs()
}

func (m *scanProgressModel) refreshLogs() {
	m.logs.SetContent(strings.Join(m.events, "\n"))
	m.logs.GotoBottom()
}

func (m scanProgressModel) percent() float64 {
	if m.total <= 0 {
		return 0
	}
	return float64(m.completed) / float64(m.total)
}

func (m scanProgressModel) elapsed() time.Duration {
	if m.finished && !m.finishedAt.IsZero() {
		return m.finishedAt.Sub(m.startedAt)
	}
	return time.Since(m.startedAt)
}

func displayScanPath(path string) string {
	if path == "" {
		return ""
	}
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, path); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return rel
		}
	}
	return path
}

func renderScanSeverity(sev core.Severity) string {
	switch sev {
	case core.SeverityCritical, core.SeverityHigh:
		return scanBadStyle.Bold(true).Render(string(sev))
	case core.SeverityMedium:
		return scanWarnStyle.Render(string(sev))
	case core.SeverityLow, core.SeverityNegligible:
		return scanGoodStyle.Render(string(sev))
	default:
		return string(sev)
	}
}

func scanBadge(stage string, finished bool, failed int) string {
	switch {
	case finished && failed > 0:
		return scanBadgeStyle.Background(lipgloss.Color("214")).Render("completed with failures")
	case finished:
		return scanBadgeStyle.Background(lipgloss.Color("42")).Render("completed")
	case strings.Contains(strings.ToLower(stage), "scanning"):
		return scanBadgeStyle.Background(lipgloss.Color("39")).Render("scanning")
	default:
		return scanBadgeStyle.Render("preparing")
	}
}

func (m scanProgressModel) targetView() string {
	current := m.current
	if current == "" {
		current = displayScanPath(m.root)
	}
	var b strings.Builder
	b.WriteString(scanLabelStyle.Render("current target"))
	b.WriteString("\n")
	b.WriteString(scanCurrentStyle.Render(current))
	return b.String()
}

func (m scanProgressModel) metricRow(width int) string {
	gap := " "
	cardWidth := maxInt(12, (width-3*len(gap))/4)
	cards := []string{
		m.metricCard("files", fmt.Sprintf("%d/%d", m.completed, m.total), cardWidth),
		m.metricCard("failed", fmt.Sprintf("%d", m.failed), cardWidth),
		m.metricCard("findings", fmt.Sprintf("%d", m.findings), cardWidth),
		m.metricCard("elapsed", m.elapsed().Round(time.Second).String(), cardWidth),
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, cards[0], gap, cards[1], gap, cards[2], gap, cards[3])
}

func (m scanProgressModel) metricCard(name, value string, width int) string {
	valueStyle := scanMetricValue
	if name == "failed" && m.failed > 0 {
		valueStyle = scanBadStyle.Bold(true)
	}
	return scanMetricStyle.Width(width).Render(scanMetricName.Render(name) + "\n" + valueStyle.Render(value))
}

func (m scanProgressModel) glamourSummary(width int) string {
	maxSeverity := "none"
	if m.maxSev != "" && m.maxSev != core.SeverityUnknown {
		maxSeverity = string(m.maxSev)
	}
	status := "completed"
	if m.failed > 0 {
		status = "completed with failures"
	}
	doc := fmt.Sprintf(
		"### Scan summary\n\n| Status | Files | Failed | Findings | Max severity |\n| --- | ---: | ---: | ---: | --- |\n| %s | %d/%d | %d | %d | %s |\n",
		status,
		m.completed,
		m.total,
		m.failed,
		m.findings,
		maxSeverity,
	)
	renderer, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle("dark"),
		glamour.WithWordWrap(maxInt(40, width-4)),
		glamour.WithTableWrap(true),
	)
	if err != nil {
		return doc
	}
	out, err := renderer.Render(doc)
	if err != nil {
		return doc
	}
	return strings.TrimRight(out, "\n")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
