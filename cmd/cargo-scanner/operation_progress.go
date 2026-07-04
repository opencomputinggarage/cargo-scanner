package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type operationProgress struct {
	program *tea.Program
	done    chan struct{}
	mu      sync.Mutex
	err     error
}

type operationProgressMsg struct {
	Kind    string
	Title   string
	Stage   string
	Detail  string
	Index   int
	Total   int
	Success bool
}

type operationProgressModel struct {
	spinner  spinner.Model
	progress progress.Model
	logs     viewport.Model

	title      string
	stage      string
	detail     string
	total      int
	completed  int
	failed     int
	events     []string
	width      int
	startedAt  time.Time
	finishedAt time.Time
	finished   bool
}

type progressLogWriter struct {
	progress *operationProgress
	buffer   bytes.Buffer
}

var (
	opPanelStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(1, 2)
	opTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	opMutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	opDetailStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true)
	opGoodStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	opWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	opBadgeStyle   = lipgloss.NewStyle().Bold(true).Padding(0, 1).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("63"))
	opMetricStyle  = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
	opCurrentStyle = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("31")).Padding(0, 1)
)

func startOperationProgress(w io.Writer, title string, total int) *operationProgress {
	model := newOperationProgressModel(title, total)
	program := tea.NewProgram(model, tea.WithOutput(w), tea.WithInput(nil))
	op := &operationProgress{program: program, done: make(chan struct{})}
	go func() {
		_, err := program.Run()
		op.mu.Lock()
		op.err = err
		op.mu.Unlock()
		close(op.done)
	}()
	return op
}

func shouldStartOperationProgress(w io.Writer) bool {
	return isInteractiveTerminal(w)
}

func (o *operationProgress) Stage(stage, detail string) {
	if o != nil {
		o.program.Send(operationProgressMsg{Kind: "stage", Stage: stage, Detail: detail})
	}
}

func (o *operationProgress) Step(index, total int, stage, detail string) {
	if o != nil {
		o.program.Send(operationProgressMsg{Kind: "step", Index: index, Total: total, Stage: stage, Detail: detail})
	}
}

func (o *operationProgress) Log(line string) {
	if o != nil {
		o.program.Send(operationProgressMsg{Kind: "log", Detail: line})
	}
}

func (o *operationProgress) Complete(success bool, detail string) {
	if o != nil {
		o.program.Send(operationProgressMsg{Kind: "complete", Success: success, Detail: detail})
	}
}

func (o *operationProgress) Stop() error {
	if o == nil {
		return nil
	}
	o.program.Send(operationProgressMsg{Kind: "done"})
	<-o.done
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.err
}

func (o *operationProgress) Writer() io.Writer {
	return &progressLogWriter{progress: o}
}

func (w *progressLogWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			w.flush()
			continue
		}
		if b != '\r' {
			_ = w.buffer.WriteByte(b)
		}
	}
	return len(p), nil
}

func (w *progressLogWriter) flush() {
	line := strings.TrimSpace(w.buffer.String())
	w.buffer.Reset()
	if line != "" {
		w.progress.Log(line)
	}
}

func newOperationProgressModel(title string, total int) operationProgressModel {
	spin := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("39"))))
	bar := progress.New(progress.WithWidth(48), progress.WithScaledGradient("#5A56E0", "#1FA88B"))
	logs := viewport.New(68, 7)
	m := operationProgressModel{
		spinner:   spin,
		progress:  bar,
		logs:      logs,
		title:     title,
		stage:     "Preparing",
		total:     total,
		events:    []string{"operation queued"},
		width:     80,
		startedAt: time.Now(),
	}
	m.refreshLogs()
	return m
}

func (m operationProgressModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m operationProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		contentWidth := maxInt(48, minInt(msg.Width-8, 96))
		m.progress.Width = maxInt(24, contentWidth-18)
		m.logs.Width = contentWidth
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
	case operationProgressMsg:
		cmd := m.handle(msg)
		cmds = append(cmds, cmd)
		if msg.Kind == "done" {
			return m, tea.Quit
		}
	}
	return m, tea.Batch(cmds...)
}

func (m *operationProgressModel) handle(msg operationProgressMsg) tea.Cmd {
	switch msg.Kind {
	case "stage":
		m.stage = msg.Stage
		m.detail = msg.Detail
		m.addEvent(msg.Stage + detailSuffix(msg.Detail))
	case "step":
		m.stage = msg.Stage
		m.detail = msg.Detail
		m.total = msg.Total
		m.addEvent(msg.Stage + detailSuffix(msg.Detail))
	case "log":
		m.addEvent(msg.Detail)
	case "complete":
		if msg.Success {
			m.completed++
		} else {
			m.failed++
		}
		if msg.Detail != "" {
			m.detail = msg.Detail
			m.addEvent(msg.Detail)
		}
		return m.progress.SetPercent(m.percent())
	case "done":
		m.finished = true
		m.finishedAt = time.Now()
		if m.failed > 0 {
			m.stage = "Completed with failures"
		} else {
			m.stage = "Completed"
		}
		return m.progress.SetPercent(1)
	}
	return nil
}

func (m operationProgressModel) View() string {
	var b strings.Builder
	contentWidth := maxInt(56, minInt(m.width-8, 100))
	icon := m.spinner.View()
	if m.finished && m.failed == 0 {
		icon = opGoodStyle.Render("✓")
	} else if m.finished {
		icon = opWarnStyle.Render("!")
	}
	b.WriteString(opTitleStyle.Render(m.title))
	b.WriteString(" ")
	b.WriteString(opBadgeStyle.Render(m.stage))
	b.WriteString("\n")
	b.WriteString(opMutedStyle.Render(icon + " " + m.elapsed().Round(time.Second).String()))
	b.WriteString("\n")
	b.WriteString(opCurrentStyle.Width(contentWidth).Render(opMutedStyle.Render("current") + "\n" + opDetailStyle.Render(emptyDefault(m.detail, "waiting"))))
	b.WriteString("\n\n")
	b.WriteString(m.progress.View())
	b.WriteString("\n\n")
	b.WriteString(m.metricRow(contentWidth))
	b.WriteString("\n\n")
	b.WriteString(opMutedStyle.Render("live log"))
	b.WriteString("\n")
	b.WriteString(m.logs.View())
	return opPanelStyle.Width(maxInt(60, minInt(m.width-4, 108))).Render(b.String()) + "\n"
}

func (m operationProgressModel) metricRow(width int) string {
	cardWidth := maxInt(14, (width-2)/3)
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		opMetricStyle.Width(cardWidth).Render(opMutedStyle.Render("completed")+"\n"+opGoodStyle.Render(fmt.Sprintf("%d/%d", m.completed, m.total))),
		" ",
		opMetricStyle.Width(cardWidth).Render(opMutedStyle.Render("failed")+"\n"+opWarnStyle.Render(fmt.Sprintf("%d", m.failed))),
		" ",
		opMetricStyle.Width(cardWidth).Render(opMutedStyle.Render("elapsed")+"\n"+opDetailStyle.Render(m.elapsed().Round(time.Second).String())),
	)
}

func (m *operationProgressModel) addEvent(event string) {
	event = strings.TrimSpace(event)
	if event == "" {
		return
	}
	m.events = append(m.events, fmt.Sprintf("%s  %s", time.Now().Format("15:04:05"), event))
	if len(m.events) > 200 {
		m.events = m.events[len(m.events)-200:]
	}
	m.refreshLogs()
}

func (m *operationProgressModel) refreshLogs() {
	m.logs.SetContent(strings.Join(m.events, "\n"))
	m.logs.GotoBottom()
}

func (m operationProgressModel) percent() float64 {
	if m.total <= 0 {
		return 0
	}
	return float64(m.completed+m.failed) / float64(m.total)
}

func (m operationProgressModel) elapsed() time.Duration {
	if m.finished && !m.finishedAt.IsZero() {
		return m.finishedAt.Sub(m.startedAt)
	}
	return time.Since(m.startedAt)
}

func detailSuffix(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	return ": " + detail
}

func emptyDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
