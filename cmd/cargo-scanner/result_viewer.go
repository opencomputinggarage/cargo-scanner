package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"

	bubbletable "github.com/charmbracelet/bubbles/table"
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

	detailsTable       bubbletable.Model
	detailsLinks       map[string]string
	detailsFindings    []findingWithTarget
	detailsFindingRows int
	selectedFinding    *findingWithTarget
	notice             string
}

type resultOpenURLMsg struct {
	label string
	err   error
}

var (
	resultFrameStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(1, 2)
	resultTitleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	resultMutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	resultGoodStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	resultWarnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	resultBadStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	resultMetricStyle = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(lipgloss.Color("62")).PaddingLeft(1)
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
	vp := viewport.New(resultContentWidth(width), height-8)
	model := resultViewerModel{
		reports: reports,
		mode:    resultDetailsMode,
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
		m.width = maxInt(72, msg.Width)
		m.height = maxInt(18, msg.Height)
		m.view.Width = resultContentWidth(m.width)
		m.view.Height = maxInt(8, m.height-8)
		m.refresh()
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			if m.selectedFinding != nil && msg.String() == "esc" {
				m.selectedFinding = nil
				m.notice = ""
				return m, nil
			}
			return m, tea.Quit
		case "enter":
			if m.mode == resultDetailsMode && m.detailsFindingRows > 0 {
				index := m.detailsTable.Cursor()
				if index >= 0 && index < len(m.detailsFindings) {
					finding := m.detailsFindings[index]
					m.selectedFinding = &finding
					m.notice = ""
				}
			}
		case "o":
			if m.mode == resultDetailsMode && m.selectedFinding != nil {
				label := resultFindingLabel(m.selectedFinding.finding)
				if rawURL := strings.TrimSpace(m.selectedFinding.finding.URL); rawURL != "" {
					m.notice = resultMutedStyle.Render("opening ") + label
					return m, openResultURLCmd(label, rawURL)
				}
			}
		}
	case resultOpenURLMsg:
		if msg.err != nil {
			m.notice = resultBadStyle.Render("open failed: ") + msg.err.Error()
		} else {
			m.notice = resultGoodStyle.Render("opened ") + msg.label
		}
	}
	if m.mode == resultDetailsMode && m.detailsFindingRows > 0 && m.selectedFinding == nil {
		m.detailsTable, cmd = m.detailsTable.Update(msg)
		return m, cmd
	}
	m.view, cmd = m.view.Update(msg)
	return m, cmd
}

func (m resultViewerModel) View() string {
	frameWidth := resultFrameWidth(m.width)
	contentWidth := resultFrameContentWidth(frameWidth)
	header := lipgloss.JoinHorizontal(lipgloss.Top,
		resultTitleStyle.Render("Vulnerabilities"),
		"  ",
		resultMutedStyle.Render(resultScannerSummary(m.reports)),
	)
	help := resultMutedStyle.Render("q/esc: quit")
	if m.detailsFindingRows > 0 {
		help = resultMutedStyle.Render("↑/↓: select  enter: details  q/esc: quit")
		if m.selectedFinding != nil {
			help = resultMutedStyle.Render("o: open link  esc: close details  q: quit")
		}
		content := resultVulnerabilityViewerContent(m.reports, m.detailsTable, m.detailsLinks, m.detailsFindingRows, m.selectedFinding, m.notice, contentWidth)
		body := lipgloss.JoinVertical(lipgloss.Left, header, "", content, "", help)
		return resultFrameStyle.Width(frameWidth).Render(body) + "\n"
	}
	body := lipgloss.JoinVertical(lipgloss.Left, header, "", m.view.View(), "", help)
	return resultFrameStyle.Width(frameWidth).Render(body) + "\n"
}

func resultFrameWidth(terminalWidth int) int {
	return maxInt(40, terminalWidth-6)
}

func resultContentWidth(terminalWidth int) int {
	return resultFrameContentWidth(resultFrameWidth(terminalWidth))
}

func resultFrameContentWidth(frameWidth int) int {
	return maxInt(20, frameWidth-resultFrameStyle.GetHorizontalFrameSize())
}

func resultScannerSummary(reports []core.Report) string {
	if len(reports) == 0 {
		return "-"
	}
	scanner := strings.TrimSpace(reports[0].Scanner.Name)
	if reports[0].Scanner.Version != "" {
		scanner += " " + reports[0].Scanner.Version
	}
	if scanner == "" {
		scanner = "scanner"
	}
	if len(reports) > 1 {
		scanner += fmt.Sprintf(" / %d targets", len(reports))
	}
	return scanner
}

func (m *resultViewerModel) refresh() {
	if m.mode == resultDetailsMode {
		m.detailsTable, m.detailsLinks, m.detailsFindings, m.detailsFindingRows = resultDetailsTable(m.reports, m.view.Width, m.view.Height)
		if m.detailsFindingRows == 0 {
			m.view.SetContent(resultVulnerabilitySummarySection(m.reports, m.view.Width) + "\n\n" + resultGoodStyle.Render("No findings."))
		}
		return
	}
	m.view.SetContent(resultSummaryContent(m.reports, m.view.Width))
}

func resultVulnerabilityViewerContent(reports []core.Report, t bubbletable.Model, links map[string]string, count int, selected *findingWithTarget, notice string, width int) string {
	view := resultVulnerabilitySummarySection(reports, width) + "\n\n" + resultDetailsTableView(t, links, count, selected, notice, width)
	return view
}

func resultVulnerabilitySummarySection(reports []core.Report, width int) string {
	summary := aggregateResultSummary(reports)
	metrics := []resultMetricData{
		{label: "Targets", value: strconv.Itoa(len(reports))},
		{label: "Failed", value: severityCount(summary.failed, summary.failed > 0)},
		{label: "Findings", value: strconv.Itoa(summary.total)},
		{label: "Max", value: severityValue(summary.maxSeverity)},
		{label: "Status", value: resultStatusValue(summary.failed == 0)},
	}
	return resultTitleStyle.Render("Summary") + "\n" + resultMetricRow(metrics, width) + "\n" + resultSeveritySection(summary, width)
}

func resultSummaryContent(reports []core.Report, width int) string {
	summary := aggregateResultSummary(reports)
	metrics := []resultMetricData{
		{label: "Targets", value: strconv.Itoa(len(reports))},
		{label: "Failed", value: severityCount(summary.failed, summary.failed > 0)},
		{label: "Findings", value: strconv.Itoa(summary.total)},
		{label: "Max", value: severityValue(summary.maxSeverity)},
		{label: "Status", value: resultStatusValue(summary.failed == 0)},
	}
	var b strings.Builder
	b.WriteString(resultMetricRow(metrics, width))
	b.WriteString("\n\n")
	b.WriteString(resultSeveritySection(summary, width))
	b.WriteString("\n\n")
	b.WriteString(resultTopRisks(reports, width))
	b.WriteString("\n\n")
	b.WriteString(resultTargetTable(reports, width))
	return b.String()
}

func resultSeveritySection(summary resultSummary, width int) string {
	label := resultTitleStyle.Render("Severity")
	gap := "  "
	barWidth := maxInt(12, width-lipgloss.Width("Severity")-lipgloss.Width(gap)-8)
	return label + gap + resultSeverityBar(summary, barWidth)
}

type resultMetricData struct {
	label string
	value string
}

func resultMetricRow(metrics []resultMetricData, width int) string {
	if len(metrics) == 0 {
		return ""
	}
	gap := " "
	cardWidth := maxInt(9, (width-(len(metrics)-1)*lipgloss.Width(gap))/len(metrics))
	for cardWidth > 6 {
		cards := make([]string, 0, len(metrics))
		for _, metric := range metrics {
			cards = append(cards, resultMetric(metric.label, metric.value, cardWidth))
		}
		row := lipgloss.JoinHorizontal(lipgloss.Top, cards...)
		if lipgloss.Width(row) <= width {
			return row
		}
		cardWidth--
	}
	cards := make([]string, 0, len(metrics))
	for _, metric := range metrics {
		cards = append(cards, resultMetric(metric.label, metric.value, 6))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, cards...)
}

func resultDetailsContent(reports []core.Report, width int) string {
	findings := allFindings(reports)
	if len(findings) == 0 {
		return resultGoodStyle.Render("No findings.") + "\n\n" + resultMutedStyle.Render("Press q to close.")
	}
	sortFindings(findings)
	cols := resultFindingColumns(width)
	title := resultTitleStyle.Render("Findings")
	count := resultMutedStyle.Render(fmt.Sprintf("%d finding(s), sorted by severity", len(findings)))
	rows, links := resultFindingRows(findings)
	return title + "  " + count + "\n" + resultTableWithLinks(cols, rows, width, links)
}

func resultDetailsTable(reports []core.Report, width, height int) (bubbletable.Model, map[string]string, []findingWithTarget, int) {
	findings := allFindings(reports)
	if len(findings) == 0 {
		return bubbletable.New(), nil, nil, 0
	}
	sortFindings(findings)
	rows, links := resultFindingRows(findings)
	tableHeight := maxInt(4, height-2)
	return newResultTable(resultFindingColumns(width), rows, width, tableHeight, true, true), links, findings, len(rows)
}

func resultDetailsTableView(t bubbletable.Model, links map[string]string, count int, selected *findingWithTarget, notice string, width int) string {
	title := resultTitleStyle.Render("Findings")
	meta := resultMutedStyle.Render(fmt.Sprintf("%d finding(s), sorted by severity", count))
	view := title + "  " + meta + "\n" + t.View()
	if selected != nil {
		view += "\n\n" + resultFindingDetailView(*selected, width)
	}
	if strings.TrimSpace(notice) != "" {
		view += "\n" + notice
	}
	return view
}

func resultFindingDetailView(item findingWithTarget, width int) string {
	f := item.finding
	width = maxInt(40, width)
	rows := []string{
		resultDetailRow("ID", resultFindingLabel(f), width),
		resultDetailRow("Severity", strings.ToUpper(string(f.Severity)), width),
		resultDetailRow("Source", emptyDisplay(f.Source), width),
		resultDetailRow("Package", strings.TrimSpace(f.PackageName+" "+f.PackageVersion), width),
		resultDetailRow("Package type", emptyDisplay(f.PackageType), width),
		resultDetailRow("Fixed", strings.Join(f.FixedVersions, ", "), width),
		resultDetailRow("Target", emptyDisplay(item.target), width),
		resultDetailRow("Location", emptyDisplay(f.Location), width),
		resultDetailRow("URL", emptyDisplay(f.URL), width),
	}
	divider := resultMutedStyle.Render(strings.Repeat("-", width))
	return resultTitleStyle.Render("Finding details") + "\n" + divider + "\n" + strings.Join(rows, "\n")
}

func resultDetailRow(label, value string, width int) string {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	labelWidth := 13
	valueWidth := maxInt(8, width-labelWidth)
	labelText := padRight(label+":", labelWidth)
	return resultMutedStyle.Render(labelText) + truncateVisible(value, valueWidth)
}

func padRight(value string, width int) string {
	if lipgloss.Width(value) >= width {
		return truncateVisible(value, width)
	}
	return value + strings.Repeat(" ", width-lipgloss.Width(value))
}

func truncateVisible(value string, width int) string {
	value = strings.TrimSpace(value)
	if width <= 0 || lipgloss.Width(value) <= width {
		return value
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}
	var b strings.Builder
	for _, r := range value {
		next := b.String() + string(r)
		if lipgloss.Width(next)+3 > width {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "..."
}

func emptyDisplay(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
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

func resultTopRisks(reports []core.Report, width int) string {
	findings := allFindings(reports)
	if len(findings) == 0 {
		return resultTitleStyle.Render("Top risks") + "\n" + resultGoodStyle.Render("No findings to prioritize.")
	}
	sortFindings(findings)
	limit := minInt(5, len(findings))
	cols := resultFindingColumns(width)
	note := ""
	if len(findings) > limit {
		note = "\n" + resultMutedStyle.Render(fmt.Sprintf("Showing top %d of %d findings. Terminal viewer shows the full sorted table.", limit, len(findings)))
	}
	rows, links := resultFindingRows(findings[:limit])
	return resultTitleStyle.Render("Top risks") + "\n" + resultTableWithLinks(cols, rows, width, links) + note
}

func resultFindingColumns(width int) []bubbletable.Column {
	available := maxInt(48, width-(5*2))
	severityWidth := 11
	fixedWidth := 12
	vulnerabilityWidth := minInt(32, maxInt(18, available/4))
	remaining := available - severityWidth - vulnerabilityWidth - fixedWidth
	packageWidth := maxInt(14, remaining*45/100)
	targetWidth := maxInt(14, remaining-packageWidth)
	return []bubbletable.Column{
		{Title: "Severity", Width: severityWidth},
		{Title: "Vulnerability", Width: vulnerabilityWidth},
		{Title: "Package", Width: packageWidth},
		{Title: "Fixed", Width: fixedWidth},
		{Title: "Target", Width: targetWidth},
	}
}

func resultFindingRows(findings []findingWithTarget) ([]bubbletable.Row, map[string]string) {
	rows := make([]bubbletable.Row, 0, len(findings))
	links := make(map[string]string)
	for _, item := range findings {
		f := item.finding
		fixed := ""
		if len(f.FixedVersions) > 0 {
			fixed = f.FixedVersions[0]
		}
		pkg := strings.TrimSpace(f.PackageName + " " + f.PackageVersion)
		label := resultFindingLabel(f)
		if label != "-" && strings.TrimSpace(f.URL) != "" {
			links[label] = strings.TrimSpace(f.URL)
		}
		rows = append(rows, bubbletable.Row{
			strings.ToUpper(string(f.Severity)),
			label,
			pkg,
			fixed,
			item.target,
		})
	}
	return rows, links
}

func resultFindingLabel(f core.Finding) string {
	label := strings.TrimSpace(f.ID)
	rawURL := strings.TrimSpace(f.URL)
	if label == "" && rawURL == "" {
		return "-"
	}
	if label == "" {
		return rawURL
	}
	if rawURL == "" {
		return label
	}
	return label
}

func sortFindings(findings []findingWithTarget) {
	sort.SliceStable(findings, func(i, j int) bool {
		a := findings[i].finding
		b := findings[j].finding
		left := core.SeverityRank(a.Severity)
		right := core.SeverityRank(b.Severity)
		if left != right {
			return left > right
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		aPkg := strings.TrimSpace(a.PackageName + " " + a.PackageVersion)
		bPkg := strings.TrimSpace(b.PackageName + " " + b.PackageVersion)
		if aPkg != bPkg {
			return aPkg < bPkg
		}
		return findings[i].target < findings[j].target
	})
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
	reports = append([]core.Report(nil), reports...)
	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].Status != reports[j].Status {
			return reports[i].Status == core.StatusFailed
		}
		left := core.SeverityRank(reports[i].Summary.MaxSeverity())
		right := core.SeverityRank(reports[j].Summary.MaxSeverity())
		if left != right {
			return left > right
		}
		if reports[i].Summary.Total != reports[j].Summary.Total {
			return reports[i].Summary.Total > reports[j].Summary.Total
		}
		return reports[i].Target.Path < reports[j].Target.Path
	})
	rows := make([]bubbletable.Row, 0, len(reports))
	for _, r := range reports {
		rows = append(rows, bubbletable.Row{
			string(r.Status),
			r.Target.Path,
			strconv.Itoa(r.Summary.Total),
			string(r.Summary.MaxSeverity()),
		})
	}
	cols := []bubbletable.Column{
		{Title: "Status", Width: 14},
		{Title: "Target", Width: maxInt(24, width-48)},
		{Title: "Findings", Width: 10},
		{Title: "Max", Width: 10},
	}
	return resultTitleStyle.Render("Targets") + "\n" + resultTable(cols, rows, width)
}

func resultTable(cols []bubbletable.Column, rows []bubbletable.Row, width int) string {
	return resultTableWithLinks(cols, rows, width, nil)
}

func resultTableWithLinks(cols []bubbletable.Column, rows []bubbletable.Row, width int, links map[string]string) string {
	if len(cols) == 0 {
		return ""
	}
	t := newResultTable(cols, rows, width, len(rows)+1, false, false)
	out := t.View()
	return resultApplyTableLinks(out, links)
}

func newResultTable(cols []bubbletable.Column, rows []bubbletable.Row, width, height int, focused, fill bool) bubbletable.Model {
	tableWidth := maxInt(24, width-1)
	cols = fitResultColumns(cols, tableWidth, fill)
	styles := bubbletable.DefaultStyles()
	t := bubbletable.New(
		bubbletable.WithColumns(cols),
		bubbletable.WithRows(rows),
		bubbletable.WithFocused(focused),
		bubbletable.WithHeight(height),
		bubbletable.WithWidth(tableWidth),
		bubbletable.WithStyles(styles),
	)
	if focused {
		t.Focus()
	}
	return t
}

func fitResultColumns(cols []bubbletable.Column, width int, fill bool) []bubbletable.Column {
	out := append([]bubbletable.Column(nil), cols...)
	available := maxInt(len(out), width-(len(out)*2)-1)
	total := resultColumnWidth(out)
	for total > available {
		index := widestResultColumn(out)
		if out[index].Width <= 8 {
			break
		}
		out[index].Width--
		total--
	}
	for fill && total < available {
		index := widestResultColumn(out)
		out[index].Width++
		total++
	}
	return out
}

func resultColumnWidth(cols []bubbletable.Column) int {
	total := 0
	for _, col := range cols {
		total += col.Width
	}
	return total
}

func widestResultColumn(cols []bubbletable.Column) int {
	index := 0
	for i := 1; i < len(cols); i++ {
		if cols[i].Width > cols[index].Width {
			index = i
		}
	}
	return index
}

func resultApplyTableLinks(view string, links map[string]string) string {
	if len(links) == 0 || os.Getenv("NO_COLOR") != "" || os.Getenv("CARGO_SCANNER_PLAIN") != "" {
		return view
	}
	labels := make([]string, 0, len(links))
	for label := range links {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool {
		return len(labels[i]) > len(labels[j])
	})
	for _, label := range labels {
		rawURL := strings.TrimSpace(links[label])
		if rawURL == "" || !(strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://")) {
			continue
		}
		view = strings.ReplaceAll(view, label, resultHyperlink(label, rawURL))
	}
	return view
}

func resultHyperlink(label, rawURL string) string {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("CARGO_SCANNER_PLAIN") != "" {
		return label
	}
	return "\x1b]8;;" + rawURL + "\x1b\\" + label + "\x1b]8;;\x1b\\"
}

func openResultURLCmd(label, rawURL string) tea.Cmd {
	return func() tea.Msg {
		return resultOpenURLMsg{label: label, err: openResultURL(rawURL)}
	}
}

func openResultURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || !(strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://")) {
		return fmt.Errorf("unsupported URL")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	return cmd.Start()
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
