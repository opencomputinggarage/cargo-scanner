package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	bubblestable "github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
	"github.com/opencomputinggarage/cargo-scanner/internal/ui"
)

var (
	reportFrameStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(1, 2)
	reportHeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	reportSubtleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	reportLabelStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	reportValueStyle   = lipgloss.NewStyle().Bold(true)
	reportMetricStyle  = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(lipgloss.Color("62")).PaddingLeft(1)
	reportGoodStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	reportWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	reportBadStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	reportUnknownStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Bold(true)
)

func WriteText(w io.Writer, r core.Report) error {
	_, err := fmt.Fprintln(w, reportView(r))
	return err
}

func reportView(r core.Report) string {
	const width = 100
	contentWidth := width - reportFrameStyle.GetHorizontalFrameSize()
	sections := []string{
		reportHero(r, contentWidth),
		reportMeta(r, contentWidth),
	}
	if r.Status == core.StatusFailed {
		sections = append(sections, reportFailure(r, contentWidth))
	} else {
		sections = append(sections, reportSummary(r.Summary, contentWidth))
		sections = append(sections, reportFindings(r, contentWidth))
	}
	content := strings.Join(sections, "\n\n")
	vp := viewport.New(contentWidth, lipgloss.Height(content))
	vp.SetContent(content)
	return reportFrameStyle.Width(width).Render(vp.View())
}

func reportHero(r core.Report, width int) string {
	title := reportHeaderStyle.Render("Cargo Scanner")
	status := reportStatusBadge(r)
	summary := reportHeroSummary(r)
	left := lipgloss.NewStyle().Width(width - lipgloss.Width(status) - 2).Render(title + "\n" + reportSubtleStyle.Render(summary))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, status)
}

func reportHeroSummary(r core.Report) string {
	switch r.Status {
	case core.StatusFailed:
		return "Scan did not complete. Review the error below."
	case core.StatusNotApplicable:
		return "Scanner completed without vulnerability findings."
	default:
		if r.Summary.Total == 0 {
			return "No vulnerability findings detected."
		}
		return fmt.Sprintf("%d finding(s), max severity %s", r.Summary.Total, strings.ToUpper(string(r.Summary.MaxSeverity())))
	}
}

func reportStatusBadge(r core.Report) string {
	style := reportUnknownStyle
	switch r.Status {
	case core.StatusCompleted:
		if r.Summary.Total == 0 {
			style = reportGoodStyle
		} else if core.SeverityRank(r.Summary.MaxSeverity()) >= core.SeverityRank(core.SeverityHigh) {
			style = reportBadStyle
		} else {
			style = reportWarnStyle
		}
	case core.StatusFailed:
		style = reportBadStyle
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(style.GetForeground()).
		Padding(0, 1).
		Render(strings.ToUpper(string(r.Status)))
}

func reportMeta(r core.Report, width int) string {
	scanner := r.Scanner.Name
	if r.Scanner.Version != "" {
		scanner += " " + r.Scanner.Version
	}
	cardWidth := (width - 4) / 3
	started := r.StartedAt.Format("2006-01-02 15:04:05 UTC")
	duration := r.EndedAt.Sub(r.StartedAt).String()
	return lipgloss.JoinHorizontal(lipgloss.Top,
		reportMetric("Target", ui.Code(r.Target.Path), cardWidth),
		reportMetric("Scanner", scanner+"\n"+reportSubtleStyle.Render(r.Scanner.Runtime), cardWidth),
		reportMetric("Started", started+"\n"+reportSubtleStyle.Render(duration), cardWidth),
	)
}

func reportMetric(label, value string, width int) string {
	return reportMetricStyle.Width(width).Render(reportLabelStyle.Render(label) + "\n" + reportValueStyle.Render(value))
}

func reportFailure(r core.Report, width int) string {
	message := strings.TrimSpace(r.Error)
	if message == "" {
		message = "scanner exited without a detailed error message"
	}
	return lipgloss.NewStyle().
		Width(width).
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.Color("196")).
		PaddingLeft(1).
		Render(reportBadStyle.Render("Error") + "\n" + message)
}

func reportSummary(s core.Summary, width int) string {
	bar := severityBar(s, maxInt(24, width-2))
	stats := lipgloss.JoinHorizontal(lipgloss.Top,
		reportMetric("Critical", strconv.Itoa(s.Critical), 14),
		reportMetric("High", strconv.Itoa(s.High), 14),
		reportMetric("Medium", strconv.Itoa(s.Medium), 14),
		reportMetric("Low", strconv.Itoa(s.Low), 14),
		reportMetric("Negligible", strconv.Itoa(s.Negligible), 14),
		reportMetric("Unknown", strconv.Itoa(s.Unknown), 14),
	)
	return reportHeaderStyle.Render("Findings") + "\n" +
		reportSubtleStyle.Render(fmt.Sprintf("%d total", s.Total)) + "\n" +
		bar + "\n" +
		stats
}

func severityBar(s core.Summary, width int) string {
	if s.Total == 0 {
		return reportGoodStyle.Render(strings.Repeat("█", minInt(width, 30))) + reportSubtleStyle.Render(" clean")
	}
	segments := []struct {
		count int
		style lipgloss.Style
	}{
		{s.Critical, reportBadStyle},
		{s.High, reportBadStyle},
		{s.Medium, reportWarnStyle},
		{s.Low + s.Negligible, reportGoodStyle},
		{s.Unknown, reportUnknownStyle},
	}
	var b strings.Builder
	used := 0
	for _, segment := range segments {
		if segment.count == 0 {
			continue
		}
		size := maxInt(1, segment.count*width/s.Total)
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
		b.WriteString(reportSubtleStyle.Render(strings.Repeat("░", width-used)))
	}
	return b.String()
}

func reportFindings(r core.Report, width int) string {
	if len(r.Findings) == 0 {
		return reportGoodStyle.Render("OK") + " " + reportSubtleStyle.Render("No findings.")
	}
	findings := append([]core.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return core.SeverityRank(findings[i].Severity) > core.SeverityRank(findings[j].Severity)
	})
	limit := minInt(10, len(findings))
	note := ""
	if len(findings) > limit {
		note = reportSubtleStyle.Render(fmt.Sprintf("\nShowing top %d of %d findings.", limit, len(findings)))
	}
	links := findingLinks(findings[:limit])
	if links != "" {
		links = "\n\n" + links
	}
	return reportHeaderStyle.Render("Top findings") + "\n" + findingsTable(findings[:limit], width) + note + links
}

func findingsTable(findings []core.Finding, width int) string {
	rows := make([]bubblestable.Row, 0, len(findings))
	for _, f := range findings {
		fixed := ""
		if len(f.FixedVersions) > 0 {
			fixed = f.FixedVersions[0]
		}
		pkg := strings.TrimSpace(f.PackageName + " " + f.PackageVersion)
		rows = append(rows, bubblestable.Row{
			strings.ToUpper(string(f.Severity)),
			f.ID,
			pkg,
			fixed,
		})
	}
	columns := []bubblestable.Column{
		{Title: "Severity", Width: 10},
		{Title: "ID", Width: 18},
		{Title: "Package", Width: maxInt(18, width-58)},
		{Title: "Fixed", Width: 18},
	}
	styles := bubblestable.DefaultStyles()
	styles.Header = styles.Header.Bold(true).Foreground(lipgloss.Color("75")).Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(lipgloss.Color("238"))
	styles.Cell = styles.Cell.Foreground(lipgloss.Color("252"))
	styles.Selected = styles.Cell
	t := bubblestable.New(
		bubblestable.WithColumns(columns),
		bubblestable.WithRows(rows),
		bubblestable.WithHeight(len(rows)+1),
		bubblestable.WithWidth(width),
		bubblestable.WithStyles(styles),
	)
	return colorizeSeverityColumn(t.View())
}

func findingLinks(findings []core.Finding) string {
	var lines []string
	for _, f := range findings {
		if strings.TrimSpace(f.URL) == "" {
			continue
		}
		label := f.ID
		if label == "" {
			label = f.URL
		}
		lines = append(lines, reportSubtleStyle.Render("open ")+terminalHyperlink(label, f.URL))
	}
	if len(lines) == 0 {
		return ""
	}
	return reportHeaderStyle.Render("Details") + "\n" + strings.Join(lines, "\n")
}

func terminalHyperlink(label, rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	label = strings.TrimSpace(label)
	if label == "" {
		label = rawURL
	}
	if rawURL == "" || !(strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://")) {
		return label
	}
	if plainReportOutput() {
		return label + " " + reportSubtleStyle.Render(rawURL)
	}
	return "\x1b]8;;" + rawURL + "\x1b\\" + label + "\x1b]8;;\x1b\\"
}

func plainReportOutput() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("CARGO_SCANNER_PLAIN") != ""
}

func WriteTextList(w io.Writer, reports []core.Report) error {
	for i, r := range reports {
		if i > 0 {
			if _, err := fmt.Fprintln(w, "\n---"); err != nil {
				return err
			}
		}
		if err := WriteText(w, r); err != nil {
			return err
		}
	}
	return nil
}

func colorizeSeverityColumn(view string) string {
	lines := strings.Split(view, "\n")
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "CRITICAL"), strings.HasPrefix(trimmed, "HIGH"):
			lines[i] = reportBadStyle.Render(line)
		case strings.HasPrefix(trimmed, "MEDIUM"):
			lines[i] = reportWarnStyle.Render(line)
		case strings.HasPrefix(trimmed, "LOW"), strings.HasPrefix(trimmed, "NEGLIGIBLE"):
			lines[i] = reportGoodStyle.Render(line)
		}
	}
	return strings.Join(lines, "\n")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
