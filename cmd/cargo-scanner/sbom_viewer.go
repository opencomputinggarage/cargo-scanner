package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	bubbletable "github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

type sbomViewerModel struct {
	report     core.Report
	summary    cyclonedxSummary
	components []cyclonedxComponent
	table      bubbletable.Model
	width      int
	height     int
	selected   *cyclonedxComponent
}

func showSBOMViewer(stdout io.Writer, report core.Report) error {
	summary, err := parseCycloneDXSummary(report.SBOM.ContentJSON)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, sbomTextView(report, 100))
		return nil
	}
	model := newSBOMViewerModel(report, summary)
	_, err = tea.NewProgram(model, tea.WithOutput(stdout), tea.WithInput(os.Stdin)).Run()
	return err
}

func newSBOMViewerModel(report core.Report, summary cyclonedxSummary) sbomViewerModel {
	width := 100
	height := 26
	model := sbomViewerModel{
		report:     report,
		summary:    summary,
		components: sortedCycloneDXComponents(summary.Components),
		width:      width,
		height:     height,
	}
	model.refresh()
	return model
}

func (m sbomViewerModel) Init() tea.Cmd {
	return nil
}

func (m sbomViewerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = maxInt(72, msg.Width)
		m.height = maxInt(18, msg.Height)
		m.refresh()
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.selected != nil {
				m.selected = nil
				return m, nil
			}
			return m, tea.Quit
		case "enter":
			if len(m.components) > 0 {
				index := m.table.Cursor()
				if index >= 0 && index < len(m.components) {
					component := m.components[index]
					m.selected = &component
				}
			}
		}
	}
	if len(m.components) > 0 && m.selected == nil {
		m.table, cmd = m.table.Update(msg)
	}
	return m, cmd
}

func (m sbomViewerModel) View() string {
	frameWidth := resultFrameWidth(m.width)
	contentWidth := resultFrameContentWidth(frameWidth)
	header := lipgloss.JoinHorizontal(lipgloss.Top,
		resultTitleStyle.Render("SBOM"),
		"  ",
		resultMutedStyle.Render(m.report.Target.Path),
	)
	content := sbomSummarySection(m.report, m.summary, contentWidth) + "\n\n" + sbomViewerComponentsView(m.table, len(m.components))
	if m.selected != nil {
		content += "\n\n" + sbomComponentDetailView(*m.selected, contentWidth)
	}
	help := resultMutedStyle.Render("↑/↓: select  enter: details  q/esc: quit")
	if m.selected != nil {
		help = resultMutedStyle.Render("esc: close details  q: quit")
	}
	body := lipgloss.JoinVertical(lipgloss.Left, header, "", content, "", help)
	return resultFrameStyle.Width(frameWidth).Render(body) + "\n"
}

func (m *sbomViewerModel) refresh() {
	contentWidth := resultContentWidth(m.width)
	height := maxInt(4, m.height-14)
	m.table = newResultTable(sbomComponentColumns(contentWidth), sbomComponentRows(m.components), contentWidth, height, true, true)
}

func sbomViewerComponentsView(table bubbletable.Model, count int) string {
	title := resultTitleStyle.Render("Components")
	meta := resultMutedStyle.Render(fmt.Sprintf("%d component(s)", count))
	if count == 0 {
		return title + "  " + meta + "\n" + resultMutedStyle.Render("No components listed.")
	}
	return title + "  " + meta + "\n" + table.View()
}

func sbomComponentDetailView(component cyclonedxComponent, width int) string {
	purl := component.PURL
	if purl == "" {
		purl = component.PackageURL
	}
	rows := []string{
		resultDetailRow("Type", emptyDisplay(component.Type), width),
		resultDetailRow("Name", emptyDisplay(component.Name), width),
		resultDetailRow("Version", emptyDisplay(component.Version), width),
		resultDetailRow("PURL", emptyDisplay(purl), width),
		resultDetailRow("BOM ref", emptyDisplay(component.BOMRef), width),
		resultDetailRow("Publisher", emptyDisplay(component.Publisher), width),
		resultDetailRow("Scope", emptyDisplay(component.Scope), width),
	}
	divider := resultMutedStyle.Render(strings.Repeat("-", width))
	return resultTitleStyle.Render("Component details") + "\n" + divider + "\n" + strings.Join(rows, "\n")
}

func sbomComponentColumns(width int) []bubbletable.Column {
	return []bubbletable.Column{
		{Title: "Type", Width: 12},
		{Title: "Name", Width: maxInt(18, width/3)},
		{Title: "Version", Width: 16},
		{Title: "PURL", Width: maxInt(18, width-width/3-36)},
	}
}

func sbomComponentRows(components []cyclonedxComponent) []bubbletable.Row {
	rows := make([]bubbletable.Row, 0, len(components))
	for _, component := range components {
		version := component.Version
		if version == "" {
			version = "-"
		}
		purl := component.PURL
		if purl == "" {
			purl = component.PackageURL
		}
		rows = append(rows, bubbletable.Row{
			emptyDisplay(component.Type),
			emptyDisplay(component.Name),
			version,
			emptyDisplay(purl),
		})
	}
	return rows
}

func sortedCycloneDXComponents(components []cyclonedxComponent) []cyclonedxComponent {
	out := append([]cyclonedxComponent(nil), components...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Name < out[j].Name
	})
	return out
}
