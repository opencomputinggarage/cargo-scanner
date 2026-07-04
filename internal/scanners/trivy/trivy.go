package trivy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/byeonggi/cargo-scanner/internal/core"
)

type Scanner struct {
	Binary string
}

func New() Scanner {
	return Scanner{Binary: "trivy"}
}

func (s Scanner) Name() string {
	return "trivy"
}

func (s Scanner) Detect(ctx context.Context, rt core.Runtime) core.Capability {
	capability := core.Capability{Name: s.Name(), Runtime: rt.Name()}
	if _, err := rt.LookPath(ctx, s.Binary); err != nil {
		capability.Error = err.Error()
		return capability
	}
	capability.Detected = true
	result, err := rt.Run(ctx, core.RunRequest{Binary: s.Binary, Args: []string{"--version"}})
	if err != nil {
		capability.Error = strings.TrimSpace(string(result.Stderr))
		return capability
	}
	capability.Version = parseVersion(result.Stdout)
	return capability
}

func (s Scanner) Scan(ctx context.Context, rt core.Runtime, target core.Target, opts core.ScanOptions) (core.Report, error) {
	started := time.Now().UTC()
	capability := s.Detect(ctx, rt)
	if !capability.Detected {
		return unavailableReport(target, s.Name(), rt.Name(), capability.Error, started), fmt.Errorf("scanner %q unavailable: %s", s.Name(), capability.Error)
	}
	workDir, cleanup, err := core.PrepareWorkspace(target)
	if err != nil {
		return core.Report{}, err
	}
	defer cleanup()
	inputDir, mounts := core.RuntimePath(rt, workDir.InputDir)
	result, runErr := rt.Run(ctx, core.RunRequest{
		Binary: s.Binary,
		Args: []string{
			"fs",
			"--scanners", "vuln",
			"--format", "json",
			"--skip-java-db-update",
			inputDir,
		},
		Env:    []string{"TRIVY_DISABLE_VEX_NOTICE=true"},
		Mounts: mounts,
	})
	ended := time.Now().UTC()
	report := core.Report{
		Target: target,
		Scanner: core.ScannerInfo{
			Name:    s.Name(),
			Version: capability.Version,
			Runtime: rt.Name(),
		},
		StartedAt: started,
		EndedAt:   ended,
	}
	if runErr != nil {
		report.Status = core.StatusFailed
		report.Error = strings.TrimSpace(string(result.Stderr))
		return report, runErr
	}
	findings, err := Parse(result.Stdout)
	if err != nil {
		return core.Report{}, err
	}
	report.Status = core.StatusCompleted
	report.Findings = findings
	report.Summary = core.Summarize(findings)
	if opts.KeepRaw {
		report.Raw = append(report.Raw, core.RawOutput{Tool: s.Name(), Format: "json", Content: string(result.Stdout)})
	}
	return report, nil
}

func unavailableReport(target core.Target, scannerName, runtimeName, msg string, started time.Time) core.Report {
	return core.Report{
		Target: target,
		Scanner: core.ScannerInfo{
			Name:    scannerName,
			Runtime: runtimeName,
		},
		Status:    core.StatusFailed,
		Error:     msg,
		StartedAt: started,
		EndedAt:   time.Now().UTC(),
	}
}

var versionRe = regexp.MustCompile(`(?m)^Version:\s*([^\s]+)`)

func parseVersion(out []byte) string {
	text := strings.TrimSpace(string(out))
	if m := versionRe.FindStringSubmatch(text); len(m) == 2 {
		return m[1]
	}
	if line, _, ok := strings.Cut(text, "\n"); ok {
		return strings.TrimSpace(line)
	}
	return text
}
