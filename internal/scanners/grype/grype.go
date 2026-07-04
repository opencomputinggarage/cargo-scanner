package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

type Scanner struct {
	Binary string
}

func New() Scanner {
	return Scanner{Binary: "grype"}
}

func (s Scanner) Name() string {
	return "grype"
}

func (s Scanner) Detect(ctx context.Context, rt core.Runtime) core.Capability {
	capability := core.Capability{Name: s.Name(), Runtime: rt.Name()}
	if _, err := rt.LookPath(ctx, s.Binary); err != nil {
		capability.Error = err.Error()
		return capability
	}
	capability.Detected = true
	result, err := rt.Run(ctx, core.RunRequest{
		Binary: s.Binary,
		Args:   []string{"version", "-o", "json"},
		Env:    []string{"GRYPE_CHECK_FOR_APP_UPDATE=false"},
	})
	if err != nil {
		capability.Error = strings.TrimSpace(string(result.Stderr))
		return capability
	}
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(result.Stdout, &doc); err == nil {
		capability.Version = doc.Version
	}
	if capability.Version == "" {
		capability.Version = strings.TrimSpace(string(result.Stdout))
	}
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
	scanTarget := "dir:" + inputDir
	result, runErr := rt.Run(ctx, core.RunRequest{
		Binary: s.Binary,
		Args:   []string{scanTarget, "-o", "json"},
		Env: []string{
			"GRYPE_DB_AUTO_UPDATE=true",
			"GRYPE_CHECK_FOR_APP_UPDATE=false",
		},
		Mounts: mounts,
	})
	ended := time.Now().UTC()
	if runErr != nil {
		return core.Report{
			Target: target,
			Scanner: core.ScannerInfo{
				Name:    s.Name(),
				Version: capability.Version,
				Runtime: rt.Name(),
			},
			Status:    core.StatusFailed,
			Error:     strings.TrimSpace(string(result.Stderr)),
			StartedAt: started,
			EndedAt:   ended,
		}, runErr
	}

	findings, err := Parse(result.Stdout)
	if err != nil {
		return core.Report{}, err
	}
	report := core.Report{
		Target: target,
		Scanner: core.ScannerInfo{
			Name:    s.Name(),
			Version: capability.Version,
			Runtime: rt.Name(),
		},
		Status:    core.StatusCompleted,
		Findings:  findings,
		Summary:   core.Summarize(findings),
		StartedAt: started,
		EndedAt:   ended,
	}
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
