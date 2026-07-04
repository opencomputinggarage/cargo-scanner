package syft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/byeonggi/cargo-scanner/internal/core"
)

type Scanner struct {
	Binary string
}

func New() Scanner {
	return Scanner{Binary: "syft"}
}

func (s Scanner) Name() string {
	return "syft"
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
		Env:    []string{"SYFT_CHECK_FOR_APP_UPDATE=false"},
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
	report, err := s.GenerateSBOM(ctx, rt, target, opts)
	if err != nil {
		return report, err
	}
	report.Status = core.StatusNotApplicable
	report.Error = "syft generates SBOM inventory and does not produce vulnerability findings"
	return report, nil
}

func (s Scanner) GenerateSBOM(ctx context.Context, rt core.Runtime, target core.Target, opts core.ScanOptions) (core.Report, error) {
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
		Args:   []string{"dir:" + inputDir, "-o", "cyclonedx-json"},
		Env:    []string{"SYFT_CHECK_FOR_APP_UPDATE=false"},
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
	report.Status = core.StatusCompleted
	report.SBOM = &core.SBOM{
		Format:           "cyclonedx-json",
		Generator:        s.Name(),
		GeneratorVersion: capability.Version,
		ContentDigest:    "sha256:" + sha256Hex(result.Stdout),
		ContentJSON:      string(result.Stdout),
		CreatedAt:        time.Now().UTC(),
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

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
