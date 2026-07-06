package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/opencomputinggarage/cargo-scanner/internal/config"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", ".cargo-scanner.yaml", "config file path")
	scannerName := fs.String("scanner", "", "scanner to use")
	runtimeName := fs.String("runtime", "", "runtime to use: auto, docker, native")
	dockerImage := fs.String("docker-image", "", "scanner runtime Docker image")
	format := fs.String("format", "text", "output format: text, json, sarif")
	jsonOut := fs.Bool("json", false, "write normalized JSON")
	outputPath := fs.String("output", "", "write normalized report to file")
	rawOutputPath := fs.String("raw-output", "", "write raw scanner output to file when supported")
	failOnRaw := fs.String("fail-on", "", "exit 1 when max severity is at least this value")
	timeout := fs.Duration("timeout", 15*time.Minute, "scan timeout")
	recursive := fs.Bool("recursive", false, "scan files under a directory")
	scanTUI := fs.Bool("tui", true, "show TUI scan progress when stderr is a terminal")
	includeRaw := fs.String("include", "", "comma-separated include globs")
	excludeRaw := fs.String("exclude", "", "comma-separated exclude globs")
	fs.StringVar(scannerName, "s", *scannerName, "alias for --scanner")
	fs.StringVar(runtimeName, "u", *runtimeName, "alias for --runtime")
	fs.StringVar(format, "f", *format, "alias for --format")
	fs.BoolVar(jsonOut, "j", *jsonOut, "alias for --json")
	fs.StringVar(outputPath, "o", *outputPath, "alias for --output")
	fs.StringVar(failOnRaw, "F", *failOnRaw, "alias for --fail-on")
	fs.DurationVar(timeout, "t", *timeout, "alias for --timeout")
	fs.BoolVar(recursive, "R", *recursive, "alias for --recursive")
	fs.StringVar(includeRaw, "i", *includeRaw, "alias for --include")
	fs.StringVar(excludeRaw, "x", *excludeRaw, "alias for --exclude")
	normalizedArgs, err := normalizeScanArgs(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := fs.Parse(normalizedArgs); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		if fs.NArg() == 0 && shouldRunScanWizard(stdout, stderr) {
			return runScanWizard(ctx, stdout, stderr)
		}
		_, _ = fmt.Fprintln(stderr, "scan requires exactly one target path")
		_, _ = fmt.Fprintln(stderr, "example: cargo-scanner scan ~/Downloads --recursive")
		return 2
	}
	cfg, err := config.LoadLayered(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	applyDefaults(scannerName, runtimeName, format, timeout, &cfg, "grype")
	if *failOnRaw == "" {
		*failOnRaw = cfg.FailOn
	}
	failOn, err := core.ParseFailSeverity(*failOnRaw)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	include := mergeList(cfg.Include, splitCSV(*includeRaw))
	exclude := mergeList(cfg.Exclude, splitCSV(*excludeRaw))
	targets, err := core.DiscoverTargetsWithFilters(fs.Arg(0), *recursive, include, exclude)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "inspect target: %v\n", err)
		return 1
	}
	scanner, err := scannerByName(*scannerName)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	rt, err := runtimeByName(ctx, *runtimeName, *dockerImage, scanner.Name())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	var progress *scanProgress
	if shouldStartScanProgress(stderr, *scanTUI) {
		progress = startScanProgress(stderr, fs.Arg(0), scanner.Name(), rt.Name(), len(targets))
		defer func() {
			if err := progress.Stop(); err != nil {
				_, _ = fmt.Fprintf(stderr, "close scan tui: %v\n", err)
			}
		}()
		progress.Stage("Scanner and runtime ready")
	}
	scanCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var reports []core.Report
	exitCode := 0
	for i, target := range targets {
		if progress != nil {
			progress.StartTarget(i+1, len(targets), target)
		}
		result, err := scanner.Scan(scanCtx, rt, target, core.ScanOptions{KeepRaw: *rawOutputPath != ""})
		if progress != nil {
			progress.FinishTarget(i+1, len(targets), result, err)
		}
		reports = append(reports, result)
		if err != nil {
			exitCode = 1
			if result.Error != "" {
				_, _ = fmt.Fprintf(stderr, "%s\n", result.Error)
			} else {
				_, _ = fmt.Fprintf(stderr, "scan failed: %v\n", err)
			}
			printFailureHint(stderr, err)
			continue
		}
		if failOn != "" && core.SeverityRank(result.Summary.MaxSeverity()) >= core.SeverityRank(failOn) {
			_, _ = fmt.Fprintf(stderr, "max severity %s meets fail threshold %s\n", result.Summary.MaxSeverity(), failOn)
			exitCode = 1
		}
	}
	if *rawOutputPath != "" && len(reports) == 1 && len(reports[0].Raw) > 0 {
		if err := os.WriteFile(*rawOutputPath, []byte(reports[0].Raw[0].Content), 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "write raw output: %v\n", err)
			return 1
		}
	}
	if *jsonOut {
		*format = "json"
	}
	if shouldShowResultViewer(stdout, os.Stdin, *outputPath, *format) {
		if err := showResultViewer(stdout, reports); err != nil {
			_, _ = fmt.Fprintf(stderr, "show results: %v\n", err)
			return 1
		}
		return exitCode
	}
	if err := writeReports(*outputPath, stdout, reports, *format); err != nil {
		_, _ = fmt.Fprintf(stderr, "write report: %v\n", err)
		return 1
	}
	return exitCode
}
