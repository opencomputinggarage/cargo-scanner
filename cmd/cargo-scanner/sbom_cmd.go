package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/opencomputinggarage/cargo-scanner/internal/config"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

func runSBOM(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", ".cargo-scanner.yaml", "config file path")
	scannerName := fs.String("scanner", "", "SBOM scanner to use")
	runtimeName := fs.String("runtime", "", "runtime to use: auto, docker, native")
	dockerImage := fs.String("docker-image", "", "scanner runtime Docker image")
	format := fs.String("format", "text", "output format: text, json, sarif")
	jsonOut := fs.Bool("json", false, "write normalized JSON")
	outputPath := fs.String("output", "", "write normalized report to file")
	sbomOutputPath := fs.String("sbom-output", "", "write raw SBOM content to file")
	timeout := fs.Duration("timeout", 15*time.Minute, "scan timeout")
	recursive := fs.Bool("recursive", false, "scan files under a directory")
	includeRaw := fs.String("include", "", "comma-separated include globs")
	excludeRaw := fs.String("exclude", "", "comma-separated exclude globs")
	fs.StringVar(scannerName, "s", *scannerName, "alias for --scanner")
	fs.StringVar(runtimeName, "u", *runtimeName, "alias for --runtime")
	fs.StringVar(format, "f", *format, "alias for --format")
	fs.BoolVar(jsonOut, "j", *jsonOut, "alias for --json")
	fs.StringVar(outputPath, "o", *outputPath, "alias for --output")
	fs.StringVar(sbomOutputPath, "b", *sbomOutputPath, "alias for --sbom-output")
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
		_, _ = fmt.Fprintln(stderr, "sbom requires exactly one target path")
		_, _ = fmt.Fprintln(stderr, "example: cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	applyDefaults(scannerName, runtimeName, format, timeout, &cfg, "syft")
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
	generator, ok := scanner.(core.SBOMGenerator)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "scanner %q does not support SBOM generation\n", scanner.Name())
		return 2
	}
	rt, err := runtimeByName(ctx, *runtimeName, *dockerImage, scanner.Name())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if scanner.Name() == "trivy" {
		_, _ = fmt.Fprintln(stderr, "Trivy may download or update its vulnerability database on first use.")
	}
	scanCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var reports []core.Report
	exitCode := 0
	for _, target := range targets {
		result, err := generator.GenerateSBOM(scanCtx, rt, target, core.ScanOptions{})
		reports = append(reports, result)
		if err != nil {
			exitCode = 1
			if result.Error != "" {
				_, _ = fmt.Fprintf(stderr, "%s\n", result.Error)
			} else {
				_, _ = fmt.Fprintf(stderr, "sbom failed: %v\n", err)
			}
			printFailureHint(stderr, err)
		}
	}
	if *jsonOut {
		*format = "json"
	}
	if *outputPath != "" || *format != "text" || len(reports) != 1 {
		if err := writeReports(*outputPath, stdout, reports, *format); err != nil {
			_, _ = fmt.Fprintf(stderr, "write report: %v\n", err)
			return 1
		}
		return exitCode
	}
	if len(reports) == 1 && reports[0].SBOM != nil {
		if *sbomOutputPath != "" {
			if err := os.WriteFile(*sbomOutputPath, []byte(reports[0].SBOM.ContentJSON), 0o600); err != nil {
				_, _ = fmt.Fprintf(stderr, "write sbom: %v\n", err)
				return 1
			}
		} else {
			_, _ = fmt.Fprint(stdout, reports[0].SBOM.ContentJSON)
			if !strings.HasSuffix(reports[0].SBOM.ContentJSON, "\n") {
				_, _ = fmt.Fprintln(stdout)
			}
		}
	}
	return exitCode
}
