package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/opencomputinggarage/cargo-scanner/internal/config"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
	"github.com/opencomputinggarage/cargo-scanner/internal/report"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/docker"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/managed"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/native"
	"github.com/opencomputinggarage/cargo-scanner/internal/scanners/grype"
	"github.com/opencomputinggarage/cargo-scanner/internal/scanners/syft"
	"github.com/opencomputinggarage/cargo-scanner/internal/scanners/trivy"
)

func runtimeByName(ctx context.Context, name string, dockerImage string, scannerName string) (core.Runtime, error) {
	image := dockerImage
	if image == "" {
		image = docker.DefaultImage(scannerName)
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto":
		dockerRuntime := docker.New(image)
		if dockerImage != "" {
			if err := dockerRuntime.Available(ctx); err == nil {
				return dockerRuntime, nil
			}
		} else if err := dockerRuntime.ImageAvailable(ctx); err == nil {
			return dockerRuntime, nil
		}
		managedRuntime := managed.New("")
		if scannerAvailable(ctx, managedRuntime, scannerName) {
			return managedRuntime, nil
		}
		return native.New(), nil
	case "docker":
		rt := docker.New(image)
		if err := rt.Available(ctx); err != nil {
			return nil, err
		}
		return rt, nil
	case "native":
		return native.New(), nil
	case "managed":
		rt := managed.New("")
		if err := rt.Available(ctx); err != nil {
			return nil, err
		}
		return rt, nil
	default:
		return nil, fmt.Errorf("runtime %q is not implemented yet", name)
	}
}

func scannerAvailable(ctx context.Context, rt core.Runtime, scannerName string) bool {
	scanner, err := scannerByName(scannerName)
	if err != nil {
		return false
	}
	return scanner.Detect(ctx, rt).Detected
}

func scannerByName(name string) (core.Scanner, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "grype":
		return grype.New(), nil
	case "trivy":
		return trivy.New(), nil
	case "syft":
		return syft.New(), nil
	default:
		return nil, fmt.Errorf("scanner %q is not implemented yet", name)
	}
}

func normalizeScanArgs(args []string) ([]string, error) {
	valueFlags := map[string]bool{
		"--scanner":      true,
		"--config":       true,
		"--runtime":      true,
		"--docker-image": true,
		"--format":       true,
		"--output":       true,
		"--raw-output":   true,
		"--sbom-output":  true,
		"--fail-on":      true,
		"--timeout":      true,
		"--include":      true,
		"--exclude":      true,
	}
	boolFlags := map[string]bool{
		"--json":      true,
		"--recursive": true,
		"--tui":       true,
	}
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			name := arg
			if before, _, ok := strings.Cut(arg, "="); ok {
				name = before
			}
			switch {
			case boolFlags[name]:
				flags = append(flags, arg)
			case valueFlags[name]:
				flags = append(flags, arg)
				if strings.Contains(arg, "=") {
					continue
				}
				if i+1 >= len(args) {
					return nil, fmt.Errorf("%s requires a value", arg)
				}
				i++
				flags = append(flags, args[i])
			default:
				return nil, fmt.Errorf("unknown option %s", arg)
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...), nil
}

func applyDefaults(scannerName, runtimeName, format *string, timeout *time.Duration, cfg *config.Config, defaultScanner string) {
	if *scannerName == "" {
		if cfg.Scanner != "" {
			*scannerName = cfg.Scanner
		} else {
			*scannerName = defaultScanner
		}
	}
	if *runtimeName == "" {
		if cfg.Runtime != "" {
			*runtimeName = cfg.Runtime
		} else {
			*runtimeName = "auto"
		}
	}
	if *format == "text" && cfg.Format != "" {
		*format = cfg.Format
	}
	if cfg.Timeout > 0 && *timeout == 15*time.Minute {
		*timeout = cfg.Timeout
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func mergeList(base, override []string) []string {
	if len(override) == 0 {
		return base
	}
	return append(append([]string(nil), base...), override...)
}

func printFailureHint(w io.Writer, err error) {
	if err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "docker unavailable"):
		_, _ = fmt.Fprintln(w, "hint: start Docker, or use --runtime managed")
	case strings.Contains(msg, "docker image"):
		_, _ = fmt.Fprintln(w, "hint: run cargo-scanner runtime pull --scanner grype, or pass --docker-image ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest")
	case strings.Contains(msg, "not installed in managed tools"), strings.Contains(msg, "unavailable"):
		_, _ = fmt.Fprintln(w, "hint: run cargo-scanner doctor --fix")
	}
}

func writeReports(path string, stdout io.Writer, reports []core.Report, format string) error {
	var w io.Writer = stdout
	if path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		w = file
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return report.WriteTextList(w, reports)
	case "json":
		if len(reports) == 1 {
			return report.WriteJSON(w, reports[0])
		}
		return report.WriteJSONArray(w, reports)
	case "sarif":
		return report.WriteSARIF(w, reports)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func isInteractiveTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && isatty.IsTerminal(file.Fd())
}
