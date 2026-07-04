package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

var version = "dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "sbom":
		return runSBOM(ctx, args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "completion":
		return runCompletion(args[1:], stdout, stderr)
	case "runtime":
		return runRuntime(ctx, args[1:], stdout, stderr)
	case "tools":
		return runTools(ctx, args[1:], stdout, stderr)
	case "cache":
		return runCache(ctx, args[1:], stdout, stderr)
	case "version":
		_, _ = fmt.Fprintf(stdout, "cargo-scanner %s\n", displayVersion())
		return 0
	case "-v", "--version":
		_, _ = fmt.Fprintf(stdout, "cargo-scanner %s\n", displayVersion())
		return 0
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	default:
		if shouldScanImplicitly(args[0]) {
			return runScan(ctx, args, stdout, stderr)
		}
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		if suggestion := suggestCommand(args[0]); suggestion != "" {
			_, _ = fmt.Fprintf(stderr, "Did you mean this?\n  cargo-scanner %s\n\n", suggestion)
		}
		usage(stderr)
		return 2
	}
}

var topLevelCommands = []string{
	"init", "scan", "sbom", "doctor", "completion", "runtime", "tools", "cache", "version", "help",
}

func suggestCommand(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return ""
	}
	best := ""
	bestDistance := 3
	for _, command := range topLevelCommands {
		distance := editDistance(input, command)
		if distance < bestDistance {
			bestDistance = distance
			best = command
		}
	}
	return best
}

func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			cur[j] = minInt(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func minInt(values ...int) int {
	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}

func shouldScanImplicitly(arg string) bool {
	if arg == "" {
		return false
	}
	if strings.HasPrefix(arg, "-") {
		return arg != "-h" && arg != "--help" && arg != "-v" && arg != "--version"
	}
	if _, err := os.Stat(arg); err == nil {
		return true
	}
	return strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~")
}

func displayVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Cargo Scanner scans inbound artifacts before you unpack them.

Usage:
  cargo-scanner init
  cargo-scanner scan [options] <path>
  cargo-scanner <path> [scan options]
  cargo-scanner sbom [options] <path>
  cargo-scanner doctor [--fix]
  cargo-scanner completion <bash|zsh|fish|powershell>
  cargo-scanner runtime pull --scanner grype
  cargo-scanner tools doctor
  cargo-scanner tools install grype
  cargo-scanner tools update all
  cargo-scanner tools update-db trivy
  cargo-scanner cache clean
  cargo-scanner version

Scan options:
  --scanner grype        Scanner to use: grype, trivy, syft
  --config path          Config file path
  --runtime auto         Runtime to use: auto, docker, managed, native
  --docker-image image   Scanner runtime image for docker runtime
  --format text          Output format: text, json, sarif
  --json                 Write normalized JSON
  --output path          Write normalized report to file
  --raw-output path      Write raw scanner JSON to file when supported
  --sbom-output path     Write raw SBOM JSON to file for sbom command
  --recursive            Scan files under a directory
  --include "*.jar"      Include glob, comma-separated
  --exclude "*.tmp"      Exclude glob, comma-separated
  --fail-on high         Exit 1 when max severity meets threshold
  --timeout 15m          Scan timeout
`)
}
