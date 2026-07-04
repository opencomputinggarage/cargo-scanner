package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
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
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
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
