package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const defaultConfig = `# Cargo Scanner project defaults.
# Personal machines usually work best with managed tools.
scanner: grype
runtime: managed
format: text
fail_on: high
timeout: 15m
include: []
exclude: ["*.tmp", "*.log", ".git/*", "node_modules/*", "dist/*", "bin/*"]
`

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", ".cargo-scanner.yaml", "config file path")
	force := fs.Bool("force", false, "overwrite an existing config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "init does not accept positional arguments")
		return 2
	}
	if _, err := os.Stat(*configPath); err == nil && !*force {
		_, _ = fmt.Fprintf(stderr, "%s already exists; use --force to overwrite\n", *configPath)
		return 1
	} else if err != nil && !os.IsNotExist(err) {
		_, _ = fmt.Fprintf(stderr, "check config: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*configPath, []byte(defaultConfig), 0o600); err != nil {
		_, _ = fmt.Fprintf(stderr, "write config: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Wrote %s\n", *configPath)
	_, _ = fmt.Fprintln(stdout, "Next:")
	_, _ = fmt.Fprintln(stdout, "  cargo-scanner doctor --fix")
	_, _ = fmt.Fprintln(stdout, "  cargo-scanner scan .")
	return 0
}
