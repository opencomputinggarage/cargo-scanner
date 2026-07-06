package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/opencomputinggarage/cargo-scanner/internal/config"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
	"github.com/opencomputinggarage/cargo-scanner/internal/ui"
)

func runConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	sub := ""
	if len(rest) > 0 {
		sub = strings.ToLower(rest[0])
	}
	switch sub {
	case "":
		if shouldRunScanWizard(stdout, stderr) {
			return configEdit(stdout, stderr)
		}
		return configShow(stdout, stderr)
	case "edit":
		if !shouldRunScanWizard(stdout, stderr) {
			_, _ = fmt.Fprintln(stderr, "config edit needs an interactive terminal; use config set instead")
			return 2
		}
		return configEdit(stdout, stderr)
	case "show", "list":
		return configShow(stdout, stderr)
	case "path":
		_, _ = fmt.Fprintln(stdout, config.GlobalPath())
		return 0
	case "get":
		if len(rest) < 2 {
			_, _ = fmt.Fprintln(stderr, "usage: cargo-scanner config get <key>")
			return 2
		}
		return configGet(stdout, stderr, rest[1])
	case "set":
		if len(rest) < 3 {
			_, _ = fmt.Fprintln(stderr, "usage: cargo-scanner config set <key> <value>")
			return 2
		}
		return configSet(stdout, stderr, rest[1], strings.Join(rest[2:], " "))
	default:
		_, _ = fmt.Fprintf(stderr, "unknown config command %q\n", sub)
		_, _ = fmt.Fprintln(stderr, "commands: show, get, set, path, edit")
		return 2
	}
}

var configKeys = []string{"scanner", "runtime", "format", "fail_on", "timeout", "include", "exclude"}

func configShow(stdout, stderr io.Writer) int {
	path := config.GlobalPath()
	cfg, err := config.Load(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, ui.Section("Global settings"))
	_, _ = fmt.Fprintln(stdout, ui.Muted(path))
	_, _ = fmt.Fprintln(stdout)
	for _, key := range configKeys {
		value := configFieldValue(cfg, key)
		if value == "" {
			value = ui.Muted("(unset)")
		}
		_, _ = fmt.Fprintf(stdout, "  %-9s %s\n", key, value)
	}
	return 0
}

func configGet(stdout, stderr io.Writer, key string) int {
	key = normalizeConfigKey(key)
	if !isConfigKey(key) {
		_, _ = fmt.Fprintf(stderr, "unknown key %q; keys: %s\n", key, strings.Join(configKeys, ", "))
		return 2
	}
	cfg, err := config.Load(config.GlobalPath())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, configFieldValue(cfg, key))
	return 0
}

func configSet(stdout, stderr io.Writer, key, value string) int {
	key = normalizeConfigKey(key)
	path := config.GlobalPath()
	cfg, err := config.Load(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	if err := applyConfigField(&cfg, key, value); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := config.Save(path, cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "save config: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s %s = %s\n", ui.Status("ok"), key, configFieldValue(cfg, key))
	_, _ = fmt.Fprintln(stdout, ui.Muted("saved to "+path))
	return 0
}

func configEdit(stdout, stderr io.Writer) int {
	path := config.GlobalPath()
	cfg, err := config.Load(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load config: %v\n", err)
		return 1
	}
	runtime := orDefault(cfg.Runtime, "auto")
	scanner := orDefault(cfg.Scanner, "grype")
	format := orDefault(cfg.Format, "text")
	failOn := cfg.FailOn

	_, _ = fmt.Fprintln(stderr, ui.Title("Cargo Scanner Settings"))
	_, _ = fmt.Fprintln(stderr, ui.Muted("Defaults for every scan. Saved to "+path))
	_, _ = fmt.Fprintln(stderr)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Default runtime").
				Description("How scanner tools are launched.").
				Options(
					huh.NewOption("auto - docker, then built-in, then PATH", "auto"),
					huh.NewOption("native - tools installed on PATH", "native"),
					huh.NewOption("managed - built-in tools", "managed"),
					huh.NewOption("docker - container image", "docker"),
				).
				Value(&runtime),
			huh.NewSelect[string]().
				Title("Default scanner").
				Options(
					huh.NewOption("Grype - vulnerabilities", "grype"),
					huh.NewOption("Trivy - vulnerabilities", "trivy"),
					huh.NewOption("Syft - SBOM inventory", "syft"),
				).
				Value(&scanner),
			huh.NewSelect[string]().
				Title("Default format").
				Options(
					huh.NewOption("text", "text"),
					huh.NewOption("json", "json"),
					huh.NewOption("sarif", "sarif"),
				).
				Value(&format),
			huh.NewSelect[string]().
				Title("Fail threshold").
				Description("Exit non-zero when max severity meets this level.").
				Options(
					huh.NewOption("Do not fail automatically", ""),
					huh.NewOption("low", "low"),
					huh.NewOption("medium", "medium"),
					huh.NewOption("high", "high"),
					huh.NewOption("critical", "critical"),
				).
				Value(&failOn),
		),
	).WithTheme(huh.ThemeCharm()).WithWidth(72)

	if err := form.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %v\n", ui.Status("skipped"), err)
		return 2
	}
	cfg.Runtime = runtime
	cfg.Scanner = scanner
	cfg.Format = format
	cfg.FailOn = failOn
	if err := config.Save(path, cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "save config: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s Saved settings to %s\n", ui.Status("ok"), path)
	return 0
}

func normalizeConfigKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "fail-on" {
		return "fail_on"
	}
	return key
}

func isConfigKey(key string) bool {
	for _, k := range configKeys {
		if k == key {
			return true
		}
	}
	return false
}

func configFieldValue(cfg config.Config, key string) string {
	switch key {
	case "scanner":
		return cfg.Scanner
	case "runtime":
		return cfg.Runtime
	case "format":
		return cfg.Format
	case "fail_on":
		return cfg.FailOn
	case "timeout":
		if cfg.Timeout > 0 {
			return cfg.Timeout.String()
		}
		return ""
	case "include":
		return strings.Join(cfg.Include, ",")
	case "exclude":
		return strings.Join(cfg.Exclude, ",")
	}
	return ""
}

func applyConfigField(cfg *config.Config, key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "scanner":
		if _, err := scannerByName(value); err != nil {
			return err
		}
		cfg.Scanner = value
	case "runtime":
		if !isValidRuntime(value) {
			return fmt.Errorf("runtime must be one of: auto, native, managed, docker")
		}
		cfg.Runtime = value
	case "format":
		if !isValidFormat(value) {
			return fmt.Errorf("format must be one of: text, json, sarif")
		}
		cfg.Format = value
	case "fail_on":
		if _, err := core.ParseFailSeverity(value); err != nil {
			return err
		}
		cfg.FailOn = value
	case "timeout":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("timeout must be a duration like 15m: %w", err)
		}
		cfg.Timeout = d
	case "include":
		cfg.Include = splitCSV(value)
	case "exclude":
		cfg.Exclude = splitCSV(value)
	default:
		return fmt.Errorf("unknown key %q; keys: %s", key, strings.Join(configKeys, ", "))
	}
	return nil
}

func isValidRuntime(value string) bool {
	switch value {
	case "auto", "native", "managed", "docker":
		return true
	}
	return false
}

func isValidFormat(value string) bool {
	switch value {
	case "text", "json", "sarif":
		return true
	}
	return false
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
