package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Scanner string
	Runtime string
	Format  string
	FailOn  string
	Timeout time.Duration
	Include []string
	Exclude []string
}

func Load(path string) (Config, error) {
	if path == "" {
		path = ".cargo-scanner.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, err
	}
	return parse(data)
}

// GlobalPath returns the path to the global settings file. It honors
// CARGO_SCANNER_HOME so it stays aligned with the managed tools root.
func GlobalPath() string {
	return filepath.Join(homeRoot(), "config.yaml")
}

func homeRoot() string {
	if v := os.Getenv("CARGO_SCANNER_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".cargo-scanner"
	}
	return filepath.Join(home, ".cargo-scanner")
}

// LoadLayered loads the global settings file first, then overlays the project
// config so project values win over global defaults.
func LoadLayered(projectPath string) (Config, error) {
	global, err := Load(GlobalPath())
	if err != nil {
		return Config{}, err
	}
	project, err := Load(projectPath)
	if err != nil {
		return Config{}, err
	}
	return Merge(global, project), nil
}

// Merge returns base with any fields set in over taking precedence.
func Merge(base, over Config) Config {
	out := base
	if over.Scanner != "" {
		out.Scanner = over.Scanner
	}
	if over.Runtime != "" {
		out.Runtime = over.Runtime
	}
	if over.Format != "" {
		out.Format = over.Format
	}
	if over.FailOn != "" {
		out.FailOn = over.FailOn
	}
	if over.Timeout > 0 {
		out.Timeout = over.Timeout
	}
	if over.Include != nil {
		out.Include = over.Include
	}
	if over.Exclude != nil {
		out.Exclude = over.Exclude
	}
	return out
}

// Save writes cfg to path in the same YAML shape the parser reads, creating
// parent directories as needed.
func Save(path string, cfg Config) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(marshal(cfg)), 0o600)
}

func marshal(cfg Config) string {
	var b strings.Builder
	b.WriteString("# Cargo Scanner global defaults.\n")
	b.WriteString("# Project .cargo-scanner.yaml files override these values.\n")
	writeString(&b, "scanner", cfg.Scanner)
	writeString(&b, "runtime", cfg.Runtime)
	writeString(&b, "format", cfg.Format)
	writeString(&b, "fail_on", cfg.FailOn)
	if cfg.Timeout > 0 {
		fmt.Fprintf(&b, "timeout: %s\n", cfg.Timeout.String())
	}
	writeStringList(&b, "include", cfg.Include)
	writeStringList(&b, "exclude", cfg.Exclude)
	return b.String()
}

func writeString(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, "%s: %q\n", key, value)
}

func writeStringList(b *strings.Builder, key string, values []string) {
	if len(values) == 0 {
		return
	}
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	fmt.Fprintf(b, "%s: [%s]\n", key, strings.Join(quoted, ", "))
}

func parse(data []byte) (Config, error) {
	var cfg Config
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		switch key {
		case "scanner":
			cfg.Scanner = value
		case "runtime":
			cfg.Runtime = value
		case "format":
			cfg.Format = value
		case "fail_on":
			cfg.FailOn = value
		case "timeout":
			if d, err := time.ParseDuration(value); err == nil {
				cfg.Timeout = d
			}
		case "include":
			cfg.Include = splitList(value)
		case "exclude":
			cfg.Exclude = splitList(value)
		}
	}
	return cfg, nil
}

func splitList(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if value == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(strings.Trim(item, `"'`))
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
