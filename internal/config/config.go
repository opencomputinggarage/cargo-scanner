package config

import (
	"os"
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
