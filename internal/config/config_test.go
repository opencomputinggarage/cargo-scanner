package config

import "testing"

func TestParse(t *testing.T) {
	cfg, err := parse([]byte(`
scanner: trivy
runtime: managed
format: sarif
fail_on: high
timeout: 30s
include: ["*.jar", "*.tgz"]
exclude: ["node_modules/**"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scanner != "trivy" || cfg.Runtime != "managed" || cfg.Format != "sarif" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.Include) != 2 || cfg.Include[0] != "*.jar" {
		t.Fatalf("unexpected include: %+v", cfg.Include)
	}
}
