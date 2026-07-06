package config

import (
	"path/filepath"
	"testing"
	"time"
)

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

func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	want := Config{
		Scanner: "grype",
		Runtime: "native",
		Format:  "json",
		FailOn:  "high",
		Timeout: 30 * time.Second,
		Include: []string{"*.jar"},
		Exclude: []string{"node_modules/*"},
	}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scanner != want.Scanner || got.Runtime != want.Runtime || got.Format != want.Format ||
		got.FailOn != want.FailOn || got.Timeout != want.Timeout {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
	if len(got.Include) != 1 || got.Include[0] != "*.jar" {
		t.Fatalf("unexpected include: %+v", got.Include)
	}
	if len(got.Exclude) != 1 || got.Exclude[0] != "node_modules/*" {
		t.Fatalf("unexpected exclude: %+v", got.Exclude)
	}
}

func TestMergeProjectOverridesGlobal(t *testing.T) {
	global := Config{Scanner: "grype", Runtime: "managed", Format: "text"}
	project := Config{Runtime: "native"}
	got := Merge(global, project)
	if got.Runtime != "native" {
		t.Fatalf("project should override runtime: %+v", got)
	}
	if got.Scanner != "grype" || got.Format != "text" {
		t.Fatalf("global values should remain: %+v", got)
	}
}
