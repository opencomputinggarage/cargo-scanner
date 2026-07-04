package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/byeonggi/cargo-scanner/internal/core"
	"github.com/byeonggi/cargo-scanner/internal/runtimes/docker"
	"github.com/byeonggi/cargo-scanner/internal/runtimes/managed"
	"github.com/byeonggi/cargo-scanner/internal/runtimes/native"
	"github.com/byeonggi/cargo-scanner/internal/scanners/grype"
	"github.com/byeonggi/cargo-scanner/internal/scanners/syft"
	"github.com/byeonggi/cargo-scanner/internal/scanners/trivy"
)

func runDoctor(ctx context.Context, stdout io.Writer) int {
	scanners := []core.Scanner{grype.New(), trivy.New(), syft.New()}
	runtimes := []core.Runtime{
		docker.New(docker.DefaultImage("grype")),
		managed.New(""),
		native.New(),
	}
	_, _ = fmt.Fprintln(stdout, "Cargo Scanner doctor")
	for _, rt := range runtimes {
		status := "ok"
		if err := rt.Available(ctx); err != nil {
			status = "missing - " + err.Error()
		}
		_, _ = fmt.Fprintf(stdout, "\nRuntime: %s (%s)\n", rt.Name(), status)
		if status != "ok" {
			continue
		}
		if dockerRuntime, ok := rt.(docker.Runtime); ok {
			if err := dockerRuntime.ImageAvailable(ctx); err != nil {
				_, _ = fmt.Fprintf(stdout, "- image: not pulled (%s)\n", compactError(err))
				_, _ = fmt.Fprintf(stdout, "- hint: cargo-scanner runtime pull --scanner grype\n")
				continue
			}
			_, _ = fmt.Fprintf(stdout, "- image: ok (%s)\n", dockerRuntime.Image)
		}
		for _, scanner := range scanners {
			c := scanner.Detect(ctx, rt)
			scannerStatus := "missing"
			if c.Detected {
				scannerStatus = "ok"
			}
			if c.Version != "" {
				_, _ = fmt.Fprintf(stdout, "- %s: %s (%s)\n", c.Name, scannerStatus, c.Version)
			} else if c.Error != "" {
				_, _ = fmt.Fprintf(stdout, "- %s: %s - %s\n", c.Name, scannerStatus, c.Error)
			} else {
				_, _ = fmt.Fprintf(stdout, "- %s: %s\n", c.Name, scannerStatus)
			}
		}
	}
	return 0
}

func compactError(err error) string {
	msg := strings.TrimSpace(err.Error())
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 180 {
		return msg[:177] + "..."
	}
	return msg
}
