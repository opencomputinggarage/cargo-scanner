package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/docker"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/managed"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/native"
	"github.com/opencomputinggarage/cargo-scanner/internal/scanners/grype"
	"github.com/opencomputinggarage/cargo-scanner/internal/scanners/syft"
	"github.com/opencomputinggarage/cargo-scanner/internal/scanners/trivy"
	"github.com/opencomputinggarage/cargo-scanner/internal/tools"
)

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fix := fs.Bool("fix", false, "install managed tools and pull the default Docker image")
	dockerImage := fs.String("docker-image", docker.DefaultImage("grype"), "Docker runtime image to check or pull")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "doctor does not accept positional arguments")
		return 2
	}
	if *fix {
		return runDoctorFix(ctx, stdout, stderr, *dockerImage)
	}
	scanners := []core.Scanner{grype.New(), trivy.New(), syft.New()}
	runtimes := []core.Runtime{
		docker.New(*dockerImage),
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

func runDoctorFix(ctx context.Context, stdout, stderr io.Writer, image string) int {
	_, _ = fmt.Fprintln(stdout, "Cargo Scanner doctor --fix")
	rt := managed.New("")
	if err := rt.Available(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "managed runtime unavailable: %v\n", err)
		return 1
	}
	installer := tools.Installer{BinDir: rt.BinDir()}
	for _, name := range tools.SupportedNames() {
		scanner, _ := scannerByName(name)
		if scanner.Detect(ctx, rt).Detected {
			_, _ = fmt.Fprintf(stdout, "- %s: already installed\n", name)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "- %s: installing...\n", name)
		result, err := installer.Install(ctx, name)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "install %s: %v\n", name, err)
			_, _ = fmt.Fprintf(stderr, "hint: retry with cargo-scanner tools install %s\n", name)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "  installed %s %s at %s\n", result.Name, result.Version, result.Path)
	}
	dockerRuntime := docker.New(image)
	if err := dockerRuntime.Available(ctx); err != nil {
		_, _ = fmt.Fprintf(stdout, "- docker: skipped (%s)\n", compactError(err))
		_, _ = fmt.Fprintln(stdout, "  hint: install/start Docker, then run cargo-scanner runtime pull --scanner grype")
		return 0
	}
	if err := dockerRuntime.ImageAvailable(ctx); err == nil {
		_, _ = fmt.Fprintf(stdout, "- docker image: already available (%s)\n", image)
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "- docker image: pulling %s...\n", image)
	if err := dockerRuntime.Pull(ctx, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "pull docker image: %v\n", err)
		_, _ = fmt.Fprintf(stderr, "hint: retry with cargo-scanner runtime pull --docker-image %s\n", image)
		return 1
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
