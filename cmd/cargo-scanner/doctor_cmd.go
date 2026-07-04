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
	"github.com/opencomputinggarage/cargo-scanner/internal/ui"
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
	_, _ = fmt.Fprintln(stdout, ui.Title("Cargo Scanner doctor"))
	managedReady := false
	dockerReady := false
	for _, rt := range runtimes {
		status := "ok"
		if err := rt.Available(ctx); err != nil {
			status = "missing - " + err.Error()
		}
		_, _ = fmt.Fprintf(stdout, "\n%s: %s (%s)\n", ui.Section("Runtime"), rt.Name(), ui.Status(statusLabel(status)))
		if status != "ok" {
			continue
		}
		if dockerRuntime, ok := rt.(docker.Runtime); ok {
			if err := dockerRuntime.ImageAvailable(ctx); err != nil {
				_, _ = fmt.Fprintf(stdout, "- image: %s (%s)\n", ui.Status("not pulled"), compactError(err))
				_, _ = fmt.Fprintf(stdout, "- hint: %s\n", ui.Code("cargo-scanner runtime pull --scanner grype"))
				continue
			}
			dockerReady = true
			_, _ = fmt.Fprintf(stdout, "- image: %s (%s)\n", ui.Status("ok"), dockerRuntime.Image)
		}
		allDetected := true
		for _, scanner := range scanners {
			c := scanner.Detect(ctx, rt)
			scannerStatus := "missing"
			if c.Detected {
				scannerStatus = "ok"
			} else {
				allDetected = false
			}
			if c.Version != "" {
				_, _ = fmt.Fprintf(stdout, "- %s: %s (%s)\n", c.Name, ui.Status(scannerStatus), c.Version)
			} else if c.Error != "" {
				_, _ = fmt.Fprintf(stdout, "- %s: %s - %s\n", c.Name, ui.Status(scannerStatus), c.Error)
			} else {
				_, _ = fmt.Fprintf(stdout, "- %s: %s\n", c.Name, ui.Status(scannerStatus))
			}
		}
		if rt.Name() == "managed" && allDetected {
			managedReady = true
		}
	}
	printDoctorNextStep(stdout, managedReady, dockerReady)
	return 0
}

func printDoctorNextStep(stdout io.Writer, managedReady, dockerReady bool) {
	_, _ = fmt.Fprintln(stdout)
	switch {
	case managedReady:
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", ui.Section("Next"), ui.Code("cargo-scanner scan ~/Downloads --recursive"))
	case dockerReady:
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", ui.Section("Next"), ui.Code("cargo-scanner scan ./artifact.jar --runtime docker"))
	default:
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", ui.Section("Next"), ui.Code("cargo-scanner doctor --fix"))
	}
}

func runDoctorFix(ctx context.Context, stdout, stderr io.Writer, image string) int {
	if !shouldStartOperationProgress(stderr) {
		_, _ = fmt.Fprintln(stdout, ui.Title("Cargo Scanner doctor --fix"))
	}
	rt := managed.New("")
	if err := rt.Available(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "managed runtime unavailable: %v\n", err)
		return 1
	}
	names := tools.SupportedNames()
	total := len(names) + 1
	var progress *operationProgress
	if shouldStartOperationProgress(stderr) {
		progress = startOperationProgress(stderr, "Repair scanner environment", total)
		defer func() {
			if err := progress.Stop(); err != nil {
				_, _ = fmt.Fprintf(stderr, "close progress ui: %v\n", err)
			}
		}()
	}
	installer := tools.Installer{BinDir: rt.BinDir()}
	if progress != nil {
		installer.Progress = func(event tools.InstallProgress) {
			progress.Stage(event.Stage, event.Tool+" "+event.Detail)
		}
	}
	for i, name := range names {
		if progress != nil {
			progress.Step(i+1, total, "Checking tool", name)
		}
		scanner, _ := scannerByName(name)
		if scanner.Detect(ctx, rt).Detected {
			if progress != nil {
				progress.Complete(true, fmt.Sprintf("%s already installed", name))
			} else {
				_, _ = fmt.Fprintf(stdout, "- %s: %s\n", name, ui.Status("installed"))
			}
			continue
		}
		if progress != nil {
			progress.Stage("Installing tool", name)
		} else {
			_, _ = fmt.Fprintf(stdout, "- %s: %s\n", name, ui.Muted("installing..."))
		}
		result, err := installer.Install(ctx, name)
		if err != nil {
			if progress != nil {
				progress.Complete(false, fmt.Sprintf("%s failed: %v", name, err))
			}
			_, _ = fmt.Fprintf(stderr, "install %s: %v\n", name, err)
			_, _ = fmt.Fprintf(stderr, "hint: retry with cargo-scanner tools install %s\n", name)
			return 1
		}
		if progress != nil {
			progress.Complete(true, fmt.Sprintf("%s %s installed", result.Name, result.Version))
		} else {
			_, _ = fmt.Fprintf(stdout, "  %s %s %s at %s\n", ui.Status("installed"), result.Name, result.Version, ui.Code(result.Path))
		}
	}
	dockerRuntime := docker.New(image)
	if progress != nil {
		progress.Step(total, total, "Checking Docker image", image)
	}
	if err := dockerRuntime.Available(ctx); err != nil {
		if progress != nil {
			progress.Complete(true, "Docker skipped: "+compactError(err))
		} else {
			_, _ = fmt.Fprintf(stdout, "- docker: %s (%s)\n", ui.Status("skipped"), compactError(err))
		}
		_, _ = fmt.Fprintf(stdout, "  hint: install/start Docker, then run %s\n", ui.Code("cargo-scanner runtime pull --scanner grype"))
		return 0
	}
	if err := dockerRuntime.ImageAvailable(ctx); err == nil {
		if progress != nil {
			progress.Complete(true, "Docker image already available")
		} else {
			_, _ = fmt.Fprintf(stdout, "- docker image: %s (%s)\n", ui.Status("available"), image)
		}
		return 0
	}
	if progress != nil {
		progress.Stage("Pulling Docker image", image)
	} else {
		_, _ = fmt.Fprintf(stdout, "- docker image: pulling %s...\n", ui.Code(image))
	}
	pullOutput := stdout
	if progress != nil {
		pullOutput = progress.Writer()
	}
	if err := dockerRuntime.Pull(ctx, pullOutput); err != nil {
		if progress != nil {
			progress.Complete(false, "Docker pull failed: "+err.Error())
		}
		_, _ = fmt.Fprintf(stderr, "pull docker image: %v\n", err)
		_, _ = fmt.Fprintf(stderr, "hint: retry with cargo-scanner runtime pull --docker-image %s\n", image)
		return 1
	}
	if progress != nil {
		progress.Complete(true, "Docker image pulled")
	}
	return 0
}

func statusLabel(status string) string {
	if strings.HasPrefix(status, "missing") {
		return "missing"
	}
	return status
}

func compactError(err error) string {
	msg := strings.TrimSpace(err.Error())
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 180 {
		return msg[:177] + "..."
	}
	return msg
}
