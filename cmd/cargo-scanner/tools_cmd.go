package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss/table"
	"github.com/opencomputinggarage/cargo-scanner/internal/core"
	"github.com/opencomputinggarage/cargo-scanner/internal/runtimes/managed"
	"github.com/opencomputinggarage/cargo-scanner/internal/tools"
	"github.com/opencomputinggarage/cargo-scanner/internal/ui"
)

func runTools(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "tools requires a subcommand: path, list, doctor, install, update, uninstall")
		return 2
	}
	rt := managed.New("")
	switch args[0] {
	case "path":
		_, _ = fmt.Fprintln(stdout, rt.BinDir())
		return 0
	case "doctor", "list":
		return runToolsList(ctx, stdout, stderr, rt)
	case "install":
		return runToolsInstall(ctx, args[1:], stdout, stderr, rt, false)
	case "update":
		return runToolsInstall(ctx, args[1:], stdout, stderr, rt, true)
	case "uninstall":
		return runToolsUninstall(args[1:], stdout, stderr, rt)
	case "update-db":
		return runToolsUpdateDB(ctx, args[1:], stdout, stderr, rt)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown tools subcommand %q\n", args[0])
		return 2
	}
}

func runToolsUninstall(args []string, stdout, stderr io.Writer, rt managed.Runtime) int {
	fs := flag.NewFlagSet("tools uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "tools uninstall requires one tool name: grype, trivy, syft, all")
		return 2
	}
	names := []string{fs.Arg(0)}
	if fs.Arg(0) == "all" {
		names = tools.SupportedNames()
	}
	for _, name := range names {
		path := rt.ToolPath(name)
		_ = os.Remove(path)
		_ = os.Remove(rt.ManifestPath(name))
		_, _ = fmt.Fprintf(stdout, "- %s removed\n", name)
	}
	return 0
}

func runToolsUpdateDB(ctx context.Context, args []string, stdout, stderr io.Writer, rt managed.Runtime) int {
	fs := flag.NewFlagSet("tools update-db", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || fs.Arg(0) != "trivy" {
		_, _ = fmt.Fprintln(stderr, "tools update-db currently supports: trivy")
		return 2
	}
	if err := rt.Available(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "managed tools unavailable: %v\n", err)
		return 1
	}
	if _, err := rt.LookPath(ctx, "trivy"); err != nil {
		_, _ = fmt.Fprintf(stderr, "trivy is not installed; run cargo-scanner tools install trivy\n")
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "Updating Trivy vulnerability database...")
	result, err := rt.Run(ctx, core.RunRequest{Binary: "trivy", Args: []string{"image", "--download-db-only"}})
	if len(result.Stdout) > 0 {
		_, _ = stdout.Write(result.Stdout)
	}
	if len(result.Stderr) > 0 {
		_, _ = stderr.Write(result.Stderr)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "update trivy db: %v\n", err)
		return 1
	}
	return 0
}

func runToolsList(ctx context.Context, stdout, stderr io.Writer, rt managed.Runtime) int {
	if err := rt.Available(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "managed tools unavailable: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n\nManaged tools path: %s\n\n", ui.Title("Managed scanner tools"), ui.Code(rt.BinDir()))
	rows := [][]string{}
	for _, name := range tools.SupportedNames() {
		scanner, _ := scannerByName(name)
		c := scanner.Detect(ctx, rt)
		if c.Detected {
			digest := ""
			if manifest, err := tools.ReadManifest(rt.ManifestPath(name)); err == nil && manifest.SHA256 != "" {
				digest = manifest.SHA256[:12]
			}
			if c.Version != "" {
				rows = append(rows, []string{name, ui.Status("installed"), c.Version, digest})
			} else {
				rows = append(rows, []string{name, ui.Status("installed"), "", digest})
			}
		} else {
			rows = append(rows, []string{name, ui.Status("missing"), "", ""})
		}
	}
	_, _ = fmt.Fprintln(stdout, table.New().
		Headers("Tool", "Status", "Version", "SHA256").
		Rows(rows...).
		Render())
	return 0
}

func runToolsInstall(ctx context.Context, args []string, stdout, stderr io.Writer, rt managed.Runtime, update bool) int {
	fs := flag.NewFlagSet("tools install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		verb := "install"
		if update {
			verb = "update"
		}
		_, _ = fmt.Fprintf(stderr, "tools %s requires one tool name: grype, trivy, syft, all\n", verb)
		return 2
	}
	names := []string{fs.Arg(0)}
	if fs.Arg(0) == "all" {
		names = tools.SupportedNames()
	}
	var progress *operationProgress
	if shouldStartOperationProgress(stderr) {
		title := "Installing scanner tools"
		if update {
			title = "Updating scanner tools"
		}
		progress = startOperationProgress(stderr, title, len(names))
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
		if update {
			if progress != nil {
				progress.Step(i+1, len(names), "Updating", name)
			} else {
				_, _ = fmt.Fprintf(stdout, "Updating %s...\n", name)
			}
		} else {
			if progress != nil {
				progress.Step(i+1, len(names), "Installing", name)
			} else {
				_, _ = fmt.Fprintf(stdout, "Installing %s...\n", name)
			}
		}
		result, err := installer.Install(ctx, name)
		if err != nil {
			if progress != nil {
				progress.Complete(false, fmt.Sprintf("%s failed: %v", name, err))
			}
			_, _ = fmt.Fprintf(stderr, "install %s: %v\n", name, err)
			return 1
		}
		if progress != nil {
			progress.Complete(true, fmt.Sprintf("%s %s installed", result.Name, result.Version))
		}
		_, _ = fmt.Fprintf(stdout, "- %s %s installed at %s\n", result.Name, result.Version, result.Path)
	}
	return 0
}
