package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/byeonggi/cargo-scanner/internal/runtimes/docker"
)

func runRuntime(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "runtime requires a subcommand: pull")
		return 2
	}
	switch args[0] {
	case "pull":
		fs := flag.NewFlagSet("runtime pull", flag.ContinueOnError)
		fs.SetOutput(stderr)
		dockerImage := fs.String("docker-image", "", "scanner runtime Docker image")
		scannerName := fs.String("scanner", "grype", "scanner image to pull")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		image := *dockerImage
		if image == "" {
			image = docker.DefaultImage(strings.ToLower(strings.TrimSpace(*scannerName)))
		}
		rt := docker.New(image)
		if err := rt.Pull(ctx, stdout); err != nil {
			_, _ = fmt.Fprintf(stderr, "pull runtime image: %v\n", err)
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown runtime subcommand %q\n", args[0])
		return 2
	}
}
