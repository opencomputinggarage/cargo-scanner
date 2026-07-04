package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/byeonggi/cargo-scanner/internal/runtimes/managed"
)

func runCache(_ context.Context, args []string, stdout, stderr io.Writer) int {
	rt := managed.New("")
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "cache requires a subcommand: path, clean")
		return 2
	}
	switch args[0] {
	case "path":
		_, _ = fmt.Fprintln(stdout, rt.CacheDir())
		return 0
	case "clean":
		if err := os.RemoveAll(rt.CacheDir()); err != nil {
			_, _ = fmt.Fprintf(stderr, "clean cache: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "Cleaned cache: %s\n", rt.CacheDir())
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown cache subcommand %q\n", args[0])
		return 2
	}
}
