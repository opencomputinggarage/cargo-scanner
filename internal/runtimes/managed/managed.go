package managed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

type Runtime struct {
	Root string
}

func New(root string) Runtime {
	if root == "" {
		root = defaultRoot()
	}
	return Runtime{Root: root}
}

func (r Runtime) Name() string {
	return "managed"
}

func (r Runtime) BinDir() string {
	return filepath.Join(r.Root, "tools", "bin")
}

func (r Runtime) CacheDir() string {
	return filepath.Join(r.Root, "cache")
}

func (r Runtime) ToolPath(binary string) string {
	return filepath.Join(r.BinDir(), executableName(binary))
}

func (r Runtime) ManifestPath(binary string) string {
	return r.ToolPath(binary) + ".json"
}

func (r Runtime) Available(context.Context) error {
	if err := os.MkdirAll(r.BinDir(), 0o700); err != nil {
		return err
	}
	return nil
}

func (r Runtime) LookPath(ctx context.Context, binary string) (string, error) {
	if err := r.Available(ctx); err != nil {
		return "", err
	}
	path := r.ToolPath(binary)
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s not installed in managed tools (%s)", binary, r.BinDir())
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory", path)
	}
	return path, nil
}

func (r Runtime) RuntimePath(hostPath string) (string, []core.Mount) {
	return hostPath, nil
}

func (r Runtime) Run(ctx context.Context, req core.RunRequest) (core.RunResult, error) {
	if req.Binary == "" {
		return core.RunResult{}, errors.New("binary is required")
	}
	binary, err := r.LookPath(ctx, req.Binary)
	if err != nil {
		return core.RunResult{}, err
	}
	cmd := exec.CommandContext(ctx, binary, req.Args...)
	cmd.Dir = req.Dir
	cmd.Env = append(os.Environ(),
		"XDG_CACHE_HOME="+r.CacheDir(),
		"TRIVY_CACHE_DIR="+filepath.Join(r.CacheDir(), "trivy"),
	)
	cmd.Env = append(cmd.Env, req.Env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	result := core.RunResult{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, err
		}
		result.ExitCode = -1
		return result, err
	}
	return result, nil
}

func executableName(binary string) string {
	if runtime.GOOS == "windows" && filepath.Ext(binary) == "" {
		return binary + ".exe"
	}
	return binary
}

func defaultRoot() string {
	if v := os.Getenv("CARGO_SCANNER_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".cargo-scanner"
	}
	return filepath.Join(home, ".cargo-scanner")
}
