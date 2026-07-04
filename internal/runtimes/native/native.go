package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/byeonggi/cargo-scanner/internal/core"
)

type Runtime struct{}

func New() Runtime {
	return Runtime{}
}

func (Runtime) Name() string {
	return "native"
}

func (Runtime) Available(context.Context) error {
	return nil
}

func (Runtime) LookPath(_ context.Context, binary string) (string, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("%s not found on PATH", binary)
	}
	return path, nil
}

func (Runtime) RuntimePath(hostPath string) (string, []core.Mount) {
	return hostPath, nil
}

func (Runtime) Run(ctx context.Context, req core.RunRequest) (core.RunResult, error) {
	if req.Binary == "" {
		return core.RunResult{}, errors.New("binary is required")
	}
	cmd := exec.CommandContext(ctx, req.Binary, req.Args...)
	cmd.Dir = req.Dir
	cmd.Env = append(os.Environ(), req.Env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
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
