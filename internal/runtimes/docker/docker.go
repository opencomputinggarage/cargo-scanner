package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

const defaultImage = "anchore/grype:latest"

type Runtime struct {
	Image string
}

func New(image string) Runtime {
	if image == "" {
		image = defaultImage
	}
	return Runtime{Image: image}
}

func DefaultImage(scanner string) string {
	switch scanner {
	case "trivy":
		return "aquasec/trivy:latest"
	case "syft":
		return "anchore/syft:latest"
	default:
		return defaultImage
	}
}

func (r Runtime) Name() string {
	return "docker"
}

func (r Runtime) Available(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found on PATH")
	}
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := bytes.TrimSpace(stderr.Bytes())
		if len(msg) > 0 {
			return fmt.Errorf("docker unavailable: %s", msg)
		}
		return fmt.Errorf("docker unavailable: %w", err)
	}
	return nil
}

func (r Runtime) ImageAvailable(ctx context.Context) error {
	if err := r.Available(ctx); err != nil {
		return err
	}
	image := exec.CommandContext(ctx, "docker", "image", "inspect", r.Image)
	var stderr bytes.Buffer
	stderr.Reset()
	image.Stderr = &stderr
	if err := image.Run(); err != nil {
		msg := bytes.TrimSpace(stderr.Bytes())
		if len(msg) > 0 {
			return fmt.Errorf("docker image %s unavailable: %s", r.Image, msg)
		}
		return fmt.Errorf("docker image %s unavailable: %w", r.Image, err)
	}
	return nil
}

func (r Runtime) LookPath(ctx context.Context, binary string) (string, error) {
	if err := r.Available(ctx); err != nil {
		return "", err
	}
	if binary == "" {
		return "", errors.New("binary is required")
	}
	return binary, nil
}

func (r Runtime) RuntimePath(hostPath string) (string, []core.Mount) {
	target := "/cargo/input"
	return target, []core.Mount{{
		Source:   hostPath,
		Target:   target,
		ReadOnly: true,
	}}
}

func (r Runtime) Pull(ctx context.Context, stdout io.Writer) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found on PATH")
	}
	cmd := exec.CommandContext(ctx, "docker", "pull", r.Image)
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	return cmd.Run()
}

func (r Runtime) Run(ctx context.Context, req core.RunRequest) (core.RunResult, error) {
	if req.Binary == "" {
		return core.RunResult{}, errors.New("binary is required")
	}
	if err := r.Available(ctx); err != nil {
		return core.RunResult{}, err
	}
	args := []string{"run", "--rm", "--entrypoint", req.Binary}
	for _, env := range req.Env {
		args = append(args, "-e", env)
	}
	for _, mount := range req.Mounts {
		source, err := filepath.Abs(mount.Source)
		if err != nil {
			return core.RunResult{}, err
		}
		mode := "rw"
		if mount.ReadOnly {
			mode = "ro"
		}
		args = append(args, "-v", source+":"+mount.Target+":"+mode)
	}
	if req.Dir != "" {
		args = append(args, "-w", req.Dir)
	}
	args = append(args, r.Image)
	args = append(args, req.Args...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = os.Environ()
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
