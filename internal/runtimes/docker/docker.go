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
	// MultiTool marks images that bundle several scanner binaries on $PATH
	// (e.g. the cargo-scanner-runtime image). For those we must select the
	// requested scanner via --entrypoint, since the image's own ENTRYPOINT
	// points at a single tool. Vendor images leave this false and run their
	// own ENTRYPOINT.
	MultiTool bool
}

func New(image string) Runtime {
	if image == "" {
		image = defaultImage
	}
	return Runtime{Image: image}
}

// NewMultiTool builds a runtime for an image that bundles multiple scanner
// binaries on $PATH, selecting the requested scanner via --entrypoint.
func NewMultiTool(image string) Runtime {
	rt := New(image)
	rt.MultiTool = true
	return rt
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
	// Each vendor scanner image already sets the scanner binary as its
	// ENTRYPOINT (e.g. /grype, /syft, trivy), so we pass only the arguments
	// and let the image's own entrypoint run. Overriding --entrypoint with a
	// bare binary name breaks images whose binary is not on $PATH (grype and
	// syft live at the image root), which Docker surfaces as a confusing
	// "unable to upgrade to tcp, received 500".
	//
	// Multi-tool images bundle every scanner on $PATH under a single
	// ENTRYPOINT, so there we override --entrypoint to select the requested
	// binary; without it every scanner would run through the image's default
	// entrypoint (e.g. grype receiving trivy's flags).
	args := []string{"run", "--rm"}
	if r.MultiTool {
		args = append(args, "--entrypoint", req.Binary)
	}
	for _, env := range req.Env {
		args = append(args, "-e", env)
	}
	for _, mount := range req.Mounts {
		source, err := filepath.Abs(mount.Source)
		if err != nil {
			return core.RunResult{}, err
		}
		// Resolve symlinks so the bind source is the real path. On macOS the
		// Docker/Podman VM only mounts canonical host paths (e.g. /private/tmp,
		// not the /tmp symlink), so mounting an unresolved symlinked path yields
		// an empty or unreadable directory and the scan silently finds nothing.
		if resolved, err := filepath.EvalSymlinks(source); err == nil {
			source = resolved
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
