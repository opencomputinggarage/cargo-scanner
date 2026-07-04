package core

import (
	"os"
	"path/filepath"
)

type Workspace struct {
	Root     string
	InputDir string
}

func PrepareWorkspace(target Target) (Workspace, func(), error) {
	root, err := os.MkdirTemp("", "cargo-scanner-*")
	if err != nil {
		return Workspace{}, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	inputDir := filepath.Join(root, "input")
	if err := os.MkdirAll(inputDir, 0o700); err != nil {
		cleanup()
		return Workspace{}, nil, err
	}
	if target.Kind == "directory" {
		return Workspace{Root: root, InputDir: target.Path}, cleanup, nil
	}
	name := filepath.Base(target.Path)
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = "artifact"
	}
	dst := filepath.Join(inputDir, name)
	if err := copyFile(target.Path, dst); err != nil {
		cleanup()
		return Workspace{}, nil, err
	}
	return Workspace{Root: root, InputDir: inputDir}, cleanup, nil
}

func RuntimePath(rt Runtime, hostPath string) (string, []Mount) {
	if mapper, ok := rt.(PathMapper); ok {
		return mapper.RuntimePath(hostPath)
	}
	return hostPath, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.ReadFrom(in); err != nil {
		return err
	}
	return out.Sync()
}
