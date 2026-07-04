package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func InspectTarget(path string) (Target, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Target{}, err
	}
	target := Target{Path: path, Size: info.Size()}
	if info.IsDir() {
		target.Kind = "directory"
		return target, nil
	}
	target.Kind = "file"
	digest, err := fileSHA256(path)
	if err != nil {
		return Target{}, fmt.Errorf("hash target: %w", err)
	}
	target.SHA256 = digest
	return target, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
