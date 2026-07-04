package core

import (
	"os"
	"path/filepath"
	"strings"
)

func DiscoverTargets(path string, recursive bool) ([]Target, error) {
	return DiscoverTargetsWithFilters(path, recursive, nil, nil)
}

func DiscoverTargetsWithFilters(path string, recursive bool, include, exclude []string) ([]Target, error) {
	target, err := InspectTarget(path)
	if err != nil {
		return nil, err
	}
	if target.Kind != "directory" || !recursive {
		if targetAllowed(target.Path, include, exclude) {
			return []Target{target}, nil
		}
		return nil, nil
	}
	var targets []Target
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		target, err := InspectTarget(p)
		if err != nil {
			return err
		}
		if !targetAllowed(p, include, exclude) {
			return nil
		}
		targets = append(targets, target)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return targets, nil
}

func targetAllowed(path string, include, exclude []string) bool {
	for _, pattern := range exclude {
		if globMatch(pattern, path) {
			return false
		}
	}
	if len(include) == 0 {
		return true
	}
	for _, pattern := range include {
		if globMatch(pattern, path) {
			return true
		}
	}
	return false
}

func globMatch(pattern, path string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	base := filepath.Base(path)
	if ok, _ := filepath.Match(pattern, base); ok {
		return true
	}
	if ok, _ := filepath.Match(pattern, path); ok {
		return true
	}
	if strings.Contains(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		if ok, _ := filepath.Match(suffix, base); ok {
			return true
		}
	}
	return false
}
