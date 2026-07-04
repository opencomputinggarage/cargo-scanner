package core

import "context"

type Runtime interface {
	Name() string
	Available(ctx context.Context) error
	LookPath(ctx context.Context, binary string) (string, error)
	Run(ctx context.Context, req RunRequest) (RunResult, error)
}

type RunRequest struct {
	Binary string
	Args   []string
	Env    []string
	Dir    string
	Mounts []Mount
}

type RunResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type PathMapper interface {
	RuntimePath(hostPath string) (string, []Mount)
}

type Capability struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Detected bool   `json:"detected"`
	Runtime  string `json:"runtime"`
	Error    string `json:"error,omitempty"`
}

type ScanOptions struct {
	KeepRaw bool
}

type Scanner interface {
	Name() string
	Detect(ctx context.Context, rt Runtime) Capability
	Scan(ctx context.Context, rt Runtime, target Target, opts ScanOptions) (Report, error)
}

type SBOMGenerator interface {
	GenerateSBOM(ctx context.Context, rt Runtime, target Target, opts ScanOptions) (Report, error)
}
