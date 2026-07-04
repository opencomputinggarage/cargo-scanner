# Cargo Scanner Usage

This document is the command reference. Start with the
[README](../README.md) if you want the shortest setup path.

## First Run

```sh
cargo-scanner init
cargo-scanner doctor --fix
cargo-scanner tui
```

`init` writes `.cargo-scanner.yaml`. `doctor --fix` installs missing managed
scanner tools and pulls the default Docker runtime image when Docker is
available.

## Scanning

The short form scans directly:

```sh
cargo-scanner ./artifact.jar
cargo-scanner ~/Downloads --recursive
```

The explicit form is equivalent:

```sh
cargo-scanner scan ./artifact.jar
cargo-scanner scan ~/Downloads --recursive
```

Useful options:

```sh
cargo-scanner ./artifact.jar --scanner grype
cargo-scanner ./artifact.jar --scanner trivy
cargo-scanner ./artifact.jar --fail-on high
cargo-scanner ./artifact.jar --timeout 30m
cargo-scanner ./downloads --recursive --include "*.jar,*.zip" --exclude "*.tmp"
```

## Runtime Selection

```sh
cargo-scanner ./artifact.jar --runtime auto
cargo-scanner ./artifact.jar --runtime managed
cargo-scanner ./artifact.jar --runtime native
cargo-scanner ./artifact.jar --runtime docker --docker-image ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest
```

Runtime guidance:

- `managed`: best default for personal machines.
- `docker`: best for CI and isolated execution.
- `native`: best when Grype, Trivy, or Syft are already managed elsewhere.
- `auto`: useful when you want Cargo Scanner to pick the first available path.

## Reports

Text report:

```sh
cargo-scanner ./artifact.jar --format text
```

JSON report:

```sh
cargo-scanner ./artifact.jar --json --output report.json
```

SARIF report:

```sh
cargo-scanner ./artifact.jar --format sarif --output results.sarif
```

Raw scanner output:

```sh
cargo-scanner ./artifact.jar --raw-output grype.raw.json
```

## SBOM

```sh
cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json
cargo-scanner sbom ./artifact.jar --json --output sbom-report.json
```

## Managed Tools

Managed tools are installed under `~/.cargo-scanner/tools/bin` unless
`CARGO_SCANNER_HOME` is set.

```sh
cargo-scanner tools path
cargo-scanner tools list
cargo-scanner tools install all
cargo-scanner tools install grype@0.115.0
cargo-scanner tools update all
cargo-scanner tools uninstall trivy
```

Each managed install downloads the upstream GitHub Release archive and its
`checksums.txt`, verifies SHA256, and writes a provenance manifest next to the
installed binary.

## Trivy Database

Trivy can take longer on first use because it needs a vulnerability database.
Prepare it explicitly:

```sh
cargo-scanner tools update-db trivy
```

## Cache

```sh
cargo-scanner cache path
cargo-scanner cache clean
```

## Shell Completion

```sh
cargo-scanner completion zsh > /usr/local/share/zsh/site-functions/_cargo-scanner
cargo-scanner completion bash > ~/.cargo-scanner-completion.bash
cargo-scanner completion fish > ~/.config/fish/completions/cargo-scanner.fish
cargo-scanner completion powershell > cargo-scanner.ps1
```

## TUI

```sh
cargo-scanner tui
```

Keyboard:

- `up/down` or `j/k`: move
- `enter`: choose an action and print the command
- `q`, `esc`, or `ctrl+c`: quit

For non-interactive checks:

```sh
cargo-scanner tui --print
```

## Troubleshooting

Use `doctor` first:

```sh
cargo-scanner doctor
```

Common fixes:

```sh
cargo-scanner doctor --fix
cargo-scanner tools install all
cargo-scanner runtime pull --scanner grype
```

Plain output:

```sh
NO_COLOR=1 cargo-scanner doctor
CARGO_SCANNER_PLAIN=1 cargo-scanner ./artifact.jar
```
