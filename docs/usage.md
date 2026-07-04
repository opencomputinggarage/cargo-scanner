# Cargo Scanner Usage

This document is the command reference. Start with the
[README](../README.md) if you want the shortest setup path.

## First Run

```sh
cargo-scanner doctor --fix
cargo-scanner scan
```

`doctor --fix` installs missing managed scanner tools and pulls the default
Docker runtime image when Docker is available. `cargo-scanner scan` starts a
short conversation and only asks questions needed for that scan.

## Scanning

Conversational scan:

```sh
cargo-scanner scan
```

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

Common options:

```sh
cargo-scanner ./artifact.jar --scanner grype
cargo-scanner ./artifact.jar --fail-on high
cargo-scanner ./downloads --recursive --include "*.jar,*.zip" --exclude "*.tmp"
```

Live progress UI:

```sh
cargo-scanner ~/Downloads --recursive
cargo-scanner ~/Downloads --recursive --tui=false
```

The live scan UI is written to stderr only when stderr is a terminal, so JSON
and SARIF output on stdout remain machine-readable.

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
cargo-scanner tools list
cargo-scanner doctor --fix
```

Advanced:

```sh
cargo-scanner tools path
cargo-scanner tools install all
cargo-scanner tools install grype@0.115.0
cargo-scanner tools update all
cargo-scanner tools uninstall trivy
```

Each managed install downloads the upstream GitHub Release archive and its
`checksums.txt`, verifies SHA256, and writes a provenance manifest next to the
installed binary.

In a terminal, install and update commands show a progress panel with release
resolution, archive download, checksum verification, extraction, and install
steps.

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

## Updating Cargo Scanner

```sh
cargo-scanner update --check
cargo-scanner update
cargo-scanner update --version v0.1.11
```

The updater verifies the GitHub Release checksum before replacing the current
executable. Use `--force` to reinstall the selected version and `--repo` to
point at another `owner/repo` during testing.

Options:

- `--check`: check only; do not install.
- `--force`: reinstall even when already on the selected version.
- `--version vX.Y.Z`: install a specific release.
- `--repo owner/repo`: update from another GitHub repo for fork testing.

If the current executable is owned by root, run with `sudo` or use the install
script with `CARGO_SCANNER_VERSION`.

## Shell Completion

```sh
cargo-scanner completion zsh > /usr/local/share/zsh/site-functions/_cargo-scanner
cargo-scanner completion bash > ~/.cargo-scanner-completion.bash
cargo-scanner completion fish > ~/.config/fish/completions/cargo-scanner.fish
cargo-scanner completion powershell > cargo-scanner.ps1
```

## TUI

```sh
cargo-scanner
cargo-scanner tui
```

Keyboard:

- `up/down` or `j/k`: move
- `/`: filter actions
- `enter`: choose and run an action
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

`doctor --fix` and `runtime pull` show live progress/log panels in a terminal.

Plain output:

```sh
NO_COLOR=1 cargo-scanner doctor
CARGO_SCANNER_PLAIN=1 cargo-scanner ./artifact.jar
```
