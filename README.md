# Cargo Scanner

Cargo Scanner scans inbound artifacts before you unpack or ship them. It wraps
Grype, Trivy, and Syft behind one CLI so you can check downloaded files, build
outputs, archives, containers, and local package artifacts with the same
workflow.

## Who It Is For

- People who want to scan files already on their machine, especially downloads
  and unpacked build artifacts.
- Developers who want one command for vulnerability reports and SBOMs.
- CI jobs that need a containerized scanner runtime.
- Teams that already use Grype, Trivy, or Syft but want a consistent local UX.

## Fastest Start

```sh
curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh | sh
cargo-scanner doctor --fix
cargo-scanner ~/Downloads --recursive
```

Prefer an interactive entry point:

```sh
cargo-scanner tui
```

The TUI shows environment status and common actions such as scanning Downloads,
fixing missing tools, generating an SBOM, and writing JSON reports.

## Install

Install the latest release with checksum verification:

```sh
curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh | sh
```

Install a specific release:

```sh
CARGO_SCANNER_VERSION=vX.Y.Z sh -c "$(curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh)"
```

Install with Go:

```sh
go install github.com/opencomputinggarage/cargo-scanner/cmd/cargo-scanner@latest
```

Download archives directly from the
[latest release](https://github.com/opencomputinggarage/cargo-scanner/releases/latest)
for macOS, Linux, and Windows.

Homebrew users can build from this repo:

```sh
brew install --HEAD ./Formula/cargo-scanner.rb
```

## First Run

For personal machines, use the managed runtime. Cargo Scanner installs scanner
CLIs under `~/.cargo-scanner/tools/bin` and keeps their cache under
`~/.cargo-scanner/cache`.

```sh
cargo-scanner init
cargo-scanner doctor --fix
cargo-scanner doctor
```

`init` writes `.cargo-scanner.yaml`. `doctor --fix` installs missing managed
tools and pulls the default Docker runtime image when Docker is available.

## Everyday Scans

Scan one artifact:

```sh
cargo-scanner ./download.jar
cargo-scanner scan ./download.jar
```

Scan a directory recursively:

```sh
cargo-scanner ~/Downloads --recursive
```

Fail when high or critical findings exist:

```sh
cargo-scanner ./artifact.tgz --fail-on high
```

Use a specific scanner:

```sh
cargo-scanner ./artifact.jar --scanner trivy
cargo-scanner ./artifact.jar --scanner grype
```

Write a JSON report:

```sh
cargo-scanner ./artifact.jar --json --output report.json
```

Write SARIF for GitHub code scanning:

```sh
cargo-scanner ./artifact.jar --format sarif --output results.sarif
```

## SBOM

Generate a CycloneDX SBOM with Syft:

```sh
cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json
```

Write a normalized JSON report around the SBOM operation:

```sh
cargo-scanner sbom ./artifact.jar --json --output sbom-report.json
```

## Runtime Choices

- `managed`: best default for personal machines. Cargo Scanner downloads and
  manages scanner binaries for you.
- `docker`: best for CI and isolated runs.
- `native`: use scanner CLIs already installed on `PATH`.
- `auto`: prefer a locally available Docker image, then managed tools, then
  native tools.

Examples:

```sh
cargo-scanner ./artifact.jar --runtime managed
cargo-scanner ./artifact.jar --runtime native
cargo-scanner ./artifact.jar --runtime docker --docker-image ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest
```

## Managed Tools

```sh
cargo-scanner tools list
cargo-scanner tools install all
cargo-scanner tools install grype@0.115.0
cargo-scanner tools update all
cargo-scanner tools update-db trivy
cargo-scanner tools uninstall trivy
```

Each managed install downloads the upstream release archive and checksum file,
verifies SHA256, installs the binary, and writes a provenance manifest next to
the binary.

Set a different managed home:

```sh
export CARGO_SCANNER_HOME="$HOME/.cache/cargo-scanner"
```

## Docker And CI

Pull the bundled runtime image:

```sh
cargo-scanner runtime pull --docker-image ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest
```

Use Cargo Scanner with Docker runtime:

```sh
cargo-scanner ./artifact.jar --runtime docker --docker-image ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest
```

Run scanner CLIs directly in CI:

```sh
docker run --rm \
  -v "$PWD:/work:ro" \
  ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest \
  grype dir:/work -o json
```

GitHub Actions example:

```yaml
name: Cargo Scanner

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh | sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - run: cargo-scanner doctor --fix
      - run: cargo-scanner . --recursive --fail-on high
```

## Shell Completion

```sh
cargo-scanner completion zsh > /usr/local/share/zsh/site-functions/_cargo-scanner
cargo-scanner completion bash > ~/.cargo-scanner-completion.bash
cargo-scanner completion fish > ~/.config/fish/completions/cargo-scanner.fish
cargo-scanner completion powershell > cargo-scanner.ps1
```

## Development

This repository uses [mise](https://mise.jdx.dev/) to pin local tool versions.
Go, Node.js, and pnpm are defined in `.mise.toml`.

```sh
mise install
mise run verify
```

Useful tasks:

```sh
mise run test
mise run build
mise run site-install
mise run site-build
mise run site-dev
```

The GitHub Pages site lives under `site/` and uses React, Vite, and pnpm:

```sh
cd site
pnpm install
pnpm dev
pnpm build
```

## Troubleshooting

Check the environment:

```sh
cargo-scanner doctor
```

Install missing managed tools:

```sh
cargo-scanner doctor --fix
```

If Docker is not available, use managed tools:

```sh
cargo-scanner ./artifact.jar --runtime managed
```

If Docker credential helpers hang while pulling from GHCR, try a clean Docker
config:

```sh
DOCKER_CONFIG="$(mktemp -d)" docker pull ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest
```

If Trivy is slow on the first run, prefetch its database:

```sh
cargo-scanner tools update-db trivy
```

Disable styled output:

```sh
NO_COLOR=1 cargo-scanner ./artifact.jar
CARGO_SCANNER_PLAIN=1 cargo-scanner doctor
```

## Useful Commands

```sh
cargo-scanner version
cargo-scanner tui
cargo-scanner init --force
cargo-scanner doctor --fix
cargo-scanner cache path
cargo-scanner cache clean
cargo-scanner tools path
cargo-scanner tools list
```

## License

Cargo Scanner is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE).
