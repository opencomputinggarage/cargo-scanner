# Cargo Scanner

Cargo Scanner scans inbound artifacts before you unpack them. It is a single
CLI for checking downloaded files, build outputs, archives, containers, and
local package artifacts with Grype, Trivy, and Syft.

## Quickstart

Install the latest binary:

```sh
curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh | sh
```

Set up a project and install managed scanner tools:

```sh
cargo-scanner init
cargo-scanner doctor --fix
```

Scan one file:

```sh
cargo-scanner scan ./download.jar
cargo-scanner ./download.jar
```

Scan downloads recursively and fail on high severity:

```sh
cargo-scanner scan ~/Downloads --recursive --fail-on high
```

Generate an SBOM:

```sh
cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json
```

## Install

Download prebuilt binaries from the
[latest release](https://github.com/opencomputinggarage/cargo-scanner/releases/latest),
or use the install script:

```sh
curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh | sh
```

Install a specific version:

```sh
CARGO_SCANNER_VERSION=vX.Y.Z sh -c "$(curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh)"
```

Build from source:

```sh
go install github.com/opencomputinggarage/cargo-scanner/cmd/cargo-scanner@latest
```

Homebrew users can build from the bundled formula:

```sh
brew install --HEAD ./Formula/cargo-scanner.rb
```

## Runtime Strategy

- `managed`: recommended for personal machines. Cargo Scanner installs scanner
  CLIs under `~/.cargo-scanner/tools/bin`.
- `docker`: recommended for CI or isolated runs. Use
  `ghcr.io/opencomputinggarage/cargo-scanner-runtime:<version>` or scanner
  official images.
- `native`: use scanner CLIs already installed on `PATH`.
- `auto`: prefer an available Docker image, then managed tools, then native.

## Common Commands

```sh
cargo-scanner doctor
cargo-scanner doctor --fix
cargo-scanner ./artifact.jar --json
cargo-scanner tools list
cargo-scanner tools install all
cargo-scanner tools update all
cargo-scanner tools update-db trivy
cargo-scanner runtime pull --docker-image ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest
cargo-scanner scan ./artifact.zip --format json --output report.json
cargo-scanner scan ./artifact.jar --format sarif --output results.sarif
cargo-scanner completion zsh
```

## CI Example

```sh
docker run --rm \
  -v "$PWD:/work:ro" \
  ghcr.io/opencomputinggarage/cargo-scanner-runtime:latest \
  grype dir:/work -o json
```

## Notes

- Managed tools are installed under `~/.cargo-scanner/tools/bin` by default.
- Set `CARGO_SCANNER_HOME` to change the managed tool root.
- `cargo-scanner doctor --fix` installs missing managed tools and pulls the
  default Docker runtime image when Docker is available.
- Trivy may download its vulnerability database on first use, so the first scan
  can take longer than later scans.
- Docker runtime can use scanner-specific official images or a bundled runtime
  image built from [docker/Dockerfile](docker/Dockerfile).
- More examples are in [docs/usage.md](docs/usage.md).
