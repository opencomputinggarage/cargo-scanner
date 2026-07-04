# Cargo Scanner

Cargo Scanner scans inbound artifacts before you unpack them.

It is a unified CLI for local package and build-output inspection. The first
runtime is native `grype`; the architecture keeps scanners and runtimes separate
so Docker, Trivy, Syft, and managed tools can be added without changing the user
workflow.

## Usage

```sh
cargo-scanner scan ./download.jar
cargo-scanner scan ./download.jar --scanner trivy
cargo-scanner sbom ./artifact.jar
cargo-scanner scan ./artifact.zip --json
cargo-scanner scan ./downloads --recursive --output report.json
cargo-scanner scan ./artifact.jar --raw-output grype.json
cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json
cargo-scanner scan ./artifact.tgz --fail-on high
cargo-scanner scan ./artifact.jar --runtime docker
cargo-scanner doctor
cargo-scanner runtime pull --scanner grype
cargo-scanner tools doctor
cargo-scanner tools list
cargo-scanner tools install grype
cargo-scanner tools install grype@0.115.0
cargo-scanner tools update all
cargo-scanner tools update-db trivy
cargo-scanner tools uninstall trivy
cargo-scanner cache clean
cargo-scanner tools install all
cargo-scanner scan ./artifact.jar --format sarif --output results.sarif
```

## Current MVP

- Auto runtime selection
- Native runtime
- Docker runtime for Grype-compatible images
- Grype scanner adapter
- Trivy vulnerability adapter
- Syft SBOM adapter
- Normalized findings model
- Text and JSON reports
- `--fail-on` exit threshold
- `doctor` command
- Recursive directory scans
- Report/raw/SBOM file outputs
- Managed tool installation with SHA256 checksum verification
- Managed install provenance manifests
- SARIF output for code scanning integrations
- Release workflow for CLI binaries and runtime image
- Optional all-in-one Docker runtime image

## Notes

- Managed tools are installed under `~/.cargo-scanner/tools/bin` by default.
- Set `CARGO_SCANNER_HOME` to change the managed tool root.
- Trivy may download its vulnerability database on first use, so the first scan
  can take longer than later scans.
- Docker runtime can use scanner-specific official images or a bundled runtime
  image built from [docker/Dockerfile](docker/Dockerfile).
- More examples are in [docs/usage.md](docs/usage.md).
