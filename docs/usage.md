# Cargo Scanner Usage

## Runtime Selection

Cargo Scanner supports three local runtimes:

- `auto`: prefer Docker when the runtime image is available, then managed tools,
  then native tools.
- `docker`: run scanner CLIs in a container.
- `managed`: run scanner CLIs installed under Cargo Scanner's tool directory.
- `native`: run scanner CLIs from the host `PATH`.

```sh
cargo-scanner scan ./artifact.jar --runtime auto
cargo-scanner scan ./artifact.jar --runtime managed
cargo-scanner scan ./artifact.jar --runtime native
```

## Managed Tools

Managed tools are installed under `~/.cargo-scanner/tools/bin` unless
`CARGO_SCANNER_HOME` is set.

```sh
cargo-scanner tools install all
cargo-scanner tools install grype@0.115.0
cargo-scanner tools list
cargo-scanner tools update all
cargo-scanner tools uninstall trivy
```

Each managed install downloads the upstream GitHub Release archive and its
`checksums.txt`, verifies SHA256, and writes a provenance manifest next to the
installed binary.

Remove a managed tool:

```sh
cargo-scanner tools uninstall trivy
```

Clean Cargo Scanner's managed runtime cache:

```sh
cargo-scanner cache clean
```

## Trivy Database

Trivy can take longer on first use because it needs a vulnerability database.
Prepare it explicitly:

```sh
cargo-scanner tools update-db trivy
```

## Reports

```sh
cargo-scanner scan ./artifact.jar --format text
cargo-scanner scan ./artifact.jar --format json --output report.json
cargo-scanner scan ./artifact.jar --format sarif --output results.sarif
```

Use SARIF output for GitHub code scanning integrations.

## SBOM

```sh
cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json
cargo-scanner sbom ./artifact.jar --json --output sbom-report.json
```
