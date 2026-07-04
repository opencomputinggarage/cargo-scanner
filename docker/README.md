# Cargo Scanner Runtime

This image bundles scanner CLIs used by Cargo Scanner:

- `grype`
- `trivy`
- `syft`

Build locally:

```sh
docker build -t cargo-scanner-runtime:local -f docker/Dockerfile .
```

Use from Cargo Scanner:

```sh
cargo-scanner scan ./artifact.jar --runtime docker --docker-image cargo-scanner-runtime:local
cargo-scanner scan ./artifact.jar --scanner trivy --runtime docker --docker-image cargo-scanner-runtime:local
cargo-scanner sbom ./artifact.jar --runtime docker --docker-image cargo-scanner-runtime:local
```
