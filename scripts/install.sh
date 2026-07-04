#!/usr/bin/env sh
set -eu

repo="${CARGO_SCANNER_REPO:-opencomputinggarage/cargo-scanner}"
version="${CARGO_SCANNER_VERSION:-latest}"
install_dir="${CARGO_SCANNER_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

case "$os" in
  darwin|linux) ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

if [ "$version" = "latest" ]; then
  version="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
fi

archive="cargo-scanner_${version#v}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$base/$archive" -o "$tmp/$archive"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"

if command -v shasum >/dev/null 2>&1; then
  expected="$(grep " $archive\$" "$tmp/checksums.txt" | awk '{print $1}')"
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  expected="$(grep " $archive\$" "$tmp/checksums.txt" | awk '{print $1}')"
  actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
else
  echo "missing shasum or sha256sum" >&2
  exit 1
fi

if [ "$expected" != "$actual" ]; then
  echo "checksum mismatch for $archive" >&2
  exit 1
fi

mkdir -p "$install_dir"
tar -xzf "$tmp/$archive" -C "$tmp"
install "$tmp/cargo-scanner" "$install_dir/cargo-scanner"

echo "installed $("$install_dir/cargo-scanner" version) to $install_dir/cargo-scanner"
echo "next: cargo-scanner doctor --fix"
