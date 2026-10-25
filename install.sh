#!/bin/sh
# hullcheck installer: downloads a prebuilt binary for your platform.
# Read-only, no telemetry. Reads this script before piping it to a shell:
#   curl -fsSL https://raw.githubusercontent.com/glferreira-devsecops/hullcheck/main/install.sh | sh
set -eu

REPO="glferreira-devsecops/hullcheck"
BIN="hullcheck"
# Install into a user-writable dir by default; override with INSTALL_DIR=...
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64)          target="x86_64-unknown-linux-musl" ;;
  Linux-aarch64|Linux-arm64) target="aarch64-unknown-linux-musl" ;;
  Darwin-arm64)          target="aarch64-apple-darwin" ;;
  Darwin-x86_64)         target="x86_64-apple-darwin" ;;
  *)
    echo "hullcheck: no prebuilt binary for $os-$arch." >&2
    echo "Build from source instead: cargo install --git https://github.com/$REPO" >&2
    exit 1
    ;;
esac

asset="hullcheck-${target}.tar.gz"
url="https://github.com/${REPO}/releases/latest/download/${asset}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "hullcheck: downloading $target ..."
curl -fsSL "$url" -o "$tmp/$asset"

# Verify the checksum published alongside the asset.
if curl -fsSL "${url}.sha256" -o "$tmp/$asset.sha256" 2>/dev/null; then
  ( cd "$tmp" && sed "s| .*| $asset|" "$asset.sha256" > sum && \
    { shasum -a 256 -c sum >/dev/null 2>&1 || sha256sum -c sum >/dev/null 2>&1; } ) \
    && echo "hullcheck: checksum ok" \
    || { echo "hullcheck: checksum mismatch, aborting" >&2; exit 1; }
fi

tar -C "$tmp" -xzf "$tmp/$asset"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/$BIN" "$INSTALL_DIR/$BIN"

echo "hullcheck: installed to $INSTALL_DIR/$BIN"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "hullcheck: add $INSTALL_DIR to your PATH to run 'hullcheck' directly." ;;
esac
