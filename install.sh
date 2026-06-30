#!/usr/bin/env bash
set -euo pipefail

REPO="zperetz/nfqcooldown"
BIN_NAME="nfqcooldown"
INSTALL_PATH="/usr/local/sbin/${BIN_NAME}"

info() {
  echo "[nfqcooldown] $*"
}

fail() {
  echo "[nfqcooldown] ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need_cmd uname
need_cmd tar
need_cmd curl

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux) GOOS="linux" ;;
  *) fail "unsupported OS: $OS" ;;
esac

case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) fail "unsupported architecture: $ARCH" ;;
esac

ASSET="${BIN_NAME}-${GOOS}-${GOARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "detected platform: ${GOOS}/${GOARCH}"
info "downloading latest release: ${ASSET}"

curl -fL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET}" \
  || fail "failed to download ${DOWNLOAD_URL}"

info "extracting"
tar -xzf "${TMP_DIR}/${ASSET}" -C "$TMP_DIR"

if [ ! -f "${TMP_DIR}/${BIN_NAME}-${GOOS}-${GOARCH}" ]; then
  fail "binary not found in archive"
fi

info "installing to ${INSTALL_PATH}"

install -m 0755 "${TMP_DIR}/${BIN_NAME}-${GOOS}-${GOARCH}" "$INSTALL_PATH" \
  || fail "failed to install binary. Try running as root or via sudo."

info "installed successfully"
"$INSTALL_PATH" --help || true
