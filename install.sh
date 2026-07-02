#!/usr/bin/env bash
set -euo pipefail

REPO="zperetz/nfqcooldown"
BIN_NAME="nfqcooldown"
INSTALL_PATH="/usr/local/sbin/${BIN_NAME}"

INSTALL_DEV=false
TAG=""

info() {
  echo "[nfqcooldown] $*"
}

fail() {
  echo "[nfqcooldown] ERROR: $*" >&2
  exit 1
}

usage() {
  cat <<EOF
nfqcooldown installer

Usage:
  install.sh
  install.sh --install-dev
  install.sh --tag v0.1.1

Options:
  --install-dev     Install development build from dev-latest
  --tag TAG         Install specific release tag
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dev)
      INSTALL_DEV=true
      shift
      ;;
    --tag)
      [[ $# -ge 2 ]] || fail "--tag requires a value"
      TAG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

if [[ "$INSTALL_DEV" == "true" && -n "$TAG" ]]; then
  fail "use either --install-dev or --tag, not both"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need_cmd uname
need_cmd tar
need_cmd curl
need_cmd install
need_cmd mktemp

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)
    GOOS="linux"
    ;;
  *)
    fail "unsupported OS: $OS"
    ;;
esac

case "$ARCH" in
  x86_64|amd64)
    GOARCH="amd64"
    ;;
  aarch64|arm64)
    GOARCH="arm64"
    ;;
  *)
    fail "unsupported architecture: $ARCH"
    ;;
esac

ASSET="${BIN_NAME}-${GOOS}-${GOARCH}.tar.gz"

if [[ "$INSTALL_DEV" == "true" ]]; then
  RELEASE_REF="dev-latest"
  info "installing development build"
elif [[ -n "$TAG" ]]; then
  RELEASE_REF="$TAG"
  info "installing release tag: ${TAG}"
else
  RELEASE_REF="latest"
  info "installing latest stable release"
fi

if [[ "$RELEASE_REF" == "latest" ]]; then
  DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${RELEASE_REF}/${ASSET}"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "detected platform: ${GOOS}/${GOARCH}"
info "downloading: ${ASSET}"
info "source: ${DOWNLOAD_URL}"

curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET}" \
  || fail "failed to download ${DOWNLOAD_URL}"

info "extracting"
tar -xzf "${TMP_DIR}/${ASSET}" -C "$TMP_DIR"

BIN_PATH="${TMP_DIR}/${BIN_NAME}-${GOOS}-${GOARCH}"

if [[ ! -f "$BIN_PATH" ]]; then
  fail "binary not found in archive: ${BIN_NAME}-${GOOS}-${GOARCH}"
fi

info "installing to ${INSTALL_PATH}"
install -m 0755 "$BIN_PATH" "$INSTALL_PATH" \
  || fail "failed to install binary. Try running as root or via sudo."

info "installed successfully"
"$INSTALL_PATH" --help || true
