#!/usr/bin/env sh
# deadcert installer
# Usage: curl -fsSL https://github.com/Zuhayr-Barhoumi/deadcert/releases/latest/download/install.sh | sh

set -eu

REPO="Zuhayr-Barhoumi/deadcert"
BINARY="deadcert"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)
    OS="linux"
    ;;
  darwin)
    OS="darwin"
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

RELEASE_URL="https://github.com/$REPO/releases/latest/download"

case "$OS" in
  windows)
    EXT=".zip"
    FILE="${BINARY}_${OS}_${ARCH}${EXT}"
    ;;
  *)
    EXT=".tar.gz"
    FILE="${BINARY}_${OS}_${ARCH}${EXT}"
    ;;
esac

DOWNLOAD_URL="${RELEASE_URL}/${FILE}"
CHECKSUM_URL="${RELEASE_URL}/checksums.txt"

TMP_DIR=$(mktemp -d)
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "Downloading $FILE..."
curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$FILE"

echo "Verifying checksum..."
curl -fsSL "$CHECKSUM_URL" -o "$TMP_DIR/checksums.txt"
(cd "$TMP_DIR" && grep " $FILE$" checksums.txt | sha256sum -c -)

echo "Extracting..."
case "$OS" in
  windows)
    unzip -q "$TMP_DIR/$FILE" -d "$TMP_DIR"
    ;;
  *)
    tar -xzf "$TMP_DIR/$FILE" -C "$TMP_DIR"
    ;;
esac

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

echo "Installed to $INSTALL_DIR/$BINARY"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "Add $INSTALL_DIR to your PATH:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    ;;
esac