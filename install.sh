#!/usr/bin/env bash
# install.sh — install proxy-manager (no Go required)
# Downloads a pre-built binary from GitHub releases.
# Falls back to building from source if Go is available and no release exists yet.
set -e

REPO="LegitDecent/proxy-manager"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
MANDIR="$PREFIX/share/man/man1"
BINARY="proxy-manager"

# ── detect OS / arch ──────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  os="linux" ;;
  Darwin) os="macos" ;;
  *)
    echo "Unsupported OS: $OS"
    echo "Download a binary manually from: https://github.com/$REPO/releases"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

ASSET="${BINARY}-${os}-${arch}"

# ── fetch latest release tag ──────────────────────────────────────────────────
echo "[*] Checking latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')

if [ -z "$LATEST" ]; then
  # No release yet — try building from source
  if command -v go &>/dev/null; then
    echo "[*] No release found. Building from source (Go $(go version | awk '{print $3}'))..."
    go build -o "$BINARY" .
    install_local=1
  else
    echo ""
    echo "No pre-built release found and Go is not installed."
    echo ""
    echo "Options:"
    echo "  1. Install Go from https://go.dev/dl/ then re-run this script"
    echo "  2. Download a binary from: https://github.com/$REPO/releases"
    exit 1
  fi
else
  echo "[*] Latest release: $LATEST"
  URL="https://github.com/$REPO/releases/download/$LATEST/$ASSET"
  echo "[*] Downloading $ASSET..."
  curl -fsSL -o "$BINARY" "$URL" || {
    echo "[-] Download failed: $URL"
    echo "    Try downloading manually from: https://github.com/$REPO/releases"
    exit 1
  }
  chmod +x "$BINARY"
  install_local=0
fi

# ── install binary ────────────────────────────────────────────────────────────
echo "[*] Installing to $BINDIR/$BINARY"
if [ ! -w "$BINDIR" ] 2>/dev/null; then
  echo "    (needs sudo for $BINDIR)"
  sudo install -d "$BINDIR"
  sudo install -m 755 "$BINARY" "$BINDIR/$BINARY"
else
  install -d "$BINDIR"
  install -m 755 "$BINARY" "$BINDIR/$BINARY"
fi

# ── install man page (if present) ────────────────────────────────────────────
if [ -f "docs/proxy-manager.1" ]; then
  echo "[*] Installing man page to $MANDIR/"
  if [ ! -w "$MANDIR" ] 2>/dev/null; then
    sudo install -d "$MANDIR"
    sudo install -m 644 docs/proxy-manager.1 "$MANDIR/proxy-manager.1"
  else
    install -d "$MANDIR"
    install -m 644 docs/proxy-manager.1 "$MANDIR/proxy-manager.1"
  fi
fi

# clean up downloaded binary if we fetched it
[ "$install_local" = "0" ] && rm -f "$BINARY"

# ── nmap notice ───────────────────────────────────────────────────────────────
echo ""
echo "  proxy-manager installed successfully."
echo ""
echo "  The built-in TCP scanner works right now with no extra installs."
echo "  For nmap mode, install nmap separately:"
echo "    macOS:          brew install nmap"
echo "    Debian/Ubuntu:  sudo apt install nmap"
echo "    Fedora:         sudo dnf install nmap"
echo ""
echo "  Quick start:"
echo "    proxy-manager help"
echo "    proxy-manager -proxlist proxies.txt -ip 192.168.1.1 -p 80,443"
echo "    man proxy-manager"
echo ""
