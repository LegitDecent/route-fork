#!/usr/bin/env bash
# install.sh — build proxy-manager from source and install it.
# Requires Go: https://go.dev/dl/
#
# For pre-built binaries (no Go needed) download from the releases page,
# then follow the one-time steps printed at the end of this script.
set -e

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
MANDIR="$PREFIX/share/man/man1"

if ! command -v go &>/dev/null; then
  echo ""
  echo "Go is not installed — can't build from source."
  echo ""
  echo "Download a pre-built binary for your platform from the releases page:"
  echo "  https://github.com/LegitDecent/proxy-manager/releases"
  echo ""
  echo "Then install it with:"
  echo "  chmod +x proxy-manager-<platform>"
  echo "  sudo mv proxy-manager-<platform> $BINDIR/proxy-manager"
  echo ""
  exit 1
fi

echo "[*] Building from source ($(go version | awk '{print $3}'))..."
go build -trimpath -ldflags="-s -w" -o proxy-manager .

echo "[*] Installing binary → $BINDIR/proxy-manager"
if [ -w "$BINDIR" ]; then
  install -d "$BINDIR"
  install -m 755 proxy-manager "$BINDIR/proxy-manager"
else
  sudo install -d "$BINDIR"
  sudo install -m 755 proxy-manager "$BINDIR/proxy-manager"
fi

if [ -f "docs/proxy-manager.1" ]; then
  echo "[*] Installing man page → $MANDIR/proxy-manager.1"
  if [ -w "$(dirname "$MANDIR")" ]; then
    install -d "$MANDIR"
    install -m 644 docs/proxy-manager.1 "$MANDIR/proxy-manager.1"
  else
    sudo install -d "$MANDIR"
    sudo install -m 644 docs/proxy-manager.1 "$MANDIR/proxy-manager.1"
  fi
fi

rm -f proxy-manager

echo ""
echo "  proxy-manager installed."
echo ""
echo "  The built-in TCP scanner works right now — no extra installs needed."
echo "  For nmap mode, install nmap:"
echo "    macOS:          brew install nmap"
echo "    Debian/Ubuntu:  sudo apt install nmap"
echo "    Fedora:         sudo dnf install nmap"
echo "    Windows:        winget install nmap"
echo ""
echo "  Try: proxy-manager help"
echo ""
