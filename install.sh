#!/usr/bin/env bash
# install.sh — build rofk from source and install it.
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
  echo "  https://github.com/LegitDecent/route-fork/releases"
  echo ""
  echo "Then install it with:"
  echo "  chmod +x rofk-<platform>"
  echo "  sudo mv rofk-<platform> $BINDIR/rofk"
  echo ""
  exit 1
fi

echo "[*] Building from source ($(go version | awk '{print $3}'))..."
go build -trimpath -ldflags="-s -w" -o rofk .

echo "[*] Installing binary → $BINDIR/rofk"
if [ -w "$BINDIR" ]; then
  install -d "$BINDIR"
  install -m 755 rofk "$BINDIR/rofk"
else
  sudo install -d "$BINDIR"
  sudo install -m 755 rofk "$BINDIR/rofk"
fi

if [ -f "docs/rofk.1" ]; then
  echo "[*] Installing man page → $MANDIR/rofk.1"
  if [ -w "$(dirname "$MANDIR")" ]; then
    install -d "$MANDIR"
    install -m 644 docs/rofk.1 "$MANDIR/rofk.1"
  else
    sudo install -d "$MANDIR"
    sudo install -m 644 docs/rofk.1 "$MANDIR/rofk.1"
  fi
fi

rm -f rofk

echo ""
echo "  rofk installed."
echo ""
echo "  The built-in TCP scanner works right now — no extra installs needed."
echo "  For nmap mode, install nmap:"
echo "    macOS:          brew install nmap"
echo "    Debian/Ubuntu:  sudo apt install nmap"
echo "    Fedora:         sudo dnf install nmap"
echo "    Windows:        winget install nmap"
echo ""
echo "  Try: rofk help"
echo ""
