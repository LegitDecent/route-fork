#!/usr/bin/env bash
# install.sh — build and install proxy-manager (Linux / macOS)
set -e

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
MANDIR="$PREFIX/share/man/man1"

echo "[*] Building proxy-manager..."
go build -o proxy-manager .

echo "[*] Installing binary to $BINDIR/proxy-manager"
install -d "$BINDIR"
install -m 755 proxy-manager "$BINDIR/proxy-manager"

echo "[*] Installing man page to $MANDIR/proxy-manager.1"
install -d "$MANDIR"
install -m 644 docs/proxy-manager.1 "$MANDIR/proxy-manager.1"

echo ""
echo "Done.  Try:"
echo "  proxy-manager help"
echo "  man proxy-manager"
