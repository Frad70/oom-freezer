#!/usr/bin/env bash
# install.sh: install oom-freezer as a system service. Idempotent.
# Requires root. Builds the binary, installs it, the config and the unit, then
# restarts the service. PREFIX defaults to /usr/local.
set -euo pipefail

SRC="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PREFIX=${PREFIX:-/usr/local}
CONFDIR=/etc/oom-freezer
UNITDIR=/etc/systemd/system

[ "$(id -u)" = 0 ] || { echo "Root is required: sudo $0"; exit 1; }

echo "[1/4] Building oom-freezer"
make -C "$SRC" -B oom-freezer

echo "[2/4] Installing $PREFIX/bin/oom-freezer"
install -d "$PREFIX/bin"
install -m 0755 "$SRC/oom-freezer" "$PREFIX/bin/oom-freezer.new"
mv -fT "$PREFIX/bin/oom-freezer.new" "$PREFIX/bin/oom-freezer"

echo "[3/4] Installing the config to $CONFDIR (an existing config is kept)"
mkdir -p "$CONFDIR"
if [ -f "$CONFDIR/oom-freezer.conf" ]; then
  install -m 0644 "$SRC/oom-freezer.conf" "$CONFDIR/oom-freezer.conf.default"
  echo "      Kept the existing config; the new default is oom-freezer.conf.default"
else
  install -m 0644 "$SRC/oom-freezer.conf" "$CONFDIR/oom-freezer.conf"
fi

echo "[4/4] Installing the systemd unit and restarting the service"
sed "s|@PREFIX@|$PREFIX|g" "$SRC/systemd/oom-freezer.service" > "$UNITDIR/oom-freezer.service"
chmod 0644 "$UNITDIR/oom-freezer.service"
systemctl daemon-reload
systemctl enable oom-freezer.service >/dev/null 2>&1
systemctl restart oom-freezer.service
echo "Done. The default config runs in dry-run mode: see journalctl -t oom-freezer."
