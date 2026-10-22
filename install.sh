#!/usr/bin/env bash
# Install Pane as a systemd service on Linux (Debian/Ubuntu/Fedora/Arch…).
#   sudo ./install.sh            install or update
#   sudo ./install.sh uninstall  remove the service (your data is kept)
set -euo pipefail
APP=/opt/pane DATA=/var/lib/pane
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
if [ "${1:-}" = uninstall ]; then
  systemctl disable --now pane 2>/dev/null || true
  rm -f /etc/systemd/system/pane.service; rm -rf "$APP"; systemctl daemon-reload
  echo "Removed. Your notes are still in $DATA."; exit 0
fi
command -v node >/dev/null || { echo "Node.js 18 or newer is required. Install it first: https://nodejs.org"; exit 1; }
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ] || { echo "Node.js 18 or newer is required."; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
id pane >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin pane
mkdir -p "$APP" "$DATA"
cp -r "$SRC/server.js" "$SRC/index.html" "$SRC/package.json" "$SRC/dict" "$SRC/icons" "$APP/"
chown -R pane:pane "$DATA"
NODE_BIN="$(command -v node)"
sed "s|/usr/bin/node|$NODE_BIN|" "$SRC/deploy/pane.service" > /etc/systemd/system/pane.service
systemctl daemon-reload
systemctl enable --now pane
sleep 1
systemctl is-active --quiet pane && echo "Pane is running on port 3000. Open http://$(hostname -I 2>/dev/null | awk '{print $1}'):3000" \
  || { echo "Pane did not start. See: journalctl -u pane -n 50"; exit 1; }
