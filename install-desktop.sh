#!/usr/bin/env bash
# Add (or refresh) a ReconDeck entry in this user's application menu.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
ENTRY_DIR="${APP_HOME}/applications"
ICON_DIR="${APP_HOME}/icons/hicolor/scalable/apps"
ENTRY="${ENTRY_DIR}/recondeck.desktop"
ICON="${ICON_DIR}/recondeck.svg"

mkdir -p "$ENTRY_DIR" "$ICON_DIR"
cp "${ROOT}/static/img/mark.svg" "$ICON"
chmod 644 "$ICON"

cat > "$ENTRY" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=ReconDeck
GenericName=Network Reconnaissance
Comment=Discover hosts and map services with nmap and arp-scan
Exec="${ROOT}/start.sh"
Icon=${ICON}
Terminal=false
Categories=Network;Security;Utility;
Keywords=nmap;arp;scan;network;ports;security;recon;
StartupNotify=true
EOF
chmod 755 "$ENTRY"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$ENTRY_DIR" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t "${APP_HOME}/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "Installed application menu entry:"
echo "  ${ENTRY}"
echo "Search for “ReconDeck” in your application launcher."
echo "Remove it by deleting that file (and the ReconDeck icon if you wish)."
