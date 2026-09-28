#!/usr/bin/env bash
# SentinelFW installer for Ubuntu/Debian. Run: sudo ./install.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo ./install.sh"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
command -v nft >/dev/null || { apt-get update -y && apt-get install -y nftables; }
SRC="$(cd "$(dirname "$0")" && pwd)"; DEST=/opt/sentinelfw
mkdir -p "$DEST"
rm -rf "$DEST/sentinelfw"
cp -r "$SRC/sentinelfw" "$SRC/sfwctl.py" "$DEST/"
[ -f /var/lib/sentinelfw/config.json ] || { mkdir -p /var/lib/sentinelfw; cp "$SRC/config.example.json" /var/lib/sentinelfw/config.json; }
python3 "$DEST/sfwctl.py" update-lists || echo "feed download failed (offline?) - will retry from the daemon"
python3 "$DEST/sfwctl.py" install-service
echo; echo "SentinelFW is running.  Status: sudo python3 $DEST/sfwctl.py status"
echo "Logs: /var/lib/sentinelfw/logs/events.jsonl"
