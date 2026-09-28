#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
python3 /opt/sentinelfw/sfwctl.py uninstall-service || true
python3 /opt/sentinelfw/sfwctl.py cleanup || true
rm -rf /opt/sentinelfw
echo "Removed. Config, lists and quarantine remain in /var/lib/sentinelfw (delete manually if desired)."
