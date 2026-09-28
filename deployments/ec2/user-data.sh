#!/usr/bin/env bash
# ==============================================================================
# SentinelFW 3.0 — AWS EC2 Bootstrap User Data
# Supports: Ubuntu 22.04 LTS / 24.04 LTS (x86_64 & ARM64 Graviton)
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "== Deploying SentinelFW 3.0 NGFW on AWS EC2             =="
echo "=========================================================="

export DEBIAN_FRONTEND=noninteractive

# 1. Update OS packages and install kernel dependencies
apt-get update -y
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    nftables \
    iptables \
    iproute2 \
    curl \
    git \
    nginx \
    certbot \
    python3-certbot-nginx \
    suricata \
    jq

# 2. Kernel Network Hardening Parameters
cat << 'EOF' > /etc/sysctl.d/99-sentinelfw.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
EOF
sysctl --system

# 3. Setup SentinelFW Installation Directory
INSTALL_DIR="/opt/sentinelfw"
DATA_DIR="/var/lib/sentinelfw"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$DATA_DIR/logs"

# 4. Clone or copy SentinelFW repository
if [ ! -d "$INSTALL_DIR/sentinelfw" ]; then
    git clone https://github.com/sentinelgate/sentinelfw.git "$INSTALL_DIR" || true
fi

# 5. Link global 'fw' CLI command
ln -sf "$INSTALL_DIR/sfwctl.py" /usr/local/bin/fw
chmod +x "$INSTALL_DIR/sfwctl.py" /usr/local/bin/fw

# 6. Install systemd background service
cat << EOF > /etc/systemd/system/sentinelfw.service
[Unit]
Description=SentinelFW 3.0 Host Firewall and Threat Matrix
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=SENTINELFW_HOME=$DATA_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/sfwctl.py run
Restart=always
RestartSec=3
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sentinelfw

# 7. Initialize lists and baseline
fw update-lists || true

echo "=========================================================="
echo "== SentinelFW 3.0 Deployed Successfully on EC2!         =="
echo "== Web Dashboard listening on: http://<EC2-IP>:9443     =="
echo "== Run 'fw status' from any terminal session.           =="
echo "=========================================================="
