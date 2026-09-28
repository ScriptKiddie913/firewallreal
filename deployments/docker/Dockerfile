# SentinelFW 3.0 Containerized Appliance
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV SENTINELFW_HOME=/var/lib/sentinelfw

# Install low-level kernel networking tools (nftables, iproute2, procps, ca-certificates, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iptables \
    iproute2 \
    procps \
    ca-certificates \
    curl \
    suricata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sentinelfw

# Copy package and launcher
COPY sentinelfw/ /opt/sentinelfw/sentinelfw/
COPY sfwctl.py /opt/sentinelfw/
COPY config.example.json /etc/sentinelfw/config.json

# Setup symbolic links for 'fw' CLI command
RUN ln -sf /opt/sentinelfw/sfwctl.py /usr/local/bin/fw && \
    chmod +x /opt/sentinelfw/sfwctl.py /usr/local/bin/fw

RUN mkdir -p /var/lib/sentinelfw /var/log/sentinelfw

EXPOSE 9443 2222 8080 2121 2323

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:9443/api/v1/status || exit 1

ENTRYPOINT ["python3", "/opt/sentinelfw/sfwctl.py", "run"]
