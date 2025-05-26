FROM ubuntu:22.04

# Install only essential packages with --no-install-recommends flag to reduce size
RUN apt-get update && apt-get install -y --no-install-recommends \
    suricata \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install minimal Python dependencies
RUN pip3 install --no-cache-dir scapy

# Configure Suricata
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY custom.rules /etc/suricata/rules/custom.rules

# Create working directories
RUN mkdir -p /var/log/suricata /var/run/suricata /opt/scripts

# Create scripts directory
WORKDIR /opt/scripts

# Simple script copy - no shell operators
COPY scripts/ /opt/scripts/
RUN chmod +x /opt/scripts/*.sh /opt/scripts/*.py 2>/dev/null || true

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]