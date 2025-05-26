FROM debian:bullseye-slim

# Install only absolute minimum tools needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-minimal \
    python3-pip \
    curl \
    netcat-traditional \
    net-tools \
    nmap \
    tcpdump \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install minimal Python packages
RUN pip3 install --no-cache-dir requests

# Copy only essential attack scripts
WORKDIR /tools
COPY scripts/http_dos.py /tools/
COPY scripts/sql_injection.sh /tools/
COPY scripts/network_monitor.sh /tools/
COPY scripts/port_scanner.py /tools/
RUN chmod +x /tools/*.sh /tools/*.py 2>/dev/null || true

# Copy startup script
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]