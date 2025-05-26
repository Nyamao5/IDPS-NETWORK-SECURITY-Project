#!/bin/bash

echo "Starting IDPS monitoring system..."

# Create directories for packet captures and logs
mkdir -p /shared/pcaps
mkdir -p /shared/logs
mkdir -p /shared/reports
mkdir -p /shared/analysis

# Fix permissions for shared directories
chmod 777 /shared/pcaps /shared/logs /shared/reports /shared/analysis

# Make sure eve.json exists with proper permissions
touch /shared/logs/eve.json
chmod 666 /shared/logs/eve.json

# Make sure all scripts are executable
if [ -d "/opt/scripts" ]; then
    chmod +x /opt/scripts/*.sh /opt/scripts/*.py
fi

# Start continuous packet capture with rotation (for learning objective 2)
echo "Starting continuous packet capture..."
tcpdump -i eth0 -G 300 -w "/shared/pcaps/capture-%Y%m%d%H%M%S.pcap" -z gzip -s 0 &
TCPDUMP_PID=$!
echo "Packet capture started with PID: $TCPDUMP_PID"

# Start Suricata in IDS mode with extended logging
echo "Starting Suricata IDPS..."
# Initialize Suricata with updated rules and configuration
suricata-update

# Remove any existing lock files to prevent startup issues
rm -f /var/run/suricata.pid
rm -f /shared/logs/eve.json.lock

# Start Suricata with proper configuration and verify it started correctly
suricata -c /etc/suricata/suricata.yaml -i eth0 &
SURICATA_PID=$!

# Verify Suricata started correctly
sleep 3
if ps -p $SURICATA_PID > /dev/null; then
    echo "Suricata started successfully with PID: $SURICATA_PID"
else
    echo "ERROR: Suricata failed to start properly. Check configuration."
    # Try starting with default settings as a fallback
    echo "Attempting fallback startup..."
    suricata -i eth0 &
    SURICATA_PID=$!
fi

# Start alert monitoring system
echo "Starting alert monitoring system..."
python3 /opt/scripts/alert_monitor.py -f /shared/logs/eve.json -o /shared/logs/alert_monitor.log &
ALERT_MONITOR_PID=$!
echo "Alert monitor started with PID: $ALERT_MONITOR_PID"

# Start automated port monitoring script every 5 minutes (for learning objective 1)
echo "Setting up periodic port monitoring..."
while true; do
    echo "======== Port Activity Report $(date) ========" >> /shared/logs/port_activity.log
    echo "Active connections by port:" >> /shared/logs/port_activity.log
    netstat -tunapl | grep LISTEN >> /shared/logs/port_activity.log
    echo "Top 10 connections by volume:" >> /shared/logs/port_activity.log
    ss -tnp | sort -k3 | tail -n 10 >> /shared/logs/port_activity.log
    echo "----------------------------------------" >> /shared/logs/port_activity.log
    sleep 300
done &
PORT_MONITOR_PID=$!
echo "Port activity monitoring started with PID: $PORT_MONITOR_PID"

# Script to generate hourly traffic reports (for learning objective 3)
echo "Setting up periodic traffic analysis..."
while true; do
    # Wait until we have PCAP files
    if ls /shared/pcaps/*.pcap* 1> /dev/null 2>&1; then
        TIME=$(date +%Y%m%d-%H%M)
        echo "Running traffic analysis at $TIME"
        
        # Get the latest PCAP file
        LATEST_PCAP=$(ls -t /shared/pcaps/*.pcap* | head -1)
        
        # Run the packet analyzer on the latest PCAP
        if [ -x /opt/scripts/packet_analyzer.py ]; then
            python3 /opt/scripts/packet_analyzer.py "$LATEST_PCAP" -o "/shared/analysis"
        fi
    else
        echo "Waiting for PCAP files to be created..."
    fi
    
    sleep 3600
done &
ANALYZER_PID=$!
echo "Traffic analyzer started with PID: $ANALYZER_PID"

# Add a log verification process
echo "Setting up log verification..."
(
while true; do
    # Check if eve.json is being written to properly
    if [ ! -s /shared/logs/eve.json ]; then
        echo "WARNING: eve.json appears empty, checking Suricata status..."
        if ! ps -p $SURICATA_PID > /dev/null; then
            echo "ERROR: Suricata not running! Attempting restart..."
            suricata -c /etc/suricata/suricata.yaml -i eth0 &
            SURICATA_PID=$!
        fi
    fi
    sleep 60
done
) &
VERIFICATION_PID=$!

echo "================================================"
echo "IDPS System Active"
echo "================================================"
echo "System components:"
echo "1. Suricata IDS (PID: $SURICATA_PID)"
echo "2. Packet Capture (PID: $TCPDUMP_PID)"
echo "3. Alert Monitor (PID: $ALERT_MONITOR_PID)"
echo "4. Port Monitor (PID: $PORT_MONITOR_PID)"
echo "5. Traffic Analyzer (PID: $ANALYZER_PID)"
echo "6. Log Verification (PID: $VERIFICATION_PID)"
echo "================================================"

echo "IDPS system is running..."
# Keep container running
tail -f /dev/null