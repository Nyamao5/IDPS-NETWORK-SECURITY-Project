#!/bin/bash

echo "Starting attacker container..."

# Create necessary directories
mkdir -p /shared/monitoring
mkdir -p /shared/logs
mkdir -p /shared/results

# Make sure all scripts are executable
chmod +x /tools/*.sh /tools/*.py

echo "================================================"
echo "IDPS Network Security Testing Environment"
echo "================================================"
echo "Available attack tools:"
echo "1. FTP Brute Force: /tools/ftp_brute.sh"
echo "2. HTTP DoS Attack: python3 /tools/http_dos.py"
echo "3. SQL Injection: /tools/sql_injection.sh"
echo "4. Port Scanner: python3 /tools/port_scanner.py web-server"
echo "5. Data Exfiltration: python3 /tools/data_exfil.py web-server -m [http|ftp|tcp]"
echo "6. Network Monitor: /tools/network_monitor.sh web-server"
echo "================================================"
echo "Starting network monitoring in background..."

# Start network monitoring in background
/tools/network_monitor.sh web-server 30 > /dev/null 2>&1 &
echo "Network monitoring started (PID: $!)"

echo "Ready for testing. Use 'docker exec -it attacker bash' to access the container."

# Keep container running
tail -f /dev/null