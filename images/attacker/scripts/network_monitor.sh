#!/bin/bash

# Network Port Monitor Script
# This script monitors network port activity and helps detect potentially suspicious connections

# Default values
TARGET_HOST=${1:-"web-server"}
MONITOR_INTERVAL=${2:-5}
OUTPUT_DIR="/shared/monitoring"

# Create output directory if it doesn't exist
mkdir -p $OUTPUT_DIR

# Log file for this monitoring session
LOG_FILE="$OUTPUT_DIR/port_monitor_$(date +%Y%m%d_%H%M%S).log"
echo "=== Network Port Monitor Started at $(date) ===" | tee -a $LOG_FILE
echo "Target: $TARGET_HOST" | tee -a $LOG_FILE
echo "Interval: $MONITOR_INTERVAL seconds" | tee -a $LOG_FILE
echo "===========================================================" | tee -a $LOG_FILE

# Function to check for unusual port activity
check_unusual_ports() {
  echo "Checking for connections on unusual ports..." | tee -a $LOG_FILE
  
  # Known service ports to exclude from unusual report
  KNOWN_PORTS="20 21 22 23 25 53 80 443 8080 8443"
  
  # Get all established connections to unusual ports
  NETSTAT_RESULT=$(netstat -tuan | grep ESTABLISHED | grep -v "127.0.0.1")
  
  echo "Current established connections:" | tee -a $LOG_FILE
  echo "$NETSTAT_RESULT" | tee -a $LOG_FILE
  
  # Look for connections to uncommon ports
  echo "Connections to unusual ports:" | tee -a $LOG_FILE
  while read -r conn; do
    if [ -n "$conn" ]; then
      PORT=$(echo $conn | awk '{print $4}' | cut -d: -f2)
      IS_COMMON=false
      
      for common_port in $KNOWN_PORTS; do
        if [ "$PORT" = "$common_port" ]; then
          IS_COMMON=true
          break
        fi
      done
      
      if [ "$IS_COMMON" = false ]; then
        echo "UNUSUAL PORT: $conn" | tee -a $LOG_FILE
      fi
    fi
  done <<< "$NETSTAT_RESULT"
  
  echo "" | tee -a $LOG_FILE
}

# Function to scan target for open ports
scan_target_ports() {
  echo "Scanning $TARGET_HOST for open ports..." | tee -a $LOG_FILE
  
  # Use nmap to scan common ports
  NMAP_RESULT=$(nmap -F $TARGET_HOST)
  echo "$NMAP_RESULT" | tee -a $LOG_FILE
  
  # Extract and display open ports
  echo "Open ports on $TARGET_HOST:" | tee -a $LOG_FILE
  OPEN_PORTS=$(echo "$NMAP_RESULT" | grep "open" | awk '{print $1}')
  echo "$OPEN_PORTS" | tee -a $LOG_FILE
  echo "" | tee -a $LOG_FILE
}

# Function to detect port scanning attempts
detect_port_scans() {
  echo "Checking for potential port scan activity..." | tee -a $LOG_FILE
  
  # Count SYN packets per source IP in the last minute
  POTENTIAL_SCANNERS=$(tcpdump -nr /shared/pcaps/$(ls -t /shared/pcaps/ | head -1) 'tcp[tcpflags] & tcp-syn != 0' 2>/dev/null | 
                   awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr | head -5)
  
  echo "Top 5 sources of SYN packets:" | tee -a $LOG_FILE
  echo "$POTENTIAL_SCANNERS" | tee -a $LOG_FILE
  
  # Highlight potential port scanners (high number of SYN packets)
  echo "$POTENTIAL_SCANNERS" | while read line; do
    COUNT=$(echo $line | awk '{print $1}')
    IP=$(echo $line | awk '{print $2}')
    
    if [ $COUNT -gt 15 ]; then
      echo "POTENTIAL PORT SCANNER: $IP with $COUNT SYN packets" | tee -a $LOG_FILE
    fi
  done
  echo "" | tee -a $LOG_FILE
}

# Function to monitor specific critical ports (FTP, HTTP, SSH)
monitor_critical_ports() {
  echo "Monitoring critical service ports..." | tee -a $LOG_FILE
  
  # Check FTP connections (port 21)
  FTP_CONNECTIONS=$(netstat -ant | grep ":21" | grep ESTABLISHED | wc -l)
  echo "Active FTP connections: $FTP_CONNECTIONS" | tee -a $LOG_FILE
  
  # Check HTTP connections (port 80)
  HTTP_CONNECTIONS=$(netstat -ant | grep ":80" | grep ESTABLISHED | wc -l)
  echo "Active HTTP connections: $HTTP_CONNECTIONS" | tee -a $LOG_FILE
  
  # Check SSH connections (port 22)
  SSH_CONNECTIONS=$(netstat -ant | grep ":22" | grep ESTABLISHED | wc -l)
  echo "Active SSH connections: $SSH_CONNECTIONS" | tee -a $LOG_FILE
  
  # Alert on excessive connections
  if [ $FTP_CONNECTIONS -gt 10 ]; then
    echo "WARNING: High number of FTP connections detected!" | tee -a $LOG_FILE
  fi
  
  if [ $HTTP_CONNECTIONS -gt 20 ]; then
    echo "WARNING: High number of HTTP connections detected!" | tee -a $LOG_FILE
  fi
  
  if [ $SSH_CONNECTIONS -gt 5 ]; then
    echo "WARNING: High number of SSH connections detected!" | tee -a $LOG_FILE
  fi
  
  echo "" | tee -a $LOG_FILE
}

# Main monitoring loop
echo "Starting continuous port monitoring. Press Ctrl+C to stop." | tee -a $LOG_FILE
COUNTER=1

while true; do
  echo "" | tee -a $LOG_FILE
  echo "=== Monitoring Iteration $COUNTER at $(date) ===" | tee -a $LOG_FILE
  
  # Run monitoring functions
  check_unusual_ports
  
  # Only run port scan occasionally to reduce network traffic
  if [ $((COUNTER % 5)) -eq 0 ]; then
    scan_target_ports
  fi
  
  detect_port_scans
  monitor_critical_ports
  
  echo "Sleeping for $MONITOR_INTERVAL seconds..." | tee -a $LOG_FILE
  echo "===========================================================" | tee -a $LOG_FILE
  
  # Sleep before next iteration
  sleep $MONITOR_INTERVAL
  COUNTER=$((COUNTER+1))
done