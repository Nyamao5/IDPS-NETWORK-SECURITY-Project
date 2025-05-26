#!/usr/bin/env python3

import json
import time
import os
import argparse
import sys
import signal
from datetime import datetime

class AlertMonitor:
    def __init__(self, alert_file, output_file=None, alert_threshold=5, watch_interval=2):
        """
        Initialize the alert monitor
        
        Parameters:
        - alert_file: Path to the Suricata eve.json file
        - output_file: Path to save alerts (None for stdout)
        - alert_threshold: Number of alerts before triggering a high-severity notification
        - watch_interval: How often to check for new alerts (seconds)
        """
        self.alert_file = alert_file
        self.output_file = output_file
        self.alert_threshold = alert_threshold
        self.watch_interval = watch_interval
        self.alert_counts = {}  # Track alert counts by source IP
        self.seen_alerts = set()  # Track already processed alert IDs
        self.running = True
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, sig, frame):
        """Handle termination signals"""
        print("\nShutting down alert monitor...")
        self.running = False
    
    def log_message(self, message, level="INFO"):
        """Log a message to output file or stdout"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{timestamp}] [{level}] {message}"
        
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(formatted_msg + "\n")
        else:
            print(formatted_msg)
    
    def process_alert(self, alert):
        """Process a single alert from Suricata"""
        # Skip if we've seen this alert before
        alert_id = f"{alert.get('timestamp', '')}-{alert.get('src_ip', '')}-{alert.get('dest_ip', '')}"
        if alert_id in self.seen_alerts:
            return
        
        self.seen_alerts.add(alert_id)
        
        # Extract relevant information
        src_ip = alert.get('src_ip', 'Unknown')
        dest_ip = alert.get('dest_ip', 'Unknown')
        signature = alert.get('alert', {}).get('signature', 'Unknown')
        category = alert.get('alert', {}).get('category', 'Unknown')
        severity = alert.get('alert', {}).get('severity', 0)
        
        # Get port information if available
        src_port = alert.get('src_port', 'Unknown')
        dest_port = alert.get('dest_port', 'Unknown')
        
        # Update alert count for this source IP
        self.alert_counts[src_ip] = self.alert_counts.get(src_ip, 0) + 1
        
        # Generate message
        message = f"Alert: {signature} | Source: {src_ip}:{src_port} -> Destination: {dest_ip}:{dest_port} | Category: {category}"
        
        # Determine alert level based on severity and count
        level = "WARNING"
        if severity >= 2 or self.alert_counts[src_ip] >= self.alert_threshold:
            level = "CRITICAL"
            message = f"HIGH SEVERITY {message}"
            
            # If we're getting many alerts from the same IP, suggest blocking
            if self.alert_counts[src_ip] >= self.alert_threshold:
                message += f" | RECOMMENDED ACTION: Block source IP {src_ip}"
        
        # Log the alert
        self.log_message(message, level)
        
        # Suggest response actions based on alert type
        if "SQL Injection" in signature:
            self.log_message(f"RESPONSE ACTION: Investigate web application at destination {dest_ip}:{dest_port} for SQL injection vulnerability", "ACTION")
        
        elif "FTP brute force" in signature or "SSH brute force" in signature:
            self.log_message(f"RESPONSE ACTION: Temporarily block {src_ip} or implement rate limiting", "ACTION")
        
        elif "DoS" in signature or "DDoS" in signature:
            self.log_message(f"RESPONSE ACTION: Apply traffic filtering for {src_ip} or distribute load", "ACTION")
            
        elif "Port scanning" in signature:
            self.log_message(f"RESPONSE ACTION: Block {src_ip} and investigate their intent", "ACTION")
    
    def start_monitoring(self):
        """Start monitoring the alert file for new alerts"""
        self.log_message(f"Starting alert monitoring on {self.alert_file}")
        self.log_message(f"Alert threshold set to {self.alert_threshold} alerts from the same source")
        
        # Track the current position in the file
        current_position = 0
        
        # Check if file exists
        if not os.path.exists(self.alert_file):
            self.log_message(f"Alert file {self.alert_file} does not exist. Waiting for it to be created...", "WARNING")
        
        # Main monitoring loop
        while self.running:
            try:
                if os.path.exists(self.alert_file):
                    with open(self.alert_file, 'r') as f:
                        # Move to the last position we read
                        f.seek(current_position)
                        
                        # Process new lines
                        for line in f:
                            line = line.strip()
                            if line:  # Skip empty lines
                                try:
                                    alert = json.loads(line)
                                    # Only process actual alerts
                                    if alert.get('event_type') == 'alert':
                                        self.process_alert(alert)
                                except json.JSONDecodeError:
                                    self.log_message(f"Error parsing alert JSON: {line}", "ERROR")
                        
                        # Update our position in the file
                        current_position = f.tell()
                
                # Sleep before checking for new alerts
                time.sleep(self.watch_interval)
                
            except Exception as e:
                self.log_message(f"Error monitoring alerts: {str(e)}", "ERROR")
                time.sleep(self.watch_interval)

def main():
    parser = argparse.ArgumentParser(description="Suricata Alert Monitor")
    parser.add_argument("-f", "--file", default="/shared/logs/eve.json", 
                      help="Path to Suricata eve.json file")
    parser.add_argument("-o", "--output", default="/shared/logs/alert_monitor.log",
                      help="Path to output log file (default: stdout)")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                      help="Number of alerts from same source before suggesting block")
    parser.add_argument("-i", "--interval", type=float, default=2.0,
                      help="Interval in seconds between checks")
    
    args = parser.parse_args()
    
    # Create monitor and start it
    monitor = AlertMonitor(
        alert_file=args.file,
        output_file=args.output,
        alert_threshold=args.threshold,
        watch_interval=args.interval
    )
    
    monitor.start_monitoring()

if __name__ == "__main__":
    main()