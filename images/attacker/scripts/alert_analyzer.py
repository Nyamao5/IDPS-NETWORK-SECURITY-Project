#!/usr/bin/env python3

import json
import os
import time

def analyze_alerts():
    """Analyze Suricata alerts from the eve.json file"""
    alert_file = "/var/log/suricata/eve.json"
    
    if not os.path.exists(alert_file):
        print(f"Alert file {alert_file} doesn't exist yet.")
        return
    
    alerts = []
    try:
        with open(alert_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if 'alert' in event:
                        alerts.append(event)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading alert file: {e}")
    
    # Process alerts
    if alerts:
        print(f"Found {len(alerts)} alerts:")
        for idx, alert in enumerate(alerts[-10:], 1):  # Show last 10 alerts
            print(f"Alert {idx}:")
            print(f"  Signature: {alert['alert']['signature']}")
            print(f"  Category: {alert['alert']['category']}")
            print(f"  Source IP: {alert['src_ip']}")
            print(f"  Destination IP: {alert['dest_ip']}")
            print(f"  Timestamp: {alert['timestamp']}")
            print()
    else:
        print("No alerts found.")

if __name__ == "__main__":
    print("Starting alert analyzer...")
    while True:
        analyze_alerts()
        time.sleep(10)  # Check every 10 seconds