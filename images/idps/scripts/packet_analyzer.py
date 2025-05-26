#!/usr/bin/env python3

import os
import sys
import argparse
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP

def analyze_pcap(pcap_file, output_dir):
    """Analyze a PCAP file and generate comprehensive reports and visualizations."""
    print(f"Analyzing PCAP file: {pcap_file}")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    try:
        # Read the pcap file
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets for analysis")
        
        # Extract basic packet information
        packet_data = []
        for i, pkt in enumerate(packets):
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
                
                # Identify port information
                src_port = dst_port = "N/A"
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                
                # Get packet length
                length = len(pkt)
                
                packet_data.append({
                    'id': i,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': proto,
                    'length': length
                })
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(packet_data)
        
        # ---- Generate Reports ----
        
        # 1. Port Activity Report
        port_report = f"{output_dir}/port_activity_{timestamp}.txt"
        with open(port_report, 'w') as f:
            f.write("=== PORT ACTIVITY REPORT ===\n\n")
            
            # Source port distribution
            f.write("Top 10 Source Ports:\n")
            src_port_counts = df['src_port'].value_counts().head(10)
            for port, count in src_port_counts.items():
                f.write(f"Port {port}: {count} packets\n")
            
            f.write("\nTop 10 Destination Ports:\n")
            dst_port_counts = df['dst_port'].value_counts().head(10)
            for port, count in dst_port_counts.items():
                f.write(f"Port {port}: {count} packets\n")
            
            # Identify potential port scanning
            f.write("\nPotential Port Scanning Activity:\n")
            # Count unique destination ports per source IP
            port_scan_check = df.groupby('src_ip')['dst_port'].nunique().sort_values(ascending=False)
            for ip, unique_ports in port_scan_check.head(5).items():
                if unique_ports > 10:  # Threshold for potential port scanning
                    f.write(f"Source IP {ip} connected to {unique_ports} different ports\n")
        
        # 2. Traffic Flow Report
        traffic_report = f"{output_dir}/traffic_flow_{timestamp}.txt"
        with open(traffic_report, 'w') as f:
            f.write("=== TRAFFIC FLOW REPORT ===\n\n")
            
            # Top source IPs by volume
            f.write("Top 10 Source IPs by Volume:\n")
            src_volume = df.groupby('src_ip')['length'].sum().sort_values(ascending=False)
            for ip, volume in src_volume.head(10).items():
                f.write(f"{ip}: {volume} bytes\n")
            
            # Top destination IPs by volume
            f.write("\nTop 10 Destination IPs by Volume:\n")
            dst_volume = df.groupby('dst_ip')['length'].sum().sort_values(ascending=False)
            for ip, volume in dst_volume.head(10).items():
                f.write(f"{ip}: {volume} bytes\n")
            
            # Potential DoS detection (high volume to specific destination)
            f.write("\nPotential DoS Activity:\n")
            flow_volume = df.groupby(['src_ip', 'dst_ip'])['length'].sum().sort_values(ascending=False)
            for (src, dst), volume in flow_volume.head(5).items():
                if volume > 1000000:  # Threshold for potential DoS (1MB)
                    f.write(f"High volume traffic: {src} -> {dst}: {volume} bytes\n")
        
        # 3. Protocol Analysis Report
        protocol_report = f"{output_dir}/protocol_analysis_{timestamp}.txt"
        with open(protocol_report, 'w') as f:
            f.write("=== PROTOCOL ANALYSIS REPORT ===\n\n")
            
            # Protocol distribution
            proto_counts = df['protocol'].value_counts()
            f.write("Protocol Distribution:\n")
            for proto, count in proto_counts.items():
                protocol_name = "TCP" if proto == 6 else "UDP" if proto == 17 else f"Protocol {proto}"
                f.write(f"{protocol_name}: {count} packets\n")
            
            # FTP traffic analysis (port 21)
            ftp_traffic = df[(df['src_port'] == 21) | (df['dst_port'] == 21)]
            f.write(f"\nFTP Traffic (Port 21): {len(ftp_traffic)} packets\n")
            
            # HTTP traffic analysis (port 80)
            http_traffic = df[(df['src_port'] == 80) | (df['dst_port'] == 80)]
            f.write(f"HTTP Traffic (Port 80): {len(http_traffic)} packets\n")
            
            # HTTPS traffic analysis (port 443)
            https_traffic = df[(df['src_port'] == 443) | (df['dst_port'] == 443)]
            f.write(f"HTTPS Traffic (Port 443): {len(https_traffic)} packets\n")
            
            # SSH traffic analysis (port 22)
            ssh_traffic = df[(df['src_port'] == 22) | (df['dst_port'] == 22)]
            f.write(f"SSH Traffic (Port 22): {len(ssh_traffic)} packets\n")
        
        # ---- Generate Visualizations ----
        
        # 1. Port distribution visualization
        plt.figure(figsize=(12, 6))
        dst_port_counts.head(10).plot(kind='bar')
        plt.title('Top 10 Destination Ports')
        plt.xlabel('Port Number')
        plt.ylabel('Packet Count')
        plt.tight_layout()
        plt.savefig(f"{output_dir}/port_distribution_{timestamp}.png")
        
        # 2. Traffic volume visualization
        plt.figure(figsize=(12, 6))
        src_volume.head(10).plot(kind='bar')
        plt.title('Top 10 Source IPs by Traffic Volume')
        plt.xlabel('Source IP')
        plt.ylabel('Bytes')
        plt.tight_layout()
        plt.savefig(f"{output_dir}/traffic_volume_{timestamp}.png")
        
        print(f"Analysis completed. Reports saved to {output_dir}/")
        return True
    
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Advanced PCAP Analyzer for Security Analysis")
    parser.add_argument("pcap_file", help="Path to PCAP file for analysis")
    parser.add_argument("-o", "--output-dir", default="/shared/analysis", help="Directory to save analysis results")
    
    args = parser.parse_args()
    analyze_pcap(args.pcap_file, args.output_dir)

if __name__ == "__main__":
    main()