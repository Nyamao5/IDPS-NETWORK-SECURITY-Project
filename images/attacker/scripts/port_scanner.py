#!/usr/bin/env python3

import sys
import socket
import argparse
import time
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port, timeout=1):
    """Scan a single port on the target and return if it's open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            sock.close()
            return port, True, service
        sock.close()
        return port, False, None
    except Exception as e:
        return port, False, None

def scan_range(target, start_port, end_port, threads=50, delay=0):
    """Scan a range of ports using multiple threads."""
    open_ports = []
    
    print(f"Starting port scan on {target} (ports {start_port}-{end_port})")
    print("=" * 60)
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan_port, target, port))
            if delay > 0:
                time.sleep(delay)
        
        for future in futures:
            port, is_open, service = future.result()
            if is_open:
                print(f"Port {port} is OPEN - Service: {service}")
                open_ports.append((port, service))
    
    print("=" * 60)
    print(f"Scan complete. Found {len(open_ports)} open ports.")
    print("=" * 60)
    
    if open_ports:
        print("Open ports summary:")
        for port, service in open_ports:
            print(f"Port {port}/tcp - {service}")
    
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (e.g., '1-1000' or '22,80,443')")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads to use")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between port scans in seconds")
    parser.add_argument("--timeout", type=float, default=1, help="Timeout for each connection attempt in seconds")
    
    args = parser.parse_args()
    
    # Parse port range
    if "-" in args.ports:
        start_port, end_port = map(int, args.ports.split("-"))
    elif "," in args.ports:
        ports = list(map(int, args.ports.split(",")))
        start_port, end_port = min(ports), max(ports)
    else:
        try:
            port = int(args.ports)
            start_port = end_port = port
        except ValueError:
            print("Invalid port specification")
            return
    
    # Run the scan
    scan_range(args.target, start_port, end_port, args.threads, args.delay)

if __name__ == "__main__":
    main()