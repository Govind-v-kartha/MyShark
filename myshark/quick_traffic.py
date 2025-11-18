#!/usr/bin/env python3
"""Generate traffic to populate the logging dashboard."""

import requests
import time

BASE_URL = "http://127.0.0.1:5000"

endpoints = [
    "/",
    "/api/recent?count=10",
    "/api/stats",
    "/api/packet/0",
    "/api/packet/1",
    "/api/hexdump/0",
    "/log",
    "/api/log",
]

print("Generating traffic to populate logs...")
for i in range(10):
    for endpoint in endpoints:
        try:
            requests.get(f"{BASE_URL}{endpoint}", timeout=1)
            print(f"✓ {endpoint}")
        except:
            print(f"✗ {endpoint}")
    print()
    time.sleep(0.5)

print("Traffic generation complete! Check http://127.0.0.1:5000/log")
