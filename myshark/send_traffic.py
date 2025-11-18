#!/usr/bin/env python3
"""Send continuous traffic to the Flask web UI to demonstrate live data."""

import requests
import time
import json
from datetime import datetime

BASE_URL = "http://127.0.0.1:5000"

def send_requests():
    """Send continuous API requests to Flask."""
    endpoints = [
        "/",
        "/api/recent?count=10",
        "/api/stats",
        "/api/packet/0",
        "/api/packet/1",
        "/api/packet/2",
        "/api/hexdump/0",
    ]
    
    print("=" * 70)
    print("MyShark Web UI - Sending Traffic")
    print("=" * 70)
    print()
    
    try:
        for i in range(15):
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] Request batch {i+1}")
            
            for endpoint in endpoints:
                try:
                    url = f"{BASE_URL}{endpoint}"
                    response = requests.get(url, timeout=2)
                    status_color = "✓" if response.status_code == 200 else "✗"
                    
                    # Show response info
                    if "json" in response.headers.get("content-type", ""):
                        try:
                            data = response.json()
                            if isinstance(data, dict) and "recent" in data:
                                count = len(data.get("recent", []))
                                print(f"  {status_color} {endpoint:30} → 200 OK ({count} packets)")
                            elif isinstance(data, dict) and "total_packets" in data:
                                total = data.get("total_packets")
                                print(f"  {status_color} {endpoint:30} → 200 OK (stats: {total} packets)")
                            else:
                                print(f"  {status_color} {endpoint:30} → 200 OK (JSON response)")
                        except:
                            print(f"  {status_color} {endpoint:30} → {response.status_code}")
                    else:
                        size = len(response.text)
                        print(f"  {status_color} {endpoint:30} → {response.status_code} ({size} bytes)")
                        
                except requests.exceptions.ConnectionError:
                    print(f"  ✗ {endpoint:30} → CONNECTION FAILED")
                except requests.exceptions.Timeout:
                    print(f"  ✗ {endpoint:30} → TIMEOUT")
                except Exception as e:
                    print(f"  ✗ {endpoint:30} → ERROR: {str(e)[:40]}")
            
            print()
            time.sleep(1)  # Wait 1 second between batches
    
    except KeyboardInterrupt:
        print("\n[STOPPED] Traffic generation stopped by user")

if __name__ == "__main__":
    send_requests()
