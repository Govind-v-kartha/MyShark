#!/usr/bin/env python3
"""Start server with demo data and send continuous traffic."""

import subprocess
import time
import requests
import threading
from datetime import datetime

def load_data():
    """Load demo data."""
    print("[SETUP] Loading demo packets...")
    subprocess.run(["python", "load_demo_data.py"], capture_output=True)
    print("[SETUP] Demo packets loaded!")

def start_server():
    """Start Flask server."""
    print("[SERVER] Starting Flask server...")
    subprocess.Popen(["python", "web_ui.py", "--host", "127.0.0.1", "--port", "5000"])
    print("[SERVER] Flask server started!")
    time.sleep(3)  # Wait for server to start

def send_traffic():
    """Send continuous traffic."""
    endpoints = [
        "/",
        "/api/recent?count=15",
        "/api/stats",
        "/api/packet/0",
        "/api/packet/5",
        "/api/hexdump/3",
    ]
    
    print("\n" + "=" * 70)
    print("LIVE TRAFFIC DEMO - MyShark Web UI")
    print("=" * 70)
    print()
    
    try:
        for i in range(20):
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] Traffic batch {i+1}/20")
            
            for endpoint in endpoints:
                try:
                    url = f"http://127.0.0.1:5000{endpoint}"
                    response = requests.get(url, timeout=2)
                    status = "✓" if response.status_code == 200 else "✗"
                    
                    if "json" in response.headers.get("content-type", ""):
                        data = response.json()
                        if isinstance(data, dict) and "recent" in data:
                            count = len(data.get("recent", []))
                            print(f"  {status} {endpoint:28} → 200 ({count} packets)")
                        elif isinstance(data, dict) and "total_packets" in data:
                            total = data.get("total_packets")
                            print(f"  {status} {endpoint:28} → 200 (stats)")
                        else:
                            print(f"  {status} {endpoint:28} → 200 (JSON)")
                    else:
                        size = len(response.text)
                        print(f"  {status} {endpoint:28} → {response.status_code} ({size} bytes)")
                        
                except Exception as e:
                    print(f"  ✗ {endpoint:28} → ERROR: {str(e)[:30]}")
            
            print()
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n[STOPPED] Traffic stopped!")

if __name__ == "__main__":
    load_data()
    start_server()
    send_traffic()
