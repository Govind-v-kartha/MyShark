#!/bin/bash
# Demo script for MyShark - Generates PCAP and starts web UI
# Usage: ./run_demo.sh

set -e

echo "MyShark Demo"
echo "============"
echo ""

# Generate demo PCAP
echo "Generating demo PCAP..."
python3 generate_demo.py

# Start web UI
echo ""
echo "Starting MyShark Web UI on http://127.0.0.1:5000"
echo "Press Ctrl+C to stop"
echo ""

python3 web_ui.py --host 127.0.0.1 --port 5000
