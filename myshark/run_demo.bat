@echo off
REM Demo script for MyShark - Generates PCAP and starts web UI
REM Usage: run_demo.bat

setlocal enabledelayedexpansion

echo MyShark Demo
echo ============
echo.

REM Generate demo PCAP
echo Generating demo PCAP...
python generate_demo.py

REM Start web UI
echo.
echo Starting MyShark Web UI on http://127.0.0.1:5000
echo Press Ctrl+C to stop
echo.

python web_ui.py --host 127.0.0.1 --port 5000
