#!/usr/bin/env python3
"""
MyShark Flask Web UI

Provides a minimal web interface for viewing captured packets:
  - GET / : Recent packets table
  - GET /api/recent : JSON API for recent packets
  - GET /packet/<id> : Detailed packet view
"""

import sys
import os

# Ensure myshark package can be imported when running this file directly
if __name__ == "__main__" or __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
from typing import Optional
from flask import Flask, render_template, jsonify

from myshark.pcap_store import PacketBuffer
from myshark.parser import hexdump


logger = logging.getLogger(__name__)


# Global packet buffer (shared with CLI/capture)
# In a production app, this would use IPC or a database
packet_buffer = PacketBuffer(maxlen=500)


def create_app(buffer: Optional[PacketBuffer] = None) -> Flask:
    """
    Create and configure Flask app.
    
    Args:
        buffer: Optional shared PacketBuffer instance
    
    Returns:
        Configured Flask app
    """
    import os
    global packet_buffer
    if buffer:
        packet_buffer = buffer
    
    # Get the templates folder relative to this file
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    
    @app.route("/")
    def index():
        """Display recent packets table."""
        return render_template("index.html")
    
    @app.route("/api/recent")
    def api_recent():
        """JSON API: Get recent packets."""
        n = 20  # Default to 20 most recent
        packets = packet_buffer.get_recent(n)
        
        result = []
        base_idx = max(0, packet_buffer.count() - n)
        
        for i, (parsed, _) in enumerate(packets):
            idx = base_idx + i
            result.append({
                "id": idx,
                "timestamp": parsed.timestamp_iso,
                "src_ip": parsed.src_ip or "N/A",
                "dst_ip": parsed.dst_ip or "N/A",
                "src_port": parsed.sport,
                "dst_port": parsed.dport,
                "protocol": parsed.l4_proto or "?",
                "summary": parsed.summary[:100]
            })
        
        return jsonify({
            "count": len(result),
            "packets": result
        })
    
    @app.route("/packet/<int:packet_id>")
    def packet_detail(packet_id: int):
        """Display detailed packet information."""
        result = packet_buffer.get(packet_id)
        
        if result is None:
            return render_template("404.html", message=f"Packet {packet_id} not found"), 404
        
        parsed, _ = result
        
        # Prepare data for template
        hex_dump_full = hexdump(parsed.raw_bytes) if parsed.raw_bytes else "No data"
        hex_dump_payload = hexdump(parsed.payload_bytes) if parsed.payload_bytes else "No payload"
        
        packet_data = {
            "id": packet_id,
            "timestamp": parsed.timestamp_iso,
            "timestamp_unix": parsed.timestamp,
            "src_mac": parsed.src_mac or "N/A",
            "dst_mac": parsed.dst_mac or "N/A",
            "src_ip": parsed.src_ip or "N/A",
            "dst_ip": parsed.dst_ip or "N/A",
            "src_port": parsed.sport or "N/A",
            "dst_port": parsed.dport or "N/A",
            "protocol": parsed.l4_proto or "N/A",
            "tcp_flags": ", ".join(parsed.tcp_flags) if parsed.tcp_flags else "N/A",
            "dns_queries": ", ".join(parsed.dns_queries) if parsed.dns_queries else "None",
            "http_host": parsed.http_host or "N/A",
            "http_path": parsed.http_path or "N/A",
            "layers": " / ".join(parsed.layers),
            "raw_bytes_len": len(parsed.raw_bytes),
            "payload_bytes_len": len(parsed.payload_bytes),
            "hex_dump_full": hex_dump_full,
            "hex_dump_payload": hex_dump_payload
        }
        
        return render_template("packet.html", packet=packet_data)
    
    @app.route("/api/stats")
    def api_stats():
        """JSON API: Get capture statistics."""
        return jsonify({
            "total_packets": packet_buffer.count(),
            "buffer_size": packet_buffer.maxlen
        })
    
    @app.errorhandler(404)
    def not_found(error):
        return render_template("404.html", message="Page not found"), 404
    
    @app.errorhandler(500)
    def server_error(error):
        logger.error(f"Server error: {error}")
        return render_template("404.html", message="Internal server error"), 500
    
    return app


if __name__ == "__main__":
    import click
    
    @click.command()
    @click.option("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    @click.option("--port", type=int, default=5000, help="Port (default: 5000)")
    @click.option("--debug", is_flag=True, help="Enable debug mode")
    def run(host: str, port: int, debug: bool):
        """Run the Flask web UI."""
        app = create_app()
        app.run(host=host, port=port, debug=debug)
    
    run()
