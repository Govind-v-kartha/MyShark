"""
Flask web UI for MyShark packet capture and inspection.

Provides:
- GET / : Recent packets table with JSON endpoint
- GET /api/recent : JSON endpoint for recent packets
- GET /packet/<id> : Detailed packet view
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, render_template, jsonify, request, abort
except ImportError:
    print("Error: Flask not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

from pcap_store import PcapStore
from parser import format_packet_display


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(store: PcapStore) -> Flask:
    """
    Create and configure Flask application.
    
    Args:
        store: PcapStore instance to use for data
        
    Returns:
        Flask app instance
    """
    app = Flask(__name__, template_folder='templates', static_folder='static')
    
    # Make store accessible to routes
    app.store = store
    
    @app.route('/')
    def index():
        """Main page with recent packets table."""
        packets = app.store.get_all()
        return render_template('index.html', packets=packets, total=len(packets))
    
    @app.route('/api/recent')
    def api_recent():
        """JSON API endpoint for recent packets."""
        count = request.args.get('count', default=50, type=int)
        packets = app.store.get_all()
        
        # Limit to recent 'count' packets
        start = max(0, len(packets) - count)
        recent = packets[start:]
        
        data = []
        for i, pkt in enumerate(recent):
            idx = start + i
            data.append({
                'id': idx,
                'timestamp': pkt.get('timestamp_iso', ''),
                'ip_src': pkt.get('ip_src', '?'),
                'ip_dst': pkt.get('ip_dst', '?'),
                'sport': pkt.get('sport'),
                'dport': pkt.get('dport'),
                'proto': pkt.get('l4_proto', '?'),
                'summary': pkt.get('summary', '')[:100],
            })
        
        return jsonify({
            'total': len(packets),
            'recent': data,
            'timestamp': datetime.now().isoformat(),
        })
    
    @app.route('/packet/<int:packet_id>')
    def packet_detail(packet_id):
        """Show detailed packet information."""
        pkt = app.store.get(packet_id)
        if not pkt:
            abort(404)
        
        formatted = format_packet_display(pkt, include_hexdump=True)
        
        return render_template('packet.html', 
                             packet_id=packet_id,
                             packet=pkt,
                             formatted_display=formatted)
    
    @app.route('/api/packet/<int:packet_id>')
    def api_packet_detail(packet_id):
        """JSON API endpoint for packet details."""
        pkt = app.store.get(packet_id)
        if not pkt:
            abort(404)
        
        # Return packet data as JSON (serializable types only)
        data = {
            'id': packet_id,
            'timestamp': pkt.get('timestamp_iso', ''),
            'timestamp_epoch': pkt.get('timestamp'),
            'layer_stack': pkt.get('layer_stack', ''),
            'ip_src': pkt.get('ip_src'),
            'ip_dst': pkt.get('ip_dst'),
            'sport': pkt.get('sport'),
            'dport': pkt.get('dport'),
            'l4_proto': pkt.get('l4_proto'),
            'tcp_flags': pkt.get('tcp_flags'),
            'dns_queries': pkt.get('dns_queries', []),
            'http_host': pkt.get('http_host'),
            'http_path': pkt.get('http_path'),
            'summary': pkt.get('summary', ''),
        }
        
        return jsonify(data)
    
    @app.route('/api/hexdump/<int:packet_id>')
    def api_hexdump(packet_id):
        """JSON endpoint for packet hex dump."""
        pkt = app.store.get(packet_id)
        if not pkt:
            abort(404)
        
        from parser import hexdump
        
        hex_full = hexdump(pkt.get('raw_bytes', b''), prefix="")
        hex_payload = hexdump(pkt.get('payload_bytes', b''), prefix="") if pkt.get('payload_bytes') else "(empty)"
        
        return jsonify({
            'full_packet': hex_full,
            'payload_only': hex_payload,
        })
    
    @app.route('/api/stats')
    def api_stats():
        """JSON endpoint for capture statistics."""
        packets = app.store.get_all()
        
        proto_count = {}
        for pkt in packets:
            proto = pkt.get('l4_proto', 'Unknown')
            proto_count[proto] = proto_count.get(proto, 0) + 1
        
        return jsonify({
            'total_packets': len(packets),
            'by_protocol': proto_count,
        })
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        return "Packet not found", 404
    
    @app.errorhandler(500)
    def server_error(error):
        """Handle 500 errors."""
        logger.error(f"Server error: {error}")
        return "Internal server error", 500
    
    return app


def main():
    """Main entry point for web UI."""
    parser = argparse.ArgumentParser(
        description="MyShark Web UI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_ui.py --host 127.0.0.1 --port 5000
  python web_ui.py --host 0.0.0.0 --port 8080
"""
    )
    
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create shared store
    store = PcapStore(maxlen=500)
    
    # Create Flask app
    app = create_app(store)
    
    # Start server
    print(f"Starting MyShark Web UI at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop")
    
    try:
        app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == '__main__':
    main()
