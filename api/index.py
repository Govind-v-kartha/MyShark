from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, ARP, IPv6, Ether, Dot11, DNS
import tempfile
import json
from typing import Dict, List, Any

app = FastAPI(
    title="MyShark - Packet Analysis Tool",
    description="Upload and analyze network packet capture files",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MyShark - Packet Analyzer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 40px;
        }
        
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        
        .upload-area {
            border: 3px dashed #667eea;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background-color: #f8f9ff;
        }
        
        .upload-area:hover {
            border-color: #764ba2;
            background-color: #f0f2ff;
        }
        
        .upload-area.dragover {
            border-color: #764ba2;
            background-color: #e8e5ff;
        }
        
        .upload-area h3 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .upload-area p {
            color: #666;
            margin-bottom: 15px;
        }
        
        .upload-area input[type="file"] {
            display: none;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            transition: transform 0.2s ease;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .spinner {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        
        .spinner.loading {
            display: block;
        }
        
        .spinner-animation {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .results {
            display: none;
        }
        
        .results.show {
            display: block;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 2em;
            font-weight: bold;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }
        
        .tab-btn {
            background: none;
            border: none;
            padding: 15px 20px;
            cursor: pointer;
            color: #666;
            font-weight: 500;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
        }
        
        .tab-btn.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .protocol-item {
            background: #f8f9ff;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        
        .protocol-item h4 {
            color: #667eea;
            margin-bottom: 8px;
        }
        
        .protocol-item p {
            color: #666;
            margin: 5px 0;
            font-size: 0.95em;
        }
        
        .error-message {
            background: #fee;
            color: #c33;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            display: none;
            border-left: 4px solid #c33;
        }
        
        .error-message.show {
            display: block;
        }
        
        .success-message {
            background: #efe;
            color: #3c3;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            display: none;
            border-left: 4px solid #3c3;
        }
        
        .success-message.show {
            display: block;
        }
        
        .packet-list {
            max-height: 600px;
            overflow-y: auto;
        }
        
        .packet-item {
            background: #f8f9ff;
            padding: 12px;
            margin-bottom: 8px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦈 MyShark</h1>
            <p>Lightweight Python packet analyzer for PCAP files</p>
        </div>
        
        <div class="card">
            <h2>Upload Packet Capture File</h2>
            <div class="upload-area" id="uploadArea">
                <h3>📁 Click or drag PCAP/PCAPNG files here</h3>
                <p>Supported formats: .pcap, .pcapng, .cap</p>
                <input type="file" id="fileInput" accept=".pcap,.pcapng,.cap" />
                <button class="btn">Choose File</button>
            </div>
            <div class="spinner" id="spinner">
                <div class="spinner-animation"></div>
                <p>Analyzing packets...</p>
            </div>
            <div class="error-message" id="errorMessage"></div>
            <div class="success-message" id="successMessage"></div>
        </div>
        
        <div class="results" id="results">
            <div class="card">
                <h2>Analysis Results</h2>
                <div class="stats-grid" id="statsGrid"></div>
                
                <div class="tabs">
                    <button class="tab-btn active" data-tab="protocols">📊 Protocols</button>
                    <button class="tab-btn" data-tab="conversations">💬 Conversations</button>
                    <button class="tab-btn" data-tab="packets">📦 Packets</button>
                </div>
                
                <div id="protocols" class="tab-content active"></div>
                <div id="conversations" class="tab-content"></div>
                <div id="packets" class="tab-content"></div>
            </div>
        </div>
    </div>
    
    <script>
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const spinner = document.getElementById('spinner');
        const errorMessage = document.getElementById('errorMessage');
        const successMessage = document.getElementById('successMessage');
        const results = document.getElementById('results');
        
        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        });
        
        fileInput.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });
        
        async function handleFiles(files) {
            if (files.length === 0) return;
            
            const file = files[0];
            const formData = new FormData();
            formData.append('file', file);
            
            errorMessage.classList.remove('show');
            successMessage.classList.remove('show');
            spinner.classList.add('loading');
            results.classList.remove('show');
            
            try {
                const response = await fetch('/', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Failed to analyze file');
                }
                
                const data = await response.json();
                displayResults(data);
                successMessage.textContent = `✓ Analysis complete! Processed ${data.summary.packet_count} packets.`;
                successMessage.classList.add('show');
            } catch (error) {
                errorMessage.textContent = `✗ Error: ${error.message}`;
                errorMessage.classList.add('show');
            } finally {
                spinner.classList.remove('loading');
            }
        }
        
        function displayResults(data) {
            // Display stats
            const statsGrid = document.getElementById('statsGrid');
            statsGrid.innerHTML = `
                <div class="stat-card">
                    <h3>Total Packets</h3>
                    <div class="value">${data.summary.packet_count}</div>
                </div>
                <div class="stat-card">
                    <h3>Unique Protocols</h3>
                    <div class="value">${data.summary.unique_protocols}</div>
                </div>
                <div class="stat-card">
                    <h3>Conversations</h3>
                    <div class="value">${data.summary.conversation_count}</div>
                </div>
                <div class="stat-card">
                    <h3>Total Size</h3>
                    <div class="value">${formatBytes(data.summary.total_size)}</div>
                </div>
            `;
            
            // Display protocols
            const protocolsDiv = document.getElementById('protocols');
            let protocolsHtml = '';
            for (const [protocol, count] of Object.entries(data.protocol_stats)) {
                protocolsHtml += `
                    <div class="protocol-item">
                        <h4>${protocol.toUpperCase()}</h4>
                        <p>Packets: ${count}</p>
                    </div>
                `;
            }
            protocolsDiv.innerHTML = protocolsHtml || '<p>No protocol data available</p>';
            
            // Display conversations
            const conversationsDiv = document.getElementById('conversations');
            let conversationsHtml = '';
            for (const conv of data.conversations) {
                conversationsHtml += `
                    <div class="protocol-item">
                        <h4>${conv.src} ↔ ${conv.dst}</h4>
                        <p>Protocol: ${conv.protocol}</p>
                        <p>Packets: ${conv.packet_count}</p>
                    </div>
                `;
            }
            conversationsDiv.innerHTML = conversationsHtml || '<p>No conversation data available</p>';
            
            // Display packets
            const packetsDiv = document.getElementById('packets');
            const packetList = document.createElement('div');
            packetList.className = 'packet-list';
            let packetsHtml = '';
            for (const packet of data.packets.slice(0, 100)) {
                packetsHtml += `
                    <div class="packet-item">
                        <strong>Packet ${packet.number}</strong><br>
                        ${packet.src ? `Src: ${packet.src} ` : ''}
                        ${packet.dst ? `Dst: ${packet.dst}` : ''}
                    </div>
                `;
            }
            packetList.innerHTML = packetsHtml || '<p>No packet data available</p>';
            packetsDiv.innerHTML = '';
            packetsDiv.appendChild(packetList);
            
            results.classList.add('show');
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }
        
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(btn.dataset.tab).classList.add('active');
            });
        });
    </script>
</body>
</html>
"""

class PacketParser:
    """Parse individual packets from pcap files."""
    
    def __init__(self, packet):
        self.packet = packet
    
    def parse(self) -> Dict[str, Any]:
        """Parse packet into dictionary."""
        result = {
            'number': 0,
            'src': None,
            'dst': None,
            'protocol': 'Unknown',
            'size': len(self.packet),
            'payload': None,
        }
        
        # Extract IP info
        if IP in self.packet:
            ip_layer = self.packet[IP]
            result['src'] = ip_layer.src
            result['dst'] = ip_layer.dst
            result['protocol'] = 'IPv4'
        elif IPv6 in self.packet:
            ipv6_layer = self.packet[IPv6]
            result['src'] = ipv6_layer.src
            result['dst'] = ipv6_layer.dst
            result['protocol'] = 'IPv6'
        elif ARP in self.packet:
            arp_layer = self.packet[ARP]
            result['src'] = arp_layer.psrc
            result['dst'] = arp_layer.pdst
            result['protocol'] = 'ARP'
        
        # Get transport protocol
        if TCP in self.packet:
            tcp_layer = self.packet[TCP]
            result['protocol'] = 'TCP'
        elif UDP in self.packet:
            udp_layer = self.packet[UDP]
            result['protocol'] = 'UDP'
        elif ICMP in self.packet:
            result['protocol'] = 'ICMP'
        
        return result

class PacketAnalyzer:
    """Analyze collections of packets."""
    
    def __init__(self, packets):
        self.packets = packets
    
    def parse_all(self) -> List[Dict[str, Any]]:
        """Parse all packets."""
        parsed = []
        for i, packet in enumerate(self.packets):
            parser = PacketParser(packet)
            p = parser.parse()
            p['number'] = i + 1
            parsed.append(p)
        return parsed
    
    def get_protocol_statistics(self) -> Dict[str, int]:
        """Get protocol statistics."""
        stats = {}
        for packet in self.packets:
            protocol = 'Other'
            if IP in packet:
                protocol = 'IP'
            elif IPv6 in packet:
                protocol = 'IPv6'
            elif ARP in packet:
                protocol = 'ARP'
            
            if TCP in packet:
                protocol = 'TCP'
            elif UDP in packet:
                protocol = 'UDP'
            elif ICMP in packet:
                protocol = 'ICMP'
            
            stats[protocol] = stats.get(protocol, 0) + 1
        return stats
    
    def get_conversation_pairs(self) -> List[Dict[str, Any]]:
        """Get conversation pairs."""
        conversations = {}
        for packet in self.packets:
            src, dst, protocol = None, None, 'Unknown'
            
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            elif IPv6 in packet:
                src = packet[IPv6].src
                dst = packet[IPv6].dst
            
            if TCP in packet:
                protocol = 'TCP'
            elif UDP in packet:
                protocol = 'UDP'
            elif ICMP in packet:
                protocol = 'ICMP'
            
            if src and dst:
                key = f"{src}-{dst}"
                if key not in conversations:
                    conversations[key] = {'src': src, 'dst': dst, 'protocol': protocol, 'packet_count': 0}
                conversations[key]['packet_count'] += 1
        
        return list(conversations.values())[:20]

@app.get("/", response_class=HTMLResponse)
async def get_root():
    """Return the HTML UI."""
    return HTML_TEMPLATE

@app.post("/")
async def analyze_packet_file(file: UploadFile = File(...)):
    """Analyze uploaded packet file."""
    try:
        # Save uploaded file to temp location
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name
        
        # Load packets
        packets = rdpcap(tmp_path)
        
        if len(packets) == 0:
            raise HTTPException(status_code=400, detail="No packets found in file")
        
        # Analyze packets
        analyzer = PacketAnalyzer(packets)
        parsed_packets = analyzer.parse_all()
        protocol_stats = analyzer.get_protocol_statistics()
        conversations = analyzer.get_conversation_pairs()
        
        # Calculate total size
        total_size = sum(len(p) for p in packets)
        
        response = {
            'summary': {
                'packet_count': len(packets),
                'unique_protocols': len(protocol_stats),
                'conversation_count': len(conversations),
                'total_size': total_size
            },
            'protocol_stats': protocol_stats,
            'conversations': conversations,
            'packets': parsed_packets[:100]
        }
        
        return JSONResponse(content=response)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing file: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "MyShark Packet Analyzer"}
