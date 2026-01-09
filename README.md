# MyShark - Lightweight Python Packet Analyzer

A comprehensive, easy-to-use web application for analyzing network packet capture (PCAP) files with detailed protocol breakdown and conversation analysis.

## Features

- **Drag-and-Drop Upload**: Simply drag PCAP/PCAPNG files into the web interface
- **Protocol Analysis**: Detailed breakdown of network protocols (IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP)
- **Conversation Tracking**: Identify and analyze communication pairs between hosts
- **Real-time Statistics**: Quick insights into packet distribution and network activity
- **Beautiful UI**: Modern, responsive web interface with gradient design
- **Packet Details**: Examine individual packets with source, destination, and protocol information

## Supported File Formats

- `.pcap` - Standard packet capture format
- `.pcapng` - Enhanced packet capture format
- `.cap` - Alternative packet capture extension

## Installation

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/Govind-v-kartha/MyShark
cd MyShark
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python web_app.py
```

4. Open your browser and navigate to `http://localhost:8000`

### Deploy to Vercel

1. Fork or create your own repository
2. Connect your GitHub repository to Vercel
3. Deploy with one click - Vercel will automatically detect the FastAPI application
4. Your app will be live at `https://your-app-name.vercel.app`

## Project Structure

```
MyShark/
├── api/
│   └── index.py          # Vercel serverless function
├── src/
│   ├── parser.py         # Packet parsing utilities
│   └── store.py          # PCAP file handling
├── templates/
│   └── index.html        # Frontend web interface
├── web_app.py            # Local development server
├── pyproject.toml        # Project configuration
├── requirements.txt      # Python dependencies
├── vercel.json           # Vercel deployment config
└── README.md             # This file
```

## Usage

1. **Upload a File**: Drag or click to select a PCAP file
2. **Wait for Analysis**: The server will analyze the packets
3. **View Results**: 
   - **Summary**: Total packet count, unique protocols, conversations
   - **Protocols**: Breakdown of network protocols detected
   - **Conversations**: Communication pairs and their statistics
   - **Packets**: Individual packet details

## Technical Stack

- **Framework**: FastAPI (Python web framework)
- **Packet Analysis**: Scapy (packet parsing library)
- **Server**: Uvicorn (ASGI web server)
- **Deployment**: Vercel (serverless platform)
- **Frontend**: HTML5 with vanilla JavaScript

## API Endpoints

### `GET /`
Returns the web UI for packet analysis

### `POST /analyze`
Analyzes an uploaded packet file
- **Body**: Multipart form data with `file` field
- **Returns**: JSON with packet analysis results

### `GET /health`
Health check endpoint

## Requirements

- Python 3.10 or higher
- FastAPI 0.115.0+
- Scapy 2.6.1+
- Uvicorn 0.32.0+

## Author

**Govind v Kartha**
- Email: knvgovind@gmail.com
- GitHub: [@Govind-v-kartha](https://github.com/Govind-v-kartha)

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

**MyShark** - Dive into your network packets with ease! 🦈
