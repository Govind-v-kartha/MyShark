# MyShark 🦈

**A comprehensive network packet analysis tool with CLI and Web UI**

MyShark is a powerful packet analysis tool that allows you to upload PCAP/PCAPNG files and get detailed packet analysis reports with an intuitive web interface.

## Features

✨ **Key Features:**
- 📤 Upload and analyze PCAP/PCAPNG files
- 🔍 Deep packet inspection and analysis
- 📊 Comprehensive analysis reports
- 🌐 Modern web UI for easy interaction
- ⚡ Fast and efficient packet processing
- 🎯 Support for multiple packet types and protocols

## Technology Stack

- **Backend:** FastAPI, Python 3.10+
- **Frontend:** HTML5, Jinja2 Templates
- **Packet Processing:** Scapy
- **Server:** Uvicorn

## Requirements

- Python >= 3.10
- pip or uv package manager

## Installation

### Using pip

```bash
pip install -r requirements.txt
```

### Using uv (recommended)

```bash
uv pip install -r requirements.txt
```

Or with the project dependencies:

```bash
uv pip install scapy fastapi uvicorn python-multipart jinja2
```

## Usage

### Running the Web Application

Start the FastAPI server:

```bash
python web_app.py
```

The web application will be available at `http://localhost:8000`

### Features

1. **Upload PCAP Files:** Upload your PCAP or PCAPNG files through the web interface
2. **View Analysis:** Get comprehensive packet analysis including:
   - Packet headers
   - Protocol information
   - Payload data
   - Traffic statistics

## Project Structure

```
MyShark/
├── web_app.py              # FastAPI web application
├── src/
│   ├── parser.py          # Packet parsing and analysis logic
│   └── store.py           # Data storage utilities
├── templates/
│   └── index.html         # Web UI template
├── uploads/               # Uploaded PCAP files directory
├── pyproject.toml         # Project configuration
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## API Endpoints

- **GET `/`** - Web interface homepage
- **POST `/analyze`** - Upload and analyze PCAP files
- **GET `/health`** - Health check endpoint

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**Govind v Kartha** - [GitHub](https://github.com/Govind-v-kartha)

## Support

For issues, questions, or suggestions, please open an issue on the [GitHub repository](https://github.com/Govind-v-kartha/MyShark/issues).

---

Made with ❤️ by Govind v Kartha
