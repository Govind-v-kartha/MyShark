"""
FastAPI Web Application for Packet Analysis
Allows users to upload PCAP/PCAPNG files and view comprehensive analysis reports.
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import tempfile
import shutil
import uuid
from typing import Dict, List, Any
import logging
import json

from scapy.all import rdpcap
from src.parser import PacketParser, PacketAnalyzer


def convert_to_serializable(obj):
    """Convert non-serializable objects to serializable types."""
    if hasattr(obj, '__float__'):
        return float(obj)
    elif hasattr(obj, '__int__'):
        return int(obj)
    elif hasattr(obj, '__str__'):
        return str(obj)
    elif isinstance(obj, bytes):
        return obj.hex()
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    return obj


def make_json_serializable(data):
    """Recursively convert data to be JSON serializable."""
    if isinstance(data, dict):
        return {k: make_json_serializable(v) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return [make_json_serializable(item) for item in data]
    elif isinstance(data, bytes):
        return data.hex()
    elif hasattr(data, '__float__'):
        return float(data)
    elif hasattr(data, '__int__'):
        return int(data)
    elif data is None or isinstance(data, (str, int, float, bool)):
        return data
    else:
        return str(data)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="MyShark - Packet Analysis Tool",
    description="Upload and analyze network packet capture files",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create uploads directory if it doesn't exist
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serve the main web interface."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze")
async def analyze_packet_capture(file: UploadFile = File(...)):
    """
    Analyze uploaded packet capture file.
    
    Args:
        file: Uploaded PCAP/PCAPNG file
        
    Returns:
        Comprehensive analysis report including:
        - Summary statistics
        - Protocol distribution
        - IP conversations
        - Detailed packet information
    """
    # Validate file type
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a .pcap or .pcapng file")
    
    # Save uploaded file to uploads directory
    upload_path = None
    try:
        # Create safe filename with unique ID and save to uploads directory
        unique_id = str(uuid.uuid4())[:8]
        safe_filename = f"{Path(file.filename).stem}_{unique_id}{Path(file.filename).suffix}"
        upload_path = UPLOAD_DIR / safe_filename
        
        with open(upload_path, 'wb') as f:
            shutil.copyfileobj(file.file, f)
        
        logger.info(f"Processing file: {file.filename}")
        
        # Load packets
        packets = rdpcap(str(upload_path))
        logger.info(f"Loaded {len(packets)} packets")
        
        if len(packets) == 0:
            raise HTTPException(status_code=400, detail="No packets found in the file")
        
        # Create analyzer
        analyzer = PacketAnalyzer(packets)
        
        # Parse all packets
        parsed_packets = analyzer.parse_all()
        
        # Get statistics
        protocol_stats = analyzer.get_protocol_statistics()
        conversations = analyzer.get_conversation_pairs()
        
        # Calculate summary statistics
        total_size = sum(pkt.get('packet_length', 0) for pkt in parsed_packets)
        
        # Prepare response
        response = {
            "summary": {
                "filename": file.filename,
                "total_packets": len(packets),
                "unique_protocols": len(protocol_stats),
                "conversation_count": len(conversations),
                "total_size": total_size
            },
            "protocol_stats": protocol_stats,
            "conversations": conversations,
            "packets": parsed_packets
        }
        
        # Make response JSON serializable
        response = make_json_serializable(response)
        
        logger.info(f"Analysis complete for {file.filename}")
        return JSONResponse(content=response)
        
    except Exception as e:
        logger.error(f"Error analyzing file: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error analyzing file: {str(e)}")
        
    finally:
        # Clean up uploaded file
        if upload_path and upload_path.exists():
            try:
                upload_path.unlink()
            except Exception as e:
                logger.warning(f"Could not delete uploaded file: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "MyShark Packet Analyzer"}


if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting MyShark Web Application...")
    logger.info("Access the application at: http://localhost:8000")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
