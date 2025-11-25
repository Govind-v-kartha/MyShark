"""MyShark - Lightweight Packet Capture and Inspection Tool"""

__version__ = "0.1.0"

# Make CLI accessible from package
from myshark.cli import cli

__all__ = ["cli"]

