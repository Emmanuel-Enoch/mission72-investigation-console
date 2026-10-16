"""
Vercel Serverless Function entrypoint for Mission 72.
Exposes the BaseHTTPRequestHandler subclass as `handler` for Vercel's Python runtime.
"""

import sys
from pathlib import Path

# Ensure 'src' and project root are on sys.path
root_dir = Path(__file__).resolve().parent.parent
src_dir = root_dir / "src"

if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from mission72.server import InvestigatorRequestHandler

# Vercel Python runtime expects a class named handler extending BaseHTTPRequestHandler
handler = InvestigatorRequestHandler
