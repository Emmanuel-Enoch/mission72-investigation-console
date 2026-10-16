"""
Main entry point for Mission 72 Suspicious Login and Activity Detector.
Enables running directly from the root workspace directory:
    python main.py analyze --train <train.csv> --eval <eval.csv>
    python main.py serve --port 8072
"""

import sys
from pathlib import Path

# Automatically ensure src is on sys.path
root_dir = Path(__file__).parent
src_dir = root_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from mission72.cli import main

if __name__ == "__main__":
    sys.exit(main())
