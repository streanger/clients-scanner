"""script for dev purposes"""
import sys
from pathlib import Path

upper = str(Path(__file__).parent.parent)
sys.path.append(upper)
from clients_scanner import scanner_entrypoint

# run scanner gui
scanner_entrypoint()
