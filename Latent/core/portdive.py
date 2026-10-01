import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Latent.core.port_scanner import scan


def scan_port(target, port):
    for found_port, service, banner in scan(target, port, threads=1):
        if found_port == port:
            return found_port, service
    return None
