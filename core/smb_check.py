import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Latent.http_client import probe_tcp_port
from core.logger import log
from core.report import write_report


def smb_check(domain, report):
    found = []
    for port in (139, 445):
        if probe_tcp_port(domain, port, timeout=0.5):
            found.append(port)
            message = f"SMB service port {port}/tcp is reachable; no share enumeration performed."
            log(message, "INFO")
            write_report(report, message)
    if not found:
        write_report(report, "No SMB ports observed.")
    return found
