import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Latent.main import Logger, is_public_target, scan_ports as main_scan_ports
from core.report import write_report


def scan_ports_compat(domain, max_port, report, threads=20):
    if not is_public_target(domain):
        raise ValueError("Refusing to scan an unresolved or non-public target.")
    ports = main_scan_ports(
        domain, min(max(1, max_port), 1000), min(max(1, threads), 20), Logger()
    )
    for port, service, banner in ports:
        write_report(report, f"PORT {port}/{service}" + (f" | {banner}" if banner else ""))
    return ports


scan_ports = scan_ports_compat
