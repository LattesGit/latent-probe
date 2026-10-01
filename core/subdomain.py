import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Latent.main import Logger, enumerate_subdomains
from core.report import write_report


def subdomain_scan(domain, wordlist, report, limit):
    findings = enumerate_subdomains(domain, wordlist, limit, Logger())
    for hostname, addresses in findings:
        write_report(report, f"{hostname} -> {', '.join(addresses)}")
    return findings
