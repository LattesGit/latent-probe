import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Latent.http_client import probe_tcp_port
from Latent.main import is_public_target

CRITICAL_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def scan_port(target, port):
    if port not in CRITICAL_PORTS:
        return None
    return (port, CRITICAL_PORTS[port]) if probe_tcp_port(target, port, timeout=0.5) else None


def smb_enum(target):
    return {
        "open": probe_tcp_port(target, 445, timeout=0.5),
        "shares": [],
        "guest": False,
        "null_session": False,
    }


def check_anonymous_services(target, port, service):
    del target, port, service
    return []


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m Latent.core.critscan <authorized-public-target>")
        return 1
    target = sys.argv[1]
    if not is_public_target(target):
        print("Refusing unresolved or non-public target.")
        return 2
    found = [result for port in CRITICAL_PORTS if (result := scan_port(target, port))]
    for port, service in found:
        print(f"{port}/{service} reachable (no authentication or enumeration attempted)")
    print(f"Checked {len(CRITICAL_PORTS)} bounded service ports; {len(found)} reachable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
