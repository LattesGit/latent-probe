import socket

from Latent.http_client import probe_tcp_port


def scan(target, port, threads=1):
    del threads
    port = int(port)
    if not 1 <= port <= 1000:
        raise ValueError("Compatibility port checks are limited to ports 1-1000.")
    if not probe_tcp_port(target, port, timeout=0.5):
        return []
    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = "unknown"
    return [(port, service, "")]
