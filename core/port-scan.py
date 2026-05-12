import socket
from core.logger import log
from core.report import write_report

def scan_ports(domain, max_port, report):
    open_ports = []

    for port in range(1, max_port + 1):
        try:
            s = socket.socket()
            s.settimeout(0.3)

            if s.connect_ex((domain, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"

                log(f"PORT {port}/{service} OPEN")
                write_report(report, f"PORT {port}/{service} OPEN")

                open_ports.append((port, service))

            s.close()

        except:
            pass

    return open_ports
