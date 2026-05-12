import socket
import subprocess
from core.logger import log
from core.report import write_report

def smb_check(domain, report):
    ports = [139, 445]
    found = []

    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(2)

            if s.connect_ex((domain, port)) == 0:
                log(f"SMB OPEN {port}")
                write_report(report, f"SMB {port} OPEN")
                found.append(port)

            s.close()
        except:
            pass

    if not found:
        write_report(report, "No SMB found")
        return

    try:
        result = subprocess.run(
            ["smbclient", "-L", f"//{domain}/", "-N"],
            capture_output=True,
            text=True,
            timeout=10
        )

        write_report(report, result.stdout)

    except:
        write_report(report, "smbclient failed")
