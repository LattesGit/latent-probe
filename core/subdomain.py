import socket
from core.logger import log
from core.report import write_report

def subdomain_scan(domain, wordlist, report, limit):
    found = []
    count = 0

    with open(wordlist, "r", errors="ignore") as f:
        for line in f:
            sub = line.strip()
            if not sub:
                continue

            full = f"{sub}.{domain}"

            try:
                ip = socket.gethostbyname(full)
                log(f"{full} -> {ip}")
                write_report(report, f"{full} -> {ip}")

                found.append((full, ip))
                count += 1

                if limit and count >= limit:
                    break

            except:
                pass

    return found
