#!/usr/bin/env python3
"""
LATENT - LITE MODULE
---------------------------------
This file is a lightweight sub-module of the main Latent framework.

MAIN ENTRY POINT:
    Latent/main.py

DO NOT RUN THIS FILE DIRECTLY IN PRODUCTION USE.
"""

import requests
import socket
from urllib.parse import urlparse
from datetime import datetime

BANNER = """
========================
   LATENT & LITE MODULE
========================
"""

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def fetch(domain):
    urls = [f"http://{domain}", f"https://{domain}"]

    for url in urls:
        try:
            r = requests.get(url, timeout=5, verify=False)
            log(f"HTML OK {url}")

            with open(f"{domain}.html", "w") as f:
                f.write(r.text)

            return r.text
        except:
            pass

    log("HTML fetch failed")
    return None


def port_scan(domain, max_port=300):
    log("Port scan started...")
    open_ports = []

    for port in range(1, max_port + 1):
        try:
            s = socket.socket()
            s.settimeout(0.2)

            if s.connect_ex((domain, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"

                log(f"PORT {port}/{service}")
                open_ports.append(port)

            s.close()
        except:
            pass

    return open_ports


def subdomain_scan(domain, wordlist, limit=30):
    log("Subdomain scan started...")
    found = []

    try:
        with open(wordlist, "r", errors="ignore") as f:
            for i, sub in enumerate(f):

                if i >= limit:
                    break

                sub = sub.strip()
                target = f"{sub}.{domain}"

                try:
                    ip = socket.gethostbyname(target)
                    log(f"{target} -> {ip}")
                    found.append(target)
                except:
                    pass
    except:
        log("Wordlist error")

    return found


# ----------------------------
# NOTE:
# This module is NOT standalone.
# It is imported and controlled by:
#   Latent/main.py
# ----------------------------

if __name__ == "__main__":
    print(BANNER)
    print("[!] This module is not intended to run standalone.")
    print("[!] Please run Latent/main.py instead.")
