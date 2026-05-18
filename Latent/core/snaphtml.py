#!/usr/bin/env python3
import requests
import sys
import os
from urllib.parse import urlparse

# repo: snaphtml

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

def fetch(target):
    if not target.startswith("http"):
        target = "http://" + target

    variants = [target, target.replace("http://", "https://")]

    for url in variants:
        try:
            print(f"[*] Deneniyor: {url}")
            r = requests.get(url, timeout=10, headers={"User-Agent": USER_AGENT}, verify=False)
            print(f"[+] {r.status_code} - {len(r.text)} bytes")

            parsed = urlparse(url)
            filename = f"{parsed.netloc}.html"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(r.text)
            print(f"[+] Kaydedildi: {filename}")

            # Basit tech fingerprint
            headers = dict(r.headers)
            print(f"[*] Server: {headers.get('Server', 'N/A')}")
            print(f"[*] Powered-By: {headers.get('X-Powered-By', 'N/A')}")
            return r.text
        except Exception as e:
            print(f"[-] Hata: {e}")

    print("[-] Cekilemedi.")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanim: python3 snaphtml.py <hedef>")
        print("Ornek: python3 snaphtml.py hedef.com")
        sys.exit(1)

    import urllib3
    urllib3.disable_warnings()
    fetch(sys.argv[1])
