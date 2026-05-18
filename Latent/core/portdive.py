#!/usr/bin/env python3
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# repo: portdive

def scan(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                try:
                    svc = socket.getservbyport(port)
                except:
                    svc = "unknown"
                return port, svc
    except:
        pass
    return None

def main():
    if len(sys.argv) < 2:
        print("Kullanim: python3 portdive.py <hedef> [max_port] [threads]")
        sys.exit(1)

    target = sys.argv[1]
    max_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 200

    print(f"[*] {target} | 1-{max_port} | {threads} thread")

    found = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan, target, p): p for p in range(1, max_port + 1)}
        for f in as_completed(futures):
            res = f.result()
            if res:
                print(f"[+] OPEN {res[0]}/{res[1]}")
                found.append(res)

    print(f"[*] Toplam: {len(found)} acik port")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Durduruldu.")
