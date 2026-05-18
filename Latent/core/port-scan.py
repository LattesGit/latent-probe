#!/usr/bin/env python3
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return port, service
    except:
        pass
    return None

def main():
    if len(sys.argv) < 2:
        print("Kullanim: python3 port_scanner.py <hedef> [max_port] [threads]")
        print("Ornek: python3 port_scanner.py 192.168.1.1 1000 200")
        sys.exit(1)

    target = sys.argv[1]
    max_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 200

    print(f"[*] Hedef: {target}")
    print(f"[*] Port araligi: 1-{max_port}")
    print(f"[*] Thread sayisi: {threads}\n")

    open_ports = []
    ports = range(1, max_port + 1)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, target, p): p for p in ports}
        for f in as_completed(futures):
            res = f.result()
            if res:
                port, service = res
                print(f"[+] OPEN {port}/{service}")
                open_ports.append(res)

    print(f"\n[*] Toplam {len(open_ports)} acik port bulundu.")
    if open_ports:
        print("[*] Acik portlar:")
        for p, s in sorted(open_ports):
            print(f"    {p}/{s}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Durduruldu.")
        sys.exit(0)
