
smb_critical_scanner = '''#!/usr/bin/env python3
import socket
import subprocess
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Kritik portlar ve servisler
CRITICAL_PORTS = {
    21: "FTP",
    22: "SSH", 
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                service = CRITICAL_PORTS.get(port, "unknown")
                return port, service
    except:
        pass
    return None

def smb_enum(target):
    results = {"open": False, "shares": [], "guest": False, "null_session": False}
    
    for port in [139, 445]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((target, port)) == 0:
                    results["open"] = True
        except:
            pass
    
    if not results["open"]:
        return results
    
    # Null session test
    try:
        out = subprocess.run(
            ["smbclient", "-L", f"//{target}/", "-N", "-g"],
            capture_output=True, text=True, timeout=10
        )
        if "Disk" in out.stdout or "Sharename" in out.stdout:
            results["null_session"] = True
            for line in out.stdout.split("\\n"):
                if "|" in line and "Disk" in line:
                    share = line.split("|")[0]
                    results["shares"].append(share)
    except:
        pass
    
    # Guest test
    try:
        out = subprocess.run(
            ["smbclient", "-L", f"//{target}/", "-U", "guest%", "-g"],
            capture_output=True, text=True, timeout=10
        )
        if "Disk" in out.stdout:
            results["guest"] = True
    except:
        pass
    
    return results

def check_anonymous_services(target, port, service):
    findings = []
    
    if service == "FTP":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                banner = s.recv(1024).decode("utf-8", errors="ignore")
                s.sendall(b"USER anonymous\\r\\n")
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                if "331" in resp or "230" in resp:
                    findings.append("Anonymous FTP login enabled")
        except:
            pass
    
    elif service == "Redis":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                s.sendall(b"INFO\\r\\n")
                resp = s.recv(2048).decode("utf-8", errors="ignore")
                if "redis_version" in resp:
                    findings.append("Redis unauthenticated access")
        except:
            pass
    
    elif service == "Elasticsearch":
        try:
            import requests
            r = requests.get(f"http://{target}:{port}/_cluster/health", timeout=5)
            if r.status_code == 200 and "cluster_name" in r.text:
                findings.append("Elasticsearch unauthenticated access")
        except:
            pass
    
    return findings

def main():
    if len(sys.argv) < 2:
        print("Kullanim: python3 smb_critical.py <hedef>")
        print("Ornek: python3 smb_critical.py 192.168.1.10")
        sys.exit(1)

    target = sys.argv[1]
    
    print(f"[*] Hedef: {target}")
    print(f"[*] Kritik port taramasi basliyor...\\n")
    
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, target, p): p for p in CRITICAL_PORTS.keys()}
        for f in as_completed(futures):
            res = f.result()
            if res:
                port, service = res
                print(f"[+] {port}/{service} OPEN")
                open_ports.append(res)
    
    if not open_ports:
        print("[-] Acik kritik port bulunamadi.")
        sys.exit(0)
    
    print(f"\\n[*] {len(open_ports)} kritik port acik.\\n")
    
    # SMB detayli tarama
    smb_ports = [p for p, s in open_ports if s == "SMB"]
    if smb_ports:
        print("[*] SMB taramasi basliyor...")
        smb_results = smb_enum(target)
        
        if smb_results["open"]:
            print(f"[+] SMB servisi aktif")
            if smb_results["null_session"]:
                print(f"[!] KRITIK: Null session aktif!")
                print(f"    Paylasimlar: {', '.join(smb_results['shares'])}")
            if smb_results["guest"]:
                print(f"[!] KRITIK: Guest login aktif!")
        print()
    
    # Anonymous servis kontrolu
    print("[*] Anonymous/unauthenticated servis kontrolu...")
    for port, service in open_ports:
        findings = check_anonymous_services(target, port, service)
        for finding in findings:
            print(f"[!] {finding} ({port}/{service})")
    
    print("\\n[*] Tarama tamamlandi.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\n[!] Durduruldu.")
        sys.exit(0)
'''

with open('/mnt/agents/output/smb_critical.py', 'w', encoding='utf-8') as f:
    f.write(smb_critical_scanner)

print("SMB & Critical scanner yazildi!")
print(f"Boyut: {len(smb_critical_scanner)} karakter")

import ast
try:
    ast.parse(smb_critical_scanner)
    print("Syntax OK!")
except SyntaxError as e:
    print(f"Syntax Error: {e}")
