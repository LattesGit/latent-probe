#!/usr/bin/env python3
import os
import sys
import subprocess
import socket
import ssl
import ipaddress
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
import logging
import traceback

import requests
import urllib3

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

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 10
VERSION = ""

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
    "/joomla", "/user/login",
    "/phpmyadmin", "/pma", "/mysql",
    "/server-status", "/status",
    "/dev", "/development", "/staging", "/test",
    "/upload", "/uploads", "/files",
    "/tmp", "/temp",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/security.txt",
    "/jenkins", "/gitlab", "/ci",
    "/kibana", "/grafana", "/prometheus",
    "/hidden", "/secret", "/private",
    "/internal", "/intranet"
]

XSS_PAYLOADS = [
    r"<script>alert(1)</script>",
    r"<script>alert(document.domain)</script>",
    r"<img src=x onerror=alert(1)>",
    r"<svg onload=alert(1)>",
    r"javascript:alert(1)",
    r'" onmouseover=alert(1) x="',
    r"' onmouseover=alert(1) x='",
    r"%3Cscript%3Ealert(1)%3C/script%3E",
    r"%3Cimg%20src=x%20onerror=alert(1)%3E",
    r'"><script>alert(1)</script>',
    r"'><script>alert(1)</script>",
]

LOGIN_PATHS = ["/login", "/admin", "/wp-login.php", "/administrator", "/user/login", "/signin", "/auth"]

COMMON_USERS = ["admin", "root", "user", "test", "administrator", "guest"]

CORS_TEST_ORIGINS = [
    "https://evil.com", "http://evil.com", "null",
    "https://attacker.com", "http://localhost", "https://localhost",
    "http://127.0.0.1", "https://127.0.0.1"
]

JWT_COMMON_SECRETS = [
    "secret", "secret123", "password", "123456", "admin",
    "jwt", "token", "key", "supersecret", "changeme"
]

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 1}
CONFIDENCE_WEIGHT = {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4}

SECRET_PATTERNS = [
    r'(?:api[_-]?key|apikey|token|secret|password|passwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
    r'(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:private[_-]?key|secret[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']',
]

ERROR_SIGNATURES = [
    r"Traceback \(most recent call last\)",
    r"Warning:\s+mysql_",
    r"Fatal error:",
    r"Uncaught Exception",
    r"System\.Exception",
    r"at System\.",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider",
    r"Django Version:",
    r"Whoops!\s+There was an error",
    r"NoMethodError",
    r"PHP Parse error",
    r"java\.lang\.[A-Za-z]+Exception",
]

WAF_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai": "Akamai",
    "x-cdn": "Generic CDN",
    "server: cloudflare": "Cloudflare",
    "x-iinfo": "Incapsula",
    "x-cdn-provider": "Generic CDN",
}

CDN_SERVER_TOKENS = {
    "cloudflare": "Cloudflare",
    "akamaighost": "Akamai",
    "fastly": "Fastly",
    "cloudfront": "CloudFront",
    "varnish": "Varnish",
}


class Logger:
    def __init__(self, report_file=None, verbose=False):
        self.report_file = report_file
        self.verbose = verbose
        self.errors = []
        self.warnings = []

    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        prefixes = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERROR": "[X]", "DEBUG": "[D]"}
        prefix = prefixes.get(level, "[*]")
        line = f"{ts} {prefix} {msg}"
        print(line)
        if self.report_file:
            self.report_file.write(line + "\n")
        if level == "ERROR":
            self.errors.append(msg)
        elif level == "WARN":
            self.warnings.append(msg)

    def phase(self, text):
        print(f"\n{'='*70}")
        print(f"  {text}")
        print(f"{'='*70}")
        if self.report_file:
            self.report_file.write(f"\n{'='*70}\n  {text}\n{'='*70}\n")

    def error(self, msg, exc=None):
        self.log(msg, "ERROR")
        if exc and self.verbose:
            traceback.print_exc()

    def warn(self, msg):
        self.log(msg, "WARN")

    def ok(self, msg):
        self.log(msg, "OK")

    def debug(self, msg):
        if self.verbose:
            self.log(msg, "DEBUG")


class RateLimiter:
    def __init__(self, delay=0.5):
        self.delay = delay
        self.last = 0

    def sleep(self):
        elapsed = time.time() - self.last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last = time.time()


def safe_request(session, url, method="GET", **kwargs):
    try:
        kwargs.setdefault("timeout", TIMEOUT)
        kwargs.setdefault("headers", HEADERS)
        if method.upper() == "GET":
            return session.get(url, **kwargs)
        elif method.upper() == "POST":
            return session.post(url, **kwargs)
        elif method.upper() == "HEAD":
            return session.head(url, **kwargs)
        else:
            return session.request(method, url, **kwargs)
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception:
        return None


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


def mask_secret(value):
    return "*" * min(len(value), 8)


def resolve_all_ips(host):
    ips = set()
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ips.add(info[4][0])
    except Exception:
        pass
    return list(ips)


def is_unsafe_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def ssrf_guard(host, logger):
    ips = resolve_all_ips(host)
    if not ips:
        logger.warn(f"Could not resolve {host}, skipping SSRF pre-check")
        return True
    for ip in ips:
        if is_unsafe_ip(ip):
            logger.error(f"Refusing to scan {host} -> {ip} (private/internal address)")
            return False
    return True


def make_finding(fid, title, severity, confidence, category, target, evidence, description, remediation, references=None):
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "target": target,
        "evidence": evidence,
        "description": description,
        "remediation": remediation,
        "references": references or [],
    }


def compute_risk_score(findings):
    total = 0.0
    for f in findings:
        sw = SEVERITY_WEIGHT.get(f.get("severity", "INFO"), 1)
        cw = CONFIDENCE_WEIGHT.get(f.get("confidence", "MEDIUM"), 0.7)
        total += sw * cw
    score = min(100, round(total))
    if score <= 20:
        label = "LOW"
    elif score <= 40:
        label = "MODERATE"
    elif score <= 60:
        label = "MEDIUM"
    elif score <= 80:
        label = "HIGH"
    else:
        label = "CRITICAL"
    return score, label


def fetch_html(domain, logger, session):
    logger.phase("HTML FETCH & FINGERPRINT")
    variants = [f"http://{domain}", f"https://{domain}", f"http://www.{domain}", f"https://www.{domain}"]

    for url in variants:
        try:
            logger.log(f"Trying {url}")
            r = safe_request(session, url)
            if r is None:
                continue
            logger.ok(f"HTTP {r.status_code} - {len(r.text)} bytes")

            path = f"{domain}_index.html"
            with open(path, "w", encoding="utf-8") as f:
                f.write(r.text)
            logger.ok(f"Saved: {path}")

            tech = fingerprint_tech(r)
            logger.log(f"Technology: {json.dumps(tech, indent=2)}")
            return r.text, path, tech
        except Exception as e:
            logger.error(f"Failed: {url} -> {e}")

    logger.error("HTML fetch failed.")
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
    cms_patterns = {
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "django": "Django",
        "laravel": "Laravel",
        "rails": "Ruby on Rails",
        "spring": "Spring",
        "express": "Express.js",
        "_next": "Next.js"
    }
    for pattern, name in cms_patterns.items():
        if pattern in txt:
            tech["cms"] = name
            break

    js_libs = []
    if "jquery" in txt:
        js_libs.append("jQuery")
    if "bootstrap" in txt:
        js_libs.append("Bootstrap")
    if "axios" in txt:
        js_libs.append("Axios")
    if js_libs:
        tech["js_libraries"] = js_libs

    api_patterns = re.findall(r'["\']((?:/api|/graphql|/rest|/v\d+)[^"\'\s]*)["\']', response.text, re.IGNORECASE)
    if api_patterns:
        tech["api_endpoints"] = list(set(api_patterns[:20]))

    if "authorization" in txt or "jwt" in txt or "bearer" in txt:
        tech["auth_detected"] = True

    cors_headers = {}
    for hdr in ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials"]:
        if hdr in h:
            cors_headers[hdr] = h[hdr]
    if cors_headers:
        tech["cors_headers"] = cors_headers

    waf = set()
    for hdr, val in h.items():
        combo = f"{hdr.lower()}: {val.lower()}"
        for sig, name in WAF_SIGNATURES.items():
            if sig in hdr.lower() or sig in combo:
                waf.add(name)
    server_val = h.get("Server", "").lower()
    for token, name in CDN_SERVER_TOKENS.items():
        if token in server_val:
            waf.add(name)
    if waf:
        tech["cdn_waf"] = sorted(waf)

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
        return None
    return None


def scan_ports(domain, max_port, logger, threads=150):
    logger.phase("PORT SCAN")
    open_ports = []
    ports = list(range(1, max_port + 1))

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port_single, (domain, p)): p for p in ports}
        iterator = as_completed(futures)
        if tqdm:
            iterator = tqdm(iterator, total=len(ports), desc="Scanning ports", ncols=70)

        for f in iterator:
            res = f.result()
            if res:
                port, svc = res
                logger.ok(f"OPEN {port}/{svc}")
                open_ports.append(res)

    logger.ok(f"Found {len(open_ports)} open ports")
    return sorted(open_ports)


def smb_probe(domain, logger):
    logger.phase("SMB PROBE")
    smb_ports = [139, 445]
    found = []
    for port in smb_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((domain, port)) == 0:
                    logger.ok(f"SMB port {port} OPEN")
                    found.append(port)
        except Exception as e:
            logger.debug(f"SMB port {port} error: {e}")

    if found:
        logger.warn("SMB detected")
        try:
            out = subprocess.run(["smbclient", "-L", f"//{domain}/", "-N"], capture_output=True, text=True, timeout=10)
            if out.stdout:
                logger.ok("SMB shares retrieved")
                return out.stdout
        except Exception as e:
            logger.error(f"smbclient failed: {e}")
    else:
        logger.log("SMB ports closed")
    return None


def subdomain_sync(domain, wordlist, logger, limit):
    logger.phase("SUBDOMAIN ENUM")
    found = []

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            subs = []
            for line in f:
                sub = line.strip()
                if sub and not sub.startswith("#"):
                    subs.append(sub)
    except Exception as e:
        logger.error(f"Wordlist error: {e}")
        return found

    if limit > 0:
        subs = subs[:limit]

    logger.log(f"Testing {len(subs)} subdomains...")

    for sub in (tqdm(subs, desc="Subdomains", ncols=70) if tqdm else subs):
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            logger.ok(f"FOUND {full} -> {ip}")
            found.append((full, ip))
        except (socket.gaierror, UnicodeEncodeError):
            pass

    logger.ok(f"Total subdomains: {len(found)}")
    return found


async def subdomain_async(domain, wordlist, logger, limit):
    logger.phase("SUBDOMAIN ENUM (async)")
    found = []
    resolver = aiodns.DNSResolver()

    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            subs = []
            for line in f:
                sub = line.strip()
                if sub and not sub.startswith("#"):
                    subs.append(sub)
    except Exception as e:
        logger.error(f"Wordlist error: {e}")
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
    for coro in (tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Subdomains") if tqdm else asyncio.as_completed(tasks)):
        res = await coro
        if res:
            logger.ok(f"FOUND {res[0]} -> {res[1]}")
            found.append(res)

    logger.ok(f"Total subdomains: {len(found)}")
    return found


def xss_probe(domain, logger, session, limiter):
    logger.phase("XSS PROBE")
    pages = [f"http://{domain}", f"https://{domain}", f"http://{domain}/search", f"http://{domain}/contact"]
    hits = 0
    total_tests = 0

    for page in pages:
        try:
            limiter.sleep()
            r = safe_request(session, page)
            if r is None or "<form" not in r.text.lower():
                continue

            for payload in XSS_PAYLOADS:
                try:
                    limiter.sleep()
                    total_tests += 1
                    test = f"{page}?q={payload}&search={payload}&id={payload}"
                    r2 = safe_request(session, test)
                    if r2 and payload in r2.text:
                        logger.warn(f"XSS REFLECTED: {test}")
                        hits += 1
                except Exception as e:
                    logger.debug(f"XSS test error: {e}")
        except Exception as e:
            logger.debug(f"XSS page error: {e}")

    logger.ok(f"XSS tests done. Total: {total_tests}, Reflected: {hits}")
    return hits


def sqlmap_probe(domain, logger):
    logger.phase("SQLMAP INTEGRATION")
    targets = [f"http://{domain}", f"https://{domain}"]
    vulnerable = False

    for url in targets:
        logger.log(f"SQLMap -> {url}")
        cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level", "2", "--risk", "2", "--threads", "4", "--time-sec", "5", "--output-dir", f"./sqlmap_{domain}"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if out.stdout:
                with open(f"{domain}_sqlmap.txt", "w") as f:
                    f.write(out.stdout)
                if "vulnerable" in out.stdout.lower() or "injectable" in out.stdout.lower():
                    logger.error("SQL INJECTION DETECTED!")
                    vulnerable = True
                else:
                    logger.log("No obvious SQLi found")
        except subprocess.TimeoutExpired:
            logger.warn("SQLMap timeout")
        except FileNotFoundError:
            logger.error("sqlmap not installed")
        except Exception as e:
            logger.error(f"SQLMap error: {e}")
    return vulnerable


def dir_fuzz(domain, logger, session, limiter):
    logger.phase("DIRECTORY FUZZING")
    found = []
    for path in COMMON_DIRS:
        for proto in ["http", "https"]:
            url = f"{proto}://{domain}{path}"
            try:
                limiter.sleep()
                r = safe_request(session, url, allow_redirects=False)
                if r and r.status_code in (200, 301, 302, 401, 403):
                    status = "OK" if r.status_code == 200 else "WARN"
                    logger.log(f"[{r.status_code}] {url}", status)
                    found.append((url, r.status_code, len(r.text)))
            except Exception as e:
                logger.debug(f"Dir fuzz error: {e}")
    logger.ok(f"Found {len(found)} interesting paths")
    return found


def brute_login(domain, wordlist, logger, session, limiter):
    logger.phase("LOGIN BRUTE-FORCE")
    try:
        with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()][:100]
    except Exception:
        passwords = ["123456", "password", "admin", "admin123", "root", "toor", "guest", "qwerty", "welcome", "changeme", "default", "secret", "test", "test123"]

    candidates = []
    for path in LOGIN_PATHS:
        url = f"http://{domain}{path}"
        try:
            limiter.sleep()
            baseline = safe_request(session, url)
            if baseline is None:
                continue
            base_len = len(baseline.text)
        except Exception:
            continue

        for user in COMMON_USERS:
            for pwd in passwords[:10]:
                try:
                    limiter.sleep()
                    data = {"username": user, "password": pwd, "log": user, "pwd": pwd}
                    r = safe_request(session, url, method="POST", data=data, allow_redirects=False)
                    if r is None:
                        continue

                    if is_success(r, base_len):
                        logger.warn(f"CREDENTIALS? {user}:{pwd} @ {url}")
                        candidates.append((url, user, pwd))
                except Exception as e:
                    logger.debug(f"Brute test error: {e}")

    logger.ok(f"Brute-force finished. Candidates: {len(candidates)}")
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
    logger.phase("WHOIS")
    if not whois:
        logger.warn("python-whois not installed")
        return None
    try:
        w = whois.whois(domain)
        logger.ok(f"Registrar: {w.registrar}")
        logger.ok(f"Creation: {w.creation_date}")
        logger.ok(f"Emails: {w.emails}")
        return {
            "registrar": str(w.registrar),
            "creation": str(w.creation_date),
            "emails": str(w.emails)
        }
    except Exception as e:
        logger.error(f"WHOIS failed: {e}")
        return None


def recursive_crawl(domain, logger, session, limiter, max_depth=2, max_pages=50):
    logger.phase("RECURSIVE CRAWLER")

    if not BS4_AVAILABLE:
        logger.warn("BeautifulSoup4 not installed. Skipping crawler.")
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
            r = safe_request(session, url)
            if r is None or "text/html" not in r.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            for tag in soup.find_all(["a", "form", "link", "script", "img"]):
                href = tag.get("href") or tag.get("src") or tag.get("action")
                if href:
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc in (domain, f"www.{domain}", ""):
                        if full_url not in visited:
                            queue.append((full_url, depth + 1))
                            found_urls.append(full_url)

            logger.debug(f"Crawled [{r.status_code}] {url} | Found {len(found_urls)} links")

        except Exception as e:
            logger.debug(f"Crawl error: {e}")

    unique_urls = list(set(found_urls))
    logger.ok(f"Crawl complete. Total unique URLs: {len(unique_urls)}")
    return unique_urls


def extract_js_endpoints(domain, logger, session, limiter, crawled_urls):
    logger.phase("JS ENDPOINT EXTRACTOR")

    endpoints = set()
    js_files = []
    secret_hits = 0

    for url in crawled_urls:
        if url.endswith(".js") or ".js?" in url:
            js_files.append(url)

    if not js_files:
        logger.warn("No JS files found in crawl. Trying direct fetch...")
        for proto in ["http", "https"]:
            try:
                limiter.sleep()
                r = safe_request(session, f"{proto}://{domain}")
                if r is None or not BS4_AVAILABLE:
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                for script in soup.find_all("script", src=True):
                    src = urljoin(f"{proto}://{domain}", script["src"])
                    if ".js" in src:
                        js_files.append(src)
            except Exception as e:
                logger.debug(f"JS fetch error: {e}")

    endpoint_patterns = [
        r'["\']((?:/api|/graphql|/rest|/v\d+|/auth|/admin|/user|/login|/logout|/register|/upload|/download|/search|/config)[^"\'\s]*)["\']',
        r'(?:url|endpoint|path|route|baseURL)\s*[:=]\s*["\']([^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
        r'["\']((?:ws://|wss://)[^"\']+)["\']',
    ]

    for js_url in js_files[:20]:
        try:
            limiter.sleep()
            r = safe_request(session, js_url)
            if r is None:
                continue
            js_content = r.text

            for pattern in endpoint_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2:
                        endpoints.add(match)

            secrets_found = []
            for pattern in SECRET_PATTERNS:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                secrets_found.extend(matches)

            if secrets_found:
                secret_hits += len(secrets_found)
                logger.warn(f"SECRETS in {js_url}: {len(secrets_found)} potential leaks (masked)")

            logger.debug(f"Parsed {js_url} | Endpoints: {len(endpoints)}")

        except Exception as e:
            logger.debug(f"JS parse error: {e}")

    endpoints_list = sorted(list(endpoints))
    logger.ok(f"Total unique endpoints found: {len(endpoints_list)}")
    return endpoints_list, secret_hits


def cors_check(domain, logger, session, limiter):
    logger.phase("CORS MISCONFIGURATION CHECKS")

    findings = []
    test_urls = [f"http://{domain}", f"https://{domain}"]

    for base_url in test_urls:
        for origin in CORS_TEST_ORIGINS:
            try:
                limiter.sleep()
                headers = {"Origin": origin, "User-Agent": USER_AGENT}
                r = safe_request(session, base_url, headers=headers)
                if r is None:
                    continue

                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*" and acac.lower() == "true":
                    logger.error(f"CRITICAL: Wildcard + Credentials on {base_url}")
                    findings.append({"url": base_url, "origin": origin, "severity": "CRITICAL", "issue": "Wildcard with credentials"})
                elif acao == origin:
                    if acac.lower() == "true":
                        logger.warn(f"HIGH: Reflecting origin with credentials: {origin}")
                        findings.append({"url": base_url, "origin": origin, "severity": "HIGH", "issue": "Origin reflected with credentials"})
                    else:
                        logger.warn(f"MEDIUM: Reflecting origin without credentials: {origin}")
                        findings.append({"url": base_url, "origin": origin, "severity": "MEDIUM", "issue": "Origin reflected without credentials"})
                elif acao == "*":
                    logger.warn(f"LOW: Wildcard CORS on {base_url}")
                    findings.append({"url": base_url, "origin": origin, "severity": "LOW", "issue": "Wildcard CORS"})

            except Exception as e:
                logger.debug(f"CORS test error: {e}")

    logger.ok(f"CORS checks complete. Findings: {len(findings)}")
    return findings


def jwt_analyze(domain, logger, session, limiter):
    logger.phase("JWT ANALYZER")

    if not JWT_AVAILABLE:
        logger.warn("PyJWT not installed. Skipping JWT analysis.")
        return []

    findings = []

    jwt_locations = [
        f"http://{domain}", f"https://{domain}",
        f"http://{domain}/api", f"https://{domain}/api",
        f"http://{domain}/login", f"https://{domain}/login",
    ]

    collected_tokens = []

    for url in jwt_locations:
        try:
            limiter.sleep()
            r = safe_request(session, url)
            if r is None:
                continue

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

        except Exception as e:
            logger.debug(f"JWT fetch error: {e}")

    unique_tokens = list(set(collected_tokens))

    for token in unique_tokens[:10]:
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            logger.ok(f"JWT Found: alg={header.get('alg', 'unknown')}")
            logger.log(f"  Payload keys: {list(payload.keys())}")

            token_findings = {
                "token_preview": mask_secret(token),
                "algorithm": header.get("alg"),
                "payload_keys": list(payload.keys()),
                "issues": []
            }

            if header.get("alg") == "none":
                logger.error("CRITICAL: JWT uses 'none' algorithm!")
                token_findings["issues"].append("none_algorithm")

            if header.get("alg") in ["HS256", "HS384", "HS512"]:
                for secret in JWT_COMMON_SECRETS:
                    try:
                        jwt.decode(token, secret, algorithms=[header.get("alg")])
                        logger.error("CRITICAL: JWT cracked with a common weak secret")
                        token_findings["issues"].append("weak_secret")
                        break
                    except:
                        pass

            sensitive_keys = ["password", "secret", "admin", "role", "privilege", "email", "username", "id"]
            for key in payload:
                if any(sk in key.lower() for sk in sensitive_keys):
                    logger.warn(f"JWT contains sensitive key: {key}")
                    token_findings["issues"].append(f"sensitive_data:{key}")

            findings.append(token_findings)

        except Exception as e:
            logger.debug(f"JWT parse error: {e}")

    logger.ok(f"JWT analysis complete. Tokens analyzed: {len(findings)}")
    return findings


def take_screenshots(domain, logger, crawled_urls):
    logger.phase("SCREENSHOT SYSTEM")

    if not PLAYWRIGHT_AVAILABLE:
        logger.warn("Playwright not installed. Skipping screenshots.")
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
            context = browser.new_context(user_agent=USER_AGENT, viewport={"width": 1920, "height": 1080})

            for url in urls_to_shoot:
                try:
                    page = context.new_page()
                    page.goto(url, timeout=15000, wait_until="networkidle")

                    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url.replace("https://", "").replace("http://", ""))[:50]
                    filename = f"{screenshot_dir}/{safe_name}.png"

                    page.screenshot(path=filename, full_page=True)
                    screenshots.append({"url": url, "file": filename})
                    logger.ok(f"Screenshot: {url} -> {filename}")

                    page.close()
                except Exception as e:
                    logger.warn(f"Screenshot failed for {url}: {e}")

            browser.close()

    except Exception as e:
        logger.error(f"Playwright error: {e}")

    logger.ok(f"Screenshots taken: {len(screenshots)}")
    return screenshots


class WebSecurityScanner:
    def __init__(self, domain, logger, session=None, limiter=None, active=False,
                 max_requests=300, max_response_bytes=2_000_000, verify_tls=True):
        self.domain = domain
        self.logger = logger
        self.session = session or requests.Session()
        self.session.headers.update(HEADERS)
        self.limiter = limiter or RateLimiter(0.3)
        self.active = active
        self.max_requests = max_requests
        self.max_response_bytes = max_response_bytes
        self.verify_tls = verify_tls
        self.request_count = 0
        self.findings = []
        self.base_https = f"https://{domain}"
        self.base_http = f"http://{domain}"
        self._resp_cache = {}

    def request_budget_left(self):
        return self.request_count < self.max_requests

    def get(self, url, **kwargs):
        if not self.request_budget_left():
            self.logger.warn(f"Request budget exhausted, skipping {url}")
            return None
        parsed = urlparse(url)
        if parsed.hostname and not ssrf_guard(parsed.hostname, self.logger):
            return None
        self.limiter.sleep()
        self.request_count += 1
        kwargs.setdefault("timeout", TIMEOUT)
        kwargs.setdefault("verify", self.verify_tls)
        r = safe_request(self.session, url, method=kwargs.pop("method", "GET"), **kwargs)
        if r is not None and len(r.content) > self.max_response_bytes:
            self.logger.debug(f"Response truncated for {url}")
        return r

    def add(self, fid, title, severity, confidence, category, target, evidence, description, remediation, references=None):
        f = make_finding(fid, title, severity, confidence, category, target, evidence, description, remediation, references)
        self.findings.append(f)
        level = "ERROR" if severity == "CRITICAL" else "WARN" if severity in ("HIGH", "MEDIUM") else "INFO"
        self.logger.log(f"[{severity}] {title} @ {target}", level)
        return f

    def primary_response(self):
        for url in (self.base_https, self.base_http):
            if url in self._resp_cache:
                if self._resp_cache[url] is not None:
                    return url, self._resp_cache[url]
                continue
            r = self.get(url)
            self._resp_cache[url] = r
            if r is not None:
                return url, r
        return None, None

    def check_headers(self, url, response):
        h = response.headers
        is_https = url.startswith("https")

        checks = [
            ("Content-Security-Policy", "WEB-HEADER-001", "Missing Content-Security-Policy", "MEDIUM",
             "CSP restricts which sources scripts, styles and other resources can load from, mitigating XSS and data injection.",
             "Add a Content-Security-Policy header scoped to the origins the application actually needs."),
            ("X-Content-Type-Options", "WEB-HEADER-002", "Missing X-Content-Type-Options", "LOW",
             "Without this header browsers may MIME-sniff responses, which can enable content-type confusion attacks.",
             "Set 'X-Content-Type-Options: nosniff' on all responses."),
            ("Referrer-Policy", "WEB-HEADER-003", "Missing Referrer-Policy", "LOW",
             "Without an explicit policy, browsers may leak full URLs (including sensitive query params) to third parties via the Referer header.",
             "Set a Referrer-Policy such as 'strict-origin-when-cross-origin' or stricter."),
            ("Permissions-Policy", "WEB-HEADER-004", "Missing Permissions-Policy", "LOW",
             "Without this header, powerful browser features (camera, geolocation, etc.) are not explicitly restricted.",
             "Add a Permissions-Policy that disables features the site does not use."),
            ("Cross-Origin-Opener-Policy", "WEB-HEADER-005", "Missing Cross-Origin-Opener-Policy", "LOW",
             "COOP isolates the browsing context from cross-origin windows, mitigating some cross-window attacks (e.g. Spectre-style leaks).",
             "Set 'Cross-Origin-Opener-Policy: same-origin' where compatible with the application."),
            ("Cross-Origin-Resource-Policy", "WEB-HEADER-006", "Missing Cross-Origin-Resource-Policy", "INFO",
             "CORP controls whether other origins can embed this resource, reducing exposure to cross-origin leaks.",
             "Set 'Cross-Origin-Resource-Policy: same-origin' or 'same-site' as appropriate."),
        ]
        for hdr, fid, title, sev, desc, rem in checks:
            if hdr not in h:
                self.add(fid, title, sev, "HIGH", "Headers", url, "Header not present in response", desc, rem)

        if is_https and "Strict-Transport-Security" not in h:
            self.add("WEB-HEADER-007", "Missing Strict-Transport-Security (HSTS)", "MEDIUM", "HIGH", "Headers", url,
                      "Header not present on HTTPS response",
                      "Without HSTS, browsers may be tricked into connecting over plain HTTP, enabling downgrade/MITM attacks.",
                      "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' once HTTPS is stable site-wide.")

    def check_clickjacking(self, url, response):
        h = response.headers
        xfo = h.get("X-Frame-Options", "")
        csp = h.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        if not xfo and not has_frame_ancestors:
            self.add("WEB-CLICKJACK-001", "Missing Clickjacking Protection", "MEDIUM", "HIGH", "Clickjacking", url,
                      "No X-Frame-Options and no CSP frame-ancestors directive",
                      "The page can be embedded in a hidden iframe on an attacker site, enabling UI-redress (clickjacking) attacks.",
                      "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', and/or a CSP 'frame-ancestors' directive.")

    def check_csp_quality(self, url, response):
        csp = response.headers.get("Content-Security-Policy")
        if not csp:
            return
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            directives[tokens[0].lower()] = tokens[1:]

        for directive in ("script-src", "default-src"):
            values = directives.get(directive)
            if values is None:
                continue
            if "'unsafe-inline'" in values or "'unsafe-eval'" in values:
                self.add("WEB-CSP-001", f"Weak CSP: {directive} allows unsafe-inline/unsafe-eval", "MEDIUM", "HIGH",
                          "CSP", url, f"{directive}: {' '.join(values)}",
                          "Allowing inline scripts or eval largely defeats CSP's protection against XSS.",
                          f"Remove 'unsafe-inline'/'unsafe-eval' from {directive}; use nonces or hashes instead.")
            if "*" in values:
                self.add("WEB-CSP-002", f"Weak CSP: {directive} uses wildcard source", "MEDIUM", "HIGH",
                          "CSP", url, f"{directive}: {' '.join(values)}",
                          "A wildcard source allows loading resources from any origin, weakening CSP's restriction.",
                          f"Scope {directive} to the specific origins the application needs.")
        if "object-src" not in directives:
            self.add("WEB-CSP-003", "CSP missing object-src restriction", "LOW", "MEDIUM", "CSP", url,
                      "No object-src directive present",
                      "Without object-src, plugin-based content (Flash/Java applets) is not explicitly restricted.",
                      "Add \"object-src 'none'\" unless the application legitimately needs plugins.")

    def check_cookies(self, url, response):
        try:
            raw_cookies = response.raw.headers.getlist("Set-Cookie")
        except Exception:
            single = response.headers.get("Set-Cookie")
            raw_cookies = [single] if single else []

        for raw in raw_cookies:
            if not raw:
                continue
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
            attrs = {p.split("=")[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}

            looks_sensitive = any(k in name.lower() for k in ["session", "auth", "token", "sid", "jwt"])

            if "secure" not in attrs and url.startswith("https"):
                self.add("WEB-COOKIE-001", f"Cookie missing Secure flag: {name}", "MEDIUM" if looks_sensitive else "LOW",
                          "HIGH", "Cookies", url, f"Set-Cookie: {name}=********",
                          "Without Secure, this cookie can be transmitted over plain HTTP and intercepted in transit.",
                          "Add the 'Secure' attribute to all cookies served over HTTPS.")
            if "httponly" not in attrs:
                self.add("WEB-COOKIE-002", f"Cookie missing HttpOnly flag: {name}", "MEDIUM" if looks_sensitive else "LOW",
                          "HIGH", "Cookies", url, f"Set-Cookie: {name}=********",
                          "Without HttpOnly, client-side scripts can read this cookie, increasing impact of any XSS.",
                          "Add the 'HttpOnly' attribute to session/auth cookies.")
            samesite = attrs.get("samesite")
            if not samesite:
                self.add("WEB-COOKIE-003", f"Cookie missing SameSite attribute: {name}", "LOW", "MEDIUM", "Cookies",
                          url, f"Set-Cookie: {name}=********",
                          "Without SameSite, the cookie may be sent on cross-site requests, weakening CSRF defenses.",
                          "Set 'SameSite=Lax' or 'Strict' depending on the application's cross-site needs.")
            elif str(samesite).lower() == "none" and "secure" not in attrs:
                self.add("WEB-COOKIE-004", f"Cookie SameSite=None without Secure: {name}", "MEDIUM", "HIGH",
                          "Cookies", url, f"Set-Cookie: {name}=********",
                          "SameSite=None cookies must be Secure or browsers will reject/strip them, and without Secure the cookie is also exposed on plain HTTP.",
                          "Pair 'SameSite=None' with the 'Secure' attribute.")

    def check_tls(self):
        if not self.request_budget_left():
            return
        host = self.domain
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
        except ssl.SSLCertVerificationError as e:
            self.add("WEB-TLS-001", "TLS certificate validation failed", "HIGH", "HIGH", "TLS", f"https://{host}",
                      str(e), "The presented certificate could not be validated against trusted CAs, which breaks the HTTPS trust guarantee.",
                      "Install a valid certificate from a trusted CA covering this hostname.")
            return
        except Exception as e:
            self.logger.debug(f"TLS connect error: {e}")
            return

        self.request_count += 1

        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            self.add("WEB-TLS-002", f"Weak TLS protocol negotiated: {tls_version}", "HIGH", "HIGH", "TLS",
                      f"https://{host}", f"Negotiated protocol: {tls_version}",
                      "Old TLS/SSL versions have known cryptographic weaknesses.",
                      "Disable TLS 1.0/1.1 and SSLv3 on the server; require TLS 1.2 or newer.")

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
                if days_left < 0:
                    self.add("WEB-TLS-003", "TLS certificate expired", "CRITICAL", "HIGH", "TLS", f"https://{host}",
                              f"notAfter={not_after}", "The certificate has expired; browsers will show hard warnings or block access.",
                              "Renew the TLS certificate immediately.")
                elif days_left < 14:
                    self.add("WEB-TLS-004", f"TLS certificate expiring soon ({days_left}d)", "MEDIUM", "HIGH",
                              "TLS", f"https://{host}", f"notAfter={not_after}",
                              "The certificate will expire soon; an outage or trust warning is imminent if not renewed.",
                              "Renew the TLS certificate well before expiry and automate renewal if possible.")
            except Exception:
                pass

        san_hosts = []
        for entry_type, entry_val in cert.get("subjectAltName", []):
            if entry_type == "DNS":
                san_hosts.append(entry_val)
        hostname_ok = False
        for san in san_hosts:
            pattern = "^" + re.escape(san).replace(r"\*", "[^.]+") + "$"
            if re.match(pattern, host):
                hostname_ok = True
                break
        if san_hosts and not hostname_ok:
            self.add("WEB-TLS-005", "Certificate hostname mismatch", "HIGH", "MEDIUM", "TLS", f"https://{host}",
                      f"SAN entries: {san_hosts}", "The certificate's Subject Alternative Names do not appear to cover the requested hostname.",
                      "Issue a certificate that explicitly covers this hostname.")

    def check_http_methods(self, url):
        if not self.request_budget_left():
            return
        r = self.get(url, method="OPTIONS")
        if r is None:
            return
        allow = r.headers.get("Allow", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT")]
        if dangerous:
            self.add("WEB-METHOD-001", f"Potentially dangerous HTTP methods enabled: {', '.join(dangerous)}",
                      "MEDIUM", "MEDIUM", "HTTP Methods", url, f"Allow: {allow}",
                      "Methods like PUT/DELETE/TRACE, if not properly access-controlled, can allow file writes, deletions, or Cross-Site Tracing.",
                      "Disable unused HTTP methods at the web server or framework routing layer.")

    def check_redirects(self, base_url):
        if not self.request_budget_left():
            return
        current = base_url
        chain = [current]
        for _ in range(10):
            r = self.get(current, allow_redirects=False)
            if r is None or r.status_code not in (301, 302, 303, 307, 308):
                break
            loc = r.headers.get("Location")
            if not loc:
                break
            nxt = urljoin(current, loc)
            chain.append(nxt)
            if nxt.startswith("http://") and current.startswith("https://"):
                self.add("WEB-REDIRECT-001", "HTTPS to HTTP downgrade redirect", "HIGH", "HIGH", "Redirects",
                          base_url, f"{current} -> {nxt}",
                          "An HTTPS page redirecting to plain HTTP exposes users to interception and defeats the purpose of TLS.",
                          "Never redirect an HTTPS URL to an HTTP destination.")
            current = nxt

        if len(chain) > 5:
            self.add("WEB-REDIRECT-002", f"Excessive redirect chain ({len(chain)} hops)", "LOW", "MEDIUM",
                      "Redirects", base_url, " -> ".join(chain), "Long redirect chains slow page loads and can indicate misconfiguration.",
                      "Reduce the number of chained redirects to at most one or two hops.")

        if base_url.startswith("http://"):
            https_ok = any(u.startswith("https://") for u in chain)
            if not https_ok:
                self.add("WEB-REDIRECT-003", "No HTTP to HTTPS redirect", "MEDIUM", "HIGH", "Redirects", base_url,
                          f"Chain stayed on HTTP: {chain}",
                          "Visitors using plain HTTP are never upgraded to an encrypted connection.",
                          "Redirect all HTTP requests to the HTTPS equivalent.")

    def check_info_disclosure(self, url, response):
        h = response.headers
        if "Server" in h and re.search(r"\d+\.\d+", h["Server"]):
            self.add("WEB-INFO-001", "Server header discloses version information", "LOW", "HIGH",
                      "Information Disclosure", url, f"Server: {h['Server']}",
                      "Version strings in the Server header help attackers match known vulnerabilities to the exact software version.",
                      "Suppress or generalize the Server header at the web server / proxy layer.")
        if "X-Powered-By" in h:
            self.add("WEB-INFO-002", "X-Powered-By header discloses backend technology", "LOW", "HIGH",
                      "Information Disclosure", url, f"X-Powered-By: {h['X-Powered-By']}",
                      "This header reveals backend framework/language details useful for targeted attacks.",
                      "Disable the X-Powered-By header in the application/framework configuration.")

        body = response.text
        for pattern in ERROR_SIGNATURES:
            if re.search(pattern, body):
                self.add("WEB-INFO-003", "Application error/debug information exposed", "MEDIUM", "MEDIUM",
                          "Information Disclosure", url, f"Pattern matched: {pattern}",
                          "Stack traces or verbose error pages can leak file paths, library versions and internal logic.",
                          "Disable debug/verbose error output in production and use generic error pages.")
                break

    def check_cache_security(self, url, response):
        h = response.headers
        sensitive = any(k in url.lower() for k in ["login", "admin", "account", "dashboard", "profile", "checkout"])
        cache_control = h.get("Cache-Control", "")
        if sensitive and "no-store" not in cache_control.lower():
            self.add("WEB-CACHE-001", "Sensitive page missing no-store cache directive", "LOW", "MEDIUM",
                      "Cache", url, f"Cache-Control: {cache_control or '(none)'}",
                      "Sensitive pages without 'no-store' may be cached by browsers or intermediate proxies.",
                      "Set 'Cache-Control: no-store' on authentication and account-sensitive pages.")

    def check_mixed_content(self, url, response):
        if not url.startswith("https"):
            return
        body = response.text
        refs = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', body, re.IGNORECASE)
        if refs:
            self.add("WEB-MIXED-001", f"Mixed content: {len(refs)} HTTP resource reference(s) on HTTPS page",
                      "MEDIUM", "MEDIUM", "Mixed Content", url, refs[0],
                      "Loading subresources over plain HTTP on an HTTPS page can be intercepted or modified in transit.",
                      "Update all resource references to HTTPS or protocol-relative URLs.")

    def check_forms(self, url, response):
        if not BS4_AVAILABLE:
            return
        soup = BeautifulSoup(response.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            full_action = urljoin(url, action) if action else url
            has_password = bool(form.find("input", {"type": "password"}))

            if has_password and full_action.startswith("http://"):
                self.add("WEB-FORM-001", "Password form submits over plain HTTP", "HIGH", "HIGH", "Forms",
                          url, f"action={full_action}",
                          "Credentials submitted over HTTP can be intercepted in transit.",
                          "Serve the form and its action endpoint exclusively over HTTPS.")

            if has_password:
                pw_input = form.find("input", {"type": "password"})
                autocomplete = (pw_input.get("autocomplete") or "").lower()
                if autocomplete not in ("off", "new-password"):
                    self.add("WEB-FORM-002", "Password field without restrictive autocomplete", "LOW", "LOW",
                              "Forms", url, f"autocomplete={autocomplete or '(default)'}",
                              "Browsers may store and auto-fill the password field on shared devices.",
                              "Consider autocomplete='new-password' for registration/change-password forms.")

            action_host = urlparse(full_action).hostname
            if action_host and action_host != self.domain and action_host != f"www.{self.domain}":
                self.add("WEB-FORM-003", "Form submits to an external domain", "MEDIUM", "MEDIUM", "Forms",
                          url, f"action={full_action}",
                          "Forms posting to a third-party domain can indicate injected content or unintended data exfiltration.",
                          "Verify this is intentional; otherwise point the form action back to the application's own domain.")

    def check_common_exposures(self):
        findings_added = 0
        for path, label in [("/robots.txt", "robots.txt"), ("/sitemap.xml", "sitemap.xml"),
                             ("/.well-known/security.txt", "security.txt"), ("/security.txt", "security.txt")]:
            for proto in ("https", "http"):
                url = f"{proto}://{self.domain}{path}"
                r = self.get(url)
                if r is not None and r.status_code == 200:
                    if label == "robots.txt":
                        disallows = re.findall(r"Disallow:\s*(\S+)", r.text, re.IGNORECASE)
                        interesting = [d for d in disallows if any(k in d.lower() for k in ["admin", "config", "backup", "private", "internal"])]
                        if interesting:
                            self.add("WEB-EXPOSE-001", "robots.txt reveals sensitive-looking paths", "LOW", "MEDIUM",
                                      "Exposure", url, f"{len(interesting)} sensitive-looking Disallow entries",
                                      "robots.txt is public and listing sensitive paths just points attackers at them.",
                                      "Avoid listing sensitive paths in robots.txt; rely on proper authentication instead.")
                    if label == "security.txt":
                        findings_added += 1
                    break

    def check_directory_exposure(self):
        sensitive_files = {"/.env": "Environment file", "/.git/config": "Git config", "/.git/HEAD": "Git repository",
                            "/backup.zip": "Backup archive", "/dump.sql": "Database dump", "/database.sql": "Database dump"}
        for path, label in sensitive_files.items():
            for proto in ("https", "http"):
                if not self.request_budget_left():
                    return
                url = f"{proto}://{self.domain}{path}"
                r = self.get(url)
                if r is not None and r.status_code == 200 and len(r.content) > 0:
                    self.add("WEB-DIREXP-001", f"Sensitive file exposed: {label}", "HIGH", "MEDIUM", "Directory Exposure",
                              url, "FOUND (content not retrieved)",
                              f"{label} appears to be publicly accessible, which can leak credentials or source data.",
                              "Remove or block public access to this file; rotate any credentials it may contain.")
                    break

    def check_api_discovery(self, crawled_urls, js_endpoints):
        api_like = set()
        for u in list(crawled_urls) + list(js_endpoints):
            if re.search(r"(/api/|/graphql|/rest/|/v\d+/)", u):
                api_like.add(u)
        if api_like:
            self.add("WEB-API-001", f"{len(api_like)} API-like endpoint(s) discovered", "INFO", "HIGH",
                      "API Discovery", f"https://{self.domain}", list(api_like)[:10],
                      "These endpoints may expose additional attack surface beyond the main web UI.",
                      "Ensure all discovered API endpoints enforce authentication/authorization and input validation.")

    def check_swagger(self):
        paths = ["/swagger", "/swagger-ui", "/swagger.json", "/openapi.json", "/openapi.yaml", "/api-docs", "/v2/api-docs", "/v3/api-docs"]
        for path in paths:
            for proto in ("https", "http"):
                if not self.request_budget_left():
                    return
                url = f"{proto}://{self.domain}{path}"
                r = self.get(url)
                if r is None or r.status_code != 200:
                    continue
                title = None
                version = None
                endpoint_count = None
                try:
                    data = r.json()
                    info = data.get("info", {})
                    title = info.get("title")
                    version = info.get("version")
                    endpoint_count = len(data.get("paths", {}))
                except Exception:
                    pass
                self.add("WEB-SWAGGER-001", "API documentation publicly exposed", "MEDIUM", "HIGH",
                          "API Documentation", url,
                          f"title={title}, version={version}, endpoints={endpoint_count}",
                          "Publicly reachable API docs reveal the full surface of internal endpoints and parameters to anyone.",
                          "Restrict access to API documentation to authenticated/internal users, or remove it from production.")
                return

    def check_graphql(self):
        for path in ("/graphql", "/api/graphql", "/v1/graphql"):
            for proto in ("https", "http"):
                if not self.request_budget_left():
                    return
                url = f"{proto}://{self.domain}{path}"
                r = self.get(url)
                if r is None:
                    continue
                if r.status_code in (400, 405) or "graphql" in r.text.lower() or "query" in r.text.lower():
                    self.add("WEB-GRAPHQL-001", "GraphQL endpoint detected", "INFO", "MEDIUM", "GraphQL", url,
                              f"HTTP {r.status_code}",
                              "A GraphQL endpoint was found; if introspection is enabled it can expose the entire schema.",
                              "Disable introspection in production and enforce query depth/complexity limits.")
                    return

    def run(self, mode="all", crawled_urls=None, js_endpoints=None):
        crawled_urls = crawled_urls or []
        js_endpoints = js_endpoints or []

        run_headers = mode in ("all", "web", "headers")
        run_tls = mode in ("all", "web", "tls")
        run_cookies = mode in ("all", "web", "cookies")
        run_cors = mode in ("all", "web", "cors")
        run_api = mode in ("all", "web", "api")
        run_crawler_dependent = mode in ("all", "web", "crawler", "api")

        url, response = self.primary_response()
        if response is not None:
            if run_headers:
                self.check_headers(url, response)
                self.check_clickjacking(url, response)
                self.check_csp_quality(url, response)
                self.check_info_disclosure(url, response)
                self.check_cache_security(url, response)
                self.check_mixed_content(url, response)
            if run_cookies:
                self.check_cookies(url, response)
            if run_headers or mode in ("all", "web"):
                self.check_forms(url, response)

        if run_tls:
            self.check_tls()
            self.check_http_methods(url or self.base_https)
            self.check_redirects(self.base_http)

        if run_cors:
            cors_findings = cors_check(self.domain, self.logger, self.session, self.limiter)
            for cf in cors_findings:
                self.add("WEB-CORS-001", cf["issue"], cf["severity"],
                          "HIGH" if cf["severity"] in ("CRITICAL", "HIGH") else "MEDIUM",
                          "CORS", cf["url"], f"Origin tested: {cf['origin']}",
                          "Misconfigured CORS can allow malicious sites to read authenticated responses on behalf of a victim.",
                          "Restrict Access-Control-Allow-Origin to a known allow-list and avoid combining wildcard with credentials.")

        if mode in ("all", "web"):
            self.check_common_exposures()
            self.check_directory_exposure()

        if run_api or run_crawler_dependent:
            self.check_api_discovery(crawled_urls, js_endpoints)
            self.check_swagger()
            self.check_graphql()

        score, label = compute_risk_score(self.findings)
        return {"findings": self.findings, "risk_score": score, "risk_label": label, "requests_used": self.request_count}


def group_findings_by_severity(findings):
    grouped = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        grouped.setdefault(f.get("severity", "INFO"), []).append(f)
    return grouped


def generate_html_report(data, domain, timestamp, logger=None):
    if logger:
        logger.phase("HTML REPORT GENERATION")

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

    web_findings = data.get("web_findings", [])
    grouped = group_findings_by_severity(web_findings)
    risk_score = data.get("web_risk_score", 0)
    risk_label = data.get("web_risk_label", "LOW")

    def render_finding_group(items):
        out = ""
        for f in items:
            color = severity_colors.get(f.get("severity", "INFO"), "#6c757d")
            out += f"""
            <div class="finding" style="border-left-color: {color}">
                <span class="badge" style="background: {color}">{f.get('severity')}</span>
                <span class="badge" style="background: #555">confidence: {f.get('confidence')}</span>
                <strong>{f.get('title')}</strong><br>
                <em>{f.get('category')}</em> — {f.get('target')}<br>
                <strong>Evidence:</strong> {f.get('evidence')}<br>
                <strong>Description:</strong> {f.get('description')}<br>
                <strong>Remediation:</strong> {f.get('remediation')}
            </div>
            """
        return out if out else "<p>None found.</p>"

    web_findings_html = ""
    for sev in SEVERITY_ORDER:
        items = grouped.get(sev, [])
        web_findings_html += f"<h3>{sev} ({len(items)})</h3>{render_finding_group(items)}"

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
        .section h3 {{ color: #555; margin: 15px 0 10px 0; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #667eea; border-radius: 4px; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; color: white; font-size: 0.75em; font-weight: bold; margin-right: 10px; }}
        .screenshot {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 4px; }}
        .screenshot h4 {{ margin-bottom: 10px; color: #555; }}
        .risk-banner {{ text-align: center; padding: 20px; border-radius: 8px; margin-bottom: 20px; font-size: 1.4em; font-weight: bold; color: white; }}
        ul {{ list-style: none; padding-left: 0; }}
        ul li {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
        ul li:before {{ content: ">"; color: #667eea; margin-right: 10px; }}
        footer {{ text-align: center; padding: 20px; color: #666; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>LATENT</h1>
            <p>Professional Web &amp; Network Security Assessment Toolkit</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Target: <strong>{domain}</strong> | Generated: {timestamp}</p>
        </header>

        <div class="risk-banner" style="background: {severity_colors.get(risk_label if risk_label in severity_colors else 'MEDIUM', '#667eea')}">
            Risk Score: {risk_score}/100 — {risk_label}
        </div>

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
                <h3>{len(web_findings)}</h3>
                <p>Web Findings</p>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>{len(grouped.get('CRITICAL', []))} critical, {len(grouped.get('HIGH', []))} high, {len(grouped.get('MEDIUM', []))} medium,
            {len(grouped.get('LOW', []))} low and {len(grouped.get('INFO', []))} informational web security findings were identified for {domain}.</p>
        </div>

        <div class="section">
            <h2>Web Security Findings</h2>
            {web_findings_html}
        </div>

        <div class="section">
            <h2>Technology Fingerprinting</h2>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{json.dumps(data.get('technology', {}), indent=2)}</pre>
        </div>

        <div class="section">
            <h2>Crawled URLs ({len(data.get('crawled_urls', []))})</h2>
            <ul>{crawl_html if crawl_html else "<li>No URLs crawled</li>"}</ul>
        </div>

        <div class="section">
            <h2>JavaScript Endpoints ({len(data.get('js_endpoints', []))})</h2>
            <ul>{js_html if js_html else "<li>No endpoints found</li>"}</ul>
        </div>

        <div class="section">
            <h2>Legacy CORS Findings ({len(data.get('cors_findings', []))})</h2>
            {cors_html if cors_html else "<p>No CORS issues detected.</p>"}
        </div>

        <div class="section">
            <h2>JWT Analysis ({len(data.get('jwt_findings', []))})</h2>
            {jwt_html if jwt_html else "<p>No JWT tokens found or analyzed.</p>"}
        </div>

        <div class="section">
            <h2>Screenshots ({len(data.get('screenshots', []))})</h2>
            {screenshots_html if screenshots_html else "<p>No screenshots taken.</p>"}
        </div>

        <div class="section">
            <h2>Open Ports</h2>
            <ul>
                {''.join([f"<li>Port {p[0]}/{p[1]}</li>" for p in data.get('open_ports', [])])}
            </ul>
        </div>

        <div class="section">
            <h2>Interesting Directories ({len(data.get('directories', []))})</h2>
            <ul>
                {''.join([f"<li>[{d[1]}] {d[0]} ({d[2]} bytes)</li>" for d in data.get('directories', [])])}
            </ul>
        </div>

        <div class="section">
            <h2>WHOIS Information</h2>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{json.dumps(data.get('whois', {}), indent=2) if data.get('whois') else "No WHOIS data available."}</pre>
        </div>

        <div class="section">
            <h2>Brute Force Candidates ({len(data.get('brute_candidates', []))})</h2>
            <ul>
                {''.join([f"<li>{c[1]}:{c[2]} @ {c[0]}</li>" for c in data.get('brute_candidates', [])]) if data.get('brute_candidates') else "<li>No candidates found</li>"}
            </ul>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <p>Address CRITICAL and HIGH findings first, then MEDIUM. Re-run the scan after remediation to confirm fixes.</p>
        </div>

        <footer>
            <p>Generated by LATENT v{VERSION}</p>
            <p style="font-size: 0.8em; margin-top: 5px;">For authorized testing only. Unauthorized use is illegal.</p>
        </footer>
    </div>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    if logger:
        logger.ok(f"HTML report generated: {html_path}")

    return html_path


def build_report(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description="LATENT - Professional Web & Network Security Assessment Toolkit",
                                      epilog="Example: latent -t example.com --all")
    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    parser.add_argument("-w", "--wordlist", default="subdomains.txt", help="Subdomain/wordlist path")
    parser.add_argument("-p", "--ports", type=int, default=1000, help="Max port to scan (default: 1000)")
    parser.add_argument("--threads", type=int, default=150, help="Port scan thread count (default: 150)")
    parser.add_argument("--sub-limit", type=int, default=50, help="Subdomain limit (0=all) (default: 50)")
    parser.add_argument("--rate", type=float, default=0.3, help="Inter-request delay in seconds (default: 0.3)")
    parser.add_argument("--brute", action="store_true", help="Enable login brute-force")
    parser.add_argument("--sqlmap", action="store_true", help="Enable SQLMap integration")
    parser.add_argument("--json", action="store_true", help="Emit JSON report alongside TXT")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--screenshot", action="store_true", help="Take screenshots with Playwright")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("--crawl-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    parser.add_argument("--web", action="store_true", help="Run the full web security engine")
    parser.add_argument("--headers", action="store_true", help="Run only header/CSP/clickjacking checks")
    parser.add_argument("--tls", action="store_true", help="Run only TLS checks")
    parser.add_argument("--cookies", action="store_true", help="Run only cookie checks")
    parser.add_argument("--cors", action="store_true", help="Run only CORS checks")
    parser.add_argument("--api", action="store_true", help="Run only API/Swagger/GraphQL discovery")
    parser.add_argument("--crawler", action="store_true", help="Run crawler-dependent web checks")
    parser.add_argument("--all", action="store_true", help="Run every phase (network + web)")
    parser.add_argument("--active", action="store_true", help="Allow more intrusive checks (still non-destructive)")
    parser.add_argument("--max-requests", type=int, default=300, help="Max requests the web scanner may issue (default: 300)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    domain = resolve_domain(args.target)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_txt = f"latent_report_{domain}_{ts}.txt"
    report_json = f"latent_report_{domain}_{ts}.json"

    print(f"{'='*70}")
    print(f"                     LATENT | PROBE v{VERSION}")
    print(f"                         discord : @saintlatent")
    print(f"{'='*70}")

    web_modes = {"web": args.web, "headers": args.headers, "tls": args.tls, "cookies": args.cookies,
                 "cors": args.cors, "api": args.api, "crawler": args.crawler}
    any_web_mode = any(web_modes.values()) or args.all
    focused_mode = next((name for name, flag in web_modes.items() if flag), None)

    with open(report_txt, "w", encoding="utf-8") as rf:
        logger = Logger(rf, verbose=args.verbose)
        session = requests.Session()
        session.headers.update(HEADERS)
        limiter = RateLimiter(args.rate)

        logger.log(f"Target: {domain}")
        logger.log(f"Wordlist: {args.wordlist}")
        logger.log(f"MaxPort: {args.ports} | Threads: {args.threads} | Rate: {args.rate}s")

        if not ssrf_guard(domain, logger):
            logger.error("Target resolves to a private/internal address. Aborting for safety.")
            print("\n[!] Refusing to scan a private/internal target.")
            return

        html, html_path, tech = None, None, {}
        open_ports, smb_data, found_subs = [], None, []
        xss_hits, dirs, whois_data = 0, [], None
        sqlmap_result, brute_results = False, []
        crawled_urls, js_endpoints, secret_hits = [], [], 0
        cors_findings, jwt_findings, screenshots = [], [], []
        web_result = {"findings": [], "risk_score": 0, "risk_label": "LOW", "requests_used": 0}

        run_network_phase = args.all or not any_web_mode

        if run_network_phase:
            try:
                html, html_path, tech = fetch_html(domain, logger, session)
            except Exception as e:
                logger.error(f"HTML fetch failed: {e}")

            try:
                open_ports = scan_ports(domain, args.ports, logger, args.threads)
            except Exception as e:
                logger.error(f"Port scan failed: {e}")

            try:
                smb_data = smb_probe(domain, logger)
            except Exception as e:
                logger.error(f"SMB probe failed: {e}")

            try:
                if aiodns:
                    found_subs = asyncio.run(subdomain_async(domain, args.wordlist, logger, args.sub_limit))
                else:
                    found_subs = subdomain_sync(domain, args.wordlist, logger, args.sub_limit)
            except Exception as e:
                logger.error(f"Subdomain enum failed: {e}")

            if args.active:
                try:
                    xss_hits = xss_probe(domain, logger, session, limiter)
                except Exception as e:
                    logger.error(f"XSS probe failed: {e}")

            try:
                dirs = dir_fuzz(domain, logger, session, limiter)
            except Exception as e:
                logger.error(f"Dir fuzz failed: {e}")

            try:
                whois_data = whois_lookup(domain, logger)
            except Exception as e:
                logger.error(f"WHOIS lookup failed: {e}")

            if args.sqlmap and args.active:
                try:
                    sqlmap_result = sqlmap_probe(domain, logger)
                except Exception as e:
                    logger.error(f"SQLMap failed: {e}")

            if args.brute and args.active:
                try:
                    brute_results = brute_login(domain, args.wordlist, logger, session, limiter)
                except Exception as e:
                    logger.error(f"Brute force failed: {e}")
        else:
            try:
                html, html_path, tech = fetch_html(domain, logger, session)
            except Exception as e:
                logger.error(f"HTML fetch failed: {e}")

        need_crawl = args.all or focused_mode in ("crawler", "api", "web", None) or args.web
        if need_crawl:
            try:
                crawled_urls = recursive_crawl(domain, logger, session, limiter, args.crawl_depth, args.crawl_pages)
            except Exception as e:
                logger.error(f"Crawler failed: {e}")

            try:
                js_endpoints, secret_hits = extract_js_endpoints(domain, logger, session, limiter, crawled_urls)
            except Exception as e:
                logger.error(f"JS endpoint extraction failed: {e}")

        if run_network_phase:
            try:
                cors_findings = cors_check(domain, logger, session, limiter)
            except Exception as e:
                logger.error(f"CORS check failed: {e}")

            try:
                jwt_findings = jwt_analyze(domain, logger, session, limiter)
            except Exception as e:
                logger.error(f"JWT analysis failed: {e}")

            if args.screenshot:
                try:
                    screenshots = take_screenshots(domain, logger, crawled_urls)
                except Exception as e:
                    logger.error(f"Screenshot failed: {e}")

        if any_web_mode:
            try:
                scanner = WebSecurityScanner(domain, logger, session=session, limiter=limiter,
                                              active=args.active, max_requests=args.max_requests)
                mode = focused_mode or "all"
                web_result = scanner.run(mode=mode, crawled_urls=crawled_urls, js_endpoints=js_endpoints)
            except Exception as e:
                logger.error(f"Web security engine failed: {e}")

        summary = {
            "target": domain,
            "timestamp": ts,
            "version": VERSION,
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
            "js_secret_hits": secret_hits,
            "cors_findings": cors_findings,
            "jwt_findings": jwt_findings,
            "screenshots": screenshots,
            "web_findings": web_result["findings"],
            "web_risk_score": web_result["risk_score"],
            "web_risk_label": web_result["risk_label"],
            "web_requests_used": web_result["requests_used"],
            "errors": logger.errors,
            "warnings": logger.warnings
        }

        if args.json:
            try:
                build_report(summary, report_json)
                logger.ok(f"JSON report: {report_json}")
            except Exception as e:
                logger.error(f"JSON report failed: {e}")

        if args.html:
            try:
                html_report_path = generate_html_report(summary, domain, ts, logger=logger)
                logger.ok(f"HTML report: {html_report_path}")
            except Exception as e:
                logger.error(f"HTML report failed: {e}")

        logger.phase("SUMMARY")
        logger.ok(f"Open Ports: {len(open_ports)}")
        logger.ok(f"Subdomains: {len(found_subs)}")
        logger.ok(f"Crawled URLs: {len(crawled_urls)}")
        logger.ok(f"JS Endpoints: {len(js_endpoints)}")
        logger.ok(f"Web Findings: {len(web_result['findings'])}")
        logger.ok(f"Web Risk Score: {web_result['risk_score']}/100 ({web_result['risk_label']})")
        logger.ok(f"TXT Report: {report_txt}")

        if logger.errors:
            logger.warn(f"Total errors: {len(logger.errors)}")
        if logger.warnings:
            logger.warn(f"Total warnings: {len(logger.warnings)}")

    print(f"\n[*] Done. Report: {report_txt}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal: {e}")
        traceback.print_exc()
        sys.exit(1)
