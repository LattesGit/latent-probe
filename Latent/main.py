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
VERSION = "0.3.0"

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

    secret_patterns = [
        r'(?:api[_-]?key|apikey|token|secret|password|passwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
        r'(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:private[_-]?key|secret[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']',
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
            for pattern in secret_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                secrets_found.extend(matches)

            if secrets_found:
                logger.warn(f"SECRETS in {js_url}: {len(secrets_found)} potential leaks")
                for secret in secrets_found[:3]:
                    logger.warn(f"  -> {secret[:50]}...")

            logger.debug(f"Parsed {js_url} | Endpoints: {len(endpoints)}")

        except Exception as e:
            logger.debug(f"JS parse error: {e}")

    endpoints_list = sorted(list(endpoints))
    logger.ok(f"Total unique endpoints found: {len(endpoints_list)}")
    return endpoints_list


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
                "token_preview": token[:50] + "...",
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
                        logger.error(f"CRITICAL: JWT cracked with secret: {secret}")
                        token_findings["issues"].append(f"weak_secret:{secret}")
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
        ul li:before {{ content: ">"; color: #667eea; margin-right: 10px; }}
        .tech-tags {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
        .tag {{ background: #667eea; color: white; padding: 4px 12px; border-radius: 15px; font-size: 0.85em; }}
        footer {{ text-align: center; padding: 20px; color: #666; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>LATENT</h1>
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
            <h2>Technology Fingerprinting</h2>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{json.dumps(data.get('technology', {{}}), indent=2)}</pre>
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
            <h2>CORS Misconfiguration Findings ({len(data.get('cors_findings', []))})</h2>
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
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{json.dumps(data.get('whois', {{}}), indent=2) if data.get('whois') else "No WHOIS data available."}</pre>
        </div>

        <div class="section">
            <h2>Brute Force Candidates ({len(data.get('brute_candidates', []))})</h2>
            <ul>
                {''.join([f"<li>{c[1]}:{c[2]} @ {c[0]}</li>" for c in data.get('brute_candidates', [])]) if data.get('brute_candidates') else "<li>No candidates found</li>"}
            </ul>
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
    parser = argparse.ArgumentParser(description="LATENT - Multi-Phase Pentest Tool", epilog="Example: latent -t example.com -w subdomains.txt --html --screenshot")
    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    parser.add_argument("-w", "--wordlist", default="subdomains.txt", help="Subdomain/wordlist path")
    parser.add_argument("-p","--ports", type=int, default=1000, help="Max port to scan (default: 1000)")
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

    with open(report_txt, "w", encoding="utf-8") as rf:
        logger = Logger(rf, verbose=args.verbose)
        session = requests.Session()
        session.headers.update(HEADERS)
        limiter = RateLimiter(args.rate)

        logger.log(f"Target: {domain}")
        logger.log(f"Wordlist: {args.wordlist}")
        logger.log(f"MaxPort: {args.ports} | Threads: {args.threads} | Rate: {args.rate}s")

        try:
            html, html_path, tech = fetch_html(domain, logger, session)
        except Exception as e:
            logger.error(f"HTML fetch failed: {e}")
            html, html_path, tech = None, None, {}

        try:
            open_ports = scan_ports(domain, args.ports, logger, args.threads)
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            open_ports = []

        try:
            smb_data = smb_probe(domain, logger)
        except Exception as e:
            logger.error(f"SMB probe failed: {e}")
            smb_data = None

        try:
            if aiodns:
                found_subs = asyncio.run(subdomain_async(domain, args.wordlist, logger, args.sub_limit))
            else:
                found_subs = subdomain_sync(domain, args.wordlist, logger, args.sub_limit)
        except Exception as e:
            logger.error(f"Subdomain enum failed: {e}")
            found_subs = []

        try:
            xss_hits = xss_probe(domain, logger, session, limiter)
        except Exception as e:
            logger.error(f"XSS probe failed: {e}")
            xss_hits = 0

        try:
            dirs = dir_fuzz(domain, logger, session, limiter)
        except Exception as e:
            logger.error(f"Dir fuzz failed: {e}")
            dirs = []

        try:
            whois_data = whois_lookup(domain, logger)
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            whois_data = None

        sqlmap_result = False
        if args.sqlmap:
            try:
                sqlmap_result = sqlmap_probe(domain, logger)
            except Exception as e:
                logger.error(f"SQLMap failed: {e}")

        brute_results = []
        if args.brute:
            try:
                brute_results = brute_login(domain, args.wordlist, logger, session, limiter)
            except Exception as e:
                logger.error(f"Brute force failed: {e}")

        try:
            crawled_urls = recursive_crawl(domain, logger, session, limiter, args.crawl_depth, args.crawl_pages)
        except Exception as e:
            logger.error(f"Crawler failed: {e}")
            crawled_urls = []

        try:
            js_endpoints = extract_js_endpoints(domain, logger, session, limiter, crawled_urls)
        except Exception as e:
            logger.error(f"JS endpoint extraction failed: {e}")
            js_endpoints = []

        try:
            cors_findings = cors_check(domain, logger, session, limiter)
        except Exception as e:
            logger.error(f"CORS check failed: {e}")
            cors_findings = []

        try:
            jwt_findings = jwt_analyze(domain, logger, session, limiter)
        except Exception as e:
            logger.error(f"JWT analysis failed: {e}")
            jwt_findings = []

        screenshots = []
        if args.screenshot:
            try:
                screenshots = take_screenshots(domain, logger, crawled_urls)
            except Exception as e:
                logger.error(f"Screenshot failed: {e}")

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
            "cors_findings": cors_findings,
            "jwt_findings": jwt_findings,
            "screenshots": screenshots,
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
        logger.ok(f"XSS Reflected: {xss_hits}")
        logger.ok(f"Interesting Paths: {len(dirs)}")
        logger.ok(f"Crawled URLs: {len(crawled_urls)}")
        logger.ok(f"JS Endpoints: {len(js_endpoints)}")
        logger.ok(f"CORS Issues: {len(cors_findings)}")
        logger.ok(f"JWT Findings: {len(jwt_findings)}")
        logger.ok(f"Screenshots: {len(screenshots)}")
        logger.ok(f"Brute Candidates: {len(brute_results)}")
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
