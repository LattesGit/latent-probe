#!/usr/bin/env python3

import argparse
import html
import ipaddress
import json
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

try:
    from . import http_client as _http_client
except ImportError:
    import http_client as _http_client

sys.modules.setdefault("Latent.http_client", _http_client)
configure_http_manager = _http_client.configure

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from rich.console import Console
    from rich.panel import Panel
    RICH = True
    CONSOLE = Console()
except ImportError:
    RICH = False
    Console = Panel = CONSOLE = None

try:
    import dns.flags
    import dns.rdatatype
    import dns.resolver
    DNSPYTHON_AVAILABLE = True
except ImportError:
    dns = None
    DNSPYTHON_AVAILABLE = False


USER_AGENT = "LATENT-Security-Assessment/1.0 (authorized low-impact testing)"
TIMEOUT = 8
MAX_BODY = 1_000_000
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 1}
CONFIDENCE_WEIGHT = {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4}
ERROR_PATTERNS = (
    r"Traceback \(most recent call last\)", r"Fatal error:", r"Uncaught Exception",
    r"java\.lang\.[A-Za-z]+Exception", r"Django Version:", r"ORA-\d{5}",
    r"PHP Parse error", r"Whoops!\s+There was an error",
)
COMMON_SENSITIVE_PATHS = {
    "/.env": ("Environment file", re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", re.M)),
    "/.env.local": ("Environment file", re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", re.M)),
    "/.git/HEAD": ("Git repository metadata", re.compile(r"^ref:\s+refs/", re.M)),
    "/.git/config": ("Git configuration", re.compile(r"^\[(?:core|remote|branch)\]", re.M)),
    "/backup.zip": ("Backup archive", None),
    "/backup.tar.gz": ("Backup archive", None),
    "/dump.sql": ("Database dump", re.compile(r"\b(?:CREATE TABLE|INSERT INTO)\b", re.I)),
    "/database.sql": ("Database dump", re.compile(r"\b(?:CREATE TABLE|INSERT INTO)\b", re.I)),
    "/config.json": ("Configuration file", re.compile(r"^\s*[\[{]")),
    "/debug.log": ("Debug log", re.compile(r"error|exception|traceback", re.I)),
    "/.well-known/security.txt": ("security.txt", None),
    "/robots.txt": ("robots.txt", None),
    "/sitemap.xml": ("sitemap.xml", None),
    "/server-status": ("Server status endpoint", None),
    "/actuator/env": ("Actuator environment endpoint", re.compile(r"propertysources", re.I)),
}
API_PATHS = (
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/openapi.yaml", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui/", "/graphql", "/api/graphql",
)
LOGIN_PATTERN = re.compile(r"/(?:login|signin|sign-in|auth)(?:/|$)", re.I)
ACTION_PATH_PATTERN = re.compile(
    r"/(?:logout|signout|delete|remove|unsubscribe|disable|cancel)(?:/|$)", re.I
)


def normalize_target(value):
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    parsed = urlparse(value if "://" in value else "//" + value)
    if parsed.username or parsed.password:
        raise ValueError("Target URLs cannot include embedded credentials.")
    host = parsed.hostname
    if not host:
        raise ValueError("Provide a valid hostname or IP address.")
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Target hostname is invalid.") from exc
    if len(host) > 253 or not re.fullmatch(
        r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
        r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
        host,
    ):
        raise ValueError("Provide a valid hostname or IP address.")
    return host


def format_host(host):
    try:
        return f"[{host}]" if ipaddress.ip_address(host).version == 6 else host
    except ValueError:
        return host


def resolve_ips(host):
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def is_public_target(host):
    ips = resolve_ips(host)
    return bool(ips) and all(
        (lambda addr: addr.is_global)(ipaddress.ip_address(value)) for value in ips
    )


def ssrf_guard(host, logger=None):
    ips = resolve_ips(host)
    if not ips or any(not ipaddress.ip_address(value).is_global for value in ips):
        if logger:
            logger.warn(f"SSRF protection refused unresolved or non-public host: {host}")
        return False
    return True


def resolve_domain(target):
    return normalize_target(target)


def make_finding(fid, title, severity, confidence, category, target, evidence,
                 description, remediation):
    return {
        "id": fid,
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "target": target,
        "evidence": evidence,
        "description": description,
        "impact": description,
        "remediation": remediation,
    }


def risk_score(findings):
    score = sum(
        SEVERITY_WEIGHT.get(item.get("severity", "INFO"), 1)
        * CONFIDENCE_WEIGHT.get(item.get("confidence", "MEDIUM"), 0.7)
        for item in findings
    )
    value = min(100, round(score))
    label = (
        "LOW" if value <= 20 else "MODERATE" if value <= 40 else
        "MEDIUM" if value <= 60 else "HIGH" if value <= 80 else "CRITICAL"
    )
    return value, label


class Logger:
    def __init__(self, report_file=None, verbose=False):
        self.report_file = report_file
        self.verbose = verbose
        self.errors = []
        self.warnings = []
        self.manager = None

    def phase(self, name):
        if RICH:
            CONSOLE.print(Panel(name, expand=False, border_style="cyan"))
            if self.manager:
                CONSOLE.print(
                    f"Requests {self.manager.count}/{self.manager.budget} | "
                    f"{self.manager.elapsed:.1f}s | "
                    f"safe stop: {self.manager.stop_reason or 'not triggered'}",
                    style="dim",
                )
        else:
            print(f"\n{'=' * 64}\n  {name}\n{'=' * 64}")
            if self.manager:
                print(
                    f"Requests {self.manager.count}/{self.manager.budget} | "
                    f"{self.manager.elapsed:.1f}s | "
                    f"safe stop: {self.manager.stop_reason or 'not triggered'}"
                )
        if self.report_file:
            self.report_file.write(f"\n{'=' * 64}\n  {name}\n{'=' * 64}\n")

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefixes = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERROR": "[X]"}
        line = f"{timestamp} {prefixes.get(level, '[*]')} {message}"
        if RICH:
            styles = {"OK": "green", "WARN": "yellow", "ERROR": "bold red", "INFO": "cyan"}
            CONSOLE.print(line, style=styles.get(level, "cyan"), markup=False)
        else:
            print(line)
        if self.report_file:
            self.report_file.write(line + "\n")
        if level == "WARN":
            self.warnings.append(message)
        elif level == "ERROR":
            self.errors.append(message)

    def info(self, message):
        self.log(message)

    def ok(self, message):
        self.log(message, "OK")

    def warn(self, message):
        self.log(message, "WARN")

    def error(self, message):
        self.log(message, "ERROR")

    def debug(self, message):
        if self.verbose:
            self.log(message)


class RateLimiter:
    def __init__(self, delay=0.3):
        self.delay = max(0.2, float(delay))
        self.last = 0.0
        self.lock = threading.Lock()

    def sleep(self):
        with self.lock:
            remaining = self.delay - (time.monotonic() - self.last)
            if remaining > 0:
                time.sleep(remaining)
            self.last = time.monotonic()


class RequestManager:
    """One bounded HTTP transport for all scanner requests and redirects."""

    def __init__(self, session=None, logger=None, limiter=None, budget=300,
                 timeout=TIMEOUT, max_response_bytes=MAX_BODY, allowed_hosts=None):
        self.session = session or requests.Session()
        self.logger = logger or Logger()
        self.limiter = limiter or RateLimiter()
        self.budget = max(1, int(budget))
        self.timeout = max(1, int(timeout))
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.allowed_hosts = {host.lower().rstrip(".") for host in (allowed_hosts or [])}
        self.count = 0
        self.start_time = time.monotonic()
        self.stop_reason = None
        self.status_codes = Counter()
        self._lock = threading.Lock()
        self._consecutive_errors = 0
        self._slow_responses = 0
        self._server_errors = 0

    @property
    def elapsed(self):
        return time.monotonic() - self.start_time

    @property
    def request_count(self):
        return self.count

    def stop(self, reason):
        if self.stop_reason is None:
            self.stop_reason = reason
            self.logger.warn(f"Automatic safe stop: {reason}")

    def reserve(self):
        if self.stop_reason:
            return False
        with self._lock:
            if self.count >= self.budget:
                self.stop(f"request budget exhausted ({self.budget})")
                return False
            self.count += 1
            return True

    def _validate_destination(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            self.logger.warn(f"Refusing malformed or unsupported URL: {url}")
            return False
        host = parsed.hostname.lower().rstrip(".")
        if self.allowed_hosts and host not in self.allowed_hosts:
            self.logger.warn(f"Refusing out-of-scope HTTP destination: {host}")
            return False
        if not ssrf_guard(host, self.logger):
            self.stop(f"SSRF protection blocked {host}")
            return False
        return True

    def request(self, url, method="GET", **kwargs):
        if self.stop_reason or not self._validate_destination(url) or not self.reserve():
            return None
        self.limiter.sleep()
        headers = {"User-Agent": USER_AGENT}
        headers.update(kwargs.pop("headers", {}) or {})
        timeout = kwargs.pop("timeout", self.timeout)
        kwargs.pop("allow_redirects", None)
        verify = kwargs.pop("verify", True)
        current_method = method.upper()
        current_url = url
        current_kwargs = dict(kwargs)

        for hop in range(6):
            started = time.monotonic()
            response = None
            try:
                response = self.session.request(
                    current_method, current_url, headers=headers, timeout=timeout,
                    verify=verify, allow_redirects=False, stream=True, **current_kwargs
                )
                body = bytearray()
                truncated = False
                try:
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        remaining = self.max_response_bytes - len(body)
                        if len(chunk) > remaining:
                            body.extend(chunk[:remaining])
                            truncated = True
                            break
                        body.extend(chunk)
                finally:
                    response.close()
                response._content = bytes(body)
                response._content_consumed = True
                if truncated:
                    response.headers["X-LATENT-Response-Truncated"] = "true"
                self.status_codes[response.status_code] += 1
                self._consecutive_errors = 0
                duration = time.monotonic() - started
                self._slow_responses = self._slow_responses + 1 if duration >= 8 else 0
                self._server_errors = self._server_errors + 1 if response.status_code >= 500 else 0

                if response.status_code == 429:
                    self.stop(f"HTTP 429; Retry-After={response.headers.get('Retry-After', 'not supplied')}")
                elif response.status_code == 503 and response.headers.get("Retry-After"):
                    self.stop(f"HTTP 503 throttling; Retry-After={response.headers['Retry-After']}")
                elif response.status_code in (403, 503) and re.search(
                    r"captcha|challenge|access denied|request blocked|web application firewall",
                    response.text[:5000], re.I,
                ):
                    self.stop(f"WAF challenge/block observed (HTTP {response.status_code})")
                elif self._slow_responses >= 2:
                    self.stop("two consecutive slow responses (>=8 seconds)")
                elif self._server_errors >= 3:
                    self.stop("three consecutive server errors")

                if response.status_code not in (301, 302, 303, 307, 308):
                    return response
                location = response.headers.get("Location")
                if not location:
                    return response
                next_url = urljoin(current_url, location)
                if not self._validate_destination(next_url):
                    return response
                if hop >= 5:
                    self.stop("redirect hop limit reached")
                    return response
                if not self.reserve():
                    return response
                self.limiter.sleep()
                current_url = next_url
                if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method == "POST"
                ):
                    current_method = "GET"
                    current_kwargs.pop("data", None)
                    current_kwargs.pop("json", None)
            except requests.exceptions.Timeout:
                self._consecutive_errors += 1
                if self._consecutive_errors >= 3:
                    self.stop("three consecutive request timeouts")
                return None
            except requests.exceptions.RequestException as exc:
                self.logger.debug(f"Request failed: {exc}")
                self._consecutive_errors += 1
                if self._consecutive_errors >= 3:
                    self.stop("three consecutive request errors")
                return None
        return response


REQUEST_MANAGER = None
DISCOVERED_PARAMETERS = {}


def safe_request(session, url, method="GET", **kwargs):
    if REQUEST_MANAGER is None:
        raise RuntimeError("RequestManager must be initialized before sending HTTP requests.")
    return REQUEST_MANAGER.request(url, method, **kwargs)


def discover_site(target, manager, logger, max_pages=30, max_depth=2):
    logger.phase("DISCOVERY")
    base = f"https://{format_host(target)}"
    visited = set()
    queue = deque([(base, 0)])
    links, scripts, params, forms = [], set(), {}, []
    while queue and len(visited) < max_pages and not manager.stop_reason:
        url, depth = queue.popleft()
        normalized = urlunparse(urlparse(url)._replace(fragment=""))
        if normalized in visited:
            continue
        visited.add(normalized)
        response = manager.request(normalized)
        if response is None or "text/html" not in response.headers.get("Content-Type", "").lower():
            continue
        if BeautifulSoup is None:
            logger.warn("beautifulsoup4 is missing; HTML discovery is disabled.")
            break
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup.find_all(["a", "form", "script", "link"]):
            raw = tag.get("href") or tag.get("src") or tag.get("action")
            if not raw:
                continue
            destination = urljoin(response.url, raw)
            parsed = urlparse(destination)
            if parsed.scheme not in ("http", "https"):
                continue
            if tag.name == "script":
                if parsed.hostname not in (target, f"www.{target}"):
                    if not tag.get("integrity"):
                        scripts.add((destination, response.url, False))
                    continue
                scripts.add((destination, response.url, bool(tag.get("integrity"))))
            if parsed.hostname not in (target, f"www.{target}"):
                continue
            if ACTION_PATH_PATTERN.search(parsed.path):
                continue
            if parsed.query:
                names = set(parse_qs(parsed.query, keep_blank_values=True))
                if names:
                    params.setdefault(destination, set()).update(names)
            if tag.name == "form":
                names = {
                    field.get("name") for field in tag.find_all(["input", "textarea", "select"])
                    if field.get("name")
                }
                action_url = urljoin(response.url, tag.get("action") or response.url)
                method = (tag.get("method") or "get").lower()
                form = {"url": action_url, "method": method, "parameters": sorted(names)}
                forms.append(form)
                if method == "get" and names:
                    params.setdefault(action_url, set()).update(names)
            links.append(destination)
            if tag.name in ("a", "link") and depth < max_depth and not re.search(
                r"\.(?:css|png|jpe?g|gif|svg|ico|woff2?|pdf)$", parsed.path, re.I
            ):
                queue.append((destination, depth + 1))
    logger.ok(f"Discovered {len(set(links))} URLs, {len(scripts)} scripts, {len(params)} parameterized URLs.")
    return list(dict.fromkeys(links)), list(scripts), params, forms


class WebSecurityScanner:
    def __init__(self, domain, logger, session=None, limiter=None, active=False,
                 max_requests=300, max_response_bytes=MAX_BODY, verify_tls=True):
        self.domain = domain
        self.logger = logger
        self.session = session or requests.Session()
        self.limiter = limiter or RateLimiter()
        self.active = active
        self.verify_tls = verify_tls
        self.manager = REQUEST_MANAGER or RequestManager(
            self.session, logger, self.limiter, max_requests,
            max_response_bytes=max_response_bytes,
            allowed_hosts={domain, f"www.{domain}"},
        )
        self.findings = []
        self._seen = set()
        host = format_host(domain)
        self.base_https = f"https://{host}"
        self.base_http = f"http://{host}"
        self.discovered_params = {}
        self.discovered_scripts = []

    @property
    def request_manager(self):
        return self.manager

    @request_manager.setter
    def request_manager(self, value):
        self.manager = value

    def add(self, fid, title, severity, confidence, category, target, evidence,
            description, remediation):
        key = (fid, target, str(evidence))
        if key in self._seen:
            return None
        self._seen.add(key)
        finding = make_finding(fid, title, severity, confidence, category, target,
                               evidence, description, remediation)
        self.findings.append(finding)
        self.logger.log(f"[{severity}] {title} @ {target}",
                        "ERROR" if severity == "CRITICAL" else
                        "WARN" if severity in ("HIGH", "MEDIUM") else "INFO")
        return finding

    def get(self, url, **kwargs):
        return self.manager.request(url, kwargs.pop("method", "GET"), **kwargs)

    def primary(self):
        for candidate in (self.base_https, self.base_http):
            response = self.get(candidate)
            if response is not None:
                return response.url, response
        return None, None

    def check_headers(self, url, response):
        headers = {key.lower(): value for key, value in response.headers.items()}
        required = {
            "content-security-policy": ("WEB-HEADER-001", "Missing Content-Security-Policy", "MEDIUM",
                "Add a restrictive policy based on the resources the application requires."),
            "x-content-type-options": ("WEB-HEADER-002", "Missing X-Content-Type-Options", "LOW",
                "Set X-Content-Type-Options: nosniff."),
            "referrer-policy": ("WEB-HEADER-003", "Missing Referrer-Policy", "LOW",
                "Set strict-origin-when-cross-origin or a stricter policy."),
            "permissions-policy": ("WEB-HEADER-004", "Missing Permissions-Policy", "LOW",
                "Disable browser capabilities that the application does not need."),
            "cross-origin-opener-policy": ("WEB-HEADER-005", "Missing COOP", "LOW",
                "Set Cross-Origin-Opener-Policy: same-origin where compatible."),
            "cross-origin-resource-policy": ("WEB-HEADER-006", "Missing CORP", "INFO",
                "Set same-origin or same-site according to resource sharing requirements."),
        }
        for name, (fid, title, severity, fix) in required.items():
            if name not in headers:
                self.add(fid, title, severity, "HIGH", "Headers", url,
                         f"{name} header not present",
                         "The browser receives no explicit policy for this security control.", fix)
        if url.startswith("https://") and "strict-transport-security" not in headers:
            self.add("WEB-HEADER-007", "Missing HSTS", "MEDIUM", "HIGH", "Headers", url,
                     "Strict-Transport-Security header not present",
                     "Browsers are not instructed to require HTTPS on future visits.",
                     "After validating HTTPS site-wide, set a suitable HSTS max-age.")
        hsts = headers.get("strict-transport-security", "")
        match = re.search(r"max-age=(\d+)", hsts, re.I)
        if match and int(match.group(1)) < 15_768_000:
            self.add("WEB-HEADER-008", "HSTS max-age is short", "LOW", "MEDIUM", "Headers", url,
                     hsts, "A short HSTS lifetime reduces repeat-visit protection.",
                     "Use max-age of at least 15768000 seconds after HTTPS is stable.")
        csp = headers.get("content-security-policy", "")
        directives = {
            part.strip().split()[0].lower(): part.strip().split()[1:]
            for part in csp.split(";") if part.strip()
        }
        weak = [
            name for name, values in directives.items()
            if name in ("script-src", "default-src")
            and any(value in values for value in ("'unsafe-inline'", "'unsafe-eval'", "*"))
        ]
        if weak:
            self.add("WEB-CSP-001", "CSP contains broad script sources", "MEDIUM", "HIGH", "CSP",
                     url, f"Weak directives: {weak}",
                     "Unsafe inline/eval or wildcard sources weaken CSP's XSS mitigation.",
                     "Use nonces/hashes and restrict script sources to required origins.")
        if csp and "object-src" not in directives:
            self.add("WEB-CSP-002", "CSP lacks object-src restriction", "LOW", "MEDIUM",
                     "CSP", url, "No object-src directive",
                     "Legacy plugin content is not explicitly restricted.",
                     "Add object-src 'none' unless the application needs embedded plugins.")

    def check_cookies(self, url, response):
        try:
            cookie_headers = response.raw.headers.getlist("Set-Cookie")
        except (AttributeError, TypeError):
            value = response.headers.get("Set-Cookie")
            cookie_headers = [value] if value else []
        for raw in cookie_headers:
            parts = [item.strip() for item in raw.split(";")]
            if not parts:
                continue
            name = parts[0].split("=", 1)[0]
            attrs = {}
            for part in parts[1:]:
                key, _, value = part.partition("=")
                attrs[key.lower()] = value or True
            sensitive = bool(re.search(r"session|auth|token|sid|jwt", name, re.I))
            evidence = f"Set-Cookie: {name}=********"
            for flag, fid, title, severity in (
                ("secure", "WEB-COOKIE-001", "Cookie missing Secure", "MEDIUM" if sensitive else "LOW"),
                ("httponly", "WEB-COOKIE-002", "Cookie missing HttpOnly", "MEDIUM" if sensitive else "LOW"),
                ("samesite", "WEB-COOKIE-003", "Cookie missing SameSite", "LOW"),
            ):
                if flag not in attrs and (flag != "secure" or url.startswith("https://")):
                    self.add(fid, f"{title}: {name}", severity, "HIGH", "Cookies", url, evidence,
                             f"The {name} cookie lacks the {flag} attribute.",
                             f"Set the {flag.title()} attribute on cookies as appropriate.")
            if str(attrs.get("samesite", "")).lower() == "none" and "secure" not in attrs:
                self.add("WEB-COOKIE-004", f"SameSite=None without Secure: {name}", "MEDIUM", "HIGH",
                         "Cookies", url, evidence,
                         "Browsers require Secure for SameSite=None cookies.",
                         "Pair SameSite=None with Secure.")

    def check_cors(self, url):
        findings = []
        for origin in ("https://evil.example", "null"):
            response = self.get(url, headers={"Origin": origin})
            if response is None:
                break
            allow = response.headers.get("Access-Control-Allow-Origin", "")
            credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            if allow == origin and credentials:
                severity = "HIGH"
                title = "Untrusted origin reflected with credentials"
            elif allow == "*" and credentials:
                severity = "LOW"
                title = "Wildcard CORS with credentials signal"
            elif allow == origin:
                severity = "MEDIUM"
                title = "Untrusted origin reflected by CORS"
            elif allow == "*":
                severity = "LOW"
                title = "Wildcard CORS policy"
            else:
                continue
            finding = self.add(
                "WEB-CORS-001", title, severity, "HIGH", "CORS", url,
                f"Origin={origin}; ACAO={allow}; ACAC={credentials}",
                "A permissive cross-origin response policy may allow unwanted cross-origin access.",
                "Restrict Access-Control-Allow-Origin to explicit trusted origins and avoid credentialed wildcard policies.",
            )
            if finding:
                findings.append(finding)
        return findings

    def check_exposure(self):
        self.logger.phase("WEB SECURITY")
        for path, (label, expected) in COMMON_SENSITIVE_PATHS.items():
            if self.manager.stop_reason:
                break
            url = self.base_https + path
            response = self.get(url)
            if response is None or response.status_code != 200 or not response.content:
                continue
            text = response.text[:4000]
            if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                if path == "/robots.txt":
                    interesting = [
                        item for item in re.findall(r"^\s*Disallow:\s*(\S+)", text, re.I | re.M)
                        if re.search(r"admin|config|backup|private|internal", item, re.I)
                    ]
                    if interesting:
                        self.add(
                            "WEB-ROBOTS-001", "robots.txt lists sensitive-looking paths",
                            "LOW", "MEDIUM", "Discovery", response.url,
                            f"{len(interesting)} sensitive-looking path(s) listed",
                            "robots.txt is public and does not restrict access to listed paths.",
                            "Use authorization controls rather than relying on robots.txt to hide sensitive routes.",
                        )
                elif path == "/.well-known/security.txt":
                    contacts = len(re.findall(r"^Contact\s*:", text, re.I | re.M))
                    self.add(
                        "WEB-SECURITYTXT-001", "security.txt is publicly available",
                        "INFO", "HIGH", "Security Contact", response.url,
                        f"Contact fields: {contacts}",
                        "A published security.txt gives researchers a standard reporting contact.",
                        "Keep security contact and policy details current.",
                    )
                continue
            if path.endswith((".zip", ".gz")):
                valid = response.content.startswith(b"PK\x03\x04") or "application/zip" in response.headers.get("Content-Type", "")
            elif expected is None:
                valid = True
            else:
                valid = bool(expected.search(text))
            if valid:
                self.add("WEB-EXPOSE-001", f"Potentially exposed resource: {label}", "HIGH", "MEDIUM",
                         "Exposure", response.url, "Resource appears accessible; body content is not included in evidence.",
                         f"A public {label.lower()} can expose sensitive implementation or operational data.",
                         "Restrict access or remove the resource from public web roots. Rotate secrets if exposure is confirmed.")
        for path in ("/", "/uploads/", "/files/"):
            response = self.get(self.base_https + path)
            if response is None or response.status_code != 200:
                continue
            if re.search(r"<title>\s*index of /|<h1>\s*index of /", response.text[:4000], re.I):
                self.add("WEB-DIRLIST-001", "Directory listing appears enabled", "MEDIUM", "MEDIUM",
                         "Directory Exposure", response.url, "An 'Index of /' listing marker was observed",
                         "Directory listings expose filenames and may reveal backups or source files.",
                         "Disable automatic directory indexing.")
                break
        for url in self.discovered_urls:
            parsed = urlparse(url)
            if not re.search(r"\.(?:bak|old|orig|backup|map)$", parsed.path, re.I):
                continue
            response = self.get(url)
            if response and response.status_code == 200 and response.content:
                self.add("WEB-BACKUP-001", "Backup or source-map URL discovered", "LOW", "MEDIUM",
                         "Exposure", response.url, "HTTP 200 with non-empty response",
                         "Backup files or source maps can reveal source code or internal paths.",
                         "Remove unnecessary artifacts from public deployment directories.")

    def check_response_disclosure(self, url, response):
        headers = response.headers
        for name in ("Server", "X-Powered-By"):
            value = headers.get(name)
            if value and re.search(r"\d+\.\d+", value):
                self.add("WEB-INFO-001", f"{name} discloses version information", "LOW", "HIGH",
                         "Information Disclosure", url, f"{name}: {value}",
                         "Version information can help identify software with known vulnerabilities.",
                         f"Suppress or generalize the {name} response header.")
        body = response.text
        for pattern in ERROR_PATTERNS:
            match = re.search(pattern, body, re.I)
            if match:
                self.add("WEB-INFO-002", "Verbose error or stack trace exposed", "MEDIUM", "MEDIUM",
                         "Information Disclosure", url, f"Matched pattern: {match.group(0)[:120]}",
                         "Diagnostic output may reveal implementation and filesystem details.",
                         "Disable debug responses in production and return generic error pages.")
                break
        path_match = re.search(r"(?:/var/www/|/home/[\w-]+/|/srv/[^ <\"']+)", body)
        internal_ip = re.search(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", body
        )
        match = path_match or internal_ip
        if match:
            self.add("WEB-INFO-003", "Internal path or IP disclosed", "LOW", "LOW",
                     "Information Disclosure", url, match.group(0)[:160],
                     "The response contains a filesystem path or private IP address.",
                     "Remove internal diagnostics from production responses.")
        if response.status_code == 200 and re.search(
            r"<title>\s*(?:Apache2 Debian Default Page|Welcome to nginx|IIS Windows Server)",
            body, re.I,
        ):
            self.add("WEB-DEFAULT-001", "Default server landing page detected", "LOW", "MEDIUM",
                     "Default Configuration", url, "Known default-page title observed",
                     "The host may be serving an uncustomized default page or incorrect virtual host.",
                     "Remove the default page and verify the virtual-host configuration.")
        if response.status_code >= 500:
            self.add("WEB-STATUS-001", f"Server error response (HTTP {response.status_code})", "LOW",
                     "MEDIUM", "Response Behavior", url, f"HTTP {response.status_code}",
                     "An ordinary request returned a server-side failure.",
                     "Review application and edge logs and return consistent safe error responses.")
        cache = headers.get("Cache-Control", "").lower()
        if re.search(r"login|account|profile|admin|dashboard", url, re.I):
            if "no-store" not in cache:
                self.add("WEB-CACHE-001", "Sensitive route lacks no-store cache policy", "LOW", "MEDIUM",
                         "Cache", url, f"Cache-Control: {cache or '(missing)'}",
                         "Sensitive responses may be retained by browsers or intermediary caches.",
                         "Use Cache-Control: no-store for authenticated or user-specific responses.")
            if "public" in cache:
                self.add("WEB-CACHE-002", "Sensitive route marked publicly cacheable", "MEDIUM", "MEDIUM",
                         "Cache", url, f"Cache-Control: {cache}",
                         "Shared caches could retain a response intended for a specific user.",
                         "Use private/no-store cache directives for authenticated responses.")
        encoding = headers.get("Content-Encoding", "")
        if encoding and re.search(r"login|account|profile|token", url, re.I):
            self.add("WEB-COMPRESS-001", "Compression enabled on potentially sensitive route", "INFO", "LOW",
                     "Compression", url, f"Content-Encoding: {encoding}",
                     "Compression can contribute to side-channel risks when secrets and attacker-controlled data share responses.",
                     "Review application-specific mitigations for compressed secret-bearing responses.")

    def check_content(self, url, response):
        body = response.text
        if url.startswith("https://"):
            mixed = re.findall(r"""(?:src|href|action)=["'](http://[^"']+)""", body, re.I)
            if mixed:
                self.add("WEB-MIXED-001", "HTTP resource referenced from HTTPS page", "MEDIUM", "MEDIUM",
                         "Mixed Content", url, mixed[0],
                         "An HTTP subresource may be modified in transit.",
                         "Load subresources over HTTPS.")
        if BeautifulSoup is None:
            return
        soup = BeautifulSoup(body, "html.parser")
        for script in soup.find_all("script", src=True):
            script_url = urljoin(url, script["src"])
            host = urlparse(script_url).hostname
            if host and host not in (self.domain, f"www.{self.domain}") and not script.get("integrity"):
                self.add("WEB-SRI-001", "Third-party script has no SRI metadata", "LOW", "MEDIUM",
                         "Third-party Resources", script_url, "External script missing integrity attribute",
                         "A compromised external script executes with the application's page privileges.",
                         "Use Subresource Integrity for immutable third-party scripts.")
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            password = form.find("input", {"type": "password"})
            if password and action.startswith("http://"):
                self.add("WEB-FORM-001", "Password form submits over HTTP", "HIGH", "HIGH",
                         "Forms", url, f"Form action: {action}",
                         "Credentials submitted over HTTP can be intercepted.",
                         "Serve the form action exclusively over HTTPS.")
            if password and not password.get("autocomplete"):
                self.add("WEB-AUTH-001", "Password form has no explicit autocomplete policy",
                         "INFO", "LOW", "Authentication", url, "Password input lacks autocomplete attribute",
                         "Explicit autocomplete values communicate login/password-reset behavior to browsers.",
                         "Set autocomplete=current-password or new-password according to the form purpose.")
        csp = response.headers.get("Content-Security-Policy", "").lower()
        if "x-frame-options" not in {key.lower() for key in response.headers} and (
            not csp or "frame-ancestors" not in csp
        ):
            self.add("WEB-CLICKJACK-001", "Missing clickjacking protection", "MEDIUM", "HIGH",
                     "Headers", url, "No CSP frame-ancestors or X-Frame-Options header",
                     "The page may be embedded in a hostile frame.",
                     "Set CSP frame-ancestors or X-Frame-Options as compatible with the application.")

    def check_api(self):
        self.logger.phase("APPLICATION SECURITY / API DISCOVERY")
        for path in API_PATHS:
            if self.manager.stop_reason:
                return
            response = self.get(self.base_https + path)
            if response is None or response.status_code not in (200, 400, 401, 403, 405):
                continue
            if "swagger" in path or "openapi" in path or "api-docs" in path:
                if response.status_code == 200:
                    self.add("WEB-API-001", "API documentation endpoint is public", "MEDIUM", "HIGH",
                             "API Discovery", response.url, f"HTTP {response.status_code}",
                             "Public API documentation can disclose endpoints and data models.",
                             "Restrict documentation to authorized users or internal environments.")
            else:
                self.add("WEB-API-002", "GraphQL endpoint signal observed", "INFO", "MEDIUM",
                         "API Discovery", response.url, f"HTTP {response.status_code}",
                         "A GraphQL-like endpoint is present and should enforce authorization and query limits.",
                         "Review introspection policy, authorization, and query complexity controls.")

    def check_source_maps(self, scripts):
        for script_url, _, _ in scripts[:10]:
            if self.manager.stop_reason:
                break
            parsed = urlparse(script_url)
            if parsed.hostname not in (self.domain, f"www.{self.domain}") or not parsed.path.endswith(".js"):
                continue
            map_url = urlunparse(parsed._replace(path=parsed.path + ".map"))
            response = self.get(map_url)
            if response is None or response.status_code != 200:
                continue
            try:
                payload = response.json()
            except (ValueError, requests.exceptions.JSONDecodeError):
                continue
            if isinstance(payload, dict) and isinstance(payload.get("sources"), list):
                self.add("WEB-SOURCEMAP-001", "JavaScript source map is public", "LOW", "MEDIUM",
                         "Source Exposure", map_url, f"Source map contains {len(payload['sources'])} sources",
                         "Source maps can reveal original source filenames and implementation details.",
                         "Remove production maps or restrict access; do not include secrets in client bundles.")

    def check_waf_rate(self, url, response):
        headers = {key.lower(): value for key, value in response.headers.items()}
        waf = [name for key, name in (
            ("cf-ray", "Cloudflare"), ("x-sucuri-id", "Sucuri"),
            ("x-iinfo", "Imperva"), ("x-akamai", "Akamai"),
        ) if key in headers]
        if any(key.startswith(("ratelimit-", "x-ratelimit-")) for key in headers):
            self.add("WEB-RATE-001", "Rate-limit metadata observed", "INFO", "MEDIUM",
                     "Rate Limiting", url,
                     ", ".join(key for key in headers if key.startswith(("ratelimit-", "x-ratelimit-"))),
                     "Rate-related headers appeared in an ordinary response; enforcement is not confirmed.",
                     "Validate throttling thresholds using approved low-volume operational tests.")
        if waf:
            self.add("WEB-WAF-001", "WAF/CDN response signals observed", "INFO", "MEDIUM",
                     "WAF/CDN", url, ", ".join(waf),
                     "Response headers indicate an edge service; this does not verify rule coverage.",
                     "Keep edge policies consistent across application and API routes.")

    def check_traffic(self, url):
        self.logger.phase("CONTROLLED TRAFFIC")
        old_delay = self.manager.limiter.delay
        self.manager.limiter.delay = max(old_delay, 1.0)
        observations = []
        try:
            for _ in range(2):
                if self.manager.stop_reason:
                    break
                response = self.get(url, headers={"Cache-Control": "no-cache"})
                if response is None:
                    break
                observations.append(response.status_code)
                if response.status_code in (429, 503):
                    break
        finally:
            self.manager.limiter.delay = old_delay
        if observations:
            self.add("WEB-RATE-002", "Low-volume response behavior recorded", "INFO", "LOW",
                     "DoS Protection", url, f"At most two paced GETs: HTTP {observations}",
                     "This bounded check observes responses only; it is not a load test.",
                     "Use service telemetry to validate rate limits and connection protections.")

    def check_controlled_traffic(self, url):
        return self.check_traffic(url)

    def check_active_inputs(self, params, injection=False):
        self.logger.phase("APPLICATION SECURITY / INPUT CHECKS")
        marker = "latent" + secrets.token_hex(5)
        tests = 0
        for url, names in params.items():
            parsed = urlparse(url)
            for name in sorted(names):
                if tests >= (10 if injection else 20) or self.manager.stop_reason:
                    return
                query = parse_qs(parsed.query, keep_blank_values=True)
                query[name] = ["'" + marker if injection else marker]
                test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                baseline = self.get(url) if injection else None
                response = self.get(test_url) if not injection or baseline is not None else None
                tests += 1
                if response is None or marker not in response.text:
                    continue
                if injection:
                    baseline_signatures = {
                        pattern for pattern in ERROR_PATTERNS
                        if re.search(pattern, baseline.text, re.I)
                    }
                    new_signatures = [
                        pattern for pattern in ERROR_PATTERNS
                        if pattern not in baseline_signatures and re.search(pattern, response.text, re.I)
                    ]
                    if not new_signatures:
                        continue
                title = "Quote marker correlated with response" if injection else "Input marker reflected"
                self.add(
                    "WEB-INPUT-001" if injection else "WEB-XSS-REFLECT-001",
                    title, "INFO", "LOW", "Application Security", test_url,
                    f"Parameter={name}; harmless marker reflected; HTTP {response.status_code}"
                    + (f"; new error signatures={new_signatures[:3]}" if injection else ""),
                    "Marker reflection is an indicator only and does not confirm executable XSS or injection.",
                    "Use context-sensitive output encoding and parameterized queries; validate the sink manually.",
                )

    def check_dns(self):
        self.logger.phase("NETWORK / DNS")
        if dns is None:
            self.logger.warn("dnspython is not installed; DNS posture checks are skipped.")
            return
        try:
            ipaddress.ip_address(self.domain)
            self.logger.warn("SPF/DMARC/DNSSEC checks need a hostname, not an IP target.")
            return
        except ValueError:
            pass
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        def query(name, kind):
            try:
                answer = resolver.resolve(name, kind, raise_on_no_answer=False)
                return answer, answer.response
            except dns.exception.DNSException:
                return None, None

        txt, _ = query(self.domain, "TXT")
        values = [
            b"".join(record.strings).decode("utf-8", "replace")
            for record in (txt or [])
        ]
        spf = [item for item in values if item.lower().startswith("v=spf1")]
        if not spf:
            self.add("DNS-SPF-001", "SPF record not observed", "LOW", "MEDIUM", "DNS",
                     self.domain, "No v=spf1 TXT value found",
                     "Mail receivers have no SPF policy from this domain to evaluate sender authorization.",
                     "Publish an SPF record for authorized senders.")
        elif len(spf) > 1:
            self.add("DNS-SPF-002", "Multiple SPF records observed", "MEDIUM", "HIGH", "DNS",
                     self.domain, f"{len(spf)} SPF records found",
                     "Multiple SPF records can cause evaluation errors.",
                     "Consolidate senders into a single SPF record.")
        dmarc, _ = query(f"_dmarc.{self.domain}", "TXT")
        if not any(
            b"".join(record.strings).decode("utf-8", "replace").lower().startswith("v=dmarc1")
            for record in (dmarc or [])
        ):
            self.add("DNS-DMARC-001", "DMARC record not observed", "LOW", "MEDIUM", "DNS",
                     self.domain, f"No v=DMARC1 TXT value at _dmarc.{self.domain}",
                     "Receivers have no domain-published DMARC handling policy.",
                     "Publish a DMARC policy and tune it using aggregate reports.")
        dnskey, response = query(self.domain, "DNSKEY")
        authenticated = bool(
            dnskey and response and
            (response.flags & dns.flags.AD or any(
                rrset.rdtype == dns.rdatatype.RRSIG
                for rrset in list(response.answer) + list(response.authority)
            ))
        )
        if not authenticated:
            self.add("DNS-DNSSEC-001", "DNSSEC validation signal not observed", "INFO", "LOW", "DNS",
                     self.domain, "No authenticated DNSKEY response signal",
                     "DNS answers may lack DNSSEC authentication in some resolver paths.",
                     "Confirm signing and validation with authoritative and validating resolvers.")

    def check_dns_posture(self):
        return self.check_dns()

    def check_tls(self):
        self.logger.phase("NETWORK / TLS")
        if self.manager.stop_reason or not self.manager.reserve():
            return
        host = self.domain
        if not is_public_target(host):
            self.manager.stop("TLS probe blocked because target is not publicly routable")
            return
        try:
            self.manager.limiter.sleep()
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host) as secure:
                    cert = secure.getpeercert()
                    negotiated = secure.version()
            if negotiated in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                self.add("WEB-TLS-001", f"Weak protocol negotiated: {negotiated}", "HIGH", "HIGH",
                         "TLS", self.base_https, negotiated,
                         "The server negotiated an obsolete TLS protocol.",
                         "Require TLS 1.2 or newer.")
            not_after = cert.get("notAfter")
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (expiry - datetime.utcnow()).days
                if days < 0:
                    self.add("WEB-TLS-002", "TLS certificate expired", "CRITICAL", "HIGH", "TLS",
                             self.base_https, not_after, "The certificate is expired.",
                             "Renew the certificate immediately.")
                elif days < 14:
                    self.add("WEB-TLS-003", "TLS certificate expires soon", "MEDIUM", "HIGH",
                             "TLS", self.base_https, f"{days} days remaining",
                             "The certificate expires within 14 days.",
                             "Renew the certificate before expiry.")
        except ssl.SSLCertVerificationError as exc:
            self.add("WEB-TLS-004", "TLS certificate validation failed", "HIGH", "HIGH",
                     "TLS", self.base_https, str(exc),
                     "The certificate could not be validated by the local trust store.",
                     "Install a valid trusted certificate matching the hostname.")
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.logger.debug(f"TLS probe unavailable: {exc}")

    def check_methods_redirects(self, url):
        response = self.get(url, method="OPTIONS")
        if response is not None:
            allow = response.headers.get("Allow", "")
            dangerous = [item for item in allow.split(",")
                         if item.strip().upper() in ("PUT", "DELETE", "TRACE", "CONNECT")]
            if dangerous:
                self.add("WEB-METHOD-001", "Potentially risky HTTP methods advertised", "MEDIUM",
                         "MEDIUM", "HTTP Methods", url, f"Allow: {allow}",
                         "Write or diagnostic methods may increase risk when not required.",
                         "Disable unused methods and enforce authorization at each route.")
        http_response = self.get(self.base_http, allow_redirects=False)
        if http_response and http_response.status_code not in (301, 302, 303, 307, 308):
            self.add("WEB-REDIRECT-001", "HTTP endpoint does not redirect to HTTPS", "MEDIUM",
                     "HIGH", "Redirects", self.base_http, f"HTTP {http_response.status_code}",
                     "Plain HTTP requests may remain unencrypted.",
                     "Redirect HTTP to the equivalent HTTPS URL.")
        elif http_response and http_response.headers.get("Location", "").startswith("https://"):
            self.logger.info("HTTP-to-HTTPS redirect observed.")

    def run(self, mode="all", crawled_urls=None, js_endpoints=None,
            traffic_check=False, injection_check=False,
            crawl_pages=30, crawl_depth=2):
        if mode == "traffic":
            url, response = self.primary()
            if response is not None:
                self.check_waf_rate(url, response)
            if traffic_check and url:
                self.check_traffic(url)
            score, label = risk_score(self.findings)
            return {
                "findings": self.findings, "risk_score": score, "risk_label": label,
                "requests_used": self.manager.count, "elapsed": self.manager.elapsed,
                "safe_stop": self.manager.stop_reason, "crawled_urls": [],
                "scripts": [], "parameters": {}, "forms": [],
            }
        links, scripts, params, forms = discover_site(
            self.domain, self.manager, self.logger,
            max_pages=crawl_pages, max_depth=crawl_depth
        ) if mode in ("all", "web", "crawler", "api") or self.active else ([], [], {}, [])
        self.discovered_urls = links
        self.discovered_params = params
        global DISCOVERED_PARAMETERS
        DISCOVERED_PARAMETERS = params
        self.discovered_scripts = scripts
        url, response = (None, None) if mode == "dns" else self.primary()
        if response is not None:
            self.check_waf_rate(url, response)
            self.check_response_disclosure(url, response)
            self.check_headers(url, response)
            self.check_cookies(url, response)
            self.check_content(url, response)
            self.check_cors(url)
        if mode in ("all", "web", "api", "crawler"):
            self.check_api()
            self.check_source_maps(scripts)
            self.check_exposure()
        if mode in ("all", "web", "tls"):
            self.check_tls()
            self.check_methods_redirects(url or self.base_https)
        if mode in ("all", "web", "dns"):
            self.check_dns()
        if mode in ("all", "web", "crawler"):
            login = next((item for item in links if LOGIN_PATTERN.search(urlparse(item).path)), None)
            if login:
                response = self.get(login)
                if response and (
                    response.status_code == 429 or response.headers.get("Retry-After")
                    or any(key.lower().startswith(("ratelimit-", "x-ratelimit-"))
                           for key in response.headers)
                ):
                    self.add("WEB-AUTH-002", "Login endpoint exposes throttle metadata",
                             "INFO", "MEDIUM", "Authentication", login,
                             f"HTTP {response.status_code}; Retry-After={response.headers.get('Retry-After', '(none)')}",
                             "A passive request observed a rate-control signal; no credentials were submitted.",
                             "Confirm login throttling and recovery controls in authorized operational tests.")
        if traffic_check and url:
            self.check_traffic(url)
        if self.active:
            self.check_active_inputs(params, injection=injection_check)
        if self.manager.stop_reason:
            self.add("WEB-SAFE-STOP-001", "Assessment stopped by a safety threshold", "INFO", "HIGH",
                     "DoS Protection", url or self.base_https, self.manager.stop_reason,
                     "LATENT stopped requests after a configured protective signal.",
                     "Review service logs; resume testing only after an approved operational check.")
        score, label = risk_score(self.findings)
        return {
            "findings": self.findings, "risk_score": score, "risk_label": label,
            "requests_used": self.manager.count, "elapsed": self.manager.elapsed,
            "safe_stop": self.manager.stop_reason,
            "crawled_urls": links, "scripts": scripts, "parameters": params, "forms": forms,
        }


def scan_ports(target, limit=1000, threads=30, logger=None):
    logger = logger or Logger()
    logger.phase("NETWORK / PORT DISCOVERY")
    addresses = resolve_ips(target)
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        logger.warn("Port discovery refused an unresolved or non-public target.")
        return []
    ports = range(1, min(max(1, limit), 1000) + 1)

    def probe(port):
        for address in addresses:
            family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            try:
                with socket.socket(family, socket.SOCK_STREAM) as connection:
                    connection.settimeout(0.4)
                    if connection.connect_ex(sockaddr) != 0:
                        continue
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = "unknown"
                    banner = ""
                    if port in (21, 22, 25, 110, 143, 587):
                        connection.settimeout(0.2)
                        try:
                            banner = connection.recv(128).decode("utf-8", "replace").strip()
                        except OSError:
                            pass
                    return port, service, banner
            except (OSError, ValueError):
                continue
        return None

    found = []
    with ThreadPoolExecutor(max_workers=min(max(1, threads), 20)) as pool:
        futures = [pool.submit(probe, port) for port in ports]
        for future in as_completed(futures):
            item = future.result()
            if item:
                found.append(item)
                logger.ok(f"OPEN {item[0]}/{item[1]}" + (f" | {item[2][:100]}" if item[2] else ""))
    return sorted(found)


def cors_check(domain, logger, session, limiter):
    scope = {domain, f"www.{domain}"}
    manager = REQUEST_MANAGER or RequestManager(session, logger, limiter, allowed_hosts=scope)
    scanner = WebSecurityScanner(domain, logger, session, limiter)
    scanner.manager = manager
    url = scanner.base_https
    return scanner.check_cors(url)


def xss_probe(domain, logger, session, limiter):
    scanner = WebSecurityScanner(domain, logger, session, limiter, active=True)
    params = DISCOVERED_PARAMETERS
    if not params:
        _, _, params, _ = discover_site(domain, scanner.manager, logger)
    scanner.check_active_inputs(params)
    return [
        {"url": finding["target"], "parameter": finding["evidence"].split("Parameter=", 1)[-1].split(";", 1)[0]}
        for finding in scanner.findings if finding["id"] == "WEB-XSS-REFLECT-001"
    ]


def enumerate_subdomains(domain, wordlist, limit=50, logger=None):
    logger = logger or Logger()
    logger.phase("DISCOVERY / SUBDOMAINS")
    found = []
    try:
        with open(wordlist, encoding="utf-8", errors="ignore") as stream:
            names = [line.strip() for line in stream if line.strip() and not line.lstrip().startswith("#")]
    except OSError as exc:
        logger.warn(f"Subdomain wordlist unavailable: {exc}")
        return found
    names = names[:limit] if limit else names
    for label in names:
        candidate = f"{label}.{domain}"
        addresses = resolve_ips(candidate)
        if addresses and all(ipaddress.ip_address(item).is_global for item in addresses):
            found.append((candidate, addresses))
            logger.ok(f"{candidate} -> {', '.join(addresses)}")
    return found


def generate_html_report(data, domain, timestamp, logger=None):
    esc = lambda value: html.escape(str(value), quote=True)
    filename_domain = re.sub(r"[^A-Za-z0-9_.-]", "_", domain)
    path = f"latent_report_{filename_domain}_{timestamp}.html"
    findings = data.get("findings", data.get("web_findings", []))
    rows = []
    colors = {"CRITICAL": "#b42318", "HIGH": "#c4320a", "MEDIUM": "#b54708",
              "LOW": "#027a48", "INFO": "#475467"}
    for finding in findings:
        severity = finding.get("severity", "INFO")
        rows.append(
            '<article class="finding">'
            f'<span class="badge" style="background:{colors.get(severity, "#475467")}">{esc(severity)}</span> '
            f'<strong>{esc(finding.get("id", ""))}: {esc(finding.get("title", ""))}</strong>'
            f'<p><b>Category:</b> {esc(finding.get("category", ""))} | '
            f'<b>Confidence:</b> {esc(finding.get("confidence", ""))}</p>'
            f'<p><b>Target:</b> {esc(finding.get("target", ""))}</p>'
            f'<p><b>Evidence:</b> {esc(finding.get("evidence", ""))}</p>'
            f'<p><b>Description / impact:</b> {esc(finding.get("impact", finding.get("description", "")))}</p>'
            f'<p><b>Remediation:</b> {esc(finding.get("remediation", ""))}</p></article>'
        )
    urls = "".join(f"<li>{esc(item)}</li>" for item in data.get("crawled_urls", []))
    content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>LATENT assessment — {esc(domain)}</title>
<style>
body{{font:16px system-ui,sans-serif;background:#f3f5f8;color:#182230;margin:0}}
main{{max-width:1100px;margin:auto;padding:24px}} header,.card{{background:#fff;padding:22px;
border-radius:12px;margin-bottom:18px;box-shadow:0 2px 8px #10182812}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}}
.finding{{background:#fff;padding:18px;margin:12px 0;border-left:4px solid #6172f3;
border-radius:8px;overflow-wrap:anywhere}} .badge{{color:white;padding:4px 9px;border-radius:12px}}
pre,li{{overflow-wrap:anywhere}} footer{{color:#667085;padding:20px}}
</style></head><body><main><header><h1>LATENT Security Assessment</h1>
<p>Target: <b>{esc(domain)}</b> | Generated: {esc(timestamp)}</p></header>
<section class="grid"><div class="card"><b>Risk</b><h2>{esc(data.get("risk_score", 0))}/100</h2>
{esc(data.get("risk_label", "LOW"))}</div><div class="card"><b>Findings</b><h2>{len(findings)}</h2></div>
<div class="card"><b>Requests</b><h2>{esc(data.get("request_count", 0))}</h2></div>
<div class="card"><b>Elapsed</b><h2>{esc(data.get("elapsed", 0))}s</h2></div></section>
<section class="card"><h2>Safety</h2><p>Automatic stop: {esc(data.get("safe_stop") or "not triggered")}</p></section>
<section><h2>Findings</h2>{''.join(rows) if rows else '<p>No findings recorded.</p>'}</section>
<section class="card"><h2>Discovered URLs</h2><ul>{urls or '<li>None</li>'}</ul></section>
<footer>For authorized, low-impact security assessments only.</footer></main></body></html>"""
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(content)
    if logger:
        logger.ok(f"HTML report: {path}")
    return path


def build_report(data, path):
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False, default=str)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="LATENT — authorized low-impact security assessment"
    )
    parser.add_argument("-t", "--target", required=True, help="Target hostname or URL")
    parser.add_argument("-w", "--wordlist", default="subdomains.txt")
    parser.add_argument("-p", "--ports", type=int, default=1000)
    parser.add_argument("--threads", type=int, default=30)
    parser.add_argument("--sub-limit", type=int, default=50)
    parser.add_argument("--rate", type=float, default=0.3)
    parser.add_argument("--max-requests", type=int, default=300)
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--crawl-pages", type=int, default=30)
    for flag in ("web", "all", "headers", "tls", "cookies", "cors", "api", "crawler", "dns"):
        parser.add_argument(f"--{flag}", action="store_true")
    parser.add_argument("--active", action="store_true",
                        help="Test harmless reflection markers on discovered parameters")
    parser.add_argument("--injection", action="store_true",
                        help="Opt in to limited harmless quote-marker checks; requires --active")
    parser.add_argument("--traffic-check", action="store_true",
                        help="At most two paced GET observations; stops on throttling")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--html", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    if args.injection and not args.active:
        parser.error("--injection requires --active")
    if args.max_requests < 1 or args.ports < 1 or args.ports > 10000:
        parser.error("--max-requests must be positive and --ports must be between 1 and 10000")
    try:
        target = normalize_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if not is_public_target(target):
        parser.error("Refusing unresolved or non-public targets (SSRF safety policy).")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    txt_path = f"latent_report_{stem}_{stamp}.txt"
    json_path = f"latent_report_{stem}_{stamp}.json"
    global REQUEST_MANAGER
    with open(txt_path, "w", encoding="utf-8") as report_file:
        logger = Logger(report_file, args.verbose)
        session = requests.Session()
        limiter = RateLimiter(args.rate)
        scope = {target}
        try:
            ipaddress.ip_address(target)
        except ValueError:
            scope.add(f"www.{target}")
        REQUEST_MANAGER = RequestManager(
            session, logger, limiter, args.max_requests, allowed_hosts=scope
        )
        configure_http_manager(REQUEST_MANAGER)
        logger.manager = REQUEST_MANAGER
        logger.info(f"Target: {target}")
        logger.info(f"Request budget: {args.max_requests}; minimum interval: {limiter.delay:.1f}s")

        run_web = any((
            args.web, args.all, args.headers, args.tls, args.cookies,
            args.cors, args.api, args.crawler, args.dns, args.active,
            args.injection, args.traffic_check,
        ))
        run_network = args.all or not run_web
        ports, subdomains = [], []
        if run_network:
            logger.phase("NETWORK")
            if not is_public_target(target):
                logger.error("Target no longer resolves to a public address; aborting.")
                return 2
            ports = scan_ports(target, args.ports, args.threads, logger)
            if not re.fullmatch(r"[0-9a-fA-F:.]+", target):
                subdomains = enumerate_subdomains(target, args.wordlist, args.sub_limit, logger)

        mode = (
            "traffic" if args.traffic_check and not any((
                args.all, args.web, args.headers, args.tls, args.cookies,
                args.cors, args.api, args.crawler, args.dns, args.active, args.injection,
            )) else
            "all" if args.all or args.web else next(
            (name for name in ("headers", "tls", "cookies", "cors", "api", "crawler", "dns")
             if getattr(args, name)), "all"
            )
        )
        scanner = WebSecurityScanner(
            target, logger, session, limiter, active=args.active,
            max_requests=args.max_requests,
        )
        result = scanner.run(
            mode=mode, traffic_check=args.traffic_check,
            injection_check=args.injection,
            crawl_pages=args.crawl_pages, crawl_depth=args.crawl_depth,
        )
        findings = result["findings"]
        score, label = risk_score(findings)
        summary = {
            "target": target,
            "timestamp": stamp,
            "risk_score": score,
            "risk_label": label,
            "findings": findings,
            "open_ports": ports,
            "subdomains": subdomains,
            "crawled_urls": result["crawled_urls"],
            "scripts": result["scripts"],
            "parameters": result["parameters"],
            "forms": result["forms"],
            "request_count": REQUEST_MANAGER.count,
            "request_budget": REQUEST_MANAGER.budget,
            "elapsed": round(REQUEST_MANAGER.elapsed, 2),
            "safe_stop": REQUEST_MANAGER.stop_reason,
            "status_codes": dict(REQUEST_MANAGER.status_codes),
            "errors": logger.errors,
            "warnings": logger.warnings,
        }
        if args.json:
            build_report(summary, json_path)
            logger.ok(f"JSON report: {json_path}")
        if args.html:
            generate_html_report(summary, target, stamp, logger)
        logger.phase("FINDINGS")
        logger.ok(f"Findings: {len(findings)} | Risk: {score}/100 ({label})")
        logger.ok(f"Requests: {REQUEST_MANAGER.count}/{REQUEST_MANAGER.budget}")
        logger.ok(f"Elapsed: {REQUEST_MANAGER.elapsed:.1f}s")
        logger.info(f"Safe stop: {REQUEST_MANAGER.stop_reason or 'not triggered'}")
        logger.ok(f"Text report: {txt_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
