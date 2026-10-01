# LATENT

**Professional Web & Network Security Assessment Toolkit**

LATENT is a single-file, multi-phase reconnaissance and web security engine built for people who actually read the findings they get back. It doesn't just tell you a header is missing — it tells you why that matters, how confident it is, and what to do about it.

```
======================================================================
                     LATENT | PROBE 
                         discord : @saintlatent
======================================================================
```

> **Entry point:** `Latent/main.py` is the maintained assessment engine. Compatibility helpers in `core/` and `Latent/core/` delegate HTTP work to its bounded request manager; their TCP checks are public-target-only and capped. Credential guessing, SQLMap execution, and callback-based XSS probes remain disabled.

---

## Why LATENT

Most recon scripts dump raw output and leave you to figure out what's actually worth fixing. LATENT is built around a real **Finding model** — every issue it surfaces carries a severity, a confidence score, evidence, a plain-language description, and a concrete remediation step. Run it, get a risk score out of 100, and know immediately whether you're looking at a LOW-risk target or something that needs attention today.

It also does not assume you want to hammer a production server the moment you point it at a domain. The network inventory uses bounded TCP connection checks; HTTP input checks are passive unless explicitly enabled, and active checks use harmless markers rather than executable payloads. Credential guessing, external SQLMap traffic, and browser-driven screenshots are disabled because they can cause impact or bypass request safeguards.

---

## What it actually does

**Network / recon phase**
- Technology fingerprinting (server, framework, CMS, JS libraries, CDN/WAF detection)
- Bounded TCP port discovery (up to 10,000 ports; at most 50 workers)
- SMB share enumeration
- Subdomain enumeration (async via `aiodns` when available)
- Directory / sensitive-file discovery
- WHOIS lookup
- Recursive crawler with JavaScript endpoint extraction
- JWT discovery and weak-secret analysis
- Optional Playwright screenshots

**Web Security Engine**
- HTTP security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP)
- CSP quality analysis (unsafe-inline, unsafe-eval, wildcard sources, missing object-src)
- Cookie security (Secure, HttpOnly, SameSite — values are always masked in reports)
- Clickjacking protection
- TLS/SSL analysis (certificate validity, expiry, hostname match, weak protocol versions)
- HTTP method enumeration (flags dangerous methods like PUT/DELETE/TRACE)
- Redirect chain analysis (HTTPS-to-HTTP downgrade detection)
- Information disclosure (version banners, stack traces, debug output)
- Cache security on sensitive endpoints
- Mixed content detection
- Form security (password fields over HTTP, external form actions, autocomplete)
- CORS misconfiguration detection
- API discovery, Swagger/OpenAPI detection, GraphQL endpoint detection
- SPF, DMARC, and DNSSEC posture signals
- JavaScript source-map exposure and third-party script SRI checks
- WAF/CDN and rate-limit observations; HTTP 429, edge challenges, repeated timeouts, slow responses, and server errors trigger automatic safe stops
- robots.txt / sitemap.xml / security.txt analysis
- Automatic risk scoring (0-100) with LOW / MODERATE / MEDIUM / HIGH / CRITICAL bands

**Safety built in, not bolted on**
- Central HTTP request manager enforces a shared request budget, minimum interval, timeout, response-size cap, redirect validation, and SSRF checks
- SSRF guard refuses private, loopback, link-local, reserved, and unresolved destinations
- No credential guessing, destructive payloads, or load-generation checks are run by default
- Active reflection checks run only against discovered parameters; quote-marker injection checks require both `--injection` and `--active`
- Optional throttling observation makes at most two extra paced GET requests and stops on the first protective response
- Sensitive files are reported as *found*, never dumped

---

## Installation

```bash
git clone https://github.com/LaxenTgit/latent.git
cd latent
pip install -r requirements.txt
```

Optional modules such as `aiodns`, `python-whois`, and `PyJWT` are skipped when their packages are not installed.

---

## Usage

```bash
# Full passive web security scan with an HTML report
python3 Latent/main.py -t example.com --web --html

# Full assessment: network recon + web engine
python3 Latent/main.py -t example.com --all --html --json

# Just headers, CSP and clickjacking
python3 Latent/main.py -t example.com --headers

# Just TLS/certificate checks
python3 Latent/main.py -t example.com --tls

# Just cookies
python3 Latent/main.py -t https://example.com --cookies

# Just CORS
python3 Latent/main.py -t example.com --cors

# API / Swagger / OpenAPI / GraphQL discovery
python3 Latent/main.py -t example.com --api --crawl-depth 3 --crawl-pages 100

# Low-volume throttling observation (at most two extra requests)
python3 Latent/main.py -t example.com --traffic-check

# Harmless reflection and explicitly enabled quote-marker checks
python3 Latent/main.py -t example.com --web --active --injection --max-requests 100

# Cap the web engine's request budget
python3 Latent/main.py -t example.com --web --max-requests 100 --rate 0.5
```

### Flags

| Flag | Description |
|---|---|
| `-t, --target` | Target domain or URL (required) |
| `-w, --wordlist` | Subdomain/password wordlist path |
| `-p, --ports` | Max port to scan |
| `--threads` | Port scan thread count |
| `--sub-limit` | Subdomain enumeration limit (0 = all) |
| `--rate` | Delay between requests, in seconds |
| `--web` | Run the full web security engine |
| `--headers` / `--tls` / `--cookies` / `--cors` / `--api` / `--crawler` | Run a single focused module |
| `--dns` | Check SPF, DMARC, and DNSSEC signals |
| `--all` | Run every phase, network and web |
| `--active` | Enable harmless-marker reflection tests on discovered parameters |
| `--injection` | Explicitly enable bounded quote-marker input checks; requires `--active` |
| `--traffic-check` | Opt into at most two paced GET observations; stops on throttling |
| `--brute` / `--sqlmap` / `--screenshot` | Deprecated compatibility flags; operations are disabled |
| `--max-requests` | Hard cap shared by HTTP modules, redirects, and TLS checks |
| `--json` / `--html` | Emit JSON / HTML reports |
| `-v, --verbose` | Verbose debug logging |

---

## Sample finding

```
ID:          WEB-COOKIE-004
Title:       Cookie SameSite=None without Secure: tracking
Severity:    MEDIUM
Confidence:  HIGH
Evidence:    Set-Cookie: tracking=********
Description: SameSite=None cookies must be Secure or browsers will
             reject/strip them, and without Secure the cookie is
             also exposed on plain HTTP.
Remediation: Pair 'SameSite=None' with the 'Secure' attribute.
```

Every finding in the HTML report looks like this — severity badge, confidence, evidence, why it matters, how to fix it. No guesswork.

---

## Testing

```bash
python3 -m unittest Latent.test_main -v
```

Tests use mocked HTTP transports and do not send live network requests.

---

## Disclaimer

LATENT is built for authorized security assessments — your own infrastructure, or targets you have explicit written permission to test. Unauthorized scanning of systems you don't own or have permission to assess is illegal in most jurisdictions. Use it responsibly.

---

Built and maintained by **LaxenT**.
