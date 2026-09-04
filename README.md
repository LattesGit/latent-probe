# LATENT

**Professional Web & Network Security Assessment Toolkit**

LATENT is a single-file, multi-phase reconnaissance and web security engine built for people who actually read the findings they get back. It doesn't just tell you a header is missing — it tells you why that matters, how confident it is, and what to do about it.

```
======================================================================
                     LATENT | PROBE 
                         discord : @saintlatent
======================================================================
```

> **Note:** Most of this repo is not up to date, and everything inside the core belongs to a beta version. Expect things to change.

---

## Why LATENT

Most recon scripts dump raw output and leave you to figure out what's actually worth fixing. LATENT is built around a real **Finding model** — every issue it surfaces carries a severity, a confidence score, evidence, a plain-language description, and a concrete remediation step. Run it, get a risk score out of 100, and know immediately whether you're looking at a LOW-risk target or something that needs attention today.

It also does not assume you want to hammer a production server the moment you point it at a domain. Every intrusive capability — brute-force, SQLMap, reflected XSS probing — sits behind an explicit `--active` flag. Left alone, LATENT stays passive: it looks, it fingerprints, it reports. It does not attack.

---

## What it actually does

**Network / recon phase**
- Technology fingerprinting (server, framework, CMS, JS libraries, CDN/WAF detection)
- Port scanning with configurable thread count and port range
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
- robots.txt / sitemap.xml / security.txt analysis
- Automatic risk scoring (0-100) with LOW / MODERATE / MEDIUM / HIGH / CRITICAL bands

**Safety built in, not bolted on**
- SSRF guard resolves the target before scanning and refuses private, loopback, and link-local addresses
- Configurable request budget so the scanner can't run away on you
- Passive by default — nothing destructive fires without `--active`
- Sensitive files are reported as *found*, never dumped

---

## Installation

```bash
git clone https://github.com/LaxenTgit/latent.git
cd latent
pip install requests beautifulsoup4 tqdm python-whois aiodns PyJWT playwright --break-system-packages
```

All heavy dependencies are optional — LATENT degrades gracefully if `playwright`, `aiodns`, `python-whois`, or `PyJWT` aren't installed; those specific modules just get skipped.

---

## Usage

```bash
# Full passive web security scan with an HTML report
python3 latent.py -t example.com --web --html

# Full assessment: network recon + web engine
python3 latent.py -t example.com --all --html --json

# Just headers, CSP and clickjacking
python3 latent.py -t example.com --headers

# Just TLS/certificate checks
python3 latent.py -t example.com --tls

# Just cookies
python3 latent.py -t https://example.com --cookies

# Just CORS
python3 latent.py -t example.com --cors

# API / Swagger / OpenAPI / GraphQL discovery
python3 latent.py -t example.com --api --crawl-depth 3 --crawl-pages 100

# Everything, including the intrusive stuff, explicitly opted in
python3 latent.py -t example.com --all --active --sqlmap --brute --html

# Cap the web engine's request budget
python3 latent.py -t example.com --web --max-requests 100 --rate 0.5
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
| `--all` | Run every phase, network and web |
| `--active` | Unlock intrusive checks (still non-destructive) |
| `--brute` | Login brute-force (requires `--active`) |
| `--sqlmap` | SQLMap integration (requires `--active`) |
| `--screenshot` | Playwright screenshots of key pages |
| `--max-requests` | Hard cap on requests the web engine can issue |
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
python3 -m unittest test_latent_web.py -v
```

32 unit tests cover the web engine's logic against mocked HTTP responses — no live network calls, no accidental scans while you're just running CI.

---

## Disclaimer

LATENT is built for authorized security assessments — your own infrastructure, or targets you have explicit written permission to test. Unauthorized scanning of systems you don't own or have permission to assess is illegal in most jurisdictions. Use it responsibly.

---

Built and maintained by **LaxenT**.
