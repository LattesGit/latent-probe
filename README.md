# LATENT

> **Multi-Phase Web & Network Pentest & Reconnaissance Toolkit**

LATENT is a Python-based security assessment tool designed to automate multiple phases of **web reconnaissance, network enumeration, vulnerability probing, and report generation** from a single CLI application.

It combines several common security-testing techniques into one workflow, including port scanning, subdomain enumeration, web fingerprinting, directory discovery, XSS reflection testing, CORS analysis, JWT inspection, JavaScript endpoint extraction, crawling, optional SQLMap integration, and screenshot collection.

> ⚠️ **For authorized security testing only.**
> Only use LATENT against systems, domains, and networks that you own or have explicit permission to test.

---

## ✨ Features

### 🌐 Web Reconnaissance

* HTTP/HTTPS detection
* HTML fetching and local saving
* Technology fingerprinting
* Server and `X-Powered-By` detection
* Security header analysis
* CMS/framework detection
* JavaScript library detection
* API endpoint discovery
* Authentication/JWT indicators

### 🔎 Network Enumeration

* TCP port scanning
* Configurable maximum port
* Multi-threaded scanning
* Service name detection
* SMB port detection
* Optional SMB share enumeration

### 🌍 Subdomain Enumeration

* Wordlist-based enumeration
* DNS resolution
* Async DNS support with `aiodns`
* Configurable subdomain limit
* Progress bars with `tqdm`

### 🕷️ Web Crawling

* Recursive website crawling
* Configurable crawl depth
* Configurable page limit
* URL extraction from:

  * `<a>`
  * `<form>`
  * `<link>`
  * `<script>`
  * `<img>`

### 💉 XSS Reflection Testing

LATENT can perform basic reflected-XSS probing against discovered web pages using a predefined payload set.

The tool checks whether supplied test payloads are reflected back into the HTTP response.

### 📁 Directory Discovery

Includes common paths such as:

```text
/admin
/login
/dashboard
/api
/swagger
/.env
/.git
/backup
/phpmyadmin
/wp-admin
/uploads
/config
/debug
```

and many more.

### 🔐 Authentication Testing

Optional login testing against common authentication endpoints.

Supported paths include:

```text
/login
/admin
/wp-login.php
/administrator
/user/login
/signin
/auth
```

The feature is **disabled by default** and must be explicitly enabled with:

```bash
--brute
```

### 🗄️ SQLMap Integration

LATENT can optionally invoke SQLMap against the target.

Enable with:

```bash
--sqlmap
```

SQLMap output is stored separately for later analysis.

### 🔗 JavaScript Endpoint Extraction

LATENT analyzes JavaScript files for potentially interesting:

* API endpoints
* REST routes
* GraphQL endpoints
* Authentication routes
* WebSocket URLs
* Configuration paths
* Potentially exposed secrets

Example patterns:

```text
/api
/graphql
/rest
/auth
/login
/upload
/download
/ws://
wss://
```

### 🛡️ CORS Analysis

Tests common origins and checks for potentially dangerous CORS configurations.

Examples include:

```text
https://evil.com
http://evil.com
null
http://localhost
http://127.0.0.1
```

The tool reports findings using severity levels such as:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

### 🎫 JWT Analysis

If PyJWT is installed, LATENT can:

* Detect JWT tokens
* Decode headers
* Decode payloads without verification
* Identify signing algorithms
* Detect `alg: none`
* Test a small set of common weak secrets
* Identify potentially sensitive payload fields

### 📸 Screenshot Collection

With Playwright installed, LATENT can automatically capture screenshots of:

```text
/
 /admin
 /login
 /dashboard
 /api
 /upload
 /config
```

as well as selected crawled URLs.

### 📊 Report Generation

LATENT supports multiple report formats:

```text
TXT
JSON
HTML
```

The HTML report contains a visual dashboard with:

* Open ports
* Subdomains
* XSS results
* Interesting paths
* Crawled URLs
* JS endpoints
* CORS findings
* JWT findings
* Screenshots
* WHOIS information

---

# 🧰 Requirements

* Python **3.9+**
* Linux / Kali Linux recommended
* `pip`
* Optional external tools:

  * SQLMap
  * smbclient
  * Playwright

---

# 📦 Installation

Clone the repository:

```bash
git clone https://github.com/LaxenTgit/latent-probe.git
cd latent-probe
```

Install the main dependencies:

```bash
pip install requests urllib3 tqdm python-whois aiodns beautifulsoup4 PyJWT
```

For screenshot support:

```bash
pip install playwright
playwright install chromium
```

For SMB enumeration:

```bash
sudo apt install smbclient
```

For SQLMap integration:

```bash
sudo apt install sqlmap
```

---

# 🚀 Basic Usage

Basic scan:

```bash
python3 latent.py -t example.com
```

Specify a wordlist:

```bash
python3 latent.py -t example.com -w subdomains.txt
```

Scan the first 5000 TCP ports:

```bash
python3 latent.py -t example.com -p 5000
```

Increase scanning threads:

```bash
python3 latent.py -t example.com --threads 250
```

Enable verbose output:

```bash
python3 latent.py -t example.com -v
```

---

# 🔥 Full Scan

A more complete assessment can be started with:

```bash
python3 latent.py \
    -t example.com \
    -w subdomains.txt \
    -p 1000 \
    --threads 150 \
    --sub-limit 100 \
    --crawl-depth 2 \
    --crawl-pages 50 \
    --json \
    --html \
    --screenshot \
    -v
```

---

# ⚔️ Optional Active Testing

### Login Testing

```bash
python3 latent.py -t example.com --brute
```

### SQLMap

```bash
python3 latent.py -t example.com --sqlmap
```

### Both

```bash
python3 latent.py -t example.com --brute --sqlmap
```

> These options generate active requests against the target. Only use them where you have explicit authorization.

---

# ⚙️ CLI Options

| Option             | Description                    |
| ------------------ | ------------------------------ |
| `-t`, `--target`   | Target domain or URL           |
| `-w`, `--wordlist` | Subdomain/wordlist file        |
| `-p`, `--ports`    | Maximum TCP port               |
| `--threads`        | Number of port scanner threads |
| `--sub-limit`      | Maximum number of subdomains   |
| `--rate`           | Delay between requests         |
| `--brute`          | Enable login testing           |
| `--sqlmap`         | Enable SQLMap integration      |
| `--json`           | Generate JSON report           |
| `--html`           | Generate HTML report           |
| `--screenshot`     | Enable Playwright screenshots  |
| `--crawl-depth`    | Maximum crawler depth          |
| `--crawl-pages`    | Maximum pages to crawl         |
| `-v`, `--verbose`  | Enable verbose logging         |

---

# 📁 Output

A typical scan generates files similar to:

```text
latent_report_example.com_20260822_153000.txt
latent_report_example.com_20260822_153000.json
latent_report_example.com_20260822_153000.html

example.com_index.html
example.com_sqlmap.txt

screenshots_example.com/
├── example_com.png
├── example_com_admin.png
├── example_com_login.png
└── ...
```

---

# 🧠 Scan Workflow

LATENT follows a multi-phase workflow:

```text
                    ┌───────────────┐
                    │    TARGET     │
                    └───────┬───────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ HTML / Fingerprint│
                  └─────────┬─────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        Port Scan      Subdomains      WHOIS
              │             │
              └──────┬──────┘
                     ▼
              ┌──────────────┐
              │ Web Discovery│
              └──────┬───────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Crawler    Directories   JS
          │          │          │
          └──────────┼──────────┘
                     ▼
             ┌───────────────┐
             │ Security Tests│
             └───────┬───────┘
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
      XSS           CORS          JWT
       │
       ▼
   SQLMap / Brute
       │
       ▼
  ┌──────────────┐
  │   Reports    │
  └──────────────┘
```

---

# 🛠️ Technology Stack

LATENT is primarily written in:

```text
Python
```

Major libraries used:

* `requests`
* `urllib3`
* `asyncio`
* `aiodns`
* `BeautifulSoup4`
* `PyJWT`
* `Playwright`
* `tqdm`

External integrations:

* SQLMap
* smbclient

---

# 🔒 Security & Authorization

LATENT contains functionality capable of generating active requests and performing security tests.

You should **never** run it against:

* systems you don't own
* networks without permission
* third-party websites without authorization
* production infrastructure without approval

Recommended environments:

```text
Your own server
Local lab
CTF environment
TryHackMe
Hack The Box
Bug bounty scope
Authorized penetration test
```

Always respect the rules and scope of the environment you're testing.

---

# 🧪 Recommended Lab Environment

For learning and testing, LATENT can be used against intentionally vulnerable applications such as:

```text
OWASP Juice Shop
DVWA
Metasploitable
WebGoat
Local Docker labs
CTF targets
```

---

# ⚠️ Limitations

LATENT is intended as an automated reconnaissance and assessment helper, **not a replacement for professional penetration-testing tools or manual analysis**.

Some detections may produce:

* False positives
* False negatives
* Incomplete technology fingerprints
* Incorrect authentication candidates
* Reflected-XSS indicators that require manual verification

Findings should always be manually validated before being reported as vulnerabilities.

---

# 🗺️ Roadmap

Planned improvements:

* [ ] Better HTTP fingerprinting
* [ ] More accurate XSS detection
* [ ] Parameter discovery
* [ ] HTTP method testing
* [ ] Improved API discovery
* [ ] Better vulnerability deduplication
* [ ] CVE lookup integration
* [ ] Nuclei integration
* [ ] Better HTML dashboard
* [ ] PDF report generation
* [ ] Config file support
* [ ] Plugin architecture
* [ ] Async HTTP scanning
* [ ] Improved rate limiting
* [ ] Scope/allowlist enforcement

---

# 🤝 Contributing

Contributions, bug reports and feature suggestions are welcome.

Typical workflow:

```bash
git fork
git clone
git checkout -b feature/my-feature
```

Make your changes, test them, and open a pull request.

Please keep contributions focused on **authorized security testing and defensive research**.

---

# 📜 License

Add your preferred license here.

For example:

```text
MIT License
```

If you use a different license, replace this section accordingly.

---

# 👤 Author

**LATENT**

GitHub: [@LaxenTgit](https://github.com/LaxenTgit)

Project:

**LATENT Phase Web & Network Pentest Tool**

---

<p align="center">

**LATENT v0.3.0**

*Recon • Enumeration • Analysis • Reporting*

</p>
