# LATENT — Multi-Phase Web & Network Pentest Framework

```
██╗      █████╗ ████████╗███████╗███╗   ██╗████████╗
██║     ██╔══██╗╚══██╔══╝██╔════╝████╗  ██║╚══██╔══╝
██║     ███████║   ██║   █████╗  ██╔██╗ ██║   ██║   
██║     ██╔══██║   ██║   ██╔══╝  ██║╚██╗██║   ██║   
███████╗██║  ██║   ██║   ███████╗██║ ╚████║   ██║   
╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝   ╚═╝   
```

> **Multi-phase reconnaissance & vulnerability discovery tool for authorized penetration testing.**

---

> ⚠️ **Legal Disclaimer** — LATENT is intended for use on systems you own or have explicit written permission to test. Unauthorized use is illegal. The developers assume no liability for misuse.

---

## Features

| Module | Description |
|--------|-------------|
| 🌐 HTTP Fetch | Content grabbing over HTTP/HTTPS |
| 🔍 Port Scan | TCP connect scan across target ports |
| 🪟 SMB Check | SMB service detection & enumeration |
| 🌿 Subdomain Discovery | Wordlist-based subdomain enumeration |
| 💉 XSS Testing | Basic reflected XSS payload probing |
| 🗄️ SQLMap Integration | Automated SQL injection scanning via SQLMap |
| 🔑 Brute-Force | Login endpoint brute-force attempts |
| 📄 Reporting | Detailed TXT log + HTML & JSON report export |

---

## Requirements

- Python 3.x
- Kali Linux (recommended)
- SQLMap (for `--sqlmap` flag)

### Install dependencies

```bash
pip3 install requests
```

---

## Installation

```bash
git clone https://github.com/youruser/latent.git
cd latent
pip3 install -r requirements.txt
```

---

## Usage

```
python3 main.py -t TARGET [-w WORDLIST] [-p PORT] [--threads N] [--sub-limit N]
                [--rate N] [--brute] [--sqlmap] [--no-color] [--json] [--html]
                [--screenshot] [--crawl-depth N] [--crawl-pages N]
```

### Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `-t`, `--target` | `str` | **Required.** Target URL (e.g. `https://example.com`) |
| `-w`, `--wordlist` | `str` | Path to wordlist file for directory/subdomain brute-force |
| `-p`, `--ports` | `int` | Single port to scan (e.g. `443`) |
| `--threads` | `int` | Number of concurrent threads (default: 10) |
| `--sub-limit` | `int` | Max subdomain entries to test |
| `--rate` | `int` | Requests per second rate limit |
| `--brute` | flag | Enable login brute-force module |
| `--sqlmap` | flag | Enable SQLMap integration |
| `--no-color` | flag | Disable colored terminal output |
| `--json` | flag | Export results as JSON |
| `--html` | flag | Export results as HTML report |
| `--screenshot` | flag | Capture screenshots of discovered pages |
| `--crawl-depth` | `int` | How many levels deep the crawler follows links |
| `--crawl-pages` | `int` | Maximum number of pages to crawl |

---

## Examples

**Basic scan — just the target:**
```bash
python3 main.py -t https://example.com
```

**Full recon with wordlist, crawling, and reports:**
```bash
python3 main.py -t https://example.com -w /usr/share/wordlists/dirb/common.txt --threads 20 --rate 100 --crawl-depth 3 --crawl-pages 50 --html --json
```

**Enable brute-force and SQLMap:**
```bash
python3 main.py -t https://example.com --brute --sqlmap --html
```

**Scan a specific port with subdomain limit:**
```bash
python3 main.py -t https://example.com -p 8080 --sub-limit 200 --json
```

---

## Output

- **Terminal** — Color-coded live output (disable with `--no-color`)
- **`.txt` log** — Always generated in the working directory
- **`.json`** — Machine-readable results (with `--json`)
- **`.html`** — Human-readable report (with `--html`)

---

## Project Structure

```
latent/
├── main.py          # main code
```

---

## Creator
:LATENT
