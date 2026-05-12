import requests
from urllib.parse import urlparse
from core.logger import log
from core.report import write_report

def fetch_html(domain, report):
    urls = [
        f"http://{domain}",
        f"https://{domain}",
        f"http://www.{domain}",
        f"https://www.{domain}"
    ]

    for url in urls:
        try:
            log(f"Trying {url}")
            r = requests.get(url, timeout=10, verify=False)

            file_name = f"{domain}_index.html"
            with open(file_name, "w", encoding="utf-8") as f:
                f.write(r.text)

            log(f"Saved HTML {file_name}")
            write_report(report, f"HTML {r.status_code} from {url}")

            return r.text, file_name

        except Exception as e:
            log(f"Failed {url} -> {e}", "WARN")

    write_report(report, "HTML fetch failed")
    return None, None
