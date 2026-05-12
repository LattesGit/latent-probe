import requests
from core.logger import log
from core.report import write_report

def xss_test(domain, report):
    pages = [
        f"http://{domain}",
        f"http://{domain}/search",
        f"http://{domain}/login",
        f"https://{domain}"
    ]

    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ]

    for page in pages:
        try:
            r = requests.get(page, timeout=5)

            if "input" in r.text.lower() or "form" in r.text.lower():
                for payload in payloads:
                    test_url = f"{page}?q={payload}"

                    r2 = requests.get(test_url, timeout=5)

                    if payload in r2.text:
                        log(f"XSS POSSIBLE {test_url}", "WARN")
                        write_report(report, f"XSS {test_url}")

        except:
            pass
