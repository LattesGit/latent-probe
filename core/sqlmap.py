import subprocess
from core.logger import log
from core.report import write_report

def sqlmap_scan(domain, report):
    targets = [
        f"http://{domain}",
        f"https://{domain}"
    ]

    for t in targets:
        log(f"SQLMAP {t}")
        write_report(report, f"SQLMAP {t}")

        try:
            result = subprocess.run(
                [
                    "sqlmap", "-u", t,
                    "--batch",
                    "--random-agent",
                    "--level", "2",
                    "--risk", "2"
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            write_report(report, result.stdout)

        except Exception as e:
            write_report(report, f"SQLMAP error {e}")
