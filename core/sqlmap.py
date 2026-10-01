from core.logger import log
from core.report import write_report


def sqlmap_scan(domain, report):
    message = (
        "SQLMap execution is disabled because its generated traffic bypasses "
        "LATENT's shared request budget and low-impact limits."
    )
    log(message, "WARN")
    write_report(report, message, "WARN")
    return False
