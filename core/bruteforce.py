from core.logger import log
from core.report import write_report


def bruteforce(domain, wordlist, report):
    message = (
        "Credential brute-force is disabled: it can lock accounts and cannot "
        "be safely represented by the low-impact assessment request budget."
    )
    log(message, "WARN")
    write_report(report, message, "WARN")
    return []
