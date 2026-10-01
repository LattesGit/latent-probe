import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Latent.main import Logger, RateLimiter, WebSecurityScanner, discover_site
from Latent.http_client import manager_for_target
from core.report import write_report


def xss_test(domain, report, manager=None, logger=None):
    logger = logger or Logger()
    manager = manager or manager_for_target(domain, logger=logger)
    scanner = WebSecurityScanner(
        domain, logger, session=manager.session, limiter=manager.limiter,
        active=True, max_requests=manager.budget,
    )
    scanner.manager = manager
    _, _, parameters, _ = discover_site(domain, manager, logger, max_pages=20, max_depth=2)
    scanner.check_active_inputs(parameters)
    findings = [item for item in scanner.findings if item["id"] == "WEB-XSS-REFLECT-001"]
    for finding in findings:
        write_report(report, f"{finding['id']}: {finding['target']} | {finding['evidence']}", "INFO")
    return findings
