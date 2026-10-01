import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Latent.http_client import manager_for_target
from Latent.main import Logger, WebSecurityScanner, discover_site


def _scan(target, session=None, logger=None):
    logger = logger or Logger()
    manager = manager_for_target(target, session=session, logger=logger)
    scanner = WebSecurityScanner(
        target, logger, session=manager.session, limiter=manager.limiter,
        active=True, max_requests=manager.budget,
    )
    scanner.manager = manager
    links, scripts, params, forms = discover_site(target, manager, logger, max_pages=20, max_depth=2)
    scanner.check_active_inputs(params)
    return scanner, links, scripts, params, forms


def probe_xss(domain, session=None, rate_limiter=None, pages=None, log_callback=None):
    del rate_limiter, pages
    logger = Logger()
    if log_callback:
        logger.warn = lambda message: log_callback(message, "WARN")
    scanner, _, _, _, _ = _scan(domain, session, logger)
    return [
        {
            "url": finding["target"],
            "parameter": finding["evidence"].split("Parameter=", 1)[-1].split(";", 1)[0],
            "evidence": finding["evidence"],
            "context": "reflected marker; manual context validation recommended",
        }
        for finding in scanner.findings
        if finding["id"] == "WEB-XSS-REFLECT-001"
    ]


def probe_dom_xss(domain, session=None, rate_limiter=None, log_callback=None):
    del rate_limiter
    logger = Logger()
    if log_callback:
        logger.warn = lambda message: log_callback(message, "WARN")
    scanner, _, scripts, _, _ = _scan(domain, session, logger)
    source_patterns = ("location.search", "location.hash", "document.referrer", "window.name")
    sink_patterns = ("innerHTML", "document.write(", "eval(", "insertAdjacentHTML")
    findings = []
    for script_url, _, _ in scripts:
        response = scanner.get(script_url)
        if response is None or response.status_code != 200:
            continue
        content = response.text[:100000]
        sources = [item for item in source_patterns if item in content]
        sinks = [item for item in sink_patterns if item in content]
        if sources and sinks:
            findings.append({"file": script_url, "sources": sources, "sinks": sinks})
    return findings


def probe_blind_xss(domain, callback_url, session=None, rate_limiter=None, log_callback=None):
    del domain, callback_url, session, rate_limiter
    message = "Blind XSS callback injection is disabled; no callback payloads are sent."
    if log_callback:
        log_callback(message, "WARN")
    return []
