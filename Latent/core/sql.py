import re


def check_sqlmap_installed():
    return False


def parse_sqlmap_output(output):
    text = output or ""
    dbms_match = re.search(r"the back-end DBMS is ([^\n]+)", text, re.IGNORECASE)
    techniques = re.findall(r"Parameter [^\n]+ is ([^\n]+) injectable", text, re.IGNORECASE)
    databases = re.findall(r"^\[\*\] ([^\n]+)", text, re.MULTILINE)
    return {
        "vulnerable": "is vulnerable" in text.lower() or "injectable" in text.lower(),
        "dbms": dbms_match.group(1).strip() if dbms_match else None,
        "techniques": techniques,
        "databases": [item for item in databases if item.strip() and not item.startswith("---")],
        "tables": [],
        "columns": [],
        "dump": "dumped" in text.lower() or "dump" in text.lower(),
    }


def _disabled(log_callback=None):
    message = (
        "SQLMap-driven probes are disabled because they generate active traffic "
        "outside LATENT's request manager and safety budget."
    )
    if log_callback:
        log_callback(message, "WARN")
    return None


def run_sqlmap(url, extra_args=None, output_dir=None, log_callback=None):
    del url, extra_args, output_dir
    return _disabled(log_callback)


def run_with_tampers(url, output_dir=None, log_callback=None):
    del url, output_dir
    _disabled(log_callback)
    return []


def scan_forms(url, output_dir=None, log_callback=None):
    del url, output_dir
    return _disabled(log_callback)


def scan_cookies(url, cookie_string, output_dir=None, log_callback=None):
    del url, cookie_string, output_dir
    return _disabled(log_callback)


def scan_post_data(url, data_file, output_dir=None, log_callback=None):
    del url, data_file, output_dir
    return _disabled(log_callback)
