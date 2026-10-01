import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Latent.http_client import manager_for_target


def fetch(target, manager=None):
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if not parsed.hostname:
        raise ValueError("A valid target hostname is required.")
    manager = manager or manager_for_target(parsed.hostname)
    url = target if "://" in target else f"https://{target}"
    response = manager.request(url)
    if response is None:
        return None
    filename = f"{re.sub(r'[^A-Za-z0-9_.-]', '_', parsed.netloc)}.html"
    with open(filename, "w", encoding="utf-8") as output:
        output.write(response.text)
    print(f"[+] {response.status_code} - {len(response.content)} bytes; saved {filename}")
    return response.text


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m Latent.core.snaphtml <authorized-target>")
        raise SystemExit(1)
    fetch(sys.argv[1])
