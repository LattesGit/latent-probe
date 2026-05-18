
# SQLMap Module - sqlmap_module.py
#!/usr/bin/env python3
import subprocess
import os
import re
import json
from datetime import datetime

SQLMAP_DEFAULT_ARGS = [
    "--batch",
    "--random-agent",
    "--level", "2",
    "--risk", "2",
    "--threads", "4",
    "--time-sec", "5"
]

TAMPERS = [
    "space2comment",
    "between",
    "charencode",
    "randomcase",
    "space2plus"
]


def check_sqlmap_installed():
    try:
        result = subprocess.run(
            ["sqlmap", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except Exception:
        return False


def run_sqlmap(url, extra_args=None, output_dir=None, log_callback=None):
    if not check_sqlmap_installed():
        if log_callback:
            log_callback("sqlmap not found in PATH", "FAIL")
        return None
    
    cmd = ["sqlmap", "-u", url] + SQLMAP_DEFAULT_ARGS
    
    if extra_args:
        cmd.extend(extra_args)
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(["--output-dir", output_dir])
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_dir = f"sqlmap_output_{ts}"
        os.makedirs(default_dir, exist_ok=True)
        cmd.extend(["--output-dir", default_dir])
    
    try:
        if log_callback:
            log_callback(f"sqlmap -u {url}", "INFO")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        output = result.stdout
        
        parsed = parse_sqlmap_output(output)
        
        return {
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "stdout": output,
            "stderr": result.stderr,
            "parsed": parsed
        }
    
    except subprocess.TimeoutExpired:
        if log_callback:
            log_callback("sqlmap timeout after 300s", "WARN")
        return {"error": "timeout", "command": " ".join(cmd)}
    
    except Exception as e:
        if log_callback:
            log_callback(f"sqlmap error: {e}", "FAIL")
        return {"error": str(e), "command": " ".join(cmd)}


def parse_sqlmap_output(output):
    findings = {
        "vulnerable": False,
        "dbms": None,
        "techniques": [],
        "databases": [],
        "tables": [],
        "columns": [],
        "dump": False
    }
    
    if "is vulnerable" in output.lower() or "injectable" in output.lower():
        findings["vulnerable"] = True
    
    dbms_match = re.search(r'the back-end DBMS is ([^\n]+)', output, re.IGNORECASE)
    if dbms_match:
        findings["dbms"] = dbms_match.group(1).strip()
    
    techniques = re.findall(r'Parameter [^\n]+ is ([^\n]+) injectable', output, re.IGNORECASE)
    findings["techniques"] = techniques
    
    dbs = re.findall(r'\[\*\] ([^\n]+)', output)
    findings["databases"] = [d for d in dbs if d.strip() and not d.startswith("---")]
    
    if "dumped" in output.lower() or "dump" in output.lower():
        findings["dump"] = True
    
    return findings


def run_with_tampers(url, output_dir=None, log_callback=None):
    results = []
    
    for tamper in TAMPERS:
        extra = ["--tamper", tamper]
        result = run_sqlmap(url, extra_args=extra, output_dir=output_dir, log_callback=log_callback)
        
        if result and result.get("parsed", {}).get("vulnerable"):
            results.append({
                "tamper": tamper,
                "result": result,
                "success": True
            })
            break
        else:
            results.append({
                "tamper": tamper,
                "result": result,
                "success": False
            })
    
    return results


def scan_forms(url, output_dir=None, log_callback=None):
    if not check_sqlmap_installed():
        return None
    
    cmd = [
        "sqlmap", "-u", url,
        "--forms",
        "--batch",
        "--random-agent",
        "--level", "1",
        "--risk", "1"
    ]
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(["--output-dir", output_dir])
    
    try:
        if log_callback:
            log_callback(f"sqlmap --forms -u {url}", "INFO")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        return {
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "parsed": parse_sqlmap_output(result.stdout)
        }
    
    except Exception as e:
        return {"error": str(e), "command": " ".join(cmd)}


def scan_cookies(url, cookie_string, output_dir=None, log_callback=None):
    if not check_sqlmap_installed():
        return None
    
    cmd = [
        "sqlmap", "-u", url,
        "--cookie", cookie_string,
        "--batch",
        "--random-agent",
        "--level", "2",
        "--risk", "2"
    ]
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(["--output-dir", output_dir])
    
    try:
        if log_callback:
            log_callback(f"sqlmap --cookie -u {url}", "INFO")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        return {
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "parsed": parse_sqlmap_output(result.stdout)
        }
    
    except Exception as e:
        return {"error": str(e), "command": " ".join(cmd)}


def scan_post_data(url, data_file, output_dir=None, log_callback=None):
    if not check_sqlmap_installed():
        return None
    
    cmd = [
        "sqlmap", "-u", url,
        "--data-file", data_file,
        "--batch",
        "--random-agent",
        "--level", "2",
        "--risk", "2"
    ]
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(["--output-dir", output_dir])
    
    try:
        if log_callback:
            log_callback(f"sqlmap --data-file -u {url}", "INFO")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        return {
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "parsed": parse_sqlmap_output(result.stdout)
        }
    
    except Exception as e:
        return {"error": str(e), "command": " ".join(cmd)}


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SQLMap Integration Module")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--forms", action="store_true", help="Scan forms")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--data-file", help="POST data file")
    parser.add_argument("--tamper-loop", action="store_true", help="Try multiple tampers")
    parser.add_argument("-o", "--output", help="Output directory")
    args = parser.parse_args()
    
    print(f"[*] SQLMap Module: {args.url}")
    
    if not check_sqlmap_installed():
        print("[!] sqlmap not found. Install: apt install sqlmap")
        exit(1)
    
    if args.forms:
        result = scan_forms(args.url, output_dir=args.output)
    elif args.cookie:
        result = scan_cookies(args.url, args.cookie, output_dir=args.output)
    elif args.data_file:
        result = scan_post_data(args.url, args.data_file, output_dir=args.output)
    elif args.tamper_loop:
        results = run_with_tampers(args.url, output_dir=args.output)
        for r in results:
            status = "VULN" if r["success"] else "OK"
            print(f"[{status}] Tamper: {r['tamper']}")
        exit(0)
    else:
        result = run_sqlmap(args.url, output_dir=args.output)
    
    if result:
        print(f"[+] Return code: {result['returncode']}")
        if result.get("parsed", {}).get("vulnerable"):
            print("[!] SQL INJECTION DETECTED")
            print(f"    DBMS: {result['parsed']['dbms']}")
            print(f"    Techniques: {', '.join(result['parsed']['techniques'])}")
        else:
            print("[+] No SQLi found")
        
        if result.get("stdout"):
            log_file = f"sqlmap_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(log_file, "w") as f:
                f.write(result["stdout"])
            print(f"[*] Log saved: {log_file}")
'''

with open('/mnt/agents/output/sqlmap_module.py', 'w', encoding='utf-8') as f:
    f.write(sqlmap_code)

print("sql.py")
