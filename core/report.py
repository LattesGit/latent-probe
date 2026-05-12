from datetime import datetime

def write_report(f, msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    f.write(f"[{timestamp}] [{level}] {msg}\n")


def init_report(f, domain, wordlist, max_port, bf, sql, sub_limit):
    write_report(f, f"LATENT Pentest Report - {domain}")
    write_report(f, f"Start: {datetime.now().isoformat()}")
    write_report(f, f"Wordlist: {wordlist}")
    write_report(f, f"Max Port: {max_port}")
    write_report(f, f"Bruteforce: {bf}")
    write_report(f, f"SQLMap: {sql}")
    write_report(f, f"Subdomain limit: {sub_limit}")
    write_report(f, "=" * 60)
