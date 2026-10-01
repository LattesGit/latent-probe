import sys


def try_login(url, user, pwd):
    del url, user, pwd
    return None


def main():
    print(
        "Credential guessing is disabled. Use an authorized test account and "
        "review the site's documented authentication controls instead."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
