#!/usr/bin/env python3
"""Resolve a hostname to a same-host HTTP(S) URL with a maximum redirect count.

Prints one final URL only when the final response is HTTP 200 and text/html.
"""
import argparse
from urllib.parse import urljoin, urlparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "Mozilla/5.0 (URLBootstrap/1.0)"

def check(start, max_redirects, timeout):
    host = (urlparse(start).hostname or "").lower().rstrip(".")
    if not host:
        return None
    current = start
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    for _ in range(max_redirects + 1):
        try:
            r = session.get(current, timeout=timeout, allow_redirects=False, verify=True, stream=True)
        except requests.RequestException:
            if current.startswith("https://"):
                current = "http://" + current[len("https://"):]
                continue
            return None
        try:
            if 300 <= r.status_code < 400:
                location = r.headers.get("Location")
                if not location:
                    return None
                nxt = urljoin(current, location)
                nxt_host = (urlparse(nxt).hostname or "").lower().rstrip(".")
                if nxt_host != host:
                    return None
                current = nxt
                continue
            final_host = (urlparse(r.url).hostname or "").lower().rstrip(".")
            ctype = r.headers.get("Content-Type", "").lower()
            if r.status_code == 200 and final_host == host and "text/html" in ctype:
                return r.url
            return None
        finally:
            r.close()
    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("hostname")
    p.add_argument("-r", "--max-redirects", type=int, default=4)
    p.add_argument("-t", "--timeout", type=int, default=15)
    args = p.parse_args()
    for scheme in ("https", "http"):
        result = check(f"{scheme}://{args.hostname}/", args.max_redirects, args.timeout)
        if result:
            print(result)
            return 0
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
