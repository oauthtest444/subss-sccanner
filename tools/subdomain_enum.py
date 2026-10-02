#!/usr/bin/env python3
"""
Fast passive subdomain enumeration + same-host HTTP validation.

Sources:
  1. crt.name certificate transparency API
  2. Wayback CDX domain index

For every unique discovered subdomain:
  - resolve it with DNS
  - request https://subdomain/
  - follow at most 4 redirects
  - keep it only when the final response:
      * is HTTP 200
      * has a text/html Content-Type
      * remains on the exact same hostname

Redirects to another subdomain are skipped.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import socket
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "Mozilla/5.0 (SubdomainEnumerator/1.0)"
CRT_API = "https://crt.name/v1/search"
WAYBACK_API = "https://web.archive.org/cdx/search/cdx"

SUBDOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-61-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.I,
)


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/", 1)[0].split(":", 1)[0]
    return value


def is_subdomain(host: str, apex: str) -> bool:
    host = host.lower().rstrip(".")
    apex = apex.lower().rstrip(".")
    return host != apex and host.endswith("." + apex)


def normalize_subdomain(value: str, apex: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/", 1)[0]
    if ":" in value:
        value = value.rsplit(":", 1)[0]

    if not value or not is_subdomain(value, apex):
        return None

    if not SUBDOMAIN_RE.fullmatch(value):
        return None

    return value


def crt_subdomains(apex: str, timeout: int) -> set[str]:
    found: set[str] = set()

    try:
        r = requests.get(
            CRT_API,
            params={"apex": apex},
            headers={"User-Agent": UA},
            timeout=timeout,
        )
        r.raise_for_status()

        # crt.name may return JSON, while some deployments/proxies return
        # plain text or HTML. Do not fail the whole enumeration just because
        # the response is not JSON.
        try:
            data = r.json()

            def walk(obj):
                if isinstance(obj, str):
                    candidate = normalize_subdomain(obj, apex)
                    if candidate:
                        found.add(candidate)
                    # Also inspect strings containing SAN-style hostnames.
                    for match in re.findall(
                        rf"(?i)(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{re.escape(apex)}",
                        obj,
                    ):
                        candidate = normalize_subdomain(match, apex)
                        if candidate:
                            found.add(candidate)
                elif isinstance(obj, dict):
                    for value in obj.values():
                        walk(value)
                elif isinstance(obj, list):
                    for value in obj:
                        walk(value)

            walk(data)

        except ValueError:
            # Fallback for non-JSON response bodies.
            body = r.text or ""
            pattern = re.compile(
                rf"(?i)(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{re.escape(apex)}"
            )
            for match in pattern.findall(body):
                candidate = normalize_subdomain(match, apex)
                if candidate:
                    found.add(candidate)

            if not found:
                print(
                    f"[!] crt.name returned non-JSON data "
                    f"(HTTP {r.status_code}, Content-Type: "
                    f"{r.headers.get('Content-Type', 'unknown')})",
                    file=sys.stderr,
                )
    except Exception as exc:
        print(f"[!] crt.name error: {exc}", file=sys.stderr)

    return found


def wayback_subdomains(apex: str, timeout: int) -> set[str]:
    found: set[str] = set()

    params = {
        "url": apex,
        "matchType": "domain",
        "fl": "original",
        "collapse": "urlkey",
        "output": "text",
    }

    try:
        r = requests.get(
            WAYBACK_API,
            params=params,
            headers={"User-Agent": UA},
            timeout=timeout,
        )
        r.raise_for_status()

        for line in r.text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Equivalent to:
            # sed -E 's#^[a-zA-Z]+://##; s#/.*##; s#:[0-9]+$##'
            line = re.sub(r"^[a-zA-Z]+://", "", line)
            line = re.sub(r"/.*$", "", line)
            line = re.sub(r":[0-9]+$", "", line)

            candidate = normalize_subdomain(line, apex)
            if candidate:
                found.add(candidate)

    except Exception as exc:
        print(f"[!] Wayback error: {exc}", file=sys.stderr)

    return found


def resolve(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False
    except OSError:
        return False


def same_hostname(url: str, expected: str) -> bool:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".") == expected
    except Exception:
        return False


def validate_subdomain(
    host: str,
    timeout: int,
    max_redirects: int,
) -> tuple[str, str] | None:
    """
    Return (host, final_url) only when:
      - DNS resolves
      - final response is 200
      - Content-Type is text/html
      - final hostname exactly equals the tested hostname
      - no more than max_redirects redirects are followed

    Redirects are followed manually so a cross-subdomain redirect can be
    rejected immediately rather than silently accepted.
    """
    if not resolve(host):
        return None

    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    current = f"https://{host}/"

    for _ in range(max_redirects + 1):
        try:
            response = session.get(
                current,
                timeout=timeout,
                allow_redirects=False,
                verify=True,
                stream=True,
            )
        except requests.RequestException:
            # Some valid hosts have broken TLS. Retry over HTTP, but still
            # require the final host to remain exactly the same.
            if current.startswith("https://"):
                current = "http://" + current[len("https://"):]
                continue
            return None

        try:
            location = response.headers.get("Location")

            if response.is_redirect or response.is_permanent_redirect:
                if not location:
                    return None

                next_url = requests.compat.urljoin(current, location)
                next_host = (urlparse(next_url).hostname or "").lower().rstrip(".")

                # Explicit requirement: do not test/accept redirects to a
                # different subdomain/hostname.
                if next_host != host:
                    return None

                current = next_url
                continue

            final_host = (urlparse(response.url).hostname or "").lower().rstrip(".")
            content_type = response.headers.get("Content-Type", "").lower()

            if (
                response.status_code == 200
                and final_host == host
                and "text/html" in content_type
            ):
                return host, response.url

            return None
        finally:
            response.close()

    return None


def write_lines(path: str, values: Iterable[str]) -> None:
    Path(path).write_text(
        "\n".join(sorted(set(values))) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fast crt.name + Wayback subdomain enumeration and same-host HTML validation."
    )
    parser.add_argument("domain", help="Apex domain, e.g. byteplus.com")
    parser.add_argument(
        "-o", "--output",
        default="valid-subdomains.txt",
        help="Output file (default: valid-subdomains.txt)",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=40,
        help="Concurrent validation workers (default: 40)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=8,
        help="Per-request/DNS timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "-r", "--max-redirects",
        type=int,
        default=4,
        help="Maximum redirects per subdomain (default: 4)",
    )
    parser.add_argument(
        "--all-subs",
        default="all-subdomains.txt",
        help="Save the combined normalized subdomain list here",
    )
    args = parser.parse_args()

    apex = normalize_domain(args.domain)
    if not apex or "." not in apex:
        print("[!] Invalid apex domain.", file=sys.stderr)
        return 2

    workers = max(1, min(args.workers, 200))
    max_redirects = max(0, min(args.max_redirects, 4))

    print(f"[+] Apex domain : {apex}")
    print("[+] Sources      : crt.name + Wayback CDX")
    print(f"[+] Workers      : {workers}")
    print(f"[+] Max redirects: {max_redirects}")
    print()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        crt_future = pool.submit(crt_subdomains, apex, args.timeout)
        wb_future = pool.submit(wayback_subdomains, apex, args.timeout)

        crt = crt_future.result()
        wayback = wb_future.result()

    combined = sorted(crt | wayback)
    write_lines(args.all_subs, combined)

    print(f"[+] crt.name subdomains : {len(crt)}")
    print(f"[+] Wayback subdomains  : {len(wayback)}")
    print(f"[+] Unique subdomains   : {len(combined)}")
    print(f"[+] Saved all subs      : {args.all_subs}")
    print()

    if not combined:
        print("[!] No subdomains discovered.")
        Path(args.output).write_text("", encoding="utf-8")
        return 0

    valid: list[tuple[str, str]] = []
    total = len(combined)

    def check(host: str):
        return validate_subdomain(host, args.timeout, max_redirects)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check, host): host for host in combined}

        for index, future in enumerate(
            concurrent.futures.as_completed(futures), 1
        ):
            host = futures[future]
            try:
                result = future.result()
            except Exception:
                result = None

            if result:
                valid.append(result)
                print(f"[+] VALID [{index}/{total}] {result[0]} -> {result[1]}", flush=True)
            else:
                print(f"[-] {index}/{total} {host}", flush=True)

    valid_hosts = sorted({host for host, _ in valid})
    write_lines(args.output, valid_hosts)

    print()
    print(f"[+] Valid same-host HTML subdomains: {len(valid_hosts)}")
    print(f"[+] Saved: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
