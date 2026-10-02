#!/usr/bin/env python3

import argparse
import os
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


PAYLOAD = "https://evil.com/"

# Wait up to 10 seconds for delayed JavaScript redirects.
DEFAULT_WAIT = 10.0

# Check the browser URL every 0.5 seconds.
POLL_INTERVAL = 0.5

DEFAULT_TIMEOUT = 30000


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)


def load_urls(path):
    """
    Load target URLs.

    The URL is kept exactly as supplied.
    """

    urls = []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        for line in f:

            url = line.strip()

            if not url:
                continue

            if url.startswith("http://") or url.startswith("https://"):
                urls.append(url)

    return urls


def load_parameter_groups(path):
    """
    Each NON-EMPTY LINE in fuzz-params-list.txt is one request.

    Example:

        ?a=testtt&b=testtt&c=testtt
        ?x=testtt&y=testtt

    becomes two separate requests.

    The parameter values from the file are replaced with:

        https://evil.com/

    IMPORTANT:
    Parameters are ONLY read from this file.
    Nothing is extracted from JSON, POST bodies, HTML,
    JavaScript, or target responses.
    """

    groups = []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            if line.startswith("?"):
                line = line[1:]

            try:
                params = parse_qsl(
                    line,
                    keep_blank_values=True,
                )

            except Exception:
                continue

            if not params:
                continue

            names = []

            for name, _ in params:

                name = name.strip()

                if name:
                    names.append(name)

            if names:
                groups.append(names)

    return groups


def build_test_url(base_url, parameter_names):
    """
    Replace/add ONLY query-string parameters.

    The target path is NEVER changed.

    Example:

        https://example.com/test

    with:

        ["next", "url"]

    becomes:

        https://example.com/test?next=https%3A%2F%2Fevil.com%2F&url=https%3A%2F%2Fevil.com%2F

    NOT:

        https://example.com/test/https:/evil.com/
    """

    parts = urlsplit(base_url)

    # Existing query parameters from the target URL.
    existing = parse_qsl(
        parts.query,
        keep_blank_values=True,
    )

    tested_names = set(parameter_names)

    # Preserve existing parameters that aren't being tested.
    preserved = [
        (name, value)
        for name, value in existing
        if name not in tested_names
    ]

    # Replace each parameter from the current fuzz group.
    fuzzed = [
        (name, PAYLOAD)
        for name in parameter_names
    ]

    new_query = urlencode(
        preserved + fuzzed,
        doseq=True,
    )

    # IMPORTANT:
    # scheme
    # hostname
    # path
    # fragment
    #
    # are preserved.
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            new_query,
            parts.fragment,
        )
    )


def is_evil_redirect(original_url, current_url):
    """
    Return True only when the browser reaches evil.com.

    Example confirmed:

        https://evil.com/

        https://evil.com/test

        https://evil.com/?x=1

    NOT confirmed:

        https://chaturbate.com/v2apps/apps/https:/evil.com/
    """

    try:

        original = urlsplit(original_url)
        current = urlsplit(current_url)

        if current.scheme.lower() != "https":
            return False

        if not current.hostname:
            return False

        current_host = current.hostname.lower()

        if current_host != "evil.com":
            return False

        original_host = (
            original.hostname.lower()
            if original.hostname
            else ""
        )

        # Must actually leave the original host.
        if current_host == original_host:
            return False

        return True

    except Exception:
        return False


def wait_for_redirect(
    page,
    original_url,
    wait_seconds,
):
    """
    Wait for delayed client-side redirects.

    Checks every POLL_INTERVAL seconds.

    This handles redirects that happen several seconds
    after the initial page load.
    """

    start = time.monotonic()

    while True:

        current_url = page.url

        if is_evil_redirect(
            original_url,
            current_url,
        ):
            return current_url

        elapsed = time.monotonic() - start

        if elapsed >= wait_seconds:
            return current_url

        page.wait_for_timeout(
            int(POLL_INTERVAL * 1000)
        )


def send_discord(
    webhook,
    original_url,
    test_url,
    final_url,
    parameters,
):
    """
    Send confirmed finding to Discord.
    """

    if not webhook:

        print(
            "       ⚠️ "
            "DISCORD_WEBHOOK_URL is not configured."
        )

        return

    message = {
        "content": "🔴 **JS Redirect Vulnerability Confirmed**",
        "embeds": [
            {
                "title": "Client-Side JS Redirect Confirmed",
                "description": (
                    f"**Original URL:**\n"
                    f"{original_url}\n\n"
                    f"**Test URL:**\n"
                    f"{test_url}\n\n"
                    f"**Final URL:**\n"
                    f"{final_url}\n\n"
                    f"**Parameters:**\n"
                    f"{', '.join(parameters)}\n\n"
                    f"**Payload:**\n"
                    f"{PAYLOAD}"
                ),
            }
        ],
    }

    try:

        response = requests.post(
            webhook,
            json=message,
            timeout=10,
        )

        response.raise_for_status()

        print(
            "       📣 Discord notification sent."
        )

    except Exception as exc:

        print(
            "       ⚠️ Discord notification failed: "
            f"{exc}"
        )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Test query parameter groups for "
            "delayed client-side JavaScript redirects."
        )
    )

    parser.add_argument(
        "-l",
        "--list",
        required=True,
        help="Target URL list",
    )

    parser.add_argument(
        "-p",
        "--params",
        required=True,
        help="Parameter groups file",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="js_redirect_vulnerable.txt",
        help="Output findings file",
    )

    parser.add_argument(
        "--wait",
        type=float,
        default=DEFAULT_WAIT,
        help=(
            "Seconds to wait for delayed redirect. "
            "Default: 10"
        ),
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=(
            "Initial page navigation timeout "
            "in milliseconds."
        ),
    )

    args = parser.parse_args()

    if args.wait < 0:

        print(
            "[-] --wait cannot be negative."
        )

        return 1

    if not os.path.isfile(args.list):

        print(
            f"[-] URL list not found: "
            f"{args.list}"
        )

        return 1

    if not os.path.isfile(args.params):

        print(
            f"[-] Parameter file not found: "
            f"{args.params}"
        )

        return 1

    urls = load_urls(
        args.list
    )

    parameter_groups = load_parameter_groups(
        args.params
    )

    if not urls:

        print(
            "[-] No HTTP/HTTPS URLs found."
        )

        return 0

    if not parameter_groups:

        print(
            "[-] No parameter groups found."
        )

        return 1

    webhook = os.environ.get(
        "DISCORD_WEBHOOK_URL",
        "",
    ).strip()

    print()
    print(
        "[+] JS Redirect Tester"
    )

    print(
        f"[+] URLs          : "
        f"{len(urls)}"
    )

    print(
        f"[+] Parameter groups: "
        f"{len(parameter_groups)}"
    )

    print(
        f"[+] Payload       : "
        f"{PAYLOAD}"
    )

    print(
        f"[+] Redirect wait : "
        f"{args.wait}s"
    )

    print()

    findings = []
    seen = set()

    with sync_playwright() as playwright:

        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
            ],
        )

        context = browser.new_context(
            user_agent=USER_AGENT,
        )

        page = context.new_page()

        try:

            for url_index, base_url in enumerate(
                urls,
                1,
            ):

                print(
                    f"[{url_index}/{len(urls)}] "
                    f"{base_url}"
                )

                for group_index, parameter_group in enumerate(
                    parameter_groups,
                    1,
                ):

                    print(
                        f"    → Group "
                        f"{group_index}/"
                        f"{len(parameter_groups)} "
                        f"({len(parameter_group)} parameters)"
                    )

                    # Build request using ONLY this line's
                    # parameters.
                    test_url = build_test_url(
                        base_url,
                        parameter_group,
                    )

                    print(
                        f"       Request: "
                        f"{test_url}"
                    )

                    try:

                        page.goto(
                            test_url,
                            wait_until="domcontentloaded",
                            timeout=args.timeout,
                        )

                    except PlaywrightTimeoutError:

                        print(
                            "       ⚠️ Initial navigation "
                            "timed out; continuing to monitor "
                            "the browser URL."
                        )

                    except Exception as exc:

                        print(
                            f"       ⚠️ Navigation error: "
                            f"{exc}"
                        )

                        continue

                    # IMPORTANT:
                    #
                    # Do NOT check immediately.
                    #
                    # Some applications perform the JS redirect
                    # after 5-6 seconds.
                    final_url = wait_for_redirect(
                        page,
                        base_url,
                        args.wait,
                    )

                    if is_evil_redirect(
                        base_url,
                        final_url,
                    ):

                        print()
                        print(
                            "       🔴 "
                            "CONFIRMED CLIENT-SIDE REDIRECT!"
                        )

                        print(
                            f"       Final URL: "
                            f"{final_url}"
                        )

                        finding_key = (
                            base_url,
                            final_url,
                            tuple(parameter_group),
                        )

                        if finding_key not in seen:

                            seen.add(
                                finding_key
                            )

                            finding = {
                                "original_url": base_url,
                                "test_url": test_url,
                                "final_url": final_url,
                                "parameters": parameter_group,
                            }

                            findings.append(
                                finding
                            )

                            send_discord(
                                webhook,
                                base_url,
                                test_url,
                                final_url,
                                parameter_group,
                            )

                    else:

                        print(
                            f"       ✓ Final URL: "
                            f"{final_url}"
                        )

        finally:

            browser.close()

    # Save confirmed vulnerabilities.
    with open(
        args.output,
        "w",
        encoding="utf-8",
    ) as output:

        for finding in findings:

            output.write(
                f"Original URL: "
                f"{finding['original_url']}\n"
            )

            output.write(
                f"Test URL: "
                f"{finding['test_url']}\n"
            )

            output.write(
                f"Final URL: "
                f"{finding['final_url']}\n"
            )

            output.write(
                "Parameters: "
                + ", ".join(
                    finding["parameters"]
                )
                + "\n"
            )

            output.write(
                f"Payload: {PAYLOAD}\n"
            )

            output.write(
                "Type: Client-Side JS Redirect\n"
            )

            output.write(
                "----------------------------------------\n"
            )

    print()
    print(
        "[+] Scan completed."
    )

    print(
        f"[+] Confirmed findings: "
        f"{len(findings)}"
    )

    print(
        f"[+] Results saved to: "
        f"{args.output}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())