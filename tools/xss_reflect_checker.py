#!/usr/bin/env python3

import argparse
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import json
import os


# ============================================================
# CONFIG
# ============================================================

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)

REQUEST_DELAY = 1.4
BATCH_SIZE = 100

XSS_CONTENT_TYPES = {
    "text/html",
    "image/svg+xml",
    "text/xml",
    "application/xml",
    "application/xhtml+xml",
}

# Use your environment variable instead of hard-coding a webhook.
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

# Hop-by-hop / browser-managed headers that must not be forced.
FORBIDDEN_HEADERS = {
    "host",
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "accept-encoding",
}

COOKIE_ATTR_NAMES = {
    "samesite", "path", "domain", "secure", "httponly",
    "max-age", "expires", "priority", "partitioned",
}


def load_headers_file(path):
    """
    Parse a Burp-style headers file (one 'Name: value' per line).
    Returns a dict suitable for urllib request headers.
    Cookie/Cookies is normalized to Cookie; attributes like SameSite are dropped.
    """
    headers = {}
    cookie_parts = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            lower = key.lower()
            if lower in FORBIDDEN_HEADERS:
                continue
            if lower in ("cookie", "cookies"):
                for part in value.split(";"):
                    part = part.strip()
                    if not part or "=" not in part:
                        continue
                    name, val = part.split("=", 1)
                    name = name.strip()
                    val = val.strip()
                    if not name or name.lower() in COOKIE_ATTR_NAMES:
                        continue
                    cookie_parts.append(f"{name}={val}")
                continue
            if lower == "user-agent":
                headers["User-Agent"] = value
                continue
            headers[key] = value

    if cookie_parts:
        headers["Cookie"] = "; ".join(cookie_parts)

    return headers


# ============================================================
# JSON PARAMETER EXTRACTION
# ============================================================

INVALID_KEYS = {
    "true",
    "false",
    "null",
    "undefined",
}


ASSIGNMENT_REGEX = re.compile(
    r"""(?:\b(?:var|let|const)\s+)?"""
    r"""([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"""
    r"""(["'])(.*?)\2""",
    re.DOTALL,
)


OBJECT_EMPTY_REGEX = re.compile(
    r"""(?:["']([^"']+)["']|([A-Za-z_$][A-Za-z0-9_$-]*))"""
    r"""\s*:\s*(["'])\s*\3""",
    re.DOTALL,
)


OBJECT_UNSET_REGEX = re.compile(
    r"""(?:["']([^"']+)["']|([A-Za-z_$][A-Za-z0-9_$-]*))"""
    r"""\s*:\s*(null|undefined)\b""",
    re.IGNORECASE,
)


def add_if_empty(params, key, value):
    key = str(key or "").strip()

    if not key:
        return

    if key.lower() in INVALID_KEYS:
        return

    if value is None or str(value).strip() == "":
        params.add(key)


def extract_json_params(html):
    """
    Uses the extension-style extraction requested by the user.

    Finds:

        field = ''
        var field = ''
        field: ''
        "field": ''
        field: null
        field: undefined
    """

    import html as html_module

    source = html_module.unescape(html)

    params = set()

    # --------------------------------------------------------
    # Assignment:
    # field = ''
    # var field = ''
    # const field = ''
    # --------------------------------------------------------

    for match in ASSIGNMENT_REGEX.finditer(source):
        add_if_empty(
            params,
            match.group(1),
            match.group(3),
        )

    # --------------------------------------------------------
    # Object:
    # field: ''
    # "field": ''
    # --------------------------------------------------------

    for match in OBJECT_EMPTY_REGEX.finditer(source):
        key = match.group(1) or match.group(2)

        add_if_empty(
            params,
            key,
            "",
        )

    # --------------------------------------------------------
    # Object:
    # field: null
    # field: undefined
    # --------------------------------------------------------

    for match in OBJECT_UNSET_REGEX.finditer(source):
        key = match.group(1) or match.group(2)

        add_if_empty(
            params,
            key,
            "",
        )

    return params


# ============================================================
# HTTP
# ============================================================

def is_executable_content_type(content_type):
    """
    Keep the original content-type behavior.
    """

    if not content_type:
        return True

    ct = content_type.lower().split(";")[0].strip()

    return ct in XSS_CONTENT_TYPES


def url_encode_value(value):
    """
    Encode ONLY the parameter value.

    Example:

        testtt<a>t"'est

    becomes:

        testtt%3Ca%3Et%22%27est
    """

    return urllib.parse.quote(value, safe="")


def fetch_url(url, extra_headers=None):
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }
        if extra_headers:
            headers.update(extra_headers)

        req = urllib.request.Request(
            url,
            headers=headers,
        )

        with urllib.request.urlopen(req, timeout=15) as resp:

            body = resp.read().decode(
                "utf-8",
                errors="ignore",
            )

            return (
                body,
                resp.getheader("Content-Type", ""),
                resp.getcode(),
            )

    except urllib.error.HTTPError as e:

        try:
            body = e.read().decode(
                "utf-8",
                errors="ignore",
            )
        except Exception:
            body = None

        return (
            body,
            e.getheader("Content-Type", ""),
            e.code,
        )

    except Exception:
        return None, "", 0


# ============================================================
# PARAMETER FILE PARSING
# ============================================================

def valid_parameter_name(name):
    """
    Validate a parameter name without modifying it.
    """

    name = str(name or "").strip()

    if not name:
        return None

    if name.lower() in INVALID_KEYS:
        return None

    # Query parameter names commonly contain these characters.
    if not re.fullmatch(
        r"[A-Za-z_$][A-Za-z0-9_$.-]*",
        name,
    ):
        return None

    return name


def extract_names_from_query(query):
    """
    Extract parameter names from:

        p1=value&p2=value&p3=value

    or:

        ?p1=value&p2=value&p3=value

    Values are deliberately ignored.
    """

    query = query.strip()

    if query.startswith("?"):
        query = query[1:]

    names = []

    for part in query.split("&"):

        part = part.strip()

        if not part:
            continue

        # Remove fragment if present.
        part = part.split("#", 1)[0]

        # Parameter name is everything before '='.
        name = part.split("=", 1)[0].strip()

        # URL-decode the NAME only.
        name = urllib.parse.unquote(name)

        name = valid_parameter_name(name)

        if name:
            names.append(name)

    return names


def load_parameters(path):
    """
    Supports all of these:

        p1
        p2
        p3

    and:

        p1=value
        p2=value

    and:

        ?p1=value&p2=value&p3=value

    and even multiple query parameters on one line.

    Duplicates are removed while preserving order.
    """

    parameters = []
    seen = set()

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        for raw_line in f:

            line = raw_line.strip()

            if not line:
                continue

            # ------------------------------------------------
            # Query-string style line
            # ------------------------------------------------

            if line.startswith("?"):

                names = extract_names_from_query(line)

            # ------------------------------------------------
            # Plain parameter name
            # ------------------------------------------------

            elif "&" not in line and "=" not in line:

                name = valid_parameter_name(line)

                names = [name] if name else []

            # ------------------------------------------------
            # p1=value or p1=value&p2=value
            # ------------------------------------------------

            else:

                names = extract_names_from_query(line)

            for name in names:

                if name and name not in seen:

                    seen.add(name)
                    parameters.append(name)

    return parameters


# ============================================================
# BUILD QUERY BATCHES
# ============================================================

def build_batches(parameters, payload):
    """
    Build requests containing a maximum of 100 parameters.

    Example:

        ?p1=PAYLOAD&p2=PAYLOAD&p3=PAYLOAD

    The payload is URL-encoded here.

    The response is NOT URL-decoded during detection.
    """

    encoded_payload = url_encode_value(payload)

    batches = []

    for start in range(
        0,
        len(parameters),
        BATCH_SIZE,
    ):

        chunk = parameters[
            start:start + BATCH_SIZE
        ]

        query = "&".join(
            f"{name}={encoded_payload}"
            for name in chunk
        )

        batches.append(
            "?" + query
        )

    return batches


# ============================================================
# URL CONSTRUCTION
# ============================================================

def make_test_url(base_url, query):
    """
    Do not modify the path.

    Only append the generated query parameters.
    """

    if "?" in base_url:

        # Existing query string.
        #
        # /path?existing=value
        #
        # becomes:
        #
        # /path?existing=value&p1=payload

        return (
            base_url
            + "&"
            + query.lstrip("?")
        )

    # Normal URL:
    #
    # /path
    #
    # becomes:
    #
    # /path?p1=payload

    return (
        base_url.rstrip("/")
        + query
    )


# ============================================================
# REFLECTION DETECTION
# ============================================================

def is_reflected(body, payload):
    """
    IMPORTANT:

    The request payload is URL-encoded.

    The response is intentionally NOT URL-decoded.

    We look for the exact decoded payload in the raw
    response body, matching the behavior of the original
    working script.

    Example:

        Request:
        ?p1=testtt%3Ca%3E...

        Raw response:
        testtt<a>...

        => MATCH
    """

    if not body:
        return False

    return payload in body


# ============================================================
# WEBHOOK
# ============================================================

def send_to_webhook(vuln_url, base_url):
    if not WEBHOOK_URL:
        return

    try:

        message = {
            "content": "**🔥 Reflected XSS Found!**",
            "embeds": [
                {
                    "title": "Vulnerable URL",
                    "description": (
                        f"**Path:** {base_url}\n"
                        f"**Full URL:** "
                        f"[Vulnerable Link]({vuln_url})"
                    ),
                    "color": 0x00FF00,
                }
            ],
        }

        data = json.dumps(
            message
        ).encode("utf-8")

        req = urllib.request.Request(
            WEBHOOK_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )

        urllib.request.urlopen(
            req,
            timeout=10,
        )

    except Exception:
        pass


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="XSS Reflection Checker"
    )

    parser.add_argument(
        "-l",
        "--list",
        default="usefull-path-urls.txt",
        help="URL list",
    )

    parser.add_argument(
        "-p",
        "--params",
        default="fuzz-params-list.txt",
        help="Parameter list",
    )

    parser.add_argument(
        "-pv",
        "--payload-value",
        default='testtt<a>t"\'est',
        help="Payload",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="xss-vulnerable.txt",
        help="Output file",
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=REQUEST_DELAY,
        help="Delay between requests",
    )

    parser.add_argument(
        "-hf",
        "--headers",
        dest="headers_file",
        help="Optional auth/header file, e.g. Cookie: a=b / Csrf: token",
    )

    args = parser.parse_args()

    payload = args.payload_value
    delay = args.delay

    auth_headers = {}
    if args.headers_file:
        auth_headers = load_headers_file(args.headers_file)
        print(
            f"[+] Loaded {len(auth_headers)} header(s) "
            f"from {args.headers_file}"
        )

    print(
        "[+] Advanced XSS Reflection Checker"
    )

    print(
        f"[+] Payload: {payload}"
    )

    # ========================================================
    # LOAD URLS
    # ========================================================

    with open(
        args.list,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        paths = [
            line.strip()
            for line in f
            if line.strip().startswith(
                ("http://", "https://")
            )
        ]

    # ========================================================
    # LOAD PARAMETERS
    # ========================================================

    parameters = load_parameters(
        args.params
    )

    print(
        f"[+] URLs        : {len(paths)}"
    )

    print(
        f"[+] Parameters  : {len(parameters)}"
    )

    print(
        f"[+] Batch size  : {BATCH_SIZE}"
    )

    if not parameters:

        print(
            "[!] No parameters found in "
            f"{args.params}"
        )

        return

    # ========================================================
    # CREATE BATCHES
    # ========================================================

    batches = build_batches(
        parameters,
        payload,
    )

    print(
        f"[+] Batches     : {len(batches)}"
    )

    # Show first generated request structure.
    print(
        "[+] Parameter format:"
    )

    preview = batches[0]

    if len(preview) > 500:
        preview = preview[:500] + "..."

    print(
        f"    {preview}"
    )

    vulnerable = []

    # ========================================================
    # SCAN
    # ========================================================

    for url_number, base_url in enumerate(
        paths,
        1,
    ):

        print()
        print(
            f"[{url_number}/{len(paths)}] "
            f"{base_url}"
        )

        # ----------------------------------------------------
        # Initial request
        # ----------------------------------------------------

        initial_body, initial_ct, initial_status = fetch_url(
            base_url,
            extra_headers=auth_headers or None,
        )

        print(
            f"    Initial HTTP status : "
            f"{initial_status}"
        )

        print(
            f"    Initial Content-Type: "
            f"{initial_ct or '(empty)'}"
        )

        if not is_executable_content_type(
            initial_ct
        ):

            print(
                "    ⏭️ Skipped because of "
                "Content-Type"
            )

            time.sleep(delay)
            continue

        # ----------------------------------------------------
        # Extract empty/unset params from the page body
        # (field = '', field: '', "field": null, etc.)
        # and merge with the -p list for this URL only.
        # ----------------------------------------------------

        page_params = []
        if initial_body:
            extracted = extract_json_params(initial_body)
            seen_local = set(parameters)
            page_params = [
                name for name in sorted(extracted)
                if name not in seen_local
            ]

        url_parameters = list(parameters) + page_params

        print(
            f"    Params from list : {len(parameters)}"
        )
        print(
            f"    Params from page : {len(page_params)}"
        )
        print(
            f"    Params to test   : {len(url_parameters)}"
        )

        if not url_parameters:
            print(
                "    ⏭️ No parameters to test"
            )
            time.sleep(delay)
            continue

        url_batches = build_batches(
            url_parameters,
            payload,
        )

        print(
            "    ✅ Starting parameter fuzzing..."
        )

        # ----------------------------------------------------
        # Test each 100-parameter batch
        # ----------------------------------------------------

        for batch_number, query in enumerate(
            url_batches,
            1,
        ):

            parameter_count = query.count("=")

            test_url = make_test_url(
                base_url,
                query,
            )

            print(
                f"    → Batch "
                f"{batch_number}/{len(url_batches)} "
                f"({parameter_count} params)"
            )

            body, response_ct, status = fetch_url(
                test_url,
                extra_headers=auth_headers or None,
            )

            # ------------------------------------------------
            # IMPORTANT:
            #
            # Check the ACTUAL response body.
            #
            # Payload is already URL-encoded in the
            # request, but we search for the decoded
            # payload in the raw response.
            # ------------------------------------------------

            reflected = (
                body is not None
                and is_executable_content_type(
                    response_ct
                )
                and is_reflected(
                    body,
                    payload,
                )
            )

            # Empty Content-Type + 303/400: browsers treat the body as
            # text/plain, not HTML — skip even if the payload reflects.
            if (
                reflected
                and not (response_ct or "").strip()
                and status in (403, 400)
            ):
                print(
                    f"       HTTP {status} | "
    
