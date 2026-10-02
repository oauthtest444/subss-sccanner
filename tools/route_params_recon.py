#!/usr/bin/env python3
"""
route_params_recon.py

Purpose
-------
Extract:
  1) unique query-parameter names from an archive URL list
  2) unique route representatives
  3) valid same-host HTML/UI routes discovered from:
       - raw HTML
       - all loaded JS
       - router-like definitions
       - runtime browser navigation
  4) final routes whose summed inline <script> content length is unique

The script is intentionally discovery/validation only. It does not execute
discovered route values as payloads and does not attempt exploitation.

Dependencies:
    pip install requests beautifulsoup4 playwright
    playwright install chromium

Examples:
    python route_params_recon.py -f list.txt
    python route_params_recon.py -f list.txt -h auth.txt
    python route_params_recon.py -f list.txt -h auth.txt \
        -ro my-routes.txt -po my-params.txt
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qsl,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
from bs4 import BeautifulSoup


USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/134.0.0.0 Safari/537.36"
)

# Files are kept so each stage can be inspected/reused.
TMP_DIR = Path(".route_params_recon_tmp")
ARCHIVE_UNIQUE = TMP_DIR / "01-archive-unique-routes.txt"
ARCHIVE_HTML = TMP_DIR / "02-archive-200-html.txt"
TOP_LEVEL = TMP_DIR / "03-top-level-routes.txt"
BROWSER_DISCOVERED = TMP_DIR / "04-browser-discovered-routes.txt"
BROWSER_HTML = TMP_DIR / "05-browser-200-html.txt"
BROWSER_INLINE_UNIQUE = TMP_DIR / "05b-browser-inline-script-size-unique.txt"
BROWSER_SCOPED_ORIGIN_UNIQUE = TMP_DIR / "05c-scoped-origin-inline-script-size-unique.txt"
BROWSER_TOPLEVEL_ORIGIN_UNIQUE = TMP_DIR / "05d-toplevel-origin-inline-script-size-unique.txt"
COMBINED_HTML = TMP_DIR / "06-combined-200-html.txt"
FINAL_SCRIPT_UNIQUE = TMP_DIR / "07-final-script-size-unique.txt"

# Deliberately excludes common non-UI resources.
NON_UI_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".bmp", ".tif", ".tiff", ".avif", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".rar",
    ".7z", ".gpg", ".asc", ".pem", ".crt", ".txt", ".xml", ".json", ".csv",
    ".mp3", ".mp4", ".wav", ".webm", ".avi", ".mov", ".mkv", ".wasm",
    ".bin", ".exe", ".dmg", ".apk",
}

DYNAMIC_SEGMENT_PATTERNS = [
    ("uuid", re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )),
    ("hex", re.compile(r"^[0-9a-fA-F]{16,}$")),
    ("number", re.compile(r"^\d+$")),
]

# Strong dynamic token forms in JavaScript route construction.
# Single route-extraction regex requested by the user.
ROUTE_RE = re.compile(
    r"""(["'`])(?!//)(?!/\.)(?!/(?:\d+(?:\.\d+)?|_)\1)(?!/(?:\d+[A-Za-z]+)\1)(?![^"'`]*\.(?:js|css|png|ico|pdf|jpg|jpeg|gif|svg|webp|avif|map|json|xml|woff|woff2|ttf|eot)\1)(?:/[A-Za-z0-9_:@%+~?.-]{3,})+(?!/)\1(?!\s*:\s*function\b)"""
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Archive + browser UI-route and query-parameter recon",
        add_help=False
    )
    p.add_argument(
    "--help",
    action="help",
    help="Show this help message and exit"
)
    p.add_argument(
        "-f", "--file", required=True,
        help="File containing archive URLs, one URL per line."
    )
    p.add_argument(
        "-h", "--headers", dest="headers_file",
        help="Optional auth/header file, e.g. Cookies: a=b / Csrf: token"
    )
    p.add_argument(
        "-ro", "--route-output", default="all-uniq-routs.txt",
        help="Final route output file (default: all-uniq-routs.txt)"
    )
    p.add_argument(
        "-po", "--param-output", default="all-uniq-params.txt",
        help="Unique query-parameter output file (default: all-uniq-params.txt)"
    )
    return p.parse_args()


def read_lines(path: str) -> List[str]:
    return [
        x.strip()
        for x in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if x.strip()
    ]


def load_headers(path: Optional[str]) -> Dict[str, str]:
    headers = {"User-Agent": USER_AGENT}
    if not path:
        return headers

    for line in read_lines(path):
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            continue

        # Accept "Cookies:" as a friendly alias for HTTP "Cookie".
        if name.lower() == "cookies":
            name = "Cookie"
        elif name.lower() == "csrf":
            # Many targets use different CSRF header names. Preserve the
            # supplied name as X-CSRF-Token rather than guessing a target API.
            name = "X-CSRF-Token"

        headers[name] = value

    return headers


def canonical_origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def host_key(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def strip_fragment(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def is_http_url(url: str) -> bool:
    return urlparse(url).scheme in {"http", "https"}


def is_same_host(url: str, target_host: str) -> bool:
    return host_key(url) == target_host


def is_non_ui_path(path: str) -> bool:
    lower = path.lower()
    # Ignore dot-files/resources, but do not reject normal routes containing dots.
    last = lower.rsplit("/", 1)[-1]
    if "." in last:
        suffix = "." + last.rsplit(".", 1)[-1]
        if suffix in NON_UI_EXTENSIONS:
            return True
    return False


def looks_like_ui_route(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        return False
    if is_non_ui_path(p.path):
        return False

    path = p.path or "/"
    # API-ish paths are not automatically invalid, but common API roots are
    # excluded from UI candidates. This is intentionally conservative.
    first = path.strip("/").split("/", 1)[0].lower() if path.strip("/") else ""
    if first in {"api", "apis", "graphql", "rest", "rpc", "webhook", "webhooks"}:
        return False

    return True


def route_path(url: str) -> str:
    return urlparse(url).path or "/"


def route_without_query(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, "", ""))


# ---------------------------------------------------------------------------
# Parameter pipeline
# ---------------------------------------------------------------------------

def normalize_parameter_for_dedup(name: str) -> str:
    """
    IMPORTANT:
      - exact duplicates are removed
      - case is NOT normalized
      - structural-pattern detection is NOT used
      - numbers are normalized
      - UUID/hash-like values are normalized
    """
    n = name.strip()

    # UUID-looking parameter names.
    if DYNAMIC_SEGMENT_PATTERNS[0][1].fullmatch(n):
        return "<UUID>"

    # Long hexadecimal names often represent generated IDs/hashes.
    if DYNAMIC_SEGMENT_PATTERNS[1][1].fullmatch(n):
        return "<HEX_ID>"

    # Pure numeric parameter names.
    if DYNAMIC_SEGMENT_PATTERNS[2][1].fullmatch(n):
        return "<NUMBER>"

    # Embedded numeric suffix/prefix: abc1, abc2, abc99 -> abc#
    return re.sub(r"\d+", "#", n)


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                cur[-1] + 1,
                prev[j] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = cur
    return prev[-1]


def similar_parameter(a: str, b: str) -> bool:
    """
    Conservative similarity clustering.

    Case is intentionally significant.
    This is NOT structural-pattern detection.
    """
    if a == b:
        return True

    # Very short names are too collision-prone.
    if len(a) < 5 or len(b) < 5:
        return False

    dist = edit_distance(a, b)
    max_len = max(len(a), len(b))
    ratio = 1 - (dist / max_len)

    # Require both reasonably high similarity and a modest edit distance.
    return ratio >= 0.82 and dist <= 3


def dedupe_parameters(params: Iterable[str]) -> List[str]:
    # Stage 1: exact dedupe, preserving original spelling/case.
    exact_seen: Set[str] = set()
    exact_unique: List[str] = []
    for p in params:
        p = p.strip()
        if p and p not in exact_seen:
            exact_seen.add(p)
            exact_unique.append(p)

    # Stage 2: number/UUID/hash normalization.
    normalized_seen: Set[str] = set()
    candidates: List[str] = []
    for p in exact_unique:
        key = normalize_parameter_for_dedup(p)
        if key not in normalized_seen:
            normalized_seen.add(key)
            candidates.append(p)

    # Stage 3: conservative similarity clustering.
    representatives: List[str] = []
    for p in candidates:
        if any(similar_parameter(p, existing) for existing in representatives):
            continue
        representatives.append(p)

    return representatives


def extract_query_parameters(urls: Iterable[str]) -> List[str]:
    params: List[str] = []

    # Only accept parameter names that look like actual query keys.
    # This prevents HTML/JSON encoding fragments such as:
    #   amp;amp;hint, ;hint, ?EventId, tehttps://...
    # from becoming parameter names.
    valid_name_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")

    for url in urls:
        try:
            # Archive URLs may contain HTML-encoded separators such as &amp;.
            cleaned_url = html.unescape(url)
            query = urlparse(cleaned_url).query

            for name, _value in parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=False,
            ):
                name = html.unescape(name).strip()
                name = name.lstrip("?&;")

                # Reject fragments produced by broken/encoded URLs rather than
                # treating them as real parameter names.
                if not name or not valid_name_re.fullmatch(name):
                    continue
                if "/" in name or "\\" in name or "?" in name:
                    continue
                params.append(name)
        except Exception:
            continue

    return dedupe_parameters(params)



# ---------------------------------------------------------------------------
# Route pattern reconstruction
# ---------------------------------------------------------------------------

def classify_dynamic_segment(segment: str) -> Optional[str]:
    for kind, rx in DYNAMIC_SEGMENT_PATTERNS:
        if rx.fullmatch(segment):
            return kind

    # Long mixed tokens are treated conservatively as possible IDs.
    if len(segment) >= 20 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        return "id"

    return None


def route_pattern(url: str) -> str:
    """
    Convert a concrete route into a dedupe pattern.

    Examples:
      /users/123 -> /users/:number
      /orders/<uuid> -> /orders/:uuid

    Static textual route names are preserved.
    """
    p = urlparse(url)
    parts = [x for x in p.path.split("/") if x]

    out = []
    for seg in parts:
        kind = classify_dynamic_segment(seg)
        if kind:
            out.append(":" + kind)
        else:
            out.append(seg)

    return "/" + "/".join(out) if out else "/"



def _decode_route_escape(value: str) -> str:
    value = value.replace(r"\\/", "/")
    value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), value)
    return value


def _route_from_js_match(match: re.Match) -> Optional[str]:
    raw = match.group(0)
    q = match.group(1)
    if len(raw) < 2 or raw[0] != q or raw[-1] != q:
        return None
    path = _decode_route_escape(raw[1:-1])
    return path if path.startswith("/") else None


def extract_routes_from_html(html_text: str, base_url: str) -> List[str]:
    routes: List[str] = []
    html_text = html.unescape(html_text)
    html_text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), html_text)

    for m in ROUTE_RE.finditer(html_text):
        path = _route_from_js_match(m)
        if path:
            try:
                absolute = strip_fragment(urljoin(base_url, path))
                if is_http_url(absolute):
                    routes.append(absolute)
            except Exception:
                pass
    return routes


def extract_routes_from_js(js: str, base_url: str) -> List[str]:
    routes: List[str] = []
    for m in ROUTE_RE.finditer(js):
        path = _route_from_js_match(m)
        if path:
            try:
                absolute = strip_fragment(urljoin(base_url, path))
                if is_http_url(absolute):
                    routes.append(absolute)
            except Exception:
                pass
    return routes



# ---------------------------------------------------------------------------
# HTTP validation
# ---------------------------------------------------------------------------

class HttpClient:
    def __init__(self, headers: Dict[str, str]):
        self.session = requests.Session()
        self.session.headers.update(headers)

    def get(self, url: str, timeout: int = 20):
        try:
            return self.session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
            )
        except requests.RequestException:
            return None


def is_html_response(resp) -> bool:
    if resp is None or resp.status_code != 200:
        return False
    ctype = resp.headers.get("Content-Type", "").lower()
    return "text/html" in ctype or "application/xhtml+xml" in ctype


def validate_html_urls(
    urls: Iterable[str],
    client: HttpClient,
    target_host: str,
) -> List[str]:
    valid: List[str] = []
    seen: Set[str] = set()

    for url in urls:
        if not is_same_host(url, target_host):
            continue
        if not looks_like_ui_route(url):
            continue

        resp = client.get(url)
        if not is_html_response(resp):
            continue

        final_url = strip_fragment(resp.url)
        if not is_same_host(final_url, target_host):
            continue
        if not looks_like_ui_route(final_url):
            continue

        if final_url not in seen:
            seen.add(final_url)
            valid.append(final_url)

    return valid


# ---------------------------------------------------------------------------
# Top-level route selection
# ---------------------------------------------------------------------------

def top_level_key(url: str) -> str:
    parts = [x for x in route_path(url).split("/") if x]
    return parts[0] if parts else "/"


def choose_top_level_routes(urls: Iterable[str]) -> List[str]:
    """
    Keep one full concrete representative for each top-level path family.

    Example:
      /path/sub-path/123
      /path/sub-path/124
      /path-new/sub-path/124

    -> one representative for /path/*
       one representative for /path-new/*
    """
    groups: Dict[str, str] = {}

    for url in urls:
        key = top_level_key(url)
        groups.setdefault(key, url)

    return list(groups.values())


# ---------------------------------------------------------------------------
# Browser discovery
# ---------------------------------------------------------------------------

def scope_route_to_top_level(candidate: str, seed_url: str, target_host: str) -> Optional[str]:
    """
    Scope a route discovered while browsing a top-level seed to that seed's
    top-level path family.

    Example:
      seed:      https://host/datatester/app/179420/flight/list
      candidate: /foo/bar
      result:    https://host/datatester/foo/bar

    A candidate already beginning with the same top-level prefix is kept as-is.
    Only same-host HTTP(S) candidates are accepted.
    """
    try:
        seed = urlparse(seed_url)
        cand = urlparse(candidate)
        if cand.scheme and cand.scheme not in {"http", "https"}:
            return None

        # A regex result is normally a path. If it was converted to an
        # absolute same-host URL, keep its path/query but still apply the
        # top-level scope below.
        if cand.scheme and cand.netloc:
            if cand.hostname and cand.hostname.lower() != target_host:
                return None
            candidate_path = cand.path or "/"
            query = cand.query
        else:
            candidate_path = cand.path or "/"
            query = cand.query

        seed_parts = [x for x in (seed.path or "/").split("/") if x]
        if not seed_parts:
            return strip_fragment(urlunparse((seed.scheme, seed.netloc, candidate_path, "", query, "")))

        top_prefix = "/" + seed_parts[0]
        candidate_path = "/" + candidate_path.lstrip("/")

        if candidate_path == top_prefix or candidate_path.startswith(top_prefix + "/"):
            scoped_path = candidate_path
        else:
            scoped_path = top_prefix.rstrip("/") + candidate_path

        scoped = urlunparse((seed.scheme, seed.netloc, scoped_path, "", query, ""))
        return strip_fragment(scoped)
    except Exception:
        return None


def _validate_candidate_forms_unique_script_urls(
    urls: Iterable[str],
    client: HttpClient,
    target_host: str,
    seed_url: str,
) -> Tuple[List[str], int]:
    """Validate supplied candidates in scoped + origin forms.

    Returns (one representative per inline-script size, number of valid 200+HTML
    responses).  No routes are discovered or added here.
    """
    by_size: Dict[int, str] = {}
    tested: Set[str] = set()
    html_ok = 0

    seed = urlparse(seed_url)
    seed_parts = [x for x in (seed.path or "/").split("/") if x]
    top_prefix = "/" + seed_parts[0] if seed_parts else ""

    expanded: List[str] = []
    expanded_seen: Set[str] = set()

    for scoped in urls:
        if not is_same_host(scoped, target_host):
            continue
        parsed = urlparse(scoped)
        path = parsed.path or "/"
        query = parsed.query
        if top_prefix and (path == top_prefix or path.startswith(top_prefix + "/")):
            route_path = path[len(top_prefix):] or "/"
        else:
            route_path = path
        route_path = "/" + route_path.lstrip("/")

        forms = (
            urlunparse((seed.scheme, seed.netloc, path, "", query, "")),
            urlunparse((seed.scheme, seed.netloc, route_path, "", query, "")),
        )
        for candidate_url in forms:
            candidate_url = strip_fragment(candidate_url)
            if candidate_url not in expanded_seen:
                expanded_seen.add(candidate_url)
                expanded.append(candidate_url)

    for url in expanded:
        if url in tested:
            continue
        tested.add(url)
        if not is_same_host(url, target_host) or not looks_like_ui_route(url):
            continue
        resp = client.get(url)
        if not is_html_response(resp):
            continue
        final_url = strip_fragment(resp.url)
        if not is_same_host(final_url, target_host) or not looks_like_ui_route(final_url):
            continue
        html_ok += 1
        size = script_content_length(resp.text)
        if size not in by_size:
            by_size[size] = final_url

    return list(by_size.values()), html_ok


def _is_direct_top_level_route(candidate: str, seed_url: str) -> bool:
    """True when the original extracted route has exactly one path component."""
    try:
        cand = urlparse(candidate)
        seed = urlparse(seed_url)
        seed_parts = [x for x in (seed.path or "/").split("/") if x]
        top_prefix = "/" + seed_parts[0] if seed_parts else ""
        path = cand.path or "/"
        if top_prefix and (path == top_prefix or path.startswith(top_prefix + "/")):
            path = path[len(top_prefix):] or "/"
        parts = [x for x in path.split("/") if x]
        return len(parts) == 1
    except Exception:
        return False


def validate_scoped_and_origin_unique_script_urls(
    urls: Iterable[str],
    client: HttpClient,
    target_host: str,
    seed_url: str,
) -> Tuple[List[str], int, List[str], int]:
    """Return independent scoped/origin and direct-top-level/origin results.

    Group 1 contains every extracted candidate.
    Group 2 contains only extracted candidates that are themselves direct
    top-level routes (one path component).  Both groups independently apply
    200+HTML validation and inline-script-size deduplication.
    """
    all_candidates = list(dict.fromkeys(urls))
    all_unique, all_html = _validate_candidate_forms_unique_script_urls(
        all_candidates, client, target_host, seed_url
    )
    top_candidates = [u for u in all_candidates if _is_direct_top_level_route(u, seed_url)]
    top_unique, top_html = _validate_candidate_forms_unique_script_urls(
        top_candidates, client, target_host, seed_url
    )
    return all_unique, all_html, top_unique, top_html

def validate_scoped_unique_script_urls(
    urls: Iterable[str],
    client: HttpClient,
    target_host: str,
) -> List[str]:
    """
    Validate only the supplied candidate URLs and keep one URL per unique
    summed inline-script content length.

    This deliberately does NOT discover any additional URLs. The input list
    is the complete candidate set for that top-level page.
    """
    by_size: Dict[int, str] = {}
    tested = 0
    html_ok = 0

    for url in urls:
        if not is_same_host(url, target_host) or not looks_like_ui_route(url):
            continue
        tested += 1
        resp = client.get(url)
        if not is_html_response(resp):
            continue
        final_url = strip_fragment(resp.url)
        if not is_same_host(final_url, target_host) or not looks_like_ui_route(final_url):
            continue
        html_ok += 1
        size = script_content_length(resp.text)
        if size not in by_size:
            by_size[size] = final_url

    return list(by_size.values())


def discover_with_playwright(
    seed_urls: List[str],
    headers: Dict[str, str],
    target_host: str,
    wait_seconds: int = 8,
    js_timeout_seconds: int = 5,
) -> Tuple[List[str], List[str]]:
    """Discover UI routes from archive seed URLs only (no recursive depth).

    Browser discovery runs ONLY against the supplied seed URLs (the
    archive-derived top-level representatives). Newly extracted routes are
    validated and deduped by inline-script size, but are NEVER queued for
    further browser visits. This prevents the queue from exploding with
    rediscovered top-level / scoped variants.

    Returns:
        (pattern_deduped_candidates, unique_inline_script_size_routes)
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] Playwright is not installed. Run: pip install playwright && playwright install chromium", file=sys.stderr)
        return [], []

    def decode_embedded_unicode(text: str) -> str:
        if not text:
            return ""
        out = html.unescape(text)
        # Bootstrap/JSON blobs commonly contain literal \u003C / \u002F
        # escapes and JSON-escaped quotes such as src=\"...\".
        for _ in range(3):
            out = re.sub(
                r"\\u([0-9a-fA-F]{4})",
                lambda m: chr(int(m.group(1), 16)),
                out,
            )
            out = out.replace(r"\/", "/")
            out = out.replace(r'\"', '"')
            out = out.replace(r"\'", "'")
        return out

    def extract_embedded_script_urls(text: str, base_url: str) -> Set[str]:
        decoded = decode_embedded_unicode(text)
        found: Set[str] = set()
        if not decoded:
            return found
        try:
            soup = BeautifulSoup(decoded, "html.parser")
            for tag in soup.find_all("script"):
                src = tag.get("src")
                if not src:
                    continue
                src = src.strip().strip('\"\'')
                if not src or src.startswith(("data:", "blob:", "javascript:")):
                    continue
                # A decoded protocol-relative CDN URL must remain protocol-relative
                # until urljoin resolves it. Never turn a malformed escaped value
                # into a path under the inspected page.
                absolute = urljoin(base_url, src)
                parsed = urlparse(absolute)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    continue
                if ".map" in absolute.lower():
                    continue
                found.add(strip_fragment(absolute))
        except Exception:
            pass
        return found

    discovered: List[str] = []
    # Only the original archive-derived seeds are visited. No recursive queuing.
    seeds_to_visit: List[str] = list(dict.fromkeys(seed_urls))
    browser_unique_script: List[str] = []

    print(f"[>] Browser discovery starting: {len(seeds_to_visit)} seed URL(s)")
    print(f"[>] Browser wait per page: {wait_seconds}s")
    print("[>] Discovery depth: 0 (archive seeds only — no recursive queue)")
    print(f"[>] JavaScript source timeout: {js_timeout_seconds}s per resource")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=headers.get("User-Agent", USER_AGENT),
            extra_http_headers=headers,
            ignore_https_errors=False,
        )

        for seed_index, seed in enumerate(seeds_to_visit):
            remaining = len(seeds_to_visit) - seed_index - 1
            print(f"[>] Browser page seed={seed_index + 1}/{len(seeds_to_visit)}: {seed} (remaining: {remaining})", flush=True)
            page_discovered_before = len(discovered)
            page = context.new_page()

            # Separate sets make it obvious where a missing resource comes from.
            response_js_urls: Set[str] = set()
            request_js_urls: Set[str] = set()
            performance_js_urls: Set[str] = set()
            dom_js_urls: Set[str] = set()
            embedded_js_urls: Set[str] = set()
            js_urls: Set[str] = set()
            js_responses: Dict[str, object] = {}
            main_html_body: Optional[str] = None
            effective_seed = seed

            page.add_init_script("""
                (() => {
                    const originalPush = history.pushState;
                    const originalReplace = history.replaceState;
                    window.__route_params_recon = [];
                    history.pushState = function(state, title, url) {
                        try { if (url) window.__route_params_recon.push(String(url)); } catch (_) {}
                        return originalPush.apply(this, arguments);
                    };
                    history.replaceState = function(state, title, url) {
                        try { if (url) window.__route_params_recon.push(String(url)); } catch (_) {}
                        return originalReplace.apply(this, arguments);
                    };
                })();
            """)

            def add_js(url: str, bucket: Set[str]) -> None:
                url = (url or "").strip()
                if not url or ".map" in url.lower():
                    return
                bucket.add(url)
                js_urls.add(url)

            def on_request(request):
                try:
                    if request.resource_type == "script":
                        add_js(request.url, request_js_urls)
                except Exception:
                    pass

            def on_response(response):
                nonlocal main_html_body
                try:
                    u = (response.url or "").strip()
                    if not u or ".map" in u.lower():
                        return
                    rtype = response.request.resource_type or ""
                    if u.endswith(".js") or u.endswith(".mjs") or rtype == "script":
                        add_js(u, response_js_urls)
                        js_responses[u] = response
                    elif rtype == "document" and not main_html_body:
                        try:
                            main_html_body = response.body().decode("utf-8", "ignore")
                        except Exception:
                            pass
                except Exception:
                    pass

            page.on("request", on_request)
            page.on("response", on_response)

            try:
                started = time.monotonic()
                page.goto(seed, wait_until="domcontentloaded", timeout=30000)
                print(f"    [+] DOM loaded in {time.monotonic() - started:.1f}s; waiting {wait_seconds}s for JS...", flush=True)
                # Keep Playwright's event loop alive while dynamic scripts load.
                page.wait_for_timeout(int(wait_seconds * 1000))

                # The SPA may perform a client/server redirect after DOMContentLoaded.
                # Use the URL that is actually loaded after the full wait as the
                # discovery base and top-level scope.
                effective_seed = strip_fragment(page.url or seed)
                if effective_seed != strip_fragment(seed):
                    print(f"    [>] Final browser URL after wait: {effective_seed}", flush=True)

                raw_html = main_html_body or ""
                if not raw_html:
                    try:
                        raw_html = page.content()
                    except Exception:
                        raw_html = ""

                html_routes_raw = extract_routes_from_html(raw_html, effective_seed)
                html_routes: List[str] = []
                for candidate in html_routes_raw:
                    scoped = scope_route_to_top_level(candidate, effective_seed, target_host)
                    if scoped:
                        html_routes.append(scoped)
                discovered.extend(html_routes)
                print(f"    [+] Raw HTML regex route candidates: {len(html_routes)}", flush=True)

                # IMPORTANT FIX: decode escaped <script src> markup such as:
                # \u003Cscript src=\"\u002F\u002Fres.gcloudcache.com\u002F...js\"
                # before looking for script tags. These URLs can be absent from
                # the raw literal HTML, DOM script list, and response callback.
                embedded_js_urls.update(extract_embedded_script_urls(raw_html, page.url))
                for u in embedded_js_urls:
                    add_js(u, embedded_js_urls)

                # Enumerate every frame, not only the main frame.
                for frame in page.frames:
                    try:
                        entries = frame.evaluate("""() => performance.getEntriesByType('resource').map(e => ({
                            name: e.name || '', initiatorType: e.initiatorType || ''
                        }))""")
                        for item in entries or []:
                            if not isinstance(item, dict):
                                continue
                            u = str(item.get("name") or "").strip()
                            typ = str(item.get("initiatorType") or "")
                            if u and ".map" not in u.lower() and (u.endswith(".js") or u.endswith(".mjs") or typ == "script"):
                                add_js(u, performance_js_urls)
                    except Exception:
                        pass
                    try:
                        scripts = frame.evaluate("""() => Array.from(document.scripts || []).map(s => s.src || s.getAttribute('src') || '').filter(Boolean)""")
                        for u in scripts or []:
                            add_js(str(u), dom_js_urls)
                    except Exception:
                        pass

                print(f"    [+] Playwright response scripts : {len(response_js_urls)}", flush=True)
                print(f"    [+] Playwright request scripts  : {len(request_js_urls)}", flush=True)
                print(f"    [+] Performance script resources: {len(performance_js_urls)}", flush=True)
                print(f"    [+] DOM <script> resources      : {len(dom_js_urls)}", flush=True)
                print(f"    [+] Escaped HTML <script> src    : {len(embedded_js_urls)}", flush=True)
                print(f"    [+] Unique JS resources          : {len(js_urls)}", flush=True)
                print(f"    [+] Loaded JS resources: {len(js_urls)}", flush=True)

                # Every selected resource is scanned. Actual browser response body
                # is preferred; otherwise retrieve the source using the same browser
                # context/cookies. Regex filtering is ONLY extract_routes_from_js().
                for index, js_url in enumerate(list(js_urls), 1):
                    try:
                        print(f"    [>] JS {index}/{len(js_urls)}: {js_url[:220]}", flush=True)
                        body: Optional[bytes] = None
                        response = js_responses.get(js_url)
                        if response is not None:
                            try:
                                body = response.body()
                            except Exception:
                                body = None
                        if body is None:
                            try:
                                fallback = page.request.get(js_url, timeout=js_timeout_seconds * 1000)
                                if fallback.ok:
                                    body = fallback.body()
                            except Exception:
                                # Do not dump Playwright's long call log. Move to the
                                # next JS resource after the requested short timeout.
                                body = None
                        if body is None:
                            print(f"        [i] JS source unavailable after {js_timeout_seconds}s; continuing", flush=True)
                            continue
                        js_text = body.decode("utf-8", "ignore")
                        js_routes_raw = extract_routes_from_js(js_text, effective_seed)
                        js_routes: List[str] = []
                        for candidate in js_routes_raw:
                            scoped = scope_route_to_top_level(candidate, effective_seed, target_host)
                            if scoped:
                                js_routes.append(scoped)
                        discovered.extend(js_routes)
                        print(f"        [+] {len(body):,} bytes, {len(js_routes)} route candidate(s)", flush=True)
                    except Exception as exc:
                        print(f"        [!] JS extraction failed: {exc}", flush=True)

            except Exception as exc:
                print(f"[!] Browser error for {seed}: {exc}", file=sys.stderr)
            finally:
                page.close()

            # Persist every route discovered on this page immediately, including
            # routes that will later fail validation. This prevents losing results
            # when a later page/resource times out.
            write_lines(BROWSER_DISCOVERED, merge_route_lists(
                read_lines(str(BROWSER_DISCOVERED)) if BROWSER_DISCOVERED.exists() else [],
                discovered[page_discovered_before:],
            ))

            # Validate candidates from this seed only. Do NOT queue them for
            # further browser discovery (depth stays 0; archive seeds only).
            candidates = []
            seen_level: Set[str] = set()
            for u in discovered[page_discovered_before:]:
                u = strip_fragment(u)
                if not is_same_host(u, target_host) or u in seen_level:
                    continue
                seen_level.add(u)
                candidates.append(u)
            print(f"    [+] Unique candidates from this page: {len(candidates)}", flush=True)
            if candidates:
                print(f"    [>] Validating {len(candidates)} extracted candidate(s) in BOTH forms: /{top_level_key(seed)}{{route}} and /{{route}} ...", flush=True)
                validation_client = HttpClient(headers)
                (next_valid, scoped_html_ok, top_valid, top_html_ok) = validate_scoped_and_origin_unique_script_urls(
                    candidates, validation_client, target_host, effective_seed
                )
                print(f"    [+] Valid 200 + HTML candidates (scoped + origin forms): {scoped_html_ok}", flush=True)
                print(f"    [+] Unique inline-script-size routes (scoped + origin forms): {len(next_valid)}", flush=True)
                print(f"    [+] Valid 200 + HTML candidates (top-level-route + origin): {top_html_ok}", flush=True)
                print(f"    [+] Unique inline-script-size routes (top-level-route + origin): {len(top_valid)}", flush=True)
                print(f"    [+] Saving unique inline-script-size routes: {len(next_valid)} + {len(top_valid)} = {len(next_valid) + len(top_valid)} group entries", flush=True)

                # Persist both groups. They are NOT queued for more browser visits.
                page_unique_file = TMP_DIR / "browser-seed-inline-script-size-unique.txt"
                existing_page_unique = read_lines(str(page_unique_file)) if page_unique_file.exists() else []
                write_lines(page_unique_file, merge_route_lists(existing_page_unique, next_valid + top_valid))
                write_lines(BROWSER_INLINE_UNIQUE, merge_route_lists(
                    read_lines(str(BROWSER_INLINE_UNIQUE)) if BROWSER_INLINE_UNIQUE.exists() else [],
                    next_valid,
                ))
                write_lines(BROWSER_SCOPED_ORIGIN_UNIQUE, merge_route_lists(
                    read_lines(str(BROWSER_SCOPED_ORIGIN_UNIQUE)) if BROWSER_SCOPED_ORIGIN_UNIQUE.exists() else [],
                    next_valid,
                ))
                write_lines(BROWSER_TOPLEVEL_ORIGIN_UNIQUE, merge_route_lists(
                    read_lines(str(BROWSER_TOPLEVEL_ORIGIN_UNIQUE)) if BROWSER_TOPLEVEL_ORIGIN_UNIQUE.exists() else [],
                    top_valid,
                ))
                browser_unique_script = merge_route_lists(browser_unique_script, next_valid + top_valid)
            else:
                print("    [i] No UI candidates extracted from this seed.", flush=True)

        context.close()
        browser.close()

    pattern_seen: Set[Tuple[str, str]] = set()
    result: List[str] = []
    for url in discovered:
        url = strip_fragment(url)
        if not is_same_host(url, target_host) or not looks_like_ui_route(url):
            continue
        key = (host_key(url), route_pattern(url))
        if key in pattern_seen:
            continue
        pattern_seen.add(key)
        result.append(route_without_query(url))
    return result, browser_unique_script


# ---------------------------------------------------------------------------
# Final script-tag-content fingerprinting
# ---------------------------------------------------------------------------

SCRIPT_TAG_RE = re.compile(
    r"<script\b[^>]*>(.*?)</script\s*>",
    re.I | re.S,
)


def script_content_length(html: str) -> int:
    """
    Sum only the content between <script ...> and </script>.
    Script tag attributes themselves are not counted.
    """
    total = 0
    for match in SCRIPT_TAG_RE.finditer(html):
        total += len(match.group(1))
    return total


def unique_by_script_content_length(
    urls: Iterable[str],
    client: HttpClient,
    target_host: str,
) -> List[str]:
    by_size: Dict[int, str] = {}

    for url in urls:
        if not is_same_host(url, target_host):
            continue

        resp = client.get(url)
        if not is_html_response(resp):
            continue

        final_url = strip_fragment(resp.url)
        if not is_same_host(final_url, target_host):
            continue

        size = script_content_length(resp.text)

        # Keep one representative for each total inline-script size.
        if size not in by_size:
            by_size[size] = final_url

    return list(by_size.values())


# ---------------------------------------------------------------------------
# Files / logging
# ---------------------------------------------------------------------------

def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    unique: List[str] = []
    seen: Set[str] = set()

    for line in lines:
        line = str(line).strip()
        if line and line not in seen:
            seen.add(line)
            unique.append(line)

    path.write_text(
        "\n".join(unique) + ("\n" if unique else ""),
        encoding="utf-8",
    )


def merge_route_lists(*lists: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for items in lists:
        for url in items:
            url = strip_fragment(url)
            if url not in seen:
                seen.add(url)
                result.append(url)
    return result


def print_stage(name: str, count: int) -> None:
    print(f"[+] {name}: {count}")


def main() -> int:
    args = parse_args()
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    archive_urls = read_lines(args.file)
    if not archive_urls:
        print("[!] Input file is empty.", file=sys.stderr)
        return 1

    headers = load_headers(args.headers_file)

    # Determine target subdomain/host from the first usable archive URL.
    parsed_seed = None
    for u in archive_urls:
        try:
            p = urlparse(u)
            if p.scheme in {"http", "https"} and p.hostname:
                parsed_seed = p
                break
        except Exception:
            pass

    if parsed_seed is None:
        print("[!] No valid HTTP(S) URL found in -f file.", file=sys.stderr)
        return 1

    target_host = parsed_seed.hostname.lower()
    target_origin = canonical_origin(archive_urls[0])

    print(f"[+] Target host: {target_host}")
    print(f"[+] Seed URLs: {len(archive_urls)}")

    client = HttpClient(headers)

    # ================================================================
    # PARAMETER PIPELINE
    # ================================================================
    unique_params = extract_query_parameters(archive_urls)
    write_lines(Path(args.param_output), unique_params)
    print_stage("Unique query parameters", len(unique_params))
    print(f"[+] Parameter output: {args.param_output}")

    # ================================================================
    # ROUTE PIPELINE - archive
    # ================================================================
    archive_route_candidates = []

    for raw in archive_urls:
        try:
            p = urlparse(raw)
            if not p.hostname:
                continue
            # Only routes from the target host.
            if p.hostname.lower() != target_host:
                continue

            route_url = urlunparse(
                (p.scheme, p.netloc, p.path or "/", p.params, "", "")
            )

            if looks_like_ui_route(route_url):
                archive_route_candidates.append(route_url)
        except Exception:
            continue

    # Pattern-based route dedupe.
    pattern_seen: Set[Tuple[str, str]] = set()
    archive_unique: List[str] = []

    for u in archive_route_candidates:
        key = (host_key(u), route_pattern(u))
        if key in pattern_seen:
            continue
        pattern_seen.add(key)
        archive_unique.append(u)

    write_lines(ARCHIVE_UNIQUE, archive_unique)
    print_stage("Archive unique route representatives", len(archive_unique))

    # Validate archive routes: 200 + text/html.
    archive_html = validate_html_urls(
        archive_unique, client, target_host
    )
    write_lines(ARCHIVE_HTML, archive_html)
    print_stage("Archive routes with 200 + HTML", len(archive_html))

    # ================================================================
    # TOP LEVEL
    # ================================================================
    top_routes = choose_top_level_routes(archive_html)
    write_lines(TOP_LEVEL, top_routes)
    print_stage("Top-level archive routes", len(top_routes))

    # Remove duplicate top-level pages using the same inline-script-content
    # fingerprinting used by the final stage. Browser discovery then runs only
    # against these representatives.
    top_routes_unique = unique_by_script_content_length(
        top_routes,
        client,
        target_host,
    )
    print_stage("Top-level routes after inline-script-size dedupe", len(top_routes_unique))

    # ================================================================
    # REAL BROWSER DISCOVERY (archive seeds only — no recursive depth)
    # ================================================================
    browser_candidates, browser_unique_script = discover_with_playwright(
        top_routes_unique,
        headers,
        target_host,
        wait_seconds=8,
        js_timeout_seconds=5,
    )
    write_lines(BROWSER_DISCOVERED, browser_candidates)
    print_stage("Browser-discovered UI route candidates (pattern-deduped)", len(browser_candidates))
    print_stage("Browser unique inline-script-size routes", len(browser_unique_script))

    # Optional: also keep a classic 200+HTML validation of the pattern candidates
    # for inspection (not used in the final merge below).
    browser_html = validate_html_urls(
        browser_candidates, client, target_host
    )
    write_lines(BROWSER_HTML, browser_html)
    print_stage("Browser routes with 200 + HTML (pattern candidates)", len(browser_html))

    # ================================================================
    # MERGE archive 200+HTML + browser unique inline-script-size routes
    # ================================================================
    # As requested: combine
    #   - Archive routes with 200 + HTML
    #   - Browser unique inline-script-size routes (scoped + top-level groups)
    # then re-run unique-by-inline-script-size on the combined set.
    combined = merge_route_lists(archive_html, browser_unique_script)
    write_lines(COMBINED_HTML, combined)
    print_stage("Combined (archive 200+HTML + browser unique-script) URLs", len(combined))

    # ================================================================
    # FINAL SCRIPT-TAG CONTENT-LENGTH DEDUPE
    # ================================================================
    final_urls = unique_by_script_content_length(
        combined,
        client,
        target_host,
    )
    write_lines(FINAL_SCRIPT_UNIQUE, final_urls)
    print_stage("Final unique inline-script-size routes", len(final_urls))

    # IMPORTANT:
    # -ro remains the route output requested by the user.
    # The final script-size-unique URLs are routes, so they are written here.
    write_lines(Path(args.route_output), final_urls)

    print()
    print("[+] Done.")
    print(f"[+] Parameters : {args.param_output}")
    print(f"[+] Routes     : {args.route_output}")
    print(f"[+] Temp files : {TMP_DIR}/")
    print()
    print("[i] Route output contains full URLs.")
    print("[i] Parameter output contains query parameter names only.")
    print("[i] Case normalization and generic structural-pattern parameter")
    print("    detection are intentionally NOT used, as requested.")
    print("[i] Route dynamic reconstruction is enabled for numeric/UUID/ID")
    print("    segments and JS route expressions such as /users/:userId/settings.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
