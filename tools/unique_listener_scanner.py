#!/usr/bin/env python3
"""
Unique message-event-listener scanner.

Usage:
    python3 unique_listener_scanner.py -l list.txt -o results

The scanner:
  * opens each URL in the supplied order
  * waits 10 seconds after navigation
  * captures window/message and MessagePort "message" listeners before page
    scripts run
  * keeps only the first route for an identical listener
  * reconstructs listener/source code using the listener's toString() plus
    source files referenced by its registration stack
  * classifies the reconstructed listener code:
      - no-validation-listener.txt : Data strings, no Origin strings
      - validation-listener.txt     : Origin strings, with/without Data strings
      - p-xss-listener.txt          : Data strings + XSS sinks, no Origin strings
  * writes a JSONL audit file with every unique listener that was classified
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("[!] Playwright is required: python3 -m pip install playwright", file=sys.stderr)
    raise


WAIT_SECONDS = 10
MAX_SOURCE_FILES = 24
MAX_FUNCTIONS = 40
MAX_TRACE_DEPTH = 12

# The requested strings are treated as literal strings, except the supplied
# "window\\.open(" spelling is interpreted as window.open(.
XSS_SINKS = [
    "innerHTML=",
    "outerHTML=",
    "document.write(",
    "document.writeln(",
    "insertAdjacentHTML(",
    "eval(",
    "execScript(",
    "location=",
    "location.href=",
    "location.replace(",
    "location.assign(",
    "window.open(",
    "src=",
    ".html(",
    ".append(",
    "v-html=",
    "dangerouslySetInnerHTML=",
    "ng-bind-html=",
    "window.location=",
    "document.location=",
    "parent.location=",
    "self.location=",
    "frames[0].location=",
    "top.location=",
    "window.location.href=",
    "document.location.href=",
    "parent.location.href=",
    "self.location.href=",
    "top.location.href=",
    "window.location.assign(",
    "location.assign(",
    "window.location.replace(",
    "location.replace(",
]

ORIGIN_STRINGS = [
    ".source",
    ".origin",
    "source:",
    "origin:",
]

DATA_STRINGS = [
    ".data",
    ".type",
    "data:",
    "type:",
]


def clean_url(url: str) -> str:
    return url.strip()


def normalize_code(code: str) -> str:
    # Keep the actual source intact in output, but use a stable representation
    # for deduplication. Whitespace/comments are deliberately not removed:
    # two genuinely different listener bodies should not collapse accidentally.
    return re.sub(r"\s+", " ", code or "").strip()


def listener_key(item: dict[str, Any]) -> str:
    code = normalize_code(item.get("full_code") or item.get("listener") or "")
    event_type = str(item.get("type") or "")
    # Event type is included because the same function can legitimately be
    # registered for different event types.
    raw = event_type + "\x00" + code
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def contains_any(text: str, needles: list[str]) -> list[str]:
    lower = text.lower()
    return [needle for needle in needles if needle.lower() in lower]


def classify(code: str) -> tuple[str | None, dict[str, list[str]]]:
    data_hits = contains_any(code, DATA_STRINGS)
    origin_hits = contains_any(code, ORIGIN_STRINGS)
    xss_hits = contains_any(code, XSS_SINKS)

    # XSS candidate is specifically Data + XSS without an origin/source check.
    if data_hits and xss_hits and not origin_hits:
        return "p-xss-listener.txt", {
            "data": data_hits, "origin": origin_hits, "xss": xss_hits
        }

    # Validation category takes precedence whenever an Origin string exists.
    if origin_hits:
        return "validation-listener.txt", {
            "data": data_hits, "origin": origin_hits, "xss": xss_hits
        }

    # Interesting no-validation listener: Data exists, Origin does not.
    if data_hits:
        return "no-validation-listener.txt", {
            "data": data_hits, "origin": origin_hits, "xss": xss_hits
        }

    return None, {"data": [], "origin": [], "xss": []}


INIT_HOOK = r"""
(() => {
  if (window.__uniqueListenerScannerInstalled) return;
  window.__uniqueListenerScannerInstalled = true;

  const records = [];
  const originalAdd = EventTarget.prototype.addEventListener;
  const originalRemove = EventTarget.prototype.removeEventListener;
  const originalPortAdd =
    typeof MessagePort !== 'undefined' ? MessagePort.prototype.addEventListener : null;

  const ignored = new Set([
    'UniqueListenerScanner',
    '__uniqueListenerScanner',
  ]);

  function safeString(fn) {
    try { return typeof fn === 'function' ? Function.prototype.toString.call(fn) : String(fn); }
    catch (_) { return ''; }
  }

  function stackNow() {
    try {
      throw new Error('');
    } catch (e) {
      return String(e.stack || '').split('\n').map(x => x.trim()).filter(Boolean);
    }
  }

  function frameInfo() {
    try {
      return {
        href: location.href,
        frame: window.top === window ? 'top' : (window.name || 'iframe'),
        origin: location.origin
      };
    } catch (_) {
      return {href: '', frame: 'unknown', origin: ''};
    }
  }

  function record(target, type, listener, options) {
    if (type !== 'message' || typeof listener !== 'function') return;
    const code = safeString(listener);
    const stack = stackNow();
    const frame = frameInfo();

    // Avoid recording this scanner or common extension-injected listeners.
    const combined = code + '\n' + stack.join('\n');
    for (const word of ignored) {
      if (combined.includes(word)) return;
    }

    records.push({
      type: 'message',
      listener: code,
      full_code: code,
      stack: stack,
      target: target === window ? 'window' : 'other',
      route: frame.href,
      frame: frame.frame,
      origin: frame.origin,
      timestamp: Date.now()
    });
  }

  EventTarget.prototype.addEventListener = function(type, listener, options) {
    try { record(this, type, listener, options); } catch (_) {}
    return originalAdd.apply(this, arguments);
  };

  if (originalPortAdd) {
    MessagePort.prototype.addEventListener = function(type, listener, options) {
      try { record(this, type, listener, options); } catch (_) {}
      return originalPortAdd.apply(this, arguments);
    };
  }

  window.__uniqueListenerScannerGet = () => records.slice();
  window.__uniqueListenerScannerClear = () => { records.length = 0; };
})();
"""


async def install_and_collect(page) -> list[dict[str, Any]]:
    try:
        data = await page.evaluate("window.__uniqueListenerScannerGet ? window.__uniqueListenerScannerGet() : []")
        return data if isinstance(data, list) else []
    except Exception:
        return []


def stack_urls(stack: list[str]) -> list[str]:
    urls: list[str] = []
    seen = set()
    for line in stack or []:
        for raw in re.findall(r"https?://[^\s)\]}>,;]+", str(line), flags=re.I):
            raw = re.sub(r":\d+:\d+$", "", raw)
            try:
                u = urlparse(raw)
                if u.scheme in ("http", "https"):
                    # Preserve the source URL including query because it may be
                    # needed to retrieve the exact deployed source.
                    if raw not in seen:
                        seen.add(raw)
                        urls.append(raw)
            except Exception:
                pass
    return urls


def skip_quoted(src: str, i: int, quote: str) -> int:
    i += 1
    while i < len(src):
        if src[i] == "\\":
            i += 2
            continue
        if src[i] == quote:
            return i + 1
        i += 1
    return i


def skip_comment(src: str, i: int) -> int:
    if i + 1 < len(src) and src[i + 1] == "/":
        n = src.find("\n", i + 2)
        return len(src) if n < 0 else n + 1
    if i + 1 < len(src) and src[i + 1] == "*":
        n = src.find("*/", i + 2)
        return len(src) if n < 0 else n + 2
    return i + 1


def matching(src: str, open_pos: int, left: str, right: str) -> int:
    depth = 0
    i = open_pos
    while i < len(src):
        c = src[i]
        if c == "/" and i + 1 < len(src) and src[i + 1] in "/*":
            i = skip_comment(src, i)
            continue
        if c in "\"'`":
            i = skip_quoted(src, i, c)
            continue
        if c == left:
            depth += 1
        elif c == right:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def previous_identifier(src: str, pos: int) -> str:
    i = pos - 1
    while i >= 0 and src[i].isspace():
        i -= 1
    end = i + 1
    while i >= 0 and (src[i].isalnum() or src[i] in "_$"):
        i -= 1
    return src[i + 1:end] if i + 1 < end else ""


def extract_functions(source: str) -> dict[str, dict[str, Any]]:
    funcs: dict[str, dict[str, Any]] = {}

    def add(name: str, start: int, open_pos: int, end: int, kind: str):
        if not name or open_pos < 0 or end < 0:
            return
        code = source[start:end + 1].strip()
        if not code:
            return
        old = funcs.get(name)
        if old is None or len(code) < len(old["code"]):
            funcs[name] = {
                "name": name, "start": start, "open": open_pos,
                "end": end, "code": code, "kind": kind
            }

    fn_re = re.compile(r"\b(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\(")
    for m in fn_re.finditer(source):
        name = m.group(1) or previous_identifier(source, m.start())
        paren = source.find("(", m.start())
        close = matching(source, paren, "(", ")")
        if close < 0:
            continue
        open_pos = source.find("{", close)
        if open_pos < 0:
            continue
        end = matching(source, open_pos, "{", "}")
        add(name, m.start(), open_pos, end, "function")

    arrow_re = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
        r"(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
    )
    for m in arrow_re.finditer(source):
        name = m.group(1)
        arrow = source.find("=>", m.start())
        open_pos = source.find("{", arrow + 2)
        if open_pos < 0:
            continue
        end = matching(source, open_pos, "{", "}")
        add(name, m.start(), open_pos, end, "arrow")

    method_re = re.compile(r"(?:^|[,{;}]|\n)\s*([A-Za-z_$][\w$]*)\s*\([^()]*\)\s*\{")
    skip_names = {
        "if","for","while","switch","catch","with","function","return","throw",
        "typeof","void","delete","new","setTimeout","setInterval",
        "clearTimeout","clearInterval","Promise","Error","Array","Object",
        "String","Number","Boolean","JSON","Math","Date","RegExp","URL"
    }
    for m in method_re.finditer(source):
        name = m.group(1)
        if name in skip_names:
            continue
        open_pos = source.find("{", m.start() + m.group(0).rfind(")"))
        end = matching(source, open_pos, "{", "}")
        add(name, m.start(), open_pos, end, "method")

    return funcs


def called_names(code: str) -> list[str]:
    clean = []
    i = 0
    while i < len(code):
        c = code[i]
        if c == "/" and i + 1 < len(code) and code[i + 1] in "/*":
            i = skip_comment(code, i)
            clean.append(" ")
            continue
        if c in "\"'`":
            i = skip_quoted(code, i, c)
            clean.append(" ")
            continue
        clean.append(c)
        i += 1

    text = "".join(clean)
    names = []
    seen = set()
    for m in re.finditer(r"(?:^|[^.$\w])([A-Za-z_$][\w$]*)\s*\(", text):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


async def fetch_source_in_browser(context, url: str) -> str | None:
    # Fetch from the browser context so same-origin/cookie-protected sources
    # can be retrieved when the target page permits them.
    js = """
    async ({url}) => {
      try {
        const r = await fetch(url, {credentials:'include', cache:'no-store'});
        if (!r.ok) return null;
        return await r.text();
      } catch (_) { return null; }
    }
    """
    try:
        return await context.pages[0].evaluate(js, {"url": url})
    except Exception:
        return None


async def resolve_full_listener_code(context, item: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    listener_code = str(item.get("listener") or item.get("full_code") or "")
    urls = stack_urls(item.get("stack") or [])
    sources: dict[str, str] = {}
    queue = urls[:MAX_SOURCE_FILES]
    errors: list[str] = []

    while queue and len(sources) < MAX_SOURCE_FILES:
        url = queue.pop(0)
        if url in sources:
            continue
        source = await fetch_source_in_browser(context, url)
        if source is None:
            errors.append(url)
            continue
        sources[url] = source

        # Follow static ES-module imports/exports/dynamic imports.
        patterns = [
            r"\bimport\s+(?:[^'\";]*?\s+from\s+)?['\"]([^'\"]+)['\"]",
            r"\bexport\s+(?:[^'\";]*?\s+from\s+)['\"]([^'\"]+)['\"]",
            r"\bimport\(\s*['\"]([^'\"]+)['\"]\s*\)",
        ]
        for pat in patterns:
            for m in re.finditer(pat, source):
                try:
                    child = urljoin(url, m.group(1))
                    if urlparse(child).scheme in ("http", "https") and child not in sources:
                        if len(queue) + len(sources) < MAX_SOURCE_FILES:
                            queue.append(child)
                except Exception:
                    pass

    # The extension's trace logic starts with the actual captured listener,
    # then follows function calls into the source files.
    result_parts = [listener_code]
    all_functions: list[dict[str, Any]] = []
    for source_url, source in sources.items():
        for fn in extract_functions(source).values():
            fn = dict(fn)
            fn["url"] = source_url
            all_functions.append(fn)

    by_name: dict[str, list[dict[str, Any]]] = {}
    for fn in all_functions:
        by_name.setdefault(fn["name"], []).append(fn)

    pending = called_names(listener_code)
    wanted = set()
    depth = 0
    added = 0
    preferred_url = urls[0] if urls else None

    while pending and added < MAX_FUNCTIONS and depth < MAX_TRACE_DEPTH:
        name = pending.pop(0)
        if not name or name in wanted:
            continue
        wanted.add(name)
        candidates = by_name.get(name, [])
        if not candidates:
            continue

        fn = next((x for x in candidates if x["url"] == preferred_url), candidates[0])
        result_parts.append(
            "\n\n/* ===== Resolved function: %s | source: %s ===== */\n%s"
            % (fn["name"], fn["url"], fn["code"])
        )
        added += 1
        for child in called_names(fn["code"]):
            if child not in wanted and len(pending) < MAX_FUNCTIONS * 2:
                pending.append(child)
        depth += 1

    return "\n".join(result_parts), urls, errors


def format_record(item: dict[str, Any], category: str, hits: dict[str, list[str]],
                  full_code: str, source_urls: list[str], source_errors: list[str]) -> str:
    return (
        "\n" + "=" * 88 + "\n"
        f"ROUTE: {item.get('route', '')}\n"
        f"EVENT: {item.get('type', '')}\n"
        f"FRAME: {item.get('frame', '')}\n"
        f"CATEGORY: {category}\n"
        f"DATA MATCHES: {', '.join(hits['data']) or 'none'}\n"
        f"ORIGIN MATCHES: {', '.join(hits['origin']) or 'none'}\n"
        f"XSS SINK MATCHES: {', '.join(hits['xss']) or 'none'}\n"
        f"SOURCE URLS: {', '.join(source_urls) or 'none'}\n"
        f"SOURCE LOAD WARNINGS: {len(source_errors)}\n"
        "\n--- FULL LISTENER / TRACE CODE ---\n"
        f"{full_code.rstrip()}\n"
        + "=" * 88 + "\n"
    )


@dataclass
class ScanStats:
    urls_total: int = 0
    urls_loaded: int = 0
    listeners_seen: int = 0
    unique_listeners: int = 0
    duplicate_listeners: int = 0
    no_validation: int = 0
    validation: int = 0
    p_xss: int = 0


async def scan(args):
    urls = [
        clean_url(x) for x in Path(args.list).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        if x.strip() and not x.lstrip().startswith("#")
    ]

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    # Truncate result files at the beginning of every run.
    files = {
        "no-validation-listener.txt": out / "no-validation-listener.txt",
        "validation-listener.txt": out / "validation-listener.txt",
        "p-xss-listener.txt": out / "p-xss-listener.txt",
        "scan-results.jsonl": out / "scan-results.jsonl",
    }
    for p in files.values():
        p.write_text("", encoding="utf-8")

    stats = ScanStats(urls_total=len(urls))
    seen: set[str] = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=not args.headed,
            executable_path=args.chrome or None,
            args=["--disable-blink-features=AutomationControlled"],
        )

        context = await browser.new_context(ignore_https_errors=args.ignore_https_errors)
        await context.add_init_script(INIT_HOOK)

        # Avoid the scanner's own navigation logging from being confused with
        # the target page.
        for index, url in enumerate(urls, 1):
            page = await context.new_page()
            print(f"[{index}/{len(urls)}] {url}")

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=args.timeout * 1000)
            except PlaywrightTimeoutError:
                print("    ! navigation timeout; continuing with loaded page")
            except Exception as e:
                print(f"    ! navigation error: {e}")

            print(f"    waiting {WAIT_SECONDS}s for JavaScript/listeners to load...")
            await page.wait_for_timeout(WAIT_SECONDS * 1000)

            records = await install_and_collect(page)
            stats.listeners_seen += len(records)
            print(f"    captured {len(records)} message listeners")

            for item in records:
                code = str(item.get("listener") or item.get("full_code") or "")
                if not code:
                    continue

                key = listener_key(item)
                if key in seen:
                    stats.duplicate_listeners += 1
                    continue

                seen.add(key)
                stats.unique_listeners += 1

                # Use the current URL as the canonical route when the listener
                # was registered by a dynamically changing SPA.
                item["route"] = item.get("route") or page.url

                full_code, source_urls, source_errors = await resolve_full_listener_code(
                    context, item
                )
                item["full_code"] = full_code

                category, hits = classify(full_code)
                if not category:
                    continue

                text = format_record(
                    item, category, hits, full_code, source_urls, source_errors
                )
                with files[category].open("a", encoding="utf-8") as fh:
                    fh.write(text)

                audit = {
                    "route": item.get("route"),
                    "event": item.get("type"),
                    "frame": item.get("frame"),
                    "category": category,
                    "matches": hits,
                    "source_urls": source_urls,
                    "source_load_warnings": source_errors,
                    "listener": code,
                    "full_code": full_code,
                    "dedupe_key": key,
                }
                with files["scan-results.jsonl"].open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(audit, ensure_ascii=False) + "\n")

                if category == "no-validation-listener.txt":
                    stats.no_validation += 1
                    print("    + no-validation listener")
                elif category == "validation-listener.txt":
                    stats.validation += 1
                    print("    + validation listener")
                elif category == "p-xss-listener.txt":
                    stats.p_xss += 1
                    print("    + possible-XSS listener")

            stats.urls_loaded += 1
            await page.close()

        await browser.close()

    print("\n[+] Scan complete")
    print(f"    URLs                 : {stats.urls_total}")
    print(f"    URLs loaded          : {stats.urls_loaded}")
    print(f"    Listeners captured   : {stats.listeners_seen}")
    print(f"    Unique listeners     : {stats.unique_listeners}")
    print(f"    Duplicate listeners : {stats.duplicate_listeners}")
    print(f"    No validation       : {stats.no_validation}")
    print(f"    Validation          : {stats.validation}")
    print(f"    Possible XSS        : {stats.p_xss}")
    print(f"    Output directory    : {out.resolve()}")


def parse_args():
    ap = argparse.ArgumentParser(
        description="Find unique message event listeners and classify their full traced code."
    )
    ap.add_argument("-l", "--list", required=True, help="file containing URLs/routes, one per line")
    ap.add_argument("-o", "--output", required=True, help="output directory")
    ap.add_argument("--headed", action="store_true", help="show Chromium while scanning")
    ap.add_argument("--chrome", default=None, help="path to Chrome/Chromium executable")
    ap.add_argument(
        "--timeout", type=int, default=45,
        help="navigation timeout in seconds (default: 45)"
    )
    ap.add_argument(
        "--ignore-https-errors", action="store_true",
        help="ignore invalid TLS certificates"
    )
    return ap.parse_args()


if __name__ == "__main__":
    asyncio.run(scan(parse_args()))
