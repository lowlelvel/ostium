import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests

# ---------------------------------------------------------------- config
LINKS_FILE = Path(__file__).resolve().parent / "sub_links.txt"

FETCH_TIMEOUT_SECONDS = 5
RETRY_COUNT = 5
RUN_EVERY_SECONDS = 30 * 60

ARCHIVE_DIR = Path("./archive_all")
LOG_DIR = Path("./logs")

PROXIES = None
HEADERS = {"User-Agent": "Mozilla/5.0"}

XRAY_BINARY = "xray"
TEST_ENDPOINTS = [
    "https://cp.cloudflare.com",
    "https://www.gstatic.com",
    "https://captive.apple.com",
]
TEST_TIMEOUT = 1
TEST_WORKERS = 80

# ---- Gemini and Reddit compatibility checks ----
# Only run against configs that already passed all TEST_ENDPOINTS above.
GEMINI_TEST_URL = "https://gemini.google.com/"
GEMINI_TIMEOUT = 5
# The page tells us the country is blocked with this sentence.
# We normalize apostrophes (curly vs straight) and case before comparing.
GEMINI_BLOCKED_MARKER = "Gemini isn't currently supported in your country. Stay tuned!"

REDDIT_TEST_URL = "https://www.reddit.com/"
# Separate connect/read limits: Reddit can respond more slowly than the simple
# connectivity endpoints. No automatic retry is used, to avoid amplifying blocks.
REDDIT_TIMEOUT = (5, 8)
REDDIT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
# Avoid producing a burst of Reddit requests while the main Xray tests use
# multiple workers. These limits affect only the Reddit check.
REDDIT_MAX_CONCURRENT = 3
REDDIT_MIN_INTERVAL_SECONDS = 0.5
REDDIT_BODY_PREVIEW_CHARS = 350
REDDIT_BLOCKED_MARKERS = (
    "you've been blocked by network security",
    "you have been blocked by network security",
    "blocked by network security",
    "if you think you've been blocked by mistake",
)

_REDDIT_SEMAPHORE = threading.BoundedSemaphore(REDDIT_MAX_CONCURRENT)
_REDDIT_RATE_LOCK = threading.Lock()
_REDDIT_LAST_REQUEST_START = 0.0

CONFIG_RE = re.compile(
    r"(?:vmess|vless|trojan|ssr|ss|hysteria2|hysteria|hy2|tuic|wireguard|wg)://[^\s\"'<>`]+",
    re.IGNORECASE,
)

IS_TTY = sys.stdout.isatty()


# ---------------------------------------------------------------- helpers
def ensure_dirs() -> None:
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def ts_now() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def load_urls() -> list[str]:
    """Read subscription URLs from sub_links.txt.

    One URL per line. Blank lines and lines starting with '#' are ignored.
    Duplicates are collapsed (first occurrence wins, order preserved).
    """
    if not LINKS_FILE.exists():
        raise FileNotFoundError(f"Links file not found: {LINKS_FILE}")

    urls: list[str] = []
    seen: set[str] = set()
    for raw in LINKS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            urls.append(line)
    return urls


def b64decode_lenient(data: str) -> bytes:
    data = "".join(data.split())
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data, validate=False)


def normalize_to_text(raw: str) -> str:
    if "://" in raw:
        return raw
    try:
        decoded = b64decode_lenient(raw).decode("utf-8", errors="replace")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    out = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or "://" in s:
            out.append(line)
            continue
        try:
            decoded = b64decode_lenient(s).decode("utf-8", errors="replace")
            if "://" in decoded:
                out.append(decoded)
                continue
        except Exception:
            pass
        out.append(line)
    return "\n".join(out)


def extract_configs(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;)]}'\"><") for m in CONFIG_RE.finditer(text)]


def fetch_with_retries(url: str, timeout: int, retry_count: int) -> tuple[bool, str]:
    last_error = ""
    for attempt in range(1, retry_count + 1):
        try:
            r = requests.get(url, headers=HEADERS, proxies=PROXIES, timeout=timeout)
            r.raise_for_status()
            text = r.text.strip()
            if text:
                return True, text
            last_error = "Empty response"
        except Exception as e:
            last_error = str(e)
        if attempt < retry_count:
            time.sleep(1)
    return False, last_error


def find_latest_archive() -> Path | None:
    """Return the newest *_all_unique.txt in ARCHIVE_DIR, or None.

    The timestamp prefix (%Y-%m-%d_%H-%M-%S) is lexicographically sortable,
    so sorting by name is equivalent to sorting by time.
    """
    if not ARCHIVE_DIR.exists():
        return None
    files = sorted(ARCHIVE_DIR.glob("*_all_unique.txt"), key=lambda p: p.name)
    return files[-1] if files else None


# ---------------------------------------------------------------- parsing
def _q(params: dict, key: str, default: str = "") -> str:
    v = params.get(key)
    return v[0] if v else default


def parse_vmess(uri: str) -> dict | None:
    try:
        raw = uri[len("vmess://"):].split("#", 1)[0]
        data = json.loads(b64decode_lenient(raw).decode("utf-8", errors="replace"))
    except Exception:
        return None
    try:
        port = int(data.get("port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    try:
        aid = int(data.get("aid", 0) or 0)
    except (TypeError, ValueError):
        aid = 0
    return {
        "protocol": "vmess",
        "address": data.get("add", ""),
        "port": port,
        "uuid": data.get("id", ""),
        "alterId": aid,
        "security": data.get("scy", "auto") or "auto",
        "network": data.get("net", "tcp") or "tcp",
        "headerType": data.get("type", ""),
        "host": data.get("host", ""),
        "path": data.get("path", "") or "/",
        "tls": data.get("tls", ""),
        "sni": data.get("sni", ""),
        "alpn": data.get("alpn", ""),
        "fp": data.get("fp", ""),
        "remark": data.get("ps", ""),
    }


def parse_url_style(uri: str, protocol: str) -> dict | None:
    try:
        p = urlparse(uri)
        params = parse_qs(p.query)
        return {
            "protocol": protocol,
            "uuid": unquote(p.username or ""),
            "address": p.hostname or "",
            "port": p.port or 0,
            "remark": unquote(p.fragment or ""),
            "network": _q(params, "type", "tcp") or "tcp",
            "tls": _q(params, "security", ""),
            "sni": _q(params, "sni", ""),
            "host": _q(params, "host", ""),
            "path": _q(params, "path", "") or "/",
            "fp": _q(params, "fp", ""),
            "alpn": _q(params, "alpn", ""),
            "flow": _q(params, "flow", ""),
            "serviceName": _q(params, "serviceName", ""),
            "pbk": _q(params, "pbk", ""),
            "sid": _q(params, "sid", ""),
            "headerType": _q(params, "headerType", ""),
            "mode": _q(params, "mode", ""),
        }
    except Exception:
        return None


def parse_ss(uri: str) -> dict | None:
    try:
        p = urlparse(uri)
        remark = unquote(p.fragment or "")
        if p.username and p.hostname and p.port:
            try:
                method_pass = b64decode_lenient(unquote(p.username)).decode("utf-8", errors="replace")
                if ":" in method_pass:
                    method, password = method_pass.split(":", 1)
                    return {
                        "protocol": "ss",
                        "address": p.hostname,
                        "port": p.port,
                        "method": method,
                        "password": password,
                        "remark": remark,
                    }
            except Exception:
                pass
        decoded = b64decode_lenient(uri[len("ss://"):].split("#", 1)[0]).decode(
            "utf-8", errors="replace"
        )
        method_pass, host_port = decoded.rsplit("@", 1)
        method, password = method_pass.split(":", 1)
        host, port = host_port.rsplit(":", 1)
        return {
            "protocol": "ss",
            "address": host,
            "port": int(port),
            "method": method,
            "password": password,
            "remark": remark,
        }
    except Exception:
        return None


def parse_config(uri: str) -> dict | None:
    uri = uri.strip()
    try:
        if uri.startswith("vmess://"):
            return parse_vmess(uri)
        if uri.startswith("vless://"):
            return parse_url_style(uri, "vless")
        if uri.startswith("trojan://"):
            return parse_url_style(uri, "trojan")
        if uri.startswith("ss://"):
            return parse_ss(uri)
    except Exception:
        return None
    return None


def fingerprint(p: dict) -> tuple:
    return (
        p.get("protocol"),
        (p.get("address") or "").lower(),
        p.get("port"),
        p.get("uuid") or "",
        p.get("method") or "",
        p.get("password") or "",
        p.get("network") or "",
        p.get("tls") or "",
        p.get("sni") or "",
        p.get("host") or "",
        p.get("path") or "",
        p.get("serviceName") or "",
        p.get("flow") or "",
        p.get("pbk") or "",
        p.get("sid") or "",
        p.get("headerType") or "",
        p.get("alterId") or 0,
    )


# ---------------------------------------------------------------- xray test
def build_stream(p: dict) -> dict:
    network = p.get("network") or "tcp"
    tls = p.get("tls") or ""
    host = p.get("host") or ""
    path = p.get("path") or "/"
    stream: dict = {"network": network}

    if network == "ws":
        ws = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("serviceName") or ""}
    elif network in ("h2", "http"):
        stream["network"] = "h2"
        h2 = {"path": path}
        if host:
            h2["host"] = [h for h in host.split(",") if h]
        stream["httpSettings"] = h2
    elif network == "tcp" and p.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"path": [path], "headers": {"Host": [host] if host else []}},
            }
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": path, "host": host, "mode": p.get("mode") or ""}

    if tls == "tls":
        ts = {}
        sni = p.get("sni") or host or p.get("address") or ""
        if sni:
            ts["serverName"] = sni
        if p.get("fp"):
            ts["fingerprint"] = p["fp"]
        if p.get("alpn"):
            ts["alpn"] = [a.strip() for a in p["alpn"].split(",") if a.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = ts
    elif tls == "reality":
        rs = {}
        if p.get("sni"):
            rs["serverName"] = p["sni"]
        if p.get("fp"):
            rs["fingerprint"] = p["fp"]
        if p.get("pbk"):
            rs["publicKey"] = p["pbk"]
        if p.get("sid"):
            rs["shortId"] = p["sid"]
        stream["security"] = "reality"
        stream["realitySettings"] = rs
    else:
        stream["security"] = "none"

    return stream


def build_outbound(p: dict) -> dict | None:
    proto = p["protocol"]
    if not p.get("address") or not p.get("port"):
        return None
    try:
        port = int(p["port"])
    except (TypeError, ValueError):
        return None

    if proto in ("vmess", "vless"):
        user: dict = {"id": p["uuid"]}
        if proto == "vmess":
            user["alterId"] = int(p.get("alterId") or 0)
            user["security"] = p.get("security") or "auto"
        else:
            user["encryption"] = "none"
            if p.get("flow"):
                user["flow"] = p["flow"]
        return {
            "protocol": proto,
            "settings": {"vnext": [{
                "address": p["address"],
                "port": port,
                "users": [user],
            }]},
            "streamSettings": build_stream(p),
        }
    if proto == "trojan":
        return {
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": p["address"],
                "port": port,
                "password": p["uuid"],
            }]},
            "streamSettings": build_stream(p),
        }
    if proto == "ss":
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": p["address"],
                "port": port,
                "method": p["method"],
                "password": p["password"],
            }]},
        }
    return None


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port: int, timeout: float = 5.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ---------------------------------------------------------------- gemini check
def _normalize_for_match(s: str) -> str:
    """Lowercase + unify apostrophes so we match the marker regardless of typography."""
    return (
        s.replace("\u2018", "'")      # left single quote
         .replace("\u2019", "'")      # right single quote
         .replace("\u02BC", "'")      # modifier letter apostrophe
         .lower()
    )


def is_gemini_blocked(body: str) -> bool:
    """True when the page tells us this IP's country can't use Gemini."""
    return _normalize_for_match(GEMINI_BLOCKED_MARKER) in _normalize_for_match(body)


def find_reddit_block_marker(body: str) -> str | None:
    """Return the known Reddit security-block phrase found in a response."""
    normalized = _normalize_for_match(unescape(body or ""))
    for marker in REDDIT_BLOCKED_MARKERS:
        normalized_marker = _normalize_for_match(marker)
        if normalized_marker in normalized:
            return marker
    return None


def is_reddit_blocked(body: str) -> bool:
    """True only for a response containing a recognized Reddit block marker."""
    return find_reddit_block_marker(body) is not None


def _reddit_rate_limit() -> None:
    """Space request starts globally across worker threads."""
    global _REDDIT_LAST_REQUEST_START
    with _REDDIT_RATE_LOCK:
        now = time.monotonic()
        delay = REDDIT_MIN_INTERVAL_SECONDS - (now - _REDDIT_LAST_REQUEST_START)
        if delay > 0:
            time.sleep(delay)
        _REDDIT_LAST_REQUEST_START = time.monotonic()


def _response_excerpt(body: str, marker: str | None = None) -> str:
    """Return a short, single-line diagnostic excerpt without dumping HTML."""
    text = re.sub(r"\s+", " ", unescape(body or "")).strip()
    if not text:
        return "<empty response body>"
    if marker:
        lower_text = _normalize_for_match(text)
        lower_marker = _normalize_for_match(marker)
        pos = lower_text.find(lower_marker)
        if pos >= 0:
            start = max(0, pos - 100)
            end = min(len(text), pos + len(marker) + 180)
            return text[start:end][:REDDIT_BODY_PREVIEW_CHARS]
    return text[:REDDIT_BODY_PREVIEW_CHARS]


def classify_reddit_response(response: requests.Response) -> tuple[bool, str, str, str]:
    """Return (allowed, status, details, category) for an HTTP response.

    A generic HTTP 403 is deliberately NOT called a confirmed network-security
    block unless the response body contains one of Reddit's known block markers.
    """
    body = response.text or ""
    marker = find_reddit_block_marker(body)
    status_code = response.status_code
    content_type = response.headers.get("Content-Type", "unknown")
    final_url = response.url
    elapsed = getattr(getattr(response, "elapsed", None), "total_seconds", lambda: 0.0)()
    body_bytes = len(response.content or b"")

    history = getattr(response, "history", []) or []
    redirect_chain = " -> ".join([item.url for item in history] + [final_url])
    detail_parts = [
        f"HTTP {status_code}",
        f"redirect_chain={redirect_chain}",
        f"final_url={final_url}",
        f"content_type={content_type}",
        f"elapsed={elapsed:.2f}s",
        f"body_bytes={body_bytes}",
    ]
    for header in ("Server", "Retry-After", "X-Ratelimit-Used", "X-Ratelimit-Remaining", "X-Ratelimit-Reset", "X-Reddit-Request-Id"):
        value = response.headers.get(header)
        if value:
            detail_parts.append(f"{header}={value}")
    if marker:
        detail_parts.append(f"matched_marker={marker!r}")
    detail_parts.append(f"body_excerpt={_response_excerpt(body, marker)!r}")
    details = " | ".join(detail_parts)

    if marker:
        return False, f"Confirmed network-security block (HTTP {status_code})", details, "security_block"
    if status_code == 429:
        return False, "Rate limited (HTTP 429; no known security marker)", details, "rate_limited"
    if status_code == 403:
        return False, "HTTP 403 (no recognized Reddit security marker)", details, "unclassified_403"
    if status_code == 401:
        return False, "Authentication required (HTTP 401)", details, "login_required"
    if status_code >= 500:
        return False, f"Reddit server error (HTTP {status_code})", details, "http_error"
    if status_code >= 400:
        return False, f"HTTP error {status_code}", details, "http_error"
    if 200 <= status_code < 300:
        if not body.strip():
            return False, f"Empty response body (HTTP {status_code})", details, "other"
        final_path = urlparse(final_url).path.lower().rstrip("/")
        if final_path.startswith(("/login", "/account/login", "/register")):
            return False, f"Login page returned (HTTP {status_code})", details, "login_required"
        normalized_content_type = content_type.lower()
        if normalized_content_type != "unknown" and not any(
            kind in normalized_content_type for kind in ("text/html", "application/xhtml+xml")
        ):
            return False, f"Unexpected content type ({content_type})", details, "other"
        return True, f"Allowed (HTTP {status_code})", details, "allowed"
    if 300 <= status_code < 400:
        return False, f"Unresolved redirect (HTTP {status_code})", details, "other"
    return False, f"Unexpected HTTP status {status_code}", details, "other"


def reddit_request(proxies: dict | None = None) -> tuple[bool, str, str, str]:
    """Make one paced Reddit homepage request through the supplied proxy."""
    with _REDDIT_SEMAPHORE:
        _reddit_rate_limit()
        response = requests.get(
            REDDIT_TEST_URL,
            headers=REDDIT_HEADERS,
            proxies=proxies,
            timeout=REDDIT_TIMEOUT,
            allow_redirects=True,
        )
    return classify_reddit_response(response)


def reddit_direct_control() -> tuple[str, str]:
    """Probe Reddit once directly (not through Xray) as a runner/network control."""
    try:
        # Disable environment proxies so this is a genuine direct-runner control.
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                REDDIT_TEST_URL,
                headers=REDDIT_HEADERS,
                timeout=REDDIT_TIMEOUT,
                allow_redirects=True,
            )
        _, status, details, _ = classify_reddit_response(response)
        return status, details
    except requests.RequestException as exc:
        return f"Unreachable: {type(exc).__name__}: {exc}", f"direct_runner_exception={exc!r}"


def test_one(p: dict) -> tuple[bool, bool, bool, str, str, str, str]:
    """Return (works, gemini_ok, reddit_ok, gemini_status, reddit_status, reddit_details, reddit_category).

    `works` is the result of the original 3 reachability checks.
    Site compatibility checks run independently after those checks pass.
    """
    outbound = build_outbound(p)
    if not outbound:
        return (False, False, False,
                "Failed to build outbound configuration (invalid or missing address/port).", "", "", "")

    port = free_port()
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [outbound],
    }

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = Path(tmp) / "c.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

        proc = subprocess.Popen(
            [XRAY_BINARY, "run", "-c", str(cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        xray_output = []

        try:
            if not wait_port(port, 5.0):
                proc.terminate()
                try:
                    stdout, _ = proc.communicate(timeout=2)
                    if stdout:
                        xray_output.append(stdout)
                except Exception:
                    pass
                logs_str = "".join(xray_output)
                return (False, False, False,
                        f"Xray failed to bind/open port {port} within timeout.\nXray Debug Logs:\n{logs_str}", "", "", "")

            proxy_url = f"socks5h://127.0.0.1:{port}"
            proxies = {"http": proxy_url, "https": proxy_url}

            for url in TEST_ENDPOINTS:
                try:
                    r = requests.get(url, proxies=proxies, timeout=TEST_TIMEOUT, allow_redirects=True)
                    if r.status_code >= 500:
                        proc.terminate()
                        proc.wait(timeout=2)
                        return (False, False, False,
                                f"Test endpoint {url} returned failure status code: {r.status_code}", "", "", "")
                except requests.RequestException as req_err:
                    proc.terminate()
                    proc.wait(timeout=2)
                    try:
                        out, _ = proc.communicate(timeout=1)
                        if out:
                            xray_output.append(out)
                    except Exception:
                        pass
                    logs_str = "".join(xray_output)
                    return (False, False, False,
                            f"Request exception connecting to test endpoint {url}: {req_err}.\nXray Debug Logs:\n{logs_str}", "", "", "")

            # ---- Base checks passed. Check Gemini and Reddit independently. ----
            gemini_ok = False
            reddit_ok = False

            try:
                g = requests.get(
                    GEMINI_TEST_URL,
                    proxies=proxies,
                    timeout=GEMINI_TIMEOUT,
                    allow_redirects=True,
                )
                if g.status_code >= 400:
                    gemini_status = f"HTTP {g.status_code}"
                elif is_gemini_blocked(g.text or ""):
                    gemini_status = "Geo-blocked"
                else:
                    gemini_ok = True
                    gemini_status = "Allowed"
            except requests.RequestException as gemini_err:
                gemini_status = f"Unreachable: {gemini_err}"

            reddit_details = ""
            reddit_category = "other"
            try:
                reddit_ok, reddit_status, reddit_details, reddit_category = reddit_request(proxies)
            except requests.RequestException as reddit_err:
                reddit_status = f"Unreachable: {type(reddit_err).__name__}: {reddit_err}"
                reddit_details = f"request_exception={reddit_err!r}"
                reddit_category = "unreachable"

            return (True, gemini_ok, reddit_ok, gemini_status,
                    reddit_status, reddit_details, reddit_category)
        finally:
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=3)
                if stdout:
                    xray_output.append(stdout)
            except subprocess.TimeoutExpired:
                proc.kill()


def xray_available() -> bool:
    try:
        r = subprocess.run([XRAY_BINARY, "version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def socks_support_available() -> bool:
    """Requests needs PySocks to use socks5/socks5h proxy URLs."""
    try:
        import socks  # noqa: F401  (provided by the PySocks package)
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------- progress
def render_progress(done: int, total: int, passed: int, failed: int,
                    skipped: int, gemini_pass: int, reddit_pass: int,
                    reddit_attempted: int, gemini_reddit_pass: int,
                    start: float) -> None:
    pct = done / total if total else 1.0
    bar_w = 30
    filled = int(bar_w * pct)
    bar = "█" * filled + "░" * (bar_w - filled)
    elapsed = time.time() - start
    eta = (elapsed / done) * (total - done) if done else 0.0

    if not IS_TTY:
        if done % 50 == 0 or done == total:
            print(f"  {done}/{total}  PASS {passed}  GEMINI {gemini_pass}  "
                  f"REDDIT {reddit_pass}/{reddit_attempted}  BOTH {gemini_reddit_pass}  "
                  f"FAIL {failed}  SKIP {skipped}")
        return

    line = (
        f"\r  [{bar}] {done}/{total} ({pct * 100:5.1f}%)  "
        f"PASS {passed}  GEMINI {gemini_pass}  "
        f"REDDIT {reddit_pass}/{reddit_attempted}  BOTH {gemini_reddit_pass}  "
        f"FAIL {failed}  SKIP {skipped}  "
        f"ETA {eta:4.0f}s"
    )
    sys.stdout.write(line + "\x1b[K")
    sys.stdout.flush()


# ---------------------------------------------------------------- persistence
def save_uri_list(path: Path, uris: list[str]) -> None:
    path.write_text("\n".join(uris) + ("\n" if uris else ""), encoding="utf-8")


def save_failed_log(failures: list[tuple[str, str]]) -> Path | None:
    if not failures:
        return None
    log_file = LOG_DIR / f"{ts_now()}_failed.txt"
    with log_file.open("w", encoding="utf-8", newline="\n") as f:
        for i, (url, err) in enumerate(failures, 1):
            f.write(f"[{i}] {url}\nERROR: {err}\n{'-' * 80}\n")
    return log_file


def save_detailed_failures_log(failures: list[tuple[str, dict, str]]) -> Path | None:
    if not failures:
        return None
    log_file = LOG_DIR / f"{ts_now()}_detailed_failures.txt"
    with log_file.open("w", encoding="utf-8", newline="\n") as f:
        for i, (uri, p, reason) in enumerate(failures, 1):
            f.write(f"[{i}] URI: {uri}\n")
            f.write(f"Parsed Config: {json.dumps(p, indent=2)}\n")
            f.write(f"Detailed Failure Reason / Xray Debug Output:\n{reason}\n")
            f.write(f"{'-' * 80}\n")
    return log_file


def _append_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def _write_b64(path: Path, uris: list[str]) -> None:
    encoded = base64.b64encode("\n".join(uris).encode("utf-8")).decode("ascii")
    tmp = path.with_suffix(".tmp")
    tmp.write_text(encoded, encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------- cycle
def run_once(use_last_fetch: bool = False) -> None:
    ensure_dirs()

    # ---- source: fresh fetch OR latest archive ----
    if use_last_fetch:
        src = find_latest_archive()
        if not src:
            log(f"ERROR: --last-fetch given, but no *_all_unique.txt found in {ARCHIVE_DIR}")
            log("       Run without --last-fetch first to create one.")
            return
        log(f"Reusing archive: {src}")
        content = src.read_text(encoding="utf-8")
        raw_uris = [line.strip() for line in content.splitlines() if line.strip()]
        failures: list[tuple[str, str]] = []
        log(f"Loaded {len(raw_uris)} configs from archive")
        if not raw_uris:
            log("WARNING: archive is empty — nothing to test.")
            return
    else:
        try:
            urls = load_urls()
        except FileNotFoundError as e:
            log(f"ERROR: {e}")
            log(f"       Create {LINKS_FILE} with one URL per line.")
            return

        if not urls:
            log(f"ERROR: {LINKS_FILE} contains no URLs (all lines blank or commented).")
            return

        log(f"Starting fetch cycle ({len(urls)} URLs from {LINKS_FILE.name})...")
        raw_uris = []
        failures = []
        for url in urls:
            log(f"Fetching: {url}")
            ok, content = fetch_with_retries(url, FETCH_TIMEOUT_SECONDS, RETRY_COUNT)
            if not ok:
                failures.append((url, content))
                log(f"  FAILED: {content}")
                continue
            extracted = extract_configs(normalize_to_text(content))
            log(f"  {len(extracted)} configs")
            raw_uris.extend(extracted)

    # ---- parse + dedupe ----
    unique: list[tuple[str, dict]] = []
    seen = set()
    for uri in raw_uris:
        p = parse_config(uri)
        if not p:
            continue
        fp = fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        unique.append((uri, p))

    log(f"Total: {len(raw_uris)}  Unique: {len(unique)}")
    stamp = ts_now()

    if not use_last_fetch:
        save_uri_list(ARCHIVE_DIR / f"{stamp}_all_unique.txt", [u for u, _ in unique])

    # ---- split into testable vs skipped ----
    testable: list[tuple[str, dict]] = []
    skipped = 0
    for uri, p in unique:
        if build_outbound(p) is None:
            skipped += 1
        else:
            testable.append((uri, p))
    if skipped:
        log(f"  {skipped} configs skipped (unsupported protocol for xray tester)")

    working_txt = ARCHIVE_DIR / f"{stamp}_working.txt"
    working_b64 = ARCHIVE_DIR / f"{stamp}_working_base64.txt"
    gemini_txt = ARCHIVE_DIR / f"{stamp}_gemini_compatible_working.txt"
    gemini_b64 = ARCHIVE_DIR / f"{stamp}_gemini_compatible_working_base64.txt"
    gemini_reddit_txt = ARCHIVE_DIR / f"{stamp}_gemini_reddit_working.txt"
    working_txt.write_text("", encoding="utf-8")
    working_b64.write_text("", encoding="utf-8")
    gemini_txt.write_text("", encoding="utf-8")
    gemini_b64.write_text("", encoding="utf-8")
    gemini_reddit_txt.write_text("", encoding="utf-8")

    if not socks_support_available():
        log("ERROR: SOCKS proxy support is missing from this Python environment.")
        log('       Install it with: python -m pip install "requests[socks]"')
        log("       In GitHub Actions, install this dependency before running the script.")
        save_failed_log(failures)
        return

    if not xray_available():
        log("WARNING: xray binary not available; skipping live test.")
        save_failed_log(failures)
        return

    log(f"Testing {len(testable)} configs with verbose diagnostics (workers={TEST_WORKERS})...")

    working: list[str] = []
    gemini_working: list[str] = []
    gemini_reddit_working: list[str] = []
    detailed_failures: list[tuple[str, dict, str]] = []
    # Keep per-config site-check outcomes so a zero Reddit pass count is diagnosable.
    site_check_results: list[tuple[str, str, str, str]] = []

    def record_working(uri: str) -> None:
        working.append(uri)
        _append_line(working_txt, uri)
        _write_b64(working_b64, working)

    def record_gemini(uri: str) -> None:
        gemini_working.append(uri)
        _append_line(gemini_txt, uri)
        _write_b64(gemini_b64, gemini_working)

    def record_gemini_reddit(uri: str) -> None:
        gemini_reddit_working.append(uri)
        _append_line(gemini_reddit_txt, uri)

    passed = 0
    failed = 0
    gemini_pass = 0
    reddit_pass = 0
    reddit_attempted = 0
    reddit_security_blocks = 0
    reddit_rate_limited = 0
    reddit_unclassified_403 = 0
    reddit_login_required = 0
    reddit_http_errors = 0
    reddit_unreachable = 0
    reddit_other_fail = 0
    gemini_reddit_pass = 0
    start = time.time()
    direct_reddit_status, direct_reddit_details = reddit_direct_control()
    log(f"Direct runner Reddit control (NOT through Xray): {direct_reddit_status}")
    log(f"Reddit check pacing: max concurrent={REDDIT_MAX_CONCURRENT}, "
        f"minimum interval={REDDIT_MIN_INTERVAL_SECONDS:.2f}s, "
        f"timeout connect/read={REDDIT_TIMEOUT[0]}/{REDDIT_TIMEOUT[1]}s")

    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as ex:
        futures = {ex.submit(test_one, p): (uri, p) for uri, p in testable}
        done = 0
        for fut in as_completed(futures):
            done += 1
            uri, p = futures[fut]
            try:
                (works, gemini_ok, reddit_ok, gemini_status, reddit_status,
                 reddit_details, reddit_category) = fut.result()
                if works:
                    record_working(uri)
                    passed += 1
                    # Reddit is checked independently for every config that passes
                    # the three base connectivity endpoints.
                    reddit_attempted += 1
                    site_check_results.append((uri, gemini_status, reddit_status, reddit_details))
                    if gemini_ok:
                        record_gemini(uri)
                        gemini_pass += 1
                    if reddit_ok:
                        reddit_pass += 1
                    elif reddit_category == "security_block":
                        reddit_security_blocks += 1
                    elif reddit_category == "rate_limited":
                        reddit_rate_limited += 1
                    elif reddit_category == "unclassified_403":
                        reddit_unclassified_403 += 1
                    elif reddit_category == "login_required":
                        reddit_login_required += 1
                    elif reddit_category == "http_error":
                        reddit_http_errors += 1
                    elif reddit_category == "unreachable":
                        reddit_unreachable += 1
                    else:
                        reddit_other_fail += 1
                    if gemini_ok and reddit_ok:
                        record_gemini_reddit(uri)
                        gemini_reddit_pass += 1
                else:
                    failed += 1
                    detailed_failures.append((uri, p, gemini_status))
            except Exception as e:
                failed += 1
                detailed_failures.append((uri, p, f"Unhandled exception during test execution: {e}"))
                if IS_TTY:
                    sys.stdout.write("\n")
                log(f"  ERR testing {uri[:70]}: {e}")
            render_progress(done, len(testable), passed, failed, skipped,
                            gemini_pass, reddit_pass, reddit_attempted,
                            gemini_reddit_pass, start)

    if IS_TTY:
        sys.stdout.write("\n")
        sys.stdout.flush()

    elapsed = time.time() - start
    log(f"Testing finished in {elapsed:.0f}s — "
        f"PASS {passed}  FAIL {failed}  SKIP {skipped}  (total {len(unique)})")
    log(f"Gemini-compatible: {gemini_pass}  "
        f"Gemini-blocked/unreachable: {passed - gemini_pass}")
    log(f"Reddit checks attempted: {reddit_attempted}")
    log(f"Reddit-accessible: {reddit_pass}  "
        f"Confirmed network-security blocks: {reddit_security_blocks}  "
        f"Rate limited (HTTP 429): {reddit_rate_limited}  "
        f"Unclassified HTTP 403: {reddit_unclassified_403}  "
        f"Login required: {reddit_login_required}  "
        f"Other HTTP errors: {reddit_http_errors}  "
        f"Unreachable: {reddit_unreachable}  Other: {reddit_other_fail}")
    log(f"Gemini + Reddit compatible: {gemini_reddit_pass}")

    # Save per-config outcomes and response metadata/body excerpts. A generic
    # 403 is kept separate from a confirmed Reddit network-security page.
    site_check_log = LOG_DIR / f"{stamp}_gemini_reddit_checks.txt"
    with site_check_log.open("w", encoding="utf-8", newline="\n") as f:
        f.write("DIRECT RUNNER CONTROL (not through Xray)\n")
        f.write(f"Reddit: {direct_reddit_status}\n")
        f.write(f"Details: {direct_reddit_details}\n")
        f.write("=" * 80 + "\n")
        for i, (uri, gemini_status, reddit_status, reddit_details) in enumerate(site_check_results, 1):
            f.write(f"[{i}] URI: {uri}\n")
            f.write(f"Gemini: {gemini_status}\n")
            f.write(f"Reddit: {reddit_status}\n")
            f.write(f"Reddit details: {reddit_details}\n")
            f.write("-" * 80 + "\n")
    log(f"Saved per-config Gemini/Reddit diagnostics: {site_check_log}")
    log(f"Saved: {working_txt}  ({len(working)} configs)")
    log(f"Saved: {working_b64}")
    log(f"Saved: {gemini_txt}  ({len(gemini_working)} configs)")
    log(f"Saved: {gemini_b64}")
    log(f"Saved: {gemini_reddit_txt}  ({len(gemini_reddit_working)} configs)")

    detailed_log_path = save_detailed_failures_log(detailed_failures)
    if detailed_log_path:
        log(f"Saved detailed failure diagnostics log: {detailed_log_path}")

    failed_log = save_failed_log(failures)
    if failed_log:
        log(f"Saved failure log: {failed_log}")

    log("Fetch cycle finished.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy config fetcher & tester")
    parser.add_argument(
        "--last-fetch",
        action="store_true",
        help="Skip fetching and reuse the newest *_all_unique.txt from archive_all/",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one cycle and exit (default: loop every RUN_EVERY_SECONDS)",
    )
    args = parser.parse_args()

    if args.once:
        try:
            run_once(use_last_fetch=args.last_fetch)
        except KeyboardInterrupt:
            log("Stopped by user.")
        except Exception as e:
            log(f"Fatal error: {e}")
        return

    while True:
        try:
            run_once(use_last_fetch=args.last_fetch)
        except KeyboardInterrupt:
            log("Stopped by user.")
            break
        except Exception as e:
            ensure_dirs()
            log_file = LOG_DIR / f"{ts_now()}_failed.txt"
            log_file.write_text(f"Fatal cycle error: {e}\n", encoding="utf-8")
            log(f"Fatal cycle error logged to: {log_file}")
        time.sleep(RUN_EVERY_SECONDS)


if __name__ == "__main__":
    main()
