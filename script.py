import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
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
REDDIT_TIMEOUT = 5
REDDIT_BLOCKED_MARKERS = (
    "You've been blocked by network security.",
    "use your developer token",
    "If you think you've been blocked by mistake",
)

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


def is_reddit_blocked(body: str) -> bool:
    """True when Reddit displays its network-security block message."""
    normalized = _normalize_for_match(body)
    return any(_normalize_for_match(marker) in normalized for marker in REDDIT_BLOCKED_MARKERS)


def test_one(p: dict) -> tuple[bool, bool, bool, str, str]:
    """Return (works, gemini_ok, reddit_ok, gemini_status, reddit_status).

    `works` is the result of the original 3 reachability checks.
    Site compatibility checks run independently after those checks pass.
    """
    outbound = build_outbound(p)
    if not outbound:
        return (False, False, False,
                "Failed to build outbound configuration (invalid or missing address/port).", "")

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
                        f"Xray failed to bind/open port {port} within timeout.\nXray Debug Logs:\n{logs_str}", "")

            proxy_url = f"socks5h://127.0.0.1:{port}"
            proxies = {"http": proxy_url, "https": proxy_url}

            for url in TEST_ENDPOINTS:
                try:
                    r = requests.get(url, proxies=proxies, timeout=TEST_TIMEOUT, allow_redirects=True)
                    if r.status_code >= 500:
                        proc.terminate()
                        proc.wait(timeout=2)
                        return (False, False, False,
                                f"Test endpoint {url} returned failure status code: {r.status_code}", "")
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
                            f"Request exception connecting to test endpoint {url}: {req_err}.\nXray Debug Logs:\n{logs_str}", "")

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

            try:
                r = requests.get(
                    REDDIT_TEST_URL,
                    headers=HEADERS,
                    proxies=proxies,
                    timeout=REDDIT_TIMEOUT,
                    allow_redirects=True,
                )
                if is_reddit_blocked(r.text or ""):
                    reddit_status = "Blocked by Reddit network security"
                elif r.status_code in (403, 429):
                    reddit_status = f"Blocked/rate-limited (HTTP {r.status_code})"
                elif r.status_code >= 400:
                    reddit_status = f"HTTP {r.status_code}"
                else:
                    reddit_ok = True
                    reddit_status = "Allowed"
            except requests.RequestException as reddit_err:
                reddit_status = f"Unreachable: {reddit_err}"

            return (True, gemini_ok, reddit_ok, gemini_status, reddit_status)
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
                    gemini_reddit_pass: int, start: float) -> None:
    pct = done / total if total else 1.0
    bar_w = 30
    filled = int(bar_w * pct)
    bar = "█" * filled + "░" * (bar_w - filled)
    elapsed = time.time() - start
    eta = (elapsed / done) * (total - done) if done else 0.0

    if not IS_TTY:
        if done % 50 == 0 or done == total:
            print(f"  {done}/{total}  PASS {passed}  GEMINI {gemini_pass}  "
                  f"REDDIT {reddit_pass}  BOTH {gemini_reddit_pass}  "
                  f"FAIL {failed}  SKIP {skipped}")
        return

    line = (
        f"\r  [{bar}] {done}/{total} ({pct * 100:5.1f}%)  "
        f"PASS {passed}  GEMINI {gemini_pass}  REDDIT {reddit_pass}  "
        f"BOTH {gemini_reddit_pass}  FAIL {failed}  SKIP {skipped}  "
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
    reddit_blocked = 0
    reddit_other_fail = 0
    gemini_reddit_pass = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as ex:
        futures = {ex.submit(test_one, p): (uri, p) for uri, p in testable}
        done = 0
        for fut in as_completed(futures):
            done += 1
            uri, p = futures[fut]
            try:
                works, gemini_ok, reddit_ok, gemini_status, reddit_status = fut.result()
                if works:
                    record_working(uri)
                    passed += 1
                    if gemini_ok:
                        record_gemini(uri)
                        gemini_pass += 1
                    if reddit_ok:
                        reddit_pass += 1
                    elif reddit_status.startswith("Blocked"):
                        reddit_blocked += 1
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
                            gemini_pass, reddit_pass, gemini_reddit_pass, start)

    if IS_TTY:
        sys.stdout.write("\n")
        sys.stdout.flush()

    elapsed = time.time() - start
    log(f"Testing finished in {elapsed:.0f}s — "
        f"PASS {passed}  FAIL {failed}  SKIP {skipped}  (total {len(unique)})")
    log(f"Gemini-compatible: {gemini_pass}  "
        f"Gemini-blocked/unreachable: {passed - gemini_pass}")
    log(f"Reddit-accessible: {reddit_pass}  "
        f"Reddit-blocked/unreachable: {passed - reddit_pass}")
    log(f"Reddit network-security/rate-limit blocks: {reddit_blocked}  "
        f"Other HTTP errors/unreachable: {reddit_other_fail}")
    log(f"Gemini + Reddit compatible: {gemini_reddit_pass}")
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
