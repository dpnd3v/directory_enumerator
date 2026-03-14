"""
Directory Enumerator - OSINT Tool
High-performance async HTTP directory and file brute-force.
Includes smart SPA/catch-all detection, CDN fingerprinting, geolocation.

Dependencies:
    pip install aiohttp

Python >= 3.11 recommended.
"""

import sys
import asyncio
import argparse
import hashlib
import ipaddress
import json
import socket
import time
import urllib.request
import urllib.error
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
from pathlib import Path
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

STATUS_LABELS = {
    200: "FOUND",     201: "FOUND",    204: "FOUND",
    301: "REDIRECT",  302: "REDIRECT", 307: "REDIRECT", 308: "REDIRECT",
    401: "AUTH",      403: "FORBIDDEN",405: "METHOD",
    500: "ERROR",     503: "ERROR",
}
INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}

CDN_IP_RANGES = [
    ("103.21.244.0/22","Cloudflare"),("103.22.200.0/22","Cloudflare"),
    ("104.16.0.0/13","Cloudflare"),("104.24.0.0/14","Cloudflare"),
    ("108.162.192.0/18","Cloudflare"),("162.158.0.0/15","Cloudflare"),
    ("172.64.0.0/13","Cloudflare"),("173.245.48.0/20","Cloudflare"),
    ("188.114.96.0/20","Cloudflare"),("190.93.240.0/20","Cloudflare"),
    ("198.41.128.0/17","Cloudflare"),
    ("151.101.0.0/16","Fastly"),("199.232.0.0/16","Fastly"),
    ("13.32.0.0/15","AWS CloudFront"),("13.224.0.0/14","AWS CloudFront"),
    ("54.192.0.0/16","AWS CloudFront"),("204.246.164.0/22","AWS CloudFront"),
]
_CDN_NETS = [(ipaddress.ip_network(c), l) for c, l in CDN_IP_RANGES]
LOCALHOST_PREFIXES = ["127.","10.","192.168.","::1","0.0.0.0"]

def _hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def is_localhost(ip: str) -> bool:
    for p in LOCALHOST_PREFIXES:
        if ip.startswith(p): return True
    try:
        parts = ip.split(".")
        if len(parts) == 4 and int(parts[0]) == 172 and 16 <= int(parts[1]) <= 31:
            return True
    except Exception:
        pass
    return False

def cdn_from_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        for net, label in _CDN_NETS:
            if addr in net: return label
    except ValueError:
        pass
    return "-"

_GEO_CACHE: dict[str, str] = {}

def geolocate(ip: str) -> str:
    if ip in _GEO_CACHE: return _GEO_CACHE[ip]
    if is_localhost(ip):
        _GEO_CACHE[ip] = "localhost"; return "localhost"
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,city,country"
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            city = data.get("city",""); country = data.get("country","")
            result = f"{city}, {country}" if city else country or "-"
        else:
            result = "-"
    except Exception:
        result = "-"
    _GEO_CACHE[ip] = result
    return result

def resolve_target(hostname: str) -> dict:
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return {"ip": "-", "cdn": "-", "location": "-", "localhost": False}
    if is_localhost(ip):
        return {"ip": ip, "cdn": "localhost", "location": "localhost", "localhost": True}
    return {"ip": ip, "cdn": cdn_from_ip(ip), "location": geolocate(ip), "localhost": False}

class Baseline:
    def __init__(self, probes: list[tuple[int, bytes, str]]):
        self.probes = probes
        self.hashes  = {_hash(b) for _, b, _ in probes}
        self.sizes   = [len(b) for _, b, _ in probes]
        self.statuses = {s for s, _, _ in probes}
        self.ctypes  = [ct for _, _, ct in probes]

        self.size_min = min(self.sizes) * 0.92
        self.size_max = max(self.sizes) * 1.08

        self.is_spa = (
            len(set(self.sizes)) > 1 and
            all("text/html" in ct for ct in self.ctypes if ct != "-")
        )
        self.is_static = len(self.hashes) == 1

    def is_false_positive(self, status: int, body: bytes, ctype: str) -> bool:
        bh = _hash(body)
        bs = len(body)

        if bh in self.hashes:
            return True

        if self.is_static and status in self.statuses:
            return True

        if self.is_spa and "text/html" in ctype:
            if self.size_min <= bs <= self.size_max:
                return True

        if status in self.statuses and "text/html" in ctype and bs > 2000:
            all_html = all("text/html" in ct for ct in self.ctypes if ct != "-")
            if all_html:
                return True

        return False

    def describe(self) -> str:
        kind = "SPA/dynamic" if self.is_spa else ("static" if self.is_static else "mixed")
        sizes_str = "/".join(str(s) for s in self.sizes)
        return (f"type={kind}  statuses={sorted(self.statuses)}"
                f"  sizes={sizes_str}  filter={'html+size' if self.is_spa else 'hash'}")

def _fetch_sync(url: str, timeout: float, ua: str) -> tuple[int, bytes, str]:
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", ua)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "-")
            return resp.status, resp.read(), ct
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        ct = e.headers.get("Content-Type", "-") if hasattr(e, "headers") else "-"
        return e.code, body, ct
    except Exception:
        return 0, b"", "-"

def detect_baseline_sync(base_url: str, timeout: float, ua: str) -> Baseline | None:
    probe_paths = [
        f"{base_url}/__probe_a1b2c3__",
        f"{base_url}/__probe_x9y8z7__",
        f"{base_url}/__probe_m5n6p4__",
    ]
    probes = []
    for p in probe_paths:
        s, b, ct = _fetch_sync(p, timeout, ua)
        if s == 0: return None
        probes.append((s, b, ct))
    return Baseline(probes)

async def _fetch_async(session, url, timeout):
    try:
        async with session.get(url, allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            body = await resp.read()
            ct   = resp.headers.get("Content-Type", "-")
            redir = resp.headers.get("Location", "-") if resp.status in {301,302,307,308} else "-"
            size  = resp.headers.get("Content-Length", str(len(body)))
            return resp.status, body, ct, size, redir
    except Exception:
        return 0, b"", "-", "-", "-"

async def _detect_baseline_async(session, base_url, timeout) -> Baseline | None:
    probe_paths = [
        f"{base_url}/__probe_a1b2c3__",
        f"{base_url}/__probe_x9y8z7__",
        f"{base_url}/__probe_m5n6p4__",
    ]
    probes = []
    for p in probe_paths:
        s, b, ct, _, _ = await _fetch_async(session, p, timeout)
        if s == 0: return None
        probes.append((s, b, ct))
    return Baseline(probes)

class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate; self.capacity = capacity
        self._tokens = capacity; self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens >= 1:
                self._tokens -= 1; return
        await asyncio.sleep((1 - self._tokens) / self.rate)
        await self.acquire()

class AdaptiveThrottle:
    def __init__(self, window: int = 100, threshold: float = 0.50):
        self.threshold = threshold
        self._results: deque[bool] = deque(maxlen=window)
        self._lock = asyncio.Lock()

    async def record(self, failed: bool):
        async with self._lock: self._results.append(failed)

    @property
    def error_rate(self) -> float:
        return sum(self._results) / len(self._results) if self._results else 0.0

    async def maybe_pause(self):
        r = self.error_rate
        if r > self.threshold: await asyncio.sleep(r * 2.0)

def build_targets(word: str, extensions: list[str]) -> list[str]:
    targets = [word]
    for ext in extensions:
        targets.append(f"{word}{ext}")
    return targets

def probe_sync(base_url, word, timeout, extensions, baseline, ua) -> list[dict]:
    results = []
    for target in build_targets(word, extensions):
        url = f"{base_url}/{target.lstrip('/')}"
        status, body, ct = _fetch_sync(url, timeout, ua)
        if status not in INTERESTING: continue
        if baseline and baseline.is_false_positive(status, body, ct): continue
        redir = "-"
        if status in {301,302,307,308}:
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", ua)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    redir = r.headers.get("Location", "-")
            except Exception:
                pass
        results.append({"url": url, "status": status,
                        "label": STATUS_LABELS.get(status, str(status)),
                        "size": str(len(body)), "redir": redir,
                        "ctype": ct.split(";")[0].strip()})
    return results

async def probe_async(session, base_url, word, semaphore, bucket, throttle,
                      timeout, extensions, baseline) -> list[dict]:
    results = []
    for target in build_targets(word, extensions):
        url = f"{base_url}/{target.lstrip('/')}"
        await throttle.maybe_pause()
        await bucket.acquire()
        async with semaphore:
            status, body, ct, size, redir = await _fetch_async(session, url, timeout)
            if status == 0:
                await throttle.record(True); continue
            await throttle.record(False)
            if status not in INTERESTING: continue
            if baseline and baseline.is_false_positive(status, body, ct): continue
            results.append({"url": url, "status": status,
                            "label": STATUS_LABELS.get(status, str(status)),
                            "size": size, "redir": redir,
                            "ctype": ct.split(";")[0].strip()})
    return results

def format_results(found: list[dict]) -> str:
    found.sort(key=lambda r: (r["status"], r["url"]))
    col_url    = max((len(r["url"])         for r in found), default=3); col_url    = max(col_url,    3)
    col_status = max((len(str(r["status"])) for r in found), default=6); col_status = max(col_status, 6)
    col_label  = max((len(r["label"])       for r in found), default=4); col_label  = max(col_label,  4)
    col_size   = max((len(str(r["size"]))   for r in found), default=4); col_size   = max(col_size,   4)
    col_ctype  = max((len(r["ctype"])       for r in found), default=12); col_ctype = max(col_ctype, 12)
    col_redir  = max((len(r["redir"])       for r in found), default=8); col_redir  = max(col_redir,  8)
    header = (f"{'URL':<{col_url}}   {'STATUS':<{col_status}}   {'TIPO':<{col_label}}   "
              f"{'SIZE':<{col_size}}   {'CONTENT-TYPE':<{col_ctype}}   {'REDIRECT':<{col_redir}}")
    rows = [header, "-" * len(header)]
    for r in found:
        rows.append(f"{r['url']:<{col_url}}   {str(r['status']):<{col_status}}   "
                    f"{r['label']:<{col_label}}   {str(r['size']):<{col_size}}   "
                    f"{r['ctype']:<{col_ctype}}   {r['redir']:<{col_redir}}")
    return "\n".join(rows)

async def _run_async(base_url, words, concurrency, rps, timeout, extensions, idle_timeout, ua):
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers   = {"User-Agent": ua}
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        print("[*] Detecting baseline ...")
        baseline = await _detect_baseline_async(session, base_url, timeout)
        if baseline:
            print(f"[*] Baseline       : {baseline.describe()}")
        else:
            print("[*] Baseline       : not detected")
        print()

        bucket = TokenBucket(rate=rps, capacity=rps * 2)
        throttle = AdaptiveThrottle()
        semaphore = asyncio.Semaphore(concurrency)
        total = len(words); found = []; completed = 0
        last_hit = time.monotonic(); stop_reason = "completed"

        tasks   = [asyncio.create_task(
                       probe_async(session, base_url, w, semaphore, bucket,
                                   throttle, timeout, extensions, baseline))
                   for w in words]
        pending = set(tasks)

        while pending:
            done, pending = await asyncio.wait(pending, timeout=1.0)
            for fut in done:
                completed += 1
                res = fut.result()
                if res: found.extend(res); last_hit = time.monotonic()
            if done and (completed % 100 == 0 or completed == total):
                er = throttle.error_rate
                idle_secs = time.monotonic() - last_hit
                print(f"\r[*] {completed:>7,}/{total:,}  found:{len(found):>5,}"
                      f"{'  err:'+f'{er*100:.0f}%' if er > 0.05 else ''}"
                      f"{'  idle:'+f'{idle_secs:.0f}s/{idle_timeout:.0f}s' if idle_secs > 5 else ''}   ",
                      end="", flush=True)
            if time.monotonic() - last_hit >= idle_timeout:
                for t in pending: t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                stop_reason = "idle_timeout"; break

    print()
    return found, stop_reason

def enumerate_dirs(base_url, wordlist, concurrency, rps, timeout, extensions,
                   output_file, idle_timeout, fallback_threads, ua):
    with wordlist.open("r", encoding="utf-8", errors="ignore") as fh:
        words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    total   = len(words)
    ext_str = ", ".join(extensions) if extensions else "none"
    eta     = (total * (1 + len(extensions))) / rps if rps > 0 else 0
    hostname = urlparse(base_url).hostname or base_url

    print(f"\n[*] Target        : {base_url}")
    print("[*] Resolving target info ...")
    info = resolve_target(hostname)
    print(f"[*] IP            : {info['ip']}")
    print(f"[*] CDN           : {info['cdn']}")
    print(f"[*] Posizione     : {info['location']}")
    if info['localhost']:
        print(f"[!] WARNING       : target is localhost / private IP")
    print(f"[*] Wordlist      : {wordlist}  ({total:,} entries)")
    print(f"[*] Extensions    : {ext_str}")
    print(f"[*] Engine        : {'aiohttp async' if HAS_AIOHTTP else 'urllib threaded (pip install aiohttp)'}")
    if HAS_AIOHTTP:
        print(f"[*] Concurrency   : {concurrency} coroutines")
        print(f"[*] Rate limit    : {int(rps)} req/s")
    else:
        print(f"[*] Threads       : {fallback_threads}")
    print(f"[*] Timeout/req   : {timeout}s")
    print(f"[*] Idle stop     : {idle_timeout:.0f}s without new hits")
    print(f"[*] ETA (approx)  : {eta/60:.1f} min")
    print()

    t_start = time.monotonic()

    if HAS_AIOHTTP:
        found, stop_reason = asyncio.run(
            _run_async(base_url, words, concurrency, rps, timeout, extensions, idle_timeout, ua))
    else:
        print("[*] Detecting baseline ...")
        baseline = detect_baseline_sync(base_url, timeout, ua)
        if baseline:
            print(f"[*] Baseline       : {baseline.describe()}")
        else:
            print("[*] Baseline       : not detected")
        print()

        found = []; completed = 0
        last_hit = time.monotonic(); stop_reason = "completed"

        with ThreadPoolExecutor(max_workers=fallback_threads) as executor:
            futures = {executor.submit(probe_sync, base_url, w, timeout, extensions, baseline, ua): w
                       for w in words}
            for future in _as_completed(futures):
                completed += 1
                res = future.result()
                if res: found.extend(res); last_hit = time.monotonic()
                if completed % 100 == 0 or completed == total:
                    idle_secs = time.monotonic() - last_hit
                    print(f"\r[*] {completed:>7,}/{total:,}  found:{len(found):>5,}"
                          f"{'  idle:'+f'{idle_secs:.0f}s/{idle_timeout:.0f}s' if idle_secs > 5 else ''}   ",
                          end="", flush=True)
                if time.monotonic() - last_hit >= idle_timeout:
                    stop_reason = "idle_timeout"
                    for f in futures: f.cancel()
                    break
        print()

    elapsed = time.monotonic() - t_start
    rate    = (total * (1 + len(extensions))) / elapsed if elapsed > 0 else 0

    if stop_reason == "idle_timeout":
        print(f"\n[!] Idle timeout  : no new paths found for {idle_timeout:.0f}s — stopping early.")
    print(f"[*] Done  : {len(found)} found  |  {elapsed:.1f}s  |  {rate:,.0f} req/s avg\n")

    if not found:
        print("[-] Nothing found.")
        return

    output = format_results(found)
    print(output)

    if output_file:
        output_file.write_text(output + "\n", encoding="utf-8")
        print(f"\n[*] Saved : {output_file}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Directory Enumerator — OSINT Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Status legend:
  FOUND     200/201/204 — path exists and is accessible
  REDIRECT  301/302/307/308 — redirects (see REDIRECT column)
  AUTH      401 — requires authentication
  FORBIDDEN 403 — access denied
  METHOD    405 — endpoint exists, wrong HTTP method
  ERROR     500/503 — server-side error

Rate presets (--rps):
  --rps 50    safe      — shared hosting
  --rps 150   balanced  — default
  --rps 500   fast      — VPS / dedicated
  --rps 1000  aggressive— LAN / localhost only

Examples:
  python dir_enum.py https://example.com
  python dir_enum.py https://example.com -e .php .html .bak
  python dir_enum.py https://example.com --rps 100 -o results.txt
  python dir_enum.py https://example.com --idle 30
        """,
    )
    parser.add_argument("url")
    parser.add_argument("-w","--wordlist", default=None)
    parser.add_argument("-e","--extensions", nargs="+", default=[], metavar="EXT")
    parser.add_argument("-c","--concurrency", type=int, default=200)
    parser.add_argument("--rps",   type=float, default=150)
    parser.add_argument("-t","--timeout", type=float, default=5.0)
    parser.add_argument("--idle",  type=float, default=60.0)
    parser.add_argument("-o","--output", default=None)
    parser.add_argument("--ua", default="Mozilla/5.0 (compatible; DirEnum/1.0)")
    parser.add_argument("--threads", type=int, default=50)

    args = parser.parse_args()

    if not HAS_AIOHTTP:
        print("[!] aiohttp not found — urllib/thread fallback active.")
        print("[!] pip install aiohttp  for async mode\n")

    tool_dir = Path(__file__).parent
    auto_wl  = tool_dir / "dirs.txt"

    if args.wordlist:
        wl_path = Path(args.wordlist)
        if not wl_path.is_file():
            print(f"[!] Wordlist not found: {wl_path}", file=sys.stderr); sys.exit(1)
        wordlist = wl_path
    elif auto_wl.is_file():
        wordlist = auto_wl
        print(f"[*] Auto-detected wordlist: {auto_wl}")
    else:
        print(f"[!] No wordlist found. Place dirs.txt in {tool_dir}", file=sys.stderr); sys.exit(1)

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    try:
        enumerate_dirs(
            base_url         = url.rstrip("/"),
            wordlist         = wordlist,
            concurrency      = args.concurrency,
            rps              = args.rps,
            timeout          = args.timeout,
            extensions       = args.extensions,
            output_file      = Path(args.output) if args.output else None,
            idle_timeout     = args.idle,
            fallback_threads = args.threads,
            ua               = args.ua,
        )
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted."); sys.exit(0)

if __name__ == "__main__":
    main()
