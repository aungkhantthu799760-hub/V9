# =====================================================================
# license.py - License Management Module (V9 KHANT Strict Device Bound)
# =====================================================================
import os
import json
import hashlib
import hmac
import base64
import uuid
from datetime import datetime, timedelta

LICENSE_FILE = "license.dat"
USED_KEYS_FILE = "used_keys.txt"
DEVICE_FILE = ".device_id"

# လျှို့ဝှက် Key (ဒါကို ဘယ်သူမှ မသိအောင် ထိန်းပါ)
SECRET_KEY = b"KhantV9SecretKey2026!@#$%^&*()"

def _get_device_id():
    """ဖုန်း/ကွန်ပျူတာရဲ့ သီးသန့် ID ကို ဖန်တီးပြီး သိမ်းဆည်းခြင်း"""
    if os.path.exists(DEVICE_FILE):
        with open(DEVICE_FILE, "r") as f: 
            return f.read().strip()
    else:
        new_id = str(uuid.uuid4()).replace("-", "")[:16].upper()
        with open(DEVICE_FILE, "w") as f: 
            f.write(new_id)
        return new_id

def _is_key_used(key: str):
    """Key ကို သုံးပြီးသားလား စစ်ဆေးခြင်း"""
    if not os.path.exists(USED_KEYS_FILE): return False
    with open(USED_KEYS_FILE, "r") as f:
        used = f.read().splitlines()
    return key in used

def _mark_key_used(key: str):
    """သုံးပြီးသား Key ကို မှတ်တမ်းတင်ခြင်း"""
    with open(USED_KEYS_FILE, "a") as f:
        f.write(key + "\n")

def _encode_license(data: dict) -> str:
    """License ကို လုံခြုံအောင် Encode လုပ်ခြင်း"""
    try:
        json_str = json.dumps(data, separators=(',', ':'))
        raw = json_str.encode('utf-8')
        # HMAC နဲ့ လက်မှတ်ထိုးမယ်
        sig = hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()[:24]
        return f"{sig}.{base64.b64encode(raw).decode()}"
    except Exception: return ""

def _decode_license(encoded: str) -> dict:
    """License ကို ပြန်ပြီး ဖတ်ခြင်း"""
    try:
        if '.' not in encoded: return None
        sig, payload_b64 = encoded.split('.', 1)
        raw = base64.b64decode(payload_b64)
        expected_sig = hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()[:24]
        
        # လက်မှတ် မှန်မမှန် စစ်မယ်
        if not hmac.compare_digest(sig, expected_sig): return None
        return json.loads(raw.decode('utf-8'))
    except Exception: return None

def _generate_license_data(key: str, days: float, device_id: str) -> str:
    """License Data အသစ် ဖန်တီးခြင်း"""
    try:
        now = datetime.now()
        expiry = now + timedelta(days=days) 
        data = {
            "key_hash": hashlib.sha256(key.encode()).hexdigest()[:32],
            "device_id": device_id,
            "issued": now.strftime("%Y-%m-%d %H:%M:%S"),
            "expiry": expiry.strftime("%Y-%m-%d %H:%M:%S"),
            "days": days,
        }
        return _encode_license(data)
    except Exception: return ""

def check_approval():
    """လိုင်စင် ရှိမရှိနဲ့ သက်တမ်း စစ်ဆေးခြင်း"""
    try:
        if not os.path.exists(LICENSE_FILE): return False, "No license"
        with open(LICENSE_FILE, "r") as f: encoded = f.read().strip()
        if not encoded: return False, "Empty license"

        data = _decode_license(encoded)
        if not data: return False, "Invalid license (Tampered)"

        # ဖုန်းတစ်လုံးတည်းနဲ့ပဲ ကိုက်ညီမှုရှိမရှိ တင်းတင်းကျပ်ကျပ် စစ်ဆေးခြင်း
        current_device = _get_device_id()
        if data.get("device_id") != current_device:
            return False, "License bound to another device!"

        expiry_str = data.get("expiry", "")
        try: 
            expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
        except Exception: 
            return False, "Invalid expiry format"

        now = datetime.now()
        if now > expiry: return False, f"Expired on {expiry_str}"

        # ကျန်ရှိတဲ့ အချိန်ကို တွက်ချက်ခြင်း
        diff = expiry - now
        h, rem = divmod(diff.seconds, 3600)
        m = rem // 60
        return True, f"{diff.days}d {h}h {m}m left"
    except Exception as e: return False, f"Error: {e}"

def activate(key: str):
    """Key အသစ် ထည့်သွင်းခြင်း"""
    try:
        key = key.strip()
        
        # V9-KHANT- နဲ့ စရမယ်
        if not key.startswith("V9-KHANT-"): 
            return False, "Invalid Key Format (V9-KHANT Required)"
        
        # ဒီ Key ကို အရင်က သုံးပြီးသားလား စစ်မယ်
        if _is_key_used(key):
            return False, "This key has already been used on another device."

        parts = key.split("-")
        if len(parts) < 4: return False, "Invalid Key Structure"
        
        try: 
            days_float = float(parts[2]) 
        except: 
            days_float = 365.0

        device_id = _get_device_id()
        encoded = _generate_license_data(key, days_float, device_id)
        if not encoded: return False, "Failed to generate license"

        # License ကို သိမ်းမယ်
        with open(LICENSE_FILE, "w") as f: 
            f.write(encoded)
            
        # Key ကို သုံးပြီးသားအဖြစ် မှတ်မယ်
        _mark_key_used(key)

        is_valid, msg = check_approval()
        if is_valid: return True, f"✓ Activated! {msg}"
        return False, "Activation failed"
    except Exception as e: return False, f"Error: {e}"
