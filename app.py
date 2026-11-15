# -*- coding: utf-8 -*-
import os
import time
import random
import datetime
import socket
import struct
import zlib
import threading
import json
from enum import Enum
from typing import Any, Tuple, Optional, Dict
from collections import defaultdict

import zstandard as zstd
from Crypto.Cipher import AES
from flask import Flask, request, jsonify, render_template_string

# ============================================================================
#  DRAKVEX FULL INFO API SERVER (Railway Ready)
# ============================================================================

AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV = b'\x00' * 16

BAN_REASON_MAP = {
    1:"Account Sharing / Selling", 2:"Boosting / Rank Manipulation", 3:"Cheating / Hacking", 4:"Toxic Behavior",
    5:"Payment Fraud / Refund Abuse", 6:"Third-Party Software", 7:"Bug Exploitation", 8:"Impersonation",
    9:"Spam / Advertising", 10:"Inappropriate Name/Avatar", 11:"Match Fixing", 12:"AFK / Griefing",
    13:"Verbal Abuse", 14:"Hate Speech", 15:"Threatening Violence", 16:"Sexual Harassment",
    17:"Account Theft", 18:"Illegal Trading", 19:"Mod / Plugin Use", 20:"Emulator Abuse",
    40:"Permanent Ban — Severe Violation", 41:"Permanent Ban — Repeat Offense", 50:"Device Ban"
}

BIND_PREFIXES = [
    ("mt-and_","moonton"),("mt-ios_","moonton"),("mt_","moonton"),
    ("fb-and_","facebook"),("fb-ios_","facebook"),("fb_","facebook"),("facebook_","facebook"),
    ("gg_","google"),("google_","google"),("gp_","google"),("gpg_","google"),
    ("tt_","tiktok"),("tiktok_","tiktok"),("vk_","vk"),("tg_","telegram"),
    ("wa_","whatsapp"),("whatsapp_","whatsapp"),("apple_","apple"),("gc_","apple")
]

class SdpDataType(Enum):
    INTEGER_POSITIVE=0; INTEGER_NEGATIVE=1; FLOAT=2; DOUBLE=3; STRING=4; LIST=5; DICT=6; STRUCT_BEGIN=7; STRUCT_END=8

class SdpException(Exception): pass

class SdpStruct(dict):
    def __init__(self, data=None):
        super().__init__()
        self.data = b''
        self.offset = 0
        if isinstance(data, bytes):
            self.data = data
            self.offset = 0
            self._unpack_from_binary()
        elif data is not None:
            super().update(data)
            self._pack_to_binary()

    def _pack_to_binary(self):
        self.data = bytes([SdpDataType.STRUCT_BEGIN.value << 4])
        for tag, value in sorted(self.items()): self._pack(tag, value)
        self.data += bytes([SdpDataType.STRUCT_END.value << 4])

    def _write_number(self, value: int) -> bytes:
        result = bytearray()
        while value >= 0x80:
            result.append((value & 0x7F) | 0x80); value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    def _pack_header(self, tag: int, data_type: SdpDataType) -> None:
        if tag < 15: self.data += bytes([(data_type.value << 4) | tag])
        else:
            self.data += bytes([(data_type.value << 4) | 15])
            self.data += self._write_number(tag)

    def _pack(self, tag: int, value: Any) -> None:
        if isinstance(value, bool):
            self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
            self.data += self._write_number(1 if value else 0)
        elif isinstance(value, int):
            if value < 0:
                self._pack_header(tag, SdpDataType.INTEGER_NEGATIVE)
                self.data += self._write_number(-value)
            else:
                self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
                self.data += self._write_number(value)
        elif isinstance(value, float):
            self._pack_header(tag, SdpDataType.DOUBLE)
            packed = struct.pack("<d", value)
            self.data += self._write_number(len(packed)) + packed
        elif isinstance(value, (str, bytes)):
            self._pack_header(tag, SdpDataType.STRING)
            encoded = value.encode('utf-8') if isinstance(value, str) else value
            self.data += self._write_number(len(encoded)) + encoded
        elif isinstance(value, list):
            self._pack_header(tag, SdpDataType.LIST)
            self.data += self._write_number(len(value))
            for item in value: self._pack(0, item)
        elif isinstance(value, dict):
            if isinstance(value, SdpStruct):
                self._pack_header(tag, SdpDataType.STRUCT_BEGIN)
                for k, v in sorted(value.items()): self._pack(k, v)
                self.data += bytes([SdpDataType.STRUCT_END.value << 4])
            else:
                self._pack_header(tag, SdpDataType.DICT)
                self.data += self._write_number(len(value))
                for k, v in sorted(value.items()): self._pack(0, k); self._pack(0, v)
        else: raise SdpException(f"Unsupported: {type(value)}")

    def _unpack_from_binary(self):
        if not self.data: return
        if self.data[0] >> 4 == SdpDataType.STRUCT_BEGIN.value: self.offset = 1
        while self.offset < len(self.data):
            tag, value = self._unpack()
            if isinstance(value, SdpDataType) and value == SdpDataType.STRUCT_END: break
            self[tag] = value

    def _read_number(self) -> int:
        n = 1; val = self.data[self.offset] & 0x7F
        while self.data[self.offset + n - 1] >= 0x80:
            val |= (self.data[self.offset + n] & 0x7F) << (7 * n); n += 1
        self.offset += n
        return val

    def _unpack(self) -> Tuple[int, Any]:
        if self.offset >= len(self.data): return 0, None
        header = self.data[self.offset]
        tag = header & 0xF
        data_type = SdpDataType(header >> 4)
        self.offset += 1
        if tag == 15: tag = self._read_number()
        if data_type == SdpDataType.INTEGER_POSITIVE: return tag, self._read_number()
        elif data_type == SdpDataType.INTEGER_NEGATIVE: return tag, -self._read_number()
        elif data_type == SdpDataType.FLOAT:
            l = self._read_number(); v = struct.unpack("<f", self.data[self.offset:self.offset + l])[0]; self.offset += l; return tag, v
        elif data_type == SdpDataType.DOUBLE:
            l = self._read_number(); v = struct.unpack("<d", self.data[self.offset:self.offset + l])[0]; self.offset += l; return tag, v
        elif data_type == SdpDataType.STRING:
            l = self._read_number(); raw = self.data[self.offset:self.offset + l]; self.offset += l
            try: return tag, raw.decode('utf-8')
            except: return tag, raw
        elif data_type == SdpDataType.LIST:
            l = self._read_number(); val = []
            for _ in range(l): _, item = self._unpack(); val.append(item)
            return tag, val
        elif data_type == SdpDataType.DICT:
            l = self._read_number(); val = {}
            for _ in range(l): _, k = self._unpack(); _, v = self._unpack(); val[k] = v
            return tag, val
        elif data_type == SdpDataType.STRUCT_BEGIN:
            sd = {}
            while True:
                st, sv = self._unpack()
                if isinstance(sv, SdpDataType) and sv == SdpDataType.STRUCT_END: break
                sd[st] = sv
            return tag, SdpStruct(sd)
        elif data_type == SdpDataType.STRUCT_END: return tag, SdpDataType.STRUCT_END
        else: raise SdpException(f"Unknown SDP: {data_type}")

def map_rank(p: int) -> str:
    RANKS = [
        (0, 4, "Warrior III"), (5, 9, "Warrior II"), (10, 14, "Warrior I"),
        (15, 19, "Elite IV"), (20, 24, "Elite III"), (25, 29, "Elite II"), (30, 34, "Elite I"),
        (35, 39, "Master IV"), (40, 44, "Master III"), (45, 49, "Master II"), (50, 54, "Master I"),
        (55, 59, "Grandmaster IV"), (60, 64, "Grandmaster III"), (65, 69, "Grandmaster II"), (70, 74, "Grandmaster I"),
        (75, 81, "Epic IV"), (82, 88, "Epic III"), (89, 95, "Epic II"), (96, 107, "Epic I"),
        (108, 114, "Legend IV"), (115, 121, "Legend III"), (122, 128, "Legend II"), (129, 135, "Legend I"),
    ]
    for lo, hi, name in RANKS:
        if lo <= p <= hi: return name
    if 136 <= p <= 160: return f"Mythic {p-135}"
    if 161 <= p <= 195: return f"Mythical Honor {p-135}"
    if 196 <= p <= 235: return f"Mythical Glory {p-157}"
    if 236 <= p <= 999: return f"Mythical Immortal {p-157}"
    return "Unknown"

def map_collector_point(point: int) -> str:
    if point < 1000: return "No Tier"
    tiers = [
        (1000, 4000, "Amateur Collector"), (4000, 10000, "Junior Collector"),
        (10000, 22000, "Seasoned Collector"), (22000, 44000, "Expert Collector"),
        (44000, 84000, "Renowned Collector"), (84000, 160000, "Exalted Collector"),
        (160000, 280000, "Mega Collector"), (280000, float('inf'), "World Collector"),
    ]
    for min_p, max_p, name in tiers:
        if min_p <= point < max_p:
            if name == "World Collector": return name
            per_level = (max_p - min_p) / 5
            level = int((point - min_p) // per_level)
            roman = ["V", "IV", "III", "II", "I"][level]
            return f"{name} {roman}"
    return "Unknown"

def inspect_ban(obj, depth=0):
    found = {}
    if depth > 8: return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k).lower()
            if ks in ("ban_reason", "ban_reason_id", "reason", "banreason"):
                try:
                    code = int(v); found["ban_code"] = code; found["ban_reason"] = BAN_REASON_MAP.get(code, f"Violation #{code}")
                except: found["ban_code"] = v; found["ban_reason"] = str(v)
            if ks in ("ban_status", "banned", "is_banned", "ban_flag"):
                try:
                    if int(v) == 1: found["ban_flag"] = True
                except: pass
            if isinstance(v, (dict, list)): found.update(inspect_ban(v, depth+1))
    elif isinstance(obj, list):
        for item in obj: found.update(inspect_ban(item, depth+1))
    return found

def _extract_bind_value(plat, bind_id, info):
    if not isinstance(info, dict) or not info: return "Linked"
    strings = []
    def walk(obj, depth=0):
        if depth > 4: return
        if isinstance(obj, dict):
            for v in obj.values():
                if isinstance(v, str) and v.strip(): strings.append(v.strip())
                elif isinstance(v, (dict, list)): walk(v, depth+1)
        elif isinstance(obj, list):
            for v in obj:
                if isinstance(v, str) and v.strip(): strings.append(v.strip())
                elif isinstance(v, (dict, list)): walk(v, depth+1)
    walk(info)
    if plat == "whatsapp":
        for s in strings:
            if s.replace('+', '').replace(' ', '').isdigit() and len(s) >= 8: return s
    if plat in ["google", "moonton"]:
        for s in strings:
            if "@" in s and "." in s: return s
    for s in strings:
        if "@" in s and "." in s: return s
    for s in strings:
        if s.replace('+', '').replace(' ', '').isdigit() and len(s) >= 8: return s
    return strings[0] if strings else "Linked"

def parse_10208(res):
    out = {"binds": {}, "verif_2fa": None, "last_login_country": "Unknown"}
    for item in (res.get(1) or []):
        if not isinstance(item, dict): continue
        bind_id = str(item.get(0) or ""); info = item.get(1) or {}
        plat = None
        for prefix, p in BIND_PREFIXES:
            if bind_id.lower().startswith(prefix): plat = p; break
        if plat and plat not in ("device_and", "device_ios"): out["binds"][plat] = _extract_bind_value(plat, bind_id, info)
    for tag in (10,11,12,13):
        v = res.get(tag)
        if isinstance(v, int) and v in (0,1): out["verif_2fa"] = bool(v); break
    c23 = res.get(23)
    if isinstance(c23, dict) and isinstance(c23.get(0), str): out["last_login_country"] = c23.get(0).upper()
    return out

class DeviceManager:
    def __init__(self):
        self.devices = ["and_33c9084d10d104e2e0e95288782a92ff3h0ixfjcdk5dm3i9deffa6fb-7f6c-4b46-bcc3-a52ab97c367c"]
        self.lock = threading.Lock()
    def get_next_device(self): 
        with self.lock: return random.choice(self.devices)

class BaseConnection:
    def __init__(self, host: str, port: int):
        self.host = host; self.port = port; self.sequence = 1; self.socket = None; self.queue_data = b''
    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(15.0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))
    def cleanup(self):
        if self.socket:
            try: self.socket.close()
            except: pass
            self.socket = None; self.sequence = 1
    def send_data(self, cmd_id: int, sdp: SdpStruct):
        packet = SdpStruct({0: cmd_id, 1: self.sequence, 5: sdp.data}).data
        buf = zstd.compress(packet)
        flags = (len(buf) + 4) | (16 << 24)
        self.socket.send(flags.to_bytes(4, 'big') + buf)
        self.sequence += 1
    def recv_data(self):
        try:
            while len(self.queue_data) < 4:
                data = self.socket.recv(4096)
                if not data: return None, None
                self.queue_data += data
            flags = int.from_bytes(self.queue_data[:4], 'big'); size = flags & 0xFFFFFF; c_type = flags >> 24
            while len(self.queue_data) < size:
                data = self.socket.recv(4096)
                if not data: return None, None
                self.queue_data += data
            data = self.queue_data[4:size]; self.queue_data = self.queue_data[size:]
            if c_type == 16: data = zstd.decompress(data)
            elif c_type == 18:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                data = zstd.decompress(cipher.decrypt(data[:-1] if len(data) % 16 else data).rstrip(b'\x00'))
            result = SdpStruct(data); cmd = result.get(0); res = result.get(6) or result.get(5)
            return cmd, SdpStruct(res) if (res and isinstance(res, bytes)) else None
        except socket.timeout: return -1, None
        except: return None, None

class GameConnection(BaseConnection):
    LOGIN_HOST = 'global-login.ml.youngjoygame.com'; LOGIN_PORT = 30021
    def __init__(self, device_id: str):
        super().__init__(self.LOGIN_HOST, self.LOGIN_PORT)
        self.device_id = device_id; parts = device_id.split('_')
        info = '_'.join(parts[1:]) if len(parts) >= 2 else device_id
        self.imei_md5 = info[:32] if len(info) >= 32 else info; self.android_id = info[32:48] if len(info) >= 48 else ""
        self.channel = 'and_usa'; self.client_version = '2.2.23.1235.1'
        self.account_id = 0; self.session_key = ''; self.zone_id = 0; self.game_server_host = ''; self.game_server_port = 0; self.creation_ts = 0
    def login_to_login_server(self) -> bool:
        try:
            self.connect()
            self.send_data(1, SdpStruct({0: self.device_id, 1: f'gps_adid=&android_id={self.android_id}&device_unique_id={self.imei_md5}', 2: self.client_version, 3: self.channel, 4: 'en'}))
            cmd, res = self.recv_data()
            if cmd == 2 and res:
                self.account_id = res.get(0); self.session_key = res[1]; self.zone_id = res[2][0]; self.creation_ts = res.get(19, 0); return True
        except: pass
        return False
    def get_game_server(self) -> bool:
        try:
            self.send_data(5, SdpStruct({0: self.account_id, 1: self.session_key, 2: self.client_version, 5: self.zone_id, 6: self.channel}))
            cmd, res = self.recv_data()
            if cmd == 6 and res:
                self.game_server_host, port_str = res[1].split(':'); self.game_server_port = int(port_str); return True
        except: pass
        return False
    def connect_to_game_server(self) -> bool:
        try:
            self.cleanup(); self.host = self.game_server_host; self.port = self.game_server_port; self.connect()
            self.send_data(10001, SdpStruct({0: self.account_id, 1: self.session_key, 2: self.zone_id, 4: self.client_version, 13: self.channel, 15: self.device_id}))
            self.send_data(10101, SdpStruct({0: 0, 2: 2}))
            for _ in range(3):
                cmd, _ = self.recv_data()
                if cmd == 10002: return True
                if cmd == -1: break
        except: pass
        return False

def get_player_info_logic(guid: int, session: str) -> Optional[Dict]:
    dm = DeviceManager()
    for _ in range(10):
        device_id = dm.get_next_device()
        conn = None
        try:
            conn = GameConnection(device_id=device_id)
            if not conn.login_to_login_server(): conn.cleanup(); continue
            if not conn.get_game_server(): conn.cleanup(); continue
            if not conn.connect_to_game_server(): conn.cleanup(); continue

            result = None
            for payload in [SdpStruct({0: f"mt-and_{guid}", 1: f"token={session}&name=&id={guid}&nid=", 2: 0}), SdpStruct({0: f"mt-and_{guid}", 1: f"token={session}", 2: 0})]:
                conn.send_data(10207, payload)
                tc = 0
                while tc < 3:
                    cmd, res = conn.recv_data()
                    if cmd is None: break
                    if cmd == 10208 and res: result = res; break
                    if cmd == -1: tc += 1
                if result: break
            if not result: conn.cleanup(); continue
            
            bind_data = parse_10208(result)
            role_id, zone_id = None, None
            for role in (result.get(2) or []):
                if isinstance(role, SdpStruct): role_id, zone_id = role.get(1, 0), role.get(0, 0); break
                elif isinstance(role, (list, tuple)) and len(role) >= 3: role_id, zone_id = role[1], role[0]; break
            if not role_id: conn.cleanup(); continue

            role_detail = None; role_info = None
            conn.send_data(11153, SdpStruct({1: role_id}))
            conn.send_data(10143, SdpStruct({0: role_id, 1: zone_id}))
            deadline = time.time() + 10.0
            while time.time() < deadline:
                cmd, res = conn.recv_data()
                if cmd is None: break
                if cmd == -1: continue
                if cmd == 11154: role_detail = res
                elif cmd == 10144: role_info = res
                if role_detail and role_info: break

            if not role_detail: conn.cleanup(); continue

            player = role_detail[0][0]
            nickname = player.get(2, "Unknown"); level = player.get(3, "Unknown")
            current_rank = map_rank(player.get(8)) if player.get(8) is not None else "Unknown"
            matches = role_info.get(77, 0) if role_info else 0
            win_rate = f"{(role_info.get(22, 0) / matches * 100):.1f}%" if matches > 0 else "N/A"
            
            collector_point = player.get(136, {}).get(9, 0) if isinstance(player.get(136), dict) else 0
            collector_tier = map_collector_point(collector_point)
            
            last_login = player.get(5, 0)
            last_login_str = datetime.datetime.fromtimestamp(last_login).strftime("%Y-%m-%d %H:%M:%S") if last_login else "N/A"
            create_ts_fallback = player.get(6, 0)
            creation_date = datetime.datetime.fromtimestamp(conn.creation_ts or create_ts_fallback).strftime("%Y-%m-%d") if (conn.creation_ts or create_ts_fallback) else "N/A"

            ban_info = inspect_ban(dict(result))
            conn.cleanup()
            
            return {
                "status": "success",
                "data": {
                    "basic_info": {"nickname": nickname, "level": level, "role_id": role_id, "zone_id": zone_id},
                    "game_info": {"current_rank": current_rank, "matches": matches, "win_rate": win_rate},
                    "collector_info": {"collector_point": collector_point, "collector_tier": collector_tier},
                    "security_info": {"v2l_status": "Yes" if bind_data.get("verif_2fa") else "No"},
                    "extra_info": {"creation_date": creation_date, "last_login": last_login_str, "last_login_country": bind_data.get("last_login_country", "Unknown")},
                    "binds": bind_data.get("binds", {}),
                    "banned": ban_info.get("ban_flag", False),
                    "ban_info": ban_info
                }
            }
        except Exception:
            if conn: conn.cleanup()
    return None

# ============================================================================
#  FLASK WEB SERVER & UI
# ============================================================================
app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/fetch', methods=['POST'])
def api_fetch():
    data = request.json or {}
    guid = data.get('guid')
    session = data.get('session')
    if not guid or not session:
        return jsonify({"status": "error", "message": "GUID and Session are required"}), 400
    
    result = get_player_info_logic(int(guid), session)
    if result:
        return jsonify(result)
    return jsonify({"status": "error", "message": "Failed to fetch info after 10 retries"}), 500

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DRAKVEX INFO API</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f172a; --panel: #1e293b; --text: #f8fafc; --muted: #94a3b8;
            --accent: #8b5cf6; --accent-hover: #7c3aed; --success: #10b981; --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: var(--bg); color: var(--text); display: flex; justify-content: center; padding: 40px 20px; min-height: 100vh; }
        .container { width: 100%; max-width: 800px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { font-size: 28px; font-weight: 800; background: linear-gradient(to right, #8b5cf6, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .header p { color: var(--muted); margin-top: 8px; }
        .card { background: var(--panel); border-radius: 12px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.05); margin-bottom: 20px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; font-size: 14px; color: var(--muted); }
        .form-group input { width: 100%; padding: 12px; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: white; outline: none; transition: 0.2s; }
        .form-group input:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2); }
        .btn { width: 100%; padding: 14px; border: none; border-radius: 8px; background: var(--accent); color: white; font-weight: 700; font-size: 16px; cursor: pointer; transition: 0.2s; }
        .btn:hover { background: var(--accent-hover); transform: translateY(-2px); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        #result { display: none; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 15px; }
        .grid-item { background: #0f172a; padding: 12px; border-radius: 8px; border: 1px solid #334155; }
        .grid-label { font-size: 12px; color: var(--muted); margin-bottom: 4px; }
        .grid-value { font-weight: 600; font-size: 14px; word-break: break-all; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 700; }
        .badge-success { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .badge-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .binds { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .bind-item { background: #334155; padding: 6px 12px; border-radius: 20px; font-size: 12px; }
        .loading { text-align: center; padding: 20px; color: var(--accent); font-weight: 600; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 0.5; } 50% { opacity: 1; } 100% { opacity: 0.5; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DRAKVEX INFO API</h1>
            <p>Standalone Web Server for MLBB Full Info Fetching</p>
        </div>
        
        <div class="card">
            <div class="form-group">
                <label>GUID</label>
                <input type="text" id="guid" placeholder="Enter GUID...">
            </div>
            <div class="form-group">
                <label>SESSION</label>
                <input type="text" id="session" placeholder="Enter Session...">
            </div>
            <button class="btn" id="fetchBtn" onclick="fetchInfo()">Fetch Full Info</button>
        </div>

        <div class="card" id="result">
            <h2 style="margin-bottom: 15px; color: var(--accent);">Result</h2>
            <div id="resultContent"></div>
        </div>
    </div>

    <script>
        async function fetchInfo() {
            const guid = document.getElementById('guid').value.trim();
            const session = document.getElementById('session').value.trim();
            const btn = document.getElementById('fetchBtn');
            const resultDiv = document.getElementById('result');
            const contentDiv = document.getElementById('resultContent');

            if (!guid || !session) {
                alert("Please enter both GUID and Session!");
                return;
            }

            btn.disabled = true;
            btn.innerText = "Fetching...";
            resultDiv.style.display = 'block';
            contentDiv.innerHTML = '<div class="loading">Connecting to MLBB Server...</div>';

            try {
                const response = await fetch('/api/fetch', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ guid, session })
                });
                const data = await response.json();

                if (data.status === 'success') {
                    const d = data.data;
                    const banStatus = d.banned 
                        ? `<span class="badge badge-danger">BANNED</span>` 
                        : `<span class="badge badge-success">CLEAN</span>`;
                    
                    let bindHtml = '';
                    if (Object.keys(d.binds).length > 0) {
                        bindHtml = `<div class="grid-item" style="grid-column: span 2;">
                            <div class="grid-label">Bindings</div>
                            <div class="binds">${Object.entries(d.binds).map(([k, v]) => `<span class="bind-item"><b>${k}:</b> ${v}</span>`).join('')}</div>
                        </div>`;
                    }

                    contentDiv.innerHTML = `
                        <div style="margin-bottom: 15px; font-size: 18px; font-weight: 800;">
                            ${d.basic_info.nickname} <span style="font-size:14px; color:var(--muted);">(Lv.${d.basic_info.level})</span>
                        </div>
                        <div class="grid">
                            <div class="grid-item"><div class="grid-label">Role ID</div><div class="grid-value">${d.basic_info.role_id}</div></div>
                            <div class="grid-item"><div class="grid-label">Zone ID</div><div class="grid-value">${d.basic_info.zone_id}</div></div>
                            <div class="grid-item"><div class="grid-label">Rank</div><div class="grid-value">${d.game_info.current_rank}</div></div>
                            <div class="grid-item"><div class="grid-label">Collector</div><div class="grid-value">${d.collector_info.collector_tier}</div></div>
                            <div class="grid-item"><div class="grid-label">Matches</div><div class="grid-value">${d.game_info.matches}</div></div>
                            <div class="grid-item"><div class="grid-label">Win Rate</div><div class="grid-value">${d.game_info.win_rate}</div></div>
                            <div class="grid-item"><div class="grid-label">Created</div><div class="grid-value">${d.extra_info.creation_date}</div></div>
                            <div class="grid-item"><div class="grid-label">Last Login</div><div class="grid-value">${d.extra_info.last_login}</div></div>
                            <div class="grid-item"><div class="grid-label">Country</div><div class="grid-value">${d.extra_info.last_login_country}</div></div>
                            <div class="grid-item"><div class="grid-label">V2L/2FA</div><div class="grid-value">${d.security_info.v2l_status}</div></div>
                            <div class="grid-item"><div class="grid-label">Status</div><div class="grid-value">${banStatus}</div></div>
                            ${bindHtml}
                        </div>
                    `;
                } else {
                    contentDiv.innerHTML = `<div style="color: var(--danger); font-weight: 600; text-align: center;">Error: ${data.message}</div>`;
                }
            } catch (err) {
                contentDiv.innerHTML = `<div style="color: var(--danger); font-weight: 600; text-align: center;">Network Error: ${err.message}</div>`;
            } finally {
                btn.disabled = false;
                btn.innerText = "Fetch Full Info";
            }
        }
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting DRAKVEX INFO SERVER on port {port}...")
    app.run(host='0.0.0.0', port=port)