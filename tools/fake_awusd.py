#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Fake awusd for developing the menu-bar app without the adapter. Speaks the same unix-socket protocol (src/proto.h):
# one request line per connection, "OK"/"ERR text" then key=value / "ap ..." / "profile ..." lines. It never opens USB.
# Usage: tools/fake_awusd.py [--sock PATH] [--delay S]      (default socket: $TMPDIR/awusd.sock, like awusd as non-root)
# Test hooks: join with key "wrongpass" fails; ssid "Flaky" never finishes joining; `debug drop` drops the link;
# `debug state STATE` forces a state (NO_DEVICE, IDLE, SCANNING, JOINING, CONNECTED, RF_OFF).
import os, re, socket, sys, threading, time, argparse, random
from urllib.parse import quote, unquote

SAFE = "-._:/,+"
def enc(s):
    return "".join(c if (c.isascii() and c.isalnum()) or c in SAFE else "".join("%%%02X" % b for b in c.encode()) for c in s)

LOCK = threading.Lock()
T0 = time.time()
S = dict(state="IDLE", rf="on", country="ES", txpower=32, autojoin=1, ssid="", bssid="", ch=0, sec="", rssi=-60,
         ip="", gw="", t_conn=0, join_at=0, join_target=None, rx=0, drops=0, connects=0, scans=0)
PROFILES = [dict(ssid="MyNetwork", security="wpa2", key="x" * 8, hidden=0, priority=10, autojoin=1, default_route=0)]
APS = [  # ssid, bssid, ch, rssi, security, cipher, phy
    ("MyNetwork", "aa:bb:cc:dd:ee:ff", 7, -48, "WPA2-PSK", "CCMP", "11n"),
    ("MyNetwork-5G", "aa:bb:cc:dd:ee:00", 132, -32, "WPA2-PSK", "CCMP", "11ac"),
    ("CoffeeShop Guest", "11:22:33:44:55:66", 1, -71, "Open", "", "11n"),
    ("Old WEP Net", "11:22:33:44:55:77", 11, -80, "WEP", "WEP40", "11g"),
    ("Neighbour 5G", "de:ad:be:ef:00:01", 44, -66, "WPA2+WPA3-PSK", "CCMP", "11ac"),
    ("Flaky", "de:ad:be:ef:00:02", 6, -75, "WPA2-PSK", "CCMP", "11n"),
    ("", "de:ad:be:ef:00:03", 3, -85, "WPA2-PSK", "CCMP", "11n"),
    ("Café Ñandú", "de:ad:be:ef:00:04", 9, -90, "WPA2-PSK", "CCMP", "11n"),
]
DELAY = 0.0

def tick():
    with LOCK:
        if S["state"] == "JOINING" and time.time() >= S["join_at"] and S["join_target"] != "Flaky":
            t = next(a for a in APS if a[0] == S["join_target"])
            S.update(state="CONNECTED", ssid=t[0], bssid=t[1], ch=t[2], sec=t[4], ip="192.168.1.%d" % random.randint(20, 90),
                     gw="192.168.1.1", t_conn=time.time(), connects=S["connects"] + 1)
        if S["state"] == "CONNECTED":
            S["rx"] += random.randint(5, 40)
            ap = next((a for a in APS if a[0] == S["ssid"]), None)
            S["rssi"] = (ap[3] if ap else -60) + random.randint(-3, 3)

def parse(line):
    toks = line.split()
    cmd, pos, opt = toks[0], [], {}
    for t in toks[1:]:
        m = re.match(r"^([a-z0-9_]+)=(.*)$", t)
        if m: opt[m.group(1)] = unquote(m.group(2))
        else: pos.append(unquote(t))
    return cmd, pos, opt

def kv(k, v): return "%s=%s\n" % (k, enc(str(v)))
def err(m): return "ERR %s\n" % m

def status():
    o = "OK\n"
    o += kv("state", S["state"]) + kv("device", "absent" if S["state"] == "NO_DEVICE" else "present") + kv("rf", S["rf"])
    o += kv("country", S["country"]) + kv("uptime_s", int(time.time() - T0)) + kv("root", 1) + kv("hold", 0)
    o += kv("autojoin", S["autojoin"]) + kv("profiles", len(PROFILES)) + kv("version", "0.1.0-fake")
    if S["state"] != "NO_DEVICE":
        o += kv("txpower", S["txpower"]) + kv("channel", S["ch"] or 7)
    if S["state"] == "CONNECTED":
        o += kv("ssid", S["ssid"]) + kv("bssid", S["bssid"]) + kv("link_channel", S["ch"]) + kv("security", S["sec"])
        o += kv("pairwise", "CCMP") + kv("rssi_dbm", S["rssi"]) + kv("rx_rate_code", 13) + kv("ip", S["ip"])
        o += kv("gateway", S["gw"]) + kv("netmask", "255.255.255.0") + kv("lease_s", 86400) + kv("lease_age_s", int(time.time() - S["t_conn"]))
        o += kv("dhcp_renews", 0) + kv("dhcp_rebinds", 0) + kv("connected_s", int(time.time() - S["t_conn"]))
        o += kv("tun", "link-only (not root)") + kv("default_route", 0) + kv("rx_ap_frames", S["rx"])
    elif S["state"] == "IDLE" and S["join_target"]:
        o += kv("reconnecting", S["join_target"]) + kv("reconnect_attempt", 1) + kv("next_try_in_s", 2)
    o += kv("connects", S["connects"]) + kv("drops", S["drops"]) + kv("scans", S["scans"]) + kv("usb_errors", 0)
    return o

def scan():
    if S["state"] == "NO_DEVICE": return err("no_device")
    if S["rf"] == "off": return err("rf_off")
    S["scans"] += 1
    time.sleep(DELAY)
    o = "OK\n" + kv("cached", 0) + kv("age_s", 0) + kv("country", S["country"]) + kv("count", len(APS)) + kv("dropped", 0)
    for ssid, b, ch, rssi, sec, ci, phy in APS:
        r = rssi + random.randint(-2, 2)
        o += "ap ssid=%s hidden=%d bssid=%s ch=%d rssi=%d sec=%s cipher=%s phy=%s wps=0 ok=1 dfs=%d ht=1 vht=%d he=0 streams=1 rate=150\n" % (
            enc(ssid), 1 if not ssid else 0, b, ch, r, enc(sec), enc(ci), enc(phy), 1 if 52 <= ch <= 144 else 0, 1 if ch > 14 else 0)
    return o

def handle(line):
    cmd, pos, opt = parse(line)
    with LOCK:
        if cmd == "status": return status()
        if cmd == "ping": return "OK\n"
        if cmd == "scan": return scan()
        if cmd == "join":
            ssid = opt.get("ssid", "")
            if S["state"] == "NO_DEVICE": return err("no_device")
            if S["rf"] == "off": return err("rf_off")
            ap = next((a for a in APS if a[0] == ssid), None)
            if not ap and opt.get("hidden") == "1": ap = (ssid, "de:ad:be:ef:99:99", 6, -70, "WPA2-PSK", "CCMP", "11n"); APS.append(ap)
            if not ap: return err("join failed: scan no_probe_response")
            if ap[4] != "Open" and not opt.get("key") and not any(p["ssid"] == ssid for p in PROFILES):
                return err("join failed: no key")
            if opt.get("key") == "wrongpass": return err("join failed: handshake timeout (wrong password?)")
            S.update(state="JOINING", join_target=ssid, join_at=time.time() + 1.5)
            time.sleep(DELAY)
            return "OK\n" + kv("ssid", ssid) + kv("channel", ap[2]) + kv("security", ap[4]) + kv("tun", "link-only")
        if cmd == "leave":
            S.update(state="IDLE", join_target=None, ssid="")
            return "OK\n" + kv("state", "IDLE")
        if cmd == "rf":
            a = pos[0] if pos else ""
            if a == "off": S.update(rf="off", state="RF_OFF", join_target=None)
            elif a == "on": S.update(rf="on", state="IDLE")
            elif a != "get": return err("usage: rf on|off|get")
            return "OK\n" + kv("rf", S["rf"])
        if cmd == "txpower":
            if pos and pos[0] == "set":
                if len(pos) < 2 or not pos[1].isdigit() or int(pos[1]) > 63: return err("txpower must be 0-63")
                S["txpower"] = int(pos[1])
            return "OK\n" + kv("txpower", S["txpower"])
        if cmd == "country":
            if pos and pos[0] == "set":
                if len(pos) < 2 or pos[1].upper() not in ("00", "ES", "GB", "DE", "FR", "IT", "US", "JP"): return err("unknown country")
                S["country"] = pos[1].upper()
            return "OK\n" + kv("country", S["country"]) + kv("known", "00 ES GB DE FR IT US JP")
        if cmd == "autojoin":
            if pos and pos[0] in ("on", "off"): S["autojoin"] = 1 if pos[0] == "on" else 0
            return "OK\n" + kv("autojoin", S["autojoin"])
        if cmd == "profile":
            sub = pos[0] if pos else ""
            if sub == "list":
                return "OK\n" + "".join("profile ssid=%s security=%s hidden=%d priority=%d autojoin=%d default_route=0 key=%s\n" % (
                    enc(p["ssid"]), p["security"], p["hidden"], p["priority"], p["autojoin"], "set" if p["key"] else "none") for p in PROFILES)
            if sub == "add":
                p = dict(ssid=opt.get("ssid", ""), security=opt.get("security", "auto"), key=opt.get("key", ""),
                         hidden=int(opt.get("hidden", "0") in ("1", "true")), priority=int(opt.get("priority", 0)), autojoin=1, default_route=0)
                if not p["ssid"]: return err("invalid profile: ssid")
                PROFILES[:] = [q for q in PROFILES if q["ssid"] != p["ssid"]] + [p]
                return "OK\n"
            if sub == "remove":
                s = opt.get("ssid") or (pos[1] if len(pos) > 1 else "")
                n = len(PROFILES); PROFILES[:] = [q for q in PROFILES if q["ssid"] != s]
                return "OK\n" if len(PROFILES) < n else err("no such profile")
            if sub == "autojoin":   # profile autojoin ssid=NAME on|off  (keeps the key)
                p = next((q for q in PROFILES if q["ssid"] == opt.get("ssid")), None)
                if not p or len(pos) < 2 or pos[1] not in ("on", "off"): return err("usage: profile autojoin ssid=NAME on|off")
                p["autojoin"] = 1 if pos[1] == "on" else 0
                return "OK\n"
            return err("usage: profile add|list|remove|autojoin")
        if cmd == "debug":
            if pos and pos[0] == "drop": S["state"] = "IDLE"; S["drops"] += 1; return "OK\n"
            if pos and pos[0] == "state" and len(pos) > 1: S["state"] = pos[1]; return "OK\n"
            return err("unknown debug command")
        if cmd == "quit": threading.Thread(target=lambda: (time.sleep(.2), os._exit(0))).start(); return "OK\n"
        return err("unknown command")

def serve(c):
    try:
        buf = b""
        while b"\n" not in buf and len(buf) < 1100:
            d = c.recv(1100)
            if not d: break
            buf += d
        line = buf.split(b"\n")[0].decode("utf-8", "replace").strip()
        if os.environ.get("FAKE_AWUSD_LOG"): print(re.sub(r"key=\S+", "key=***", line), flush=True)   # never log secrets
        try: out = handle(line) if line else err("empty")
        except Exception as e: out = err("internal: %s" % e)
        c.sendall(out.encode())
    finally:
        c.close()

def main():
    global DELAY
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", default=os.path.join(os.environ.get("TMPDIR", "/tmp"), "awusd.sock"))
    ap.add_argument("--delay", type=float, default=0.0, help="seconds a scan/join takes")
    a = ap.parse_args(); DELAY = a.delay
    try: os.unlink(a.sock)
    except FileNotFoundError: pass
    s = socket.socket(socket.AF_UNIX); s.bind(a.sock); os.chmod(a.sock, 0o600); s.listen(8)
    print("fake awusd on", a.sock, flush=True)
    threading.Thread(target=lambda: [(tick(), time.sleep(0.5)) for _ in iter(int, 1)], daemon=True).start()
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()

if __name__ == "__main__": main()
