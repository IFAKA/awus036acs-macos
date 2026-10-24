#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent check for src/wps.c: pure python (hashlib, hmac, pow) + the openssl CLI for AES-128-CBC.
  wps_check.py vectors              print C-ready expected values for src/test_wps.c
  wps_check.py transcript FILE      re-derive keys from the private keys in a transcript written by test_wps (WPS_TRANSCRIPT=FILE)
                                    and verify every Authenticator, Key Wrap Authenticator, E/R-Hash and the final credential
No code is shared with the C implementation (the prime is rebuilt from the RFC 3526 formula using pi computed here)."""
import hashlib, hmac, subprocess, sys

def atan_inv(x, one):
    t = one // x; s = t; x2 = x * x; n = 3; sign = -1
    while t:
        t //= x2; s += sign * (t // n); sign = -sign; n += 2
    return s

def prime():
    one = 1 << 1600
    pi = 16 * atan_inv(5, one) - 4 * atan_inv(239, one)
    f = pi >> (1600 - 1406)                       # floor(2^1406 * pi)
    return (1 << 1536) - (1 << 1472) - 1 + (1 << 64) * (f + 741804)
P = prime()
assert P.bit_length() == 1536 and P % 2 == 1

def H(k, *parts): return hmac.new(k, b"".join(parts), hashlib.sha256).digest()
def i2b(x): return x.to_bytes(192, "big")
def aes(enc, key, iv, data):
    cmd = ["openssl", "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex()] + ([] if enc else ["-d"])
    r = subprocess.run(cmd, input=data, capture_output=True)
    if r.returncode: raise ValueError("openssl: " + r.stderr.decode())
    return r.stdout
def kdf(kdk, nbytes):
    out = b""; i = 1
    while len(out) < nbytes:
        out += H(kdk, i.to_bytes(4, "big"), b"Wi-Fi Easy and Secure Key Derivation", (nbytes * 8).to_bytes(4, "big")); i += 1
    return out[:nbytes]
def keys(priv_e, pkr, n1, mac, n2):
    shared = i2b(pow(int.from_bytes(pkr, "big"), priv_e, P))
    dh = hashlib.sha256(shared).digest()
    kdk = H(dh, n1, mac, n2)
    o = kdf(kdk, 80)
    return shared, kdk, o[:32], o[32:48], o[48:]
def psk(auth, pin):
    l1 = (len(pin) + 1) // 2
    return H(auth, pin[:l1].encode())[:16], H(auth, pin[l1:].encode())[:16]
def tlvs(b):
    i = 0; d = {}
    while i < len(b):
        t = int.from_bytes(b[i:i+2], "big"); n = int.from_bytes(b[i+2:i+4], "big")
        d.setdefault(t, b[i+4:i+4+n]); i += 4 + n
    assert i == len(b)
    return d
def tlv(t, v): return t.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v
def seal(auth, kwk, iv, plain):
    kwa = H(auth, plain)[:8]
    return iv + aes(True, kwk, iv, plain + tlv(0x101E, kwa))
def opened(auth, kwk, blob):
    pt = aes(False, kwk, blob[:16], blob[16:])
    kwa = tlvs(pt[-12:]); assert pt[-12:-8] == b"\x10\x1e\x00\x08"
    assert hmac.new(auth, pt[:-12], hashlib.sha256).digest()[:8] == pt[-8:], "KWA"
    return pt[:-12]

def vectors():
    priv_e = int.from_bytes(bytes((i * 37 + 11) & 255 for i in range(192)), "big")
    priv_r = int.from_bytes(bytes((i * 91 + 5) & 255 for i in range(192)), "big")
    pke = i2b(pow(2, priv_e, P)); pkr = i2b(pow(2, priv_r, P))
    n1 = bytes(range(1, 17)); n2 = bytes(0xA1 + i for i in range(16)); mac = bytes.fromhex("001122334455")
    es1 = bytes(0x30 + i for i in range(16)); es2 = bytes(0x50 + i for i in range(16)); rs1 = bytes(0x70 + i for i in range(16))
    iv = bytes(0xC0 + i for i in range(16))
    shared, kdk, auth, kwk, emsk = keys(priv_e, pkr, n1, mac, n2)
    assert shared == i2b(pow(int.from_bytes(pke, "big"), priv_r, P))
    p1, p2 = psk(auth, "12345670")
    out = {
        "p_sha": hashlib.sha256(i2b(P)).digest(), "pke_sha": hashlib.sha256(pke).digest(), "pkr_sha": hashlib.sha256(pkr).digest(), "shared_sha": hashlib.sha256(shared).digest(),
        "dhkey": hashlib.sha256(shared).digest(), "kdk": kdk, "auth": auth, "kwk": kwk, "emsk": emsk, "psk1": p1, "psk2": p2,
        "ehash1": H(auth, es1, p1, pke, pkr), "ehash2": H(auth, es2, p2, pke, pkr), "rhash1": H(auth, rs1, p1, pke, pkr),
        "authenticator": H(auth, b"prev-message", b"current-message")[:8],
        "seal": seal(auth, kwk, iv, tlv(0x1016, es1)),
        "pbc_psk1": psk(auth, "00000000")[0],
    }
    for k, v in out.items(): print('    {"%s", "%s"},' % (k, v.hex()))

def transcript(path):
    L = {}
    for line in open(path):
        k, _, v = line.strip().partition(" ")
        L[k] = v
    priv_e = int(L["PRIV_E"], 16); pin = L["PIN"]; mac = bytes.fromhex(L["MAC"])
    m = {i: bytes.fromhex(L["M%d" % i]) for i in range(1, 9)}
    t = {i: tlvs(m[i]) for i in m}
    n1 = t[1][0x101A]; n2 = t[2][0x1039]; pke = t[1][0x1032]; pkr = t[2][0x1032]
    assert pke == i2b(pow(2, priv_e, P)), "PKe"
    shared, kdk, auth, kwk, emsk = keys(priv_e, pkr, n1, mac, n2)
    p1, p2 = psk(auth, pin)
    for i in range(2, 9):
        body = m[i][:-12]; assert m[i][-12:-8] == b"\x10\x05\x00\x08", "M%d authenticator not last" % i
        assert H(auth, m[i-1], body)[:8] == m[i][-8:], "M%d authenticator" % i
    es1 = opened(auth, kwk, t[5][0x1018]); es2 = opened(auth, kwk, t[7][0x1018])
    rs1 = opened(auth, kwk, t[4][0x1018]); rs2 = opened(auth, kwk, t[6][0x1018])
    es1 = tlvs(es1)[0x1016]; es2 = tlvs(es2)[0x1017]; rs1 = tlvs(rs1)[0x103F]; rs2 = tlvs(rs2)[0x1040]
    assert H(auth, es1, p1, pke, pkr) == t[3][0x1014], "E-Hash1"
    assert H(auth, es2, p2, pke, pkr) == t[3][0x1015], "E-Hash2"
    assert H(auth, rs1, p1, pke, pkr) == t[4][0x103D], "R-Hash1"
    assert H(auth, rs2, p2, pke, pkr) == t[4][0x103E], "R-Hash2"
    cred = tlvs(tlvs(opened(auth, kwk, t[8][0x1018]))[0x100E])
    print("TRANSCRIPT OK  ssid=%s auth=0x%04x encr=0x%04x key=%s" % (cred[0x1045].decode(), int.from_bytes(cred[0x1003], "big"),
          int.from_bytes(cred[0x100F], "big"), cred[0x1027].decode()))

if __name__ == "__main__":
    if sys.argv[1:2] == ["vectors"]: vectors()
    elif sys.argv[1:2] == ["transcript"]: transcript(sys.argv[2])
    else: sys.exit(__doc__)
