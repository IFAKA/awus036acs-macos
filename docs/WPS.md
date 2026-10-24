# WPS enrollee engine (PBC and PIN)

Status: engine built and unit/loopback-tested only. Not wired into `awusd`/`awusctl`. Never run against a real access point.

Files: `src/wps.[ch]` (protocol), `src/bignum_dh.[ch]` (1536-bit modexp, DH group 5), `src/test_wps.c`,
`tools/wps_check.py` (independent python check). Test: `make test-wps` (also part of `make test`).

## What it is

The client (enrollee) half of WPS 2.0 registration, as in the vendor app's WPS menu. You are close to a printer asking
a router "give me the Wi-Fi password": you prove you pushed the button or know the PIN, and the router hands over
the SSID and key in an encrypted box. The code has no USB, socket or timer in it; it takes bytes in and gives bytes out.

## Integration steps (for link.c / awusd)

1. Scan. For each AP keep its IE bytes. Fill a `wps_ap_info_t` with `wps_ap_parse(ies, len, &info)` and set `info.bssid`.
2. Choose the AP.
   - PBC: `idx = wps_pbc_pick(aps, n, &count)`. `-1` = nobody has a button window open ("press the WPS button on the
     router, then retry"). `-2` = two different routers have their button window open: do NOT start, tell the user
     (config error `WPS_CFG_MULTIPLE_PBC`, 12). Two bands of one router (same UUID) count once.
   - PIN: the user picks their own AP. `wps_ap_check(&info, WPS_MODE_PIN)` must be `WPS_AP_OK`; `WPS_AP_LOCKED` means
     the AP has locked WPS setup: stop and show `wps_ap_reason_str()`.
3. Rate limit: keep a `wps_limiter_t` per BSSID. Before an attempt `wps_limiter_check(&l, now)`: `0` go, `>0` wait that many
   seconds, `-1` blocked after 5 failures until `wps_limiter_reset` (only on explicit user action). After the attempt
   `wps_limiter_record(&l, now, success)`. Delay is 30 s, doubling, max 1 h.
4. Build the config: `wps_cfg_t cfg = {0}; memcpy(cfg.mac, our_mac, 6); wps_uuid_from_mac(our_mac, cfg.uuid);`
   `cfg.pin = NULL` for PBC, or the PIN string (4 digits, or 8 digits with valid checksum: check with
   `wps_pin_valid`). If the user wants to type a PIN on the router instead, create one with `wps_pin_generate(seven, buf)`
   (you supply the 7 random digits) and display it.
5. Probe Request while scanning for the AP: `wps_build_probe_req_ie(&cfg, buf, sizeof buf)` returns a complete vendor IE
   (`dd len 00:50:f2:04 ...`, request type Enrollee, password id 4 for PBC / 0 for PIN) to append to the probe.
6. Associate to the AP as an OPEN network with the Association Request IE from `wps_build_assoc_req_ie(buf, sizeof buf)`
   and NO RSN/WPA IE (the registration runs over EAPOL on an unencrypted link; WPS APs accept this).
7. Run the session. Allocate one `wps_eap_t` (about 10 KB, use the heap), `wps_eap_init(s, &cfg)` (fails with
   `WPS_ERR_PIN` for a bad PIN). Send `wps_eap_start_frame()` (EAPOL-Start, 4 bytes) as an EAPOL data frame (ethertype
   0x888E, to the BSSID). Then for every received EAPOL frame (from the EAPOL header on, without 802.11 or LLC):
   `n = wps_eap_rx(s, frame, len, out, sizeof out)`. If `n > 0`, transmit `out[0..n)` as one EAPOL frame. `0` = nothing to
   send. `< 0` = malformed input (drop it; the session is still fine unless `wps_eap_result(s) == -1`).
   One reply per received frame: a long message is fragmented, and the AP's fragment ACKs pull the rest. A repeated
   request (same EAP id) gets the same reply again, so you do not need your own retransmit logic for AP resends.
8. Stop conditions (check `wps_eap_result(s)` after each call):
   - `1`: done. `s->en.cred` holds the result (see below). WSC_Done has been sent in the last reply; send it, then
     drop the association.
   - `-1`: failed. `s->en.fail` (`WPS_FAIL_*`) and `s->en.cfg_error` (`WPS_CFG_*`, the code we sent, or the AP's NACK
     code) tell why. `WPS_FAIL_PIN_AUTH` or an AP NACK with code 18 = wrong PIN. Call `wps_limiter_record(..., 0)`.
   - `0` with `s->en.state == WPS_ST_M2D`: the AP is not ready (no button window / PIN not enabled). Not a failure;
     report it and retry later (new session: re-associate).
   - Timeouts are the caller's: about 10 s without a frame from the AP, or 120 s for the whole session, then give up
     (`WPS_CFG_MSG_TIMEOUT`/`WPS_CFG_SESSION_TIMEOUT` if you report it).
9. Clear secrets: `wps_eap_clear(s)` (zeroes keys, PIN and credential) after you copied the credential out.

Receiving an EAP-Failure after WSC_Done is normal and keeps result `1`.

## The credential -> saved profile

`wps_cred_t`: `ssid[ssid_len]`, `auth_type`, `encr_type`, `key[key_len]` (NUL terminated), `key_is_hex_psk`, `key_index`, `mac`.

| `auth_type` | `encr_type` | profile |
|---|---|---|
| `0x0001` open | `0x0001` none | open (key empty) |
| `0x0001` open or `0x0004` shared | `0x0002` WEP | WEP, `key` is the WEP key text (`wep_parse_key`), `key_index` |
| `0x0002` WPA-PSK | TKIP `0x0004` | WPA1/TKIP |
| `0x0020` WPA2-PSK | AES `0x0008` | WPA2-PSK/CCMP |
| `0x0022` (WPA+WPA2 PSK), encr `0x000C` | mixed | WPA2-PSK, accept TKIP+CCMP |

`key` is a passphrase of 8 to 63 characters, or 64 hex digits (`key_is_hex_psk = 1`) meaning the raw PSK, which skips
PBKDF2. Save it in the awusd profile store like any manually entered network, then join normally (this is a normal
WPA2-PSK join after WPS, it is not a special mode). Auth types with 802.1X (`0x0008`, `0x0010`) are not WPS-PSK credentials
and should be rejected by the caller.

## Layers

- `wps_eap_t`: EAPOL/EAP framing. Identity reply `WFA-SimpleConfig-Enrollee-1-0`, expanded EAP type (vendor 0x372A,
  type 1), op-codes Start/ACK/NACK/MSG/Done/FRAG_ACK, flags L (length) and M (more), reassembly up to 2048 bytes,
  fragments of `cfg.frag_size` (default 1398). Answers other EAP methods with a Nak for the expanded type.
- `wps_enrollee_t`: `wps_enrollee_start()` builds M1; `wps_enrollee_rx()` consumes M2, M2D, M4, M6, M8, NACK and
  returns M3, ACK, M5, M7, Done or our NACK. Authenticator, Key Wrap Authenticator, nonces, R-Hash1/2 and the
  password id are all checked; any failure produces a NACK with the proper config error and ends the session.
- Primitives: TLV (`wps_put*`, `wps_tlv_*`), `wps_kdk`/`wps_kdf`/`wps_derive_keys`, `wps_psk`, `wps_hash`,
  `wps_authenticator`, `wps_encr_seal`/`wps_encr_open`, `wps_pin_*`, `dh_public`/`dh_shared`.

Randomness is `arc4random_buf` unless `cfg.rand_fn` is set (tests only; never set it in the daemon).

## Security note

PIN WPS is weak by design. The 8-digit PIN is checked in two halves of 4 digits (one is a checksum), so an online
attacker needs at most 11,000 tries, and "Pixie Dust" attacks recover the PIN offline from one exchange with routers that use weak
nonces. Many routers also lock setup after a few failures. Push-button is the safer method but anyone in radio
range can race the user during the two-minute window.

This client is therefore deliberately limited:

- It enrolls one PIN that the user provides, on an AP the user chose. There is no PIN iteration, no PIN list, no
  generator that walks the PIN space, and no offline-attack mode: the enrollee never exposes `E-S1`/`E-S2`/PSK material
  or the registrar's hashes outside the object, and there is no registrar code at all.
- It honours AP-setup-locked (`wps_ap_check` returns `WPS_AP_LOCKED`; the caller must not try).
- It limits itself (`wps_limiter_t`): 30 s, 60 s, 120 s ... up to 1 h between failures, and blocked after 5 failures until
  the user resets it.
- It refuses to start PBC when two registrars have an open button window (session overlap).
- It checks the DH public key from the AP (rejects 0, 1, p-1, >= p) and verifies every Authenticator in constant time.

Use it on your own network. The modular exponentiation is not constant time; the exponent is a fresh per-session
random key on a local link, which is acceptable for this use but should be revisited if the code is reused elsewhere.

## Testing

`make test-wps` runs (under AddressSanitizer + UBSan):

- PIN checksum (12345670 valid, 12345678 invalid, every one-digit error caught), generation, 4-digit PINs.
- Bignum: textbook modexp, Fermat check on the real prime, DH symmetry, invalid peer keys.
- Values generated by `tools/wps_check.py` (python hashlib/hmac/pow plus the openssl CLI for AES; the `cryptography`
  package is not installed here): public keys, DHKey, KDK, AuthKey/KeyWrapKey/EMSK, PSK1/2, E-Hash1/2, R-Hash1,
  Authenticator, a sealed Encrypted Settings blob. The prime itself is rebuilt in python from the RFC 3526 formula.
- A complete in-memory enrollee <-> registrar M1..M8 session over EAP frames (registrar written in the test file),
  PBC and PIN, single frames and 100/64-byte fragments, open network and raw 64-hex PSK credentials.
- Then `python3 tools/wps_check.py transcript build/wps_transcript.txt` re-verifies that session from scratch:
  every Authenticator, every Key Wrap Authenticator, E/R-Hash1/2, and the credential.
- Negative: wrong PIN (first half: enrollee stops at M4; second half: stops at M6; both with NACK config error 18),
  registrar-side rejection at M5 and M7 (error 18 relayed, `WPS_FAIL_AP_NACK`), password id mismatch, M2D, corrupt
  encrypted settings (error 2), bad Authenticator, other session's nonce, invalid DH key, EAP framing faults, mutated input.
- Probe/Association request IE contents, Beacon/Probe Response parsing (including IEs split in several elements),
  locked AP, PBC overlap detection, rate limiter.

Not done: air test against a real AP; integration into `awusd`; real-world quirks of vendor registrars (some send
M2 with unexpected attribute order or omit optional attributes; the parser looks attributes up by type, so order does not matter).
