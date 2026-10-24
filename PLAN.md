# AWUS036ACS (RTL8811AU, 0bda:0811) native on Apple Silicon / macOS 26

Goal: use the adapter natively on this Mac (no VM).

## Design (decided)
- Userspace driver over libusb (IOKit USB user client). No kext (vendor kext is x86_64 only),
  no dext (no signing identity, SIP on, USB transport entitlement needs Apple provisioning).
- Chip logic ported from open source aircrack-ng/rtl8812au (supports RTL8811AU/8812AU).
- Ladder (each step has a check):
  1. probe: open device, read chip regs via vendor ctrl req 0xC0/0x05      check: prints chip version
  2. power on + firmware download                                          check: FW ready bit
  3. set channel + monitor RX -> pcap                                      check: beacons seen in Wireshark/tcpdump -r
  4. TX injection                                                          check: frame heard by en0 sniffer
  5. connect (WPA2) via userspace 802.11 + utun                            check: ping over adapter

## Log
- 2026-10-24: vendor pkg + chris1111 V18 kexts = x86_64 only -> unusable. Adapter enumerates (0bda:0811).
- step 1 DONE: libusb opens + claims iface 0 unprivileged; vendor reg reads work (reg 0xF0=04411535). src/probe.c
- 2026-10-24 step 3 DONE (stage 3, `make monitor && ./build/monitor -t 20 --hop -o /tmp/cap.pcap`): real beacons from the air, pcap readable by tcpdump.
  New: src/mac.c (rtl_init_mac = _InitQueueReservedPage_8821, TX/RX FIFO boundaries 248 / 0x3E7F, TXDMA priority map by number of OUT eps (this dongle has 4: 0x05,0x06,0x08,0x09),
  driver info size 4, HIMR masked, WMAC/EDCA/retry/burst len/ARFR, MAC TX/RX enable; rtl_set_monitor = RCR AAP|APM|AM|AB|ADD3|APWRMGT|ACF|ADF|AMF|HTC_LOC|APP_ICV|APP_MIC|APP_PHYST_RXFF|APPFCS + RXFLTMAP0/1/2=0xFFFF),
  src/rx.c (bulk-IN 0x84 parser: 24-byte desc, drvinfo*8, shift, pkt_len (+4 FCS with APPFCS), 8-byte align; RPT_SEL (dw2 bit28) = C2H skipped; rssi = (phystatus[0]&0x7F)-110),
  src/pcap.c (linktype 127 radiotap: flags, rate, channel, dBm signal, HT MCS), src/monitor.c.
  Changed: src/phy.c (mac_misc moved to mac.c, rtl_init_phy calls rtl_init_mac; rtl_set_channel stores r->channel), src/rtl.h (rtl_t.channel appended), Makefile (monitor), test_phy build line.
  Findings: the phy.c as written worked on first run on the real chip: RF 0x18 readback after set_channel(6) = 0x07C06 (channel byte matches), no change needed to rtl_rf_r.
  Every frame received had a valid trailing FCS (CRC32 checked in rx.c) once APPFCS was set; without it pkt_len excludes the FCS. USB RX aggregation left off (one frame per bulk transfer).
- 2026-10-24 stages 2-5 DONE: build/wifi --tun brings up utun9; ping gw + 1.1.1.1 over the adapter, 0% loss. Open: LED, 5GHz, throughput, long-run stability, WPA3.
- 2026-10-25 5 GHz monitor RX DONE: `rtl_set_channel`'s existing 5G path (switch_band/rfe_8821/fc_area/RF 0x18 band-group bits) worked unchanged on real hardware -- no register fix was needed. Added `--hop5` (36,40,44,48,52..64,100..144,149..165, 250 ms/channel, DFS included passively) and `--hopall` to src/monitor.c.
  `./build/monitor -c 36 -t 6` -> STAGE3 OK, 246 frames, 0 CRC errors, beacons from MIWIFI_3fFU/vodafone96DB-5G/MiFibra-0D78(-5G).
  `./build/monitor -t 30 --hop5 -o /tmp/c5.pcap` -> STAGE3 OK frames=2148 beacons=259, 10 distinct SSIDs across ch 36-136 (tcpdump -nr confirms 5180-5660 MHz / 11a / CH: n match). Found the user's own router's 5G radio: BSSID aa:bb:cc:dd:ee:00 (one off the 2.4G BSSID aa:bb:cc:dd:ee:ff), SSID MyNetwork-5G, channel 132, -32 dBm (very close).
  Unverified still: 5G TX/injection (only RX tested), 40/80 MHz bandwidth, DFS CAC/radar-detect behavior (we only listen passively there).
- 2026-10-25 injection statistics DONE: new build/injtest (src/injtest.c) sends directed Probe Requests (SSID MyNetwork, random locally-administered SA, DA=BSSID=aa:bb:cc:dd:ee:ff only) at 1M CCK / 6M / 24M / 54M OFDM and counts Probe Responses addressed back to us, plus one broadcast wildcard probe counting distinct answering APs. No deauth/disassoc frame is built anywhere in this file; no destination other than the user's own router is ever used for a directed frame.
  `./build/injtest -c 7 -n 30` -> INJTEST OK 1M=30/30 6M=29/30 24M=28/30 54M=28/30 bcast_aps=2, at the existing default TX power index (0x20); no TX power change was needed to pass the >=80% bar.

## Vendor parity (goal: behave like the original "ALFA USB WiFi Driver (Build 0919).pkg")
What the vendor pkg really contains (extracted 2026-10-25, all x86_64, none loadable on Apple Silicon):
- RtWlanU / RtWlanU1827 kexts (IOUSBInterface match, one IONetworkController = a normal `en` interface), RtWlanDisk (the fake CD-ROM mode switch).
- StatusBarApp 5.0.8 (menu bar): scan list + signal bars, click-to-join open/WEP/WPA-PSK/802.1X (PEAP/TTLS/TLS/LEAP), join hidden ("Join Other"), saved profiles + auto-reconnect to last networks, create ad-hoc, WPS (PBC + PIN), Wi-Fi RF on/off, status window, country code (blocks 5 GHz "AC" in unsupported countries), TX power (`-setTxPowerAll`), RSSI, about/uninstall.
- RtWlanHelper (root helper), bundled wpa_supplicant (`-Dosx`), LaunchAgent + LaunchDaemon.

Design (one, not a menu): a root daemon `awusd` (launchd) owns the USB device: hot-plug, scan, join, reconnect, DHCP, utun. A CLI `awusctl` and a menu-bar app talk to it over a unix socket. Real `en` Wi-Fi interface is NOT possible without an Apple-granted DriverKit networking entitlement (no signing identity here), so utun is the substitute; this is the one deliberate difference.

Parity checklist (state: have / todo), each with its check:
 1 scan list with SSID/BSSID/ch/RSSI/security, 2.4+5 GHz ........ DONE 2026-10-25 (`awusctl scan`) -- check: lists MyNetwork + MyNetwork-5G
 2 join WPA2-PSK 2.4 GHz ........................................ have (wifi --tun); also as daemon (awusd) DONE 2026-10-25 air-verified
 3 join WPA2-PSK 5 GHz .......................................... DONE 2026-10-25 air-verified on ch 132 (DFS) -- ping 6/6, 0% loss
 4 join open network ............................................ DONE 2026-10-25 unit/logic only (no open AP of our own to test on air)
 5 join WEP (40/104, open+shared) ............................... DONE 2026-10-25 unit-vector tested only (not on air)
 6 WPA1/TKIP + mixed mode ....................................... DONE 2026-10-25 unit-tested only (not on air)
 7 hidden SSID ("Join Other") ................................... DONE 2026-10-25 path air-verified by forcing --hidden on our own AP (the AP itself is not hidden)
 8 WPA3-SAE (vendor wpa_supplicant is old; nice-to-have) ........ todo
 9 802.1X EAP PEAP/TTLS/TLS/LEAP ................................ todo (decide: embed wpa_supplicant via ctrl iface)
10 ad-hoc create/join ........................................... todo
11 WPS PBC + PIN ............................................... engine DONE 2026-10-25 (unit/loopback only; not integrated; not air-tested)
12 saved profiles + auto-join + auto-reconnect + hot-plug ....... DONE 2026-10-25 awusd; air-verified: autojoin, drop+backoff 1/2/4/8, debug unplug and debug wake rejoin; NEEDS USER: real unplug and real sleep
13 RF on/off, TX power ......................................... DONE 2026-10-25 air-verified (rf off: 0 frames heard, reg readback; txpower reg 0xC20 readback, persists)
14 RSSI / link speed / status query ............................ DONE 2026-10-25 air-verified (`awusctl status`)
15 country code + 5 GHz channel rules + DFS ..................... DONE 2026-10-25 air-verified (scan marks, join blocked on 132 under 00); table is a summary, not legal text
16 40/80 MHz, short GI, aggregation (throughput) ............... todo -- check: iperf3 number vs vendor claim
17 LED ......................................................... DONE 2026-10-25 register readback only; NEEDS USER: visual check
18 menu-bar app + installer pkg + uninstall ..................... DONE 2026-10-25 UI verified vs fake daemon only; pkg built, not installed
19 DHCP renew, IPv6, DNS applied to the service ................. PARTLY 2026-10-25 DHCP renew/rebind air-verified; IPv6/DNS todo; root utun + default route untested
20 USB mode-switch (fake CD) handling ........................... check if 0bda:0811 ever shows as disk

DONE 2026-10-25 checklist item 1: `build/awusctl scan [--band 2|5|all] [--dwell MS] [--passes N] [--json]` (src/awusctl.c) + pure parser src/scanparse.c with `make test-scanparse` (also in `make test`). Hardware: `--band all --dwell 250` listed 59-63 BSSIDs incl. our own 2.4G ch 7 and 5G ch 132 APs as WPA2-PSK/CCMP; `--json` passes `python3 -m json.tool`. Wildcard probes only (not on DFS 52-144), no deauth.

DONE 2026-10-25 checklist items 3-7 (lane vendor-parity). What exists: the join logic moved out of src/wifi.c into a library src/link.[ch] (`build/wifi` keeps the same CLI and output); new src/wep.[ch], src/tkip.[ch]; src/wpa.[ch] now also does key descriptor version 1 (HMAC-MD5 MIC, RC4 key data), descriptor type 254 (WPA1) and the 64-byte TKIP PTK; src/sta.[ch] got shared-key auth, hidden-SSID matching, `sta_set_channel`, 5 GHz OFDM management rates and the DFS gate; new `awusctl join`. `make test` runs test-wpa, test-net, test-scanparse, test-wep, test-tkip.
- DFS rule (src/sta.c `tx_gate`): on channels 52-144 nothing is transmitted unless a Beacon from the AP we target was heard in the last 1000 ms (so scanning there is passive until that beacon, and the gate only waits for one during scan/auth/assoc, never inside an RX callback). No radar detection exists: we only follow an AP that is already beaconing. Check: `build/wifi --ch 120` (empty DFS channel) -> `STAGE5B FAIL scan no_probe_response`, `tx: usb_completed=0` (zero frames sent).
- Item 3 (air-verified, own router, 5 GHz ch 132 DFS, WPA2-CCMP): `build/wifi --ssid <5G ssid> --bssid <5G bssid> --ch 132 --ping 192.168.1.1` -> `ping 192.168.1.1: sent 6 recv 6 loss 0% avg_rtt 1ms`, `STAGE5B OK`. `build/awusctl join --ssid <5G ssid> --bssid <5G bssid> --ch 132 --key-env TEST_PSK` -> `join OK sec=wpa2 pairwise=CCMP group=CCMP ch=132 ... ping 6/6 loss 0% avg_rtt 1ms`. Same without --ch/--bssid (channel auto-find, ~35 s as it walks 2.4 GHz then 5 GHz): `join OK ... ch=132 ... ping 6/6`. Fixes needed for 5 GHz: management/probe rate 6 Mbps OFDM instead of CCK 1 Mbps, OFDM-only supported-rates IE in the probe, no CCK rate on M1 retransmit replies.
- 2.4 GHz regression: `build/wifi --ssid <ssid> --ch 7 --ping 192.168.1.1` -> `ping ... sent 6 recv 6 loss 0%`, `STAGE5B OK`. `build/awusctl join --ssid <ssid> --ch 7 --key-env TEST_PSK` -> `join OK sec=wpa2 pairwise=CCMP group=CCMP ch=7 ... ping 6/6 loss 0%`. Auto-detect from the scan (no `--sec`) picked WPA2-CCMP both times.
- Item 7 (hidden SSID): `build/awusctl join --ssid <ssid> --hidden --key-env TEST_PSK` (no --ch, no --bssid) -> `join OK sec=wpa2 ... ch=7 ... ping 6/6 loss 0%`; also on 5 GHz with --hidden. This exercises the hidden path (directed Probe Request, accepting only a Probe Response addressed to us); our AP is not actually hidden, so a genuinely hidden AP is not air-tested.
- Item 4 (open): code path = no handshake, plain data, DHCP right after association; checked only by logic and by the negative test `--sec open` on the WPA2 AP -> `join FAIL scan ap_is_not_open` (refuses to treat a protected AP as open). NOT air-tested: no open AP of our own.
- Item 5 (WEP 40/104, open + shared key): src/wep.c with `make test-wep`: RC4 vectors from the literature (Key/Plaintext, Wiki/pedia, Secret/Attack at dawn), CRC-32 check value 0xCBF43926, WEP bodies generated with an independent Python RC4+zlib implementation, tamper/ICV tests, shared-key challenge body round trip. NOT air-tested: no WEP AP of our own, and we do not join anyone else's.
- Item 6 (WPA1/TKIP + mixed mode): src/tkip.c with `make test-tkip`: Michael published chain of vectors (802.11i), phase 1/2 mixing and the MPDU checked against the hostap reference code (20000 random inputs, zero mismatches, harness not committed) and the MPDU body recomputed independently in Python; src/wpa.c version-1 and descriptor-254 handshake tests in `make test-wpa` (HMAC-MD5 MIC recomputed with CommonCrypto, RC4 key data, G1 raw GTK) which are self-consistency tests against an authenticator written in the test, not published vectors. Mixed mode = pairwise CCMP with group TKIP: our RSN IE carries the AP's announced group cipher and the 32-byte GTK is accepted. NOT air-tested: our router offers WPA2-CCMP only.
- `awusctl join --ssid S [--bssid B] [--ch N] [--hidden] [--sec open|wep|wep-shared|wpa|wpa2|auto] [--key-env VAR] [--wep-keyid N]`: no root (no utun), DHCP, 6 pings to the gateway, then a Deauthentication (reason 3) and exit. The secret is read from the named environment variable only. Progress/results go to the terminal, register/protocol log to /tmp/awusctl.log.

DONE 2026-10-25 items 2-as-daemon, 12-15, 17, 19(part) (lane vendor-parity): src/awusd.c, src/scanlib.[ch], src/country.[ch], src/profile.[ch], src/proto.[ch], src/led.[ch], src/tun.c default-split routes, packaging/com.awus.awusd.plist. Bug found on air and fixed: a command that closed the device (wake/unplug) was followed by use of the freed device in the main loop. Not tested: root utun/default route, real sleep, real unplug, launchd install, LED visual.

DONE 2026-10-25 checklist item 18 (lane vendor-parity). Files: app/*.swift (`make app` -> build/AWUS WiFi.app, packaging/build-app.sh, Info.plist), tools/fake_awusd.py, packaging/{build-pkg.sh,postinstall,uninstall.sh,distribution.xml,com.awus.wifi.agent.plist}, `make pkg`. awusd got `version` in status and `profile autojoin ssid=X on|off` (compiles; not run on hardware). Plist now points at /usr/local/libexec/awus/awusd.
- Verified: app against tools/fake_awusd.py via `open -n ... --args --sock /tmp/fk.sock --open-menu`; screencapture showed the real menu (bars icon, lock, check, 5G/2.4G tags, disabled WPS/Ad-hoc). `--dump-menu` checked for connected and daemon-down. pkg: pkgutil --payload-files lists the expected files, `pkgutil --check-signature` = no signature, otool -L has only system libs (libusb static), plutil -lint and shellcheck clean.
- NOT verified: join/password dialogs, Status window sliders and rf toggle were not clicked through; nothing run against real awusd or hardware; pkg and uninstall.sh never executed (postinstall plist edit only tried on a temp copy); minos of the C binaries is the build host (26.0).
DONE 2026-10-25 checklist item 11 (lane vendor-parity): engine built and unit/loopback-tested only; not integrated; not air-tested. Files: src/wps.[ch] (WSC TLVs, EAP-WSC framing/fragmentation, M1-M8 enrollee state machine, KDF, PIN, encrypted settings, probe/assoc WSC IEs, AP WSC IE parse + PBC overlap, rate limiter), src/bignum_dh.[ch] (1536-bit DH), src/test_wps.c, tools/wps_check.py, docs/WPS.md (integration API + security note). `make test-wps` (also in `make test`): PIN checksum, python/openssl-generated KDF/hash/DH vectors, in-memory registrar M1-M8 for PBC and PIN incl. fragments, python re-verification of the transcript, wrong-PIN NACK 18 at M4/M6 (enrollee) and M5/M7 (registrar). Not done: awusd/awusctl integration, association with WSC IE in link.c, air test on our own AP.
