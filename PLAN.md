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
 2 join WPA2-PSK 2.4 GHz ........................................ have (wifi --tun)
 3 join WPA2-PSK 5 GHz .......................................... todo -- check: ping over ch 132/36 (DFS: check CAC)
 4 join open network ............................................ todo
 5 join WEP (40/104, open+shared) ............................... todo
 6 WPA1/TKIP + mixed mode ....................................... todo
 7 hidden SSID ("Join Other") ................................... todo
 8 WPA3-SAE (vendor wpa_supplicant is old; nice-to-have) ........ todo
 9 802.1X EAP PEAP/TTLS/TLS/LEAP ................................ todo (decide: embed wpa_supplicant via ctrl iface)
10 ad-hoc create/join ........................................... todo
11 WPS PBC + PIN ............................................... todo
12 saved profiles + auto-join + auto-reconnect + hot-plug ....... todo -- check: unplug/replug and sleep/wake rejoin
13 RF on/off, TX power ......................................... todo
14 RSSI / link speed / status query ............................ todo
15 country code + 5 GHz channel rules + DFS ..................... todo
16 40/80 MHz, short GI, aggregation (throughput) ............... todo -- check: iperf3 number vs vendor claim
17 LED ......................................................... todo
18 menu-bar app + installer pkg + uninstall ..................... todo
19 DHCP renew, IPv6, DNS applied to the service ................. todo (now IPv4 host routes only)
20 USB mode-switch (fake CD) handling ........................... check if 0bda:0811 ever shows as disk

DONE 2026-10-25 checklist item 1: `build/awusctl scan [--band 2|5|all] [--dwell MS] [--passes N] [--json]` (src/awusctl.c) + pure parser src/scanparse.c with `make test-scanparse` (also in `make test`). Hardware: `--band all --dwell 250` listed 59-63 BSSIDs incl. our own 2.4G ch 7 and 5G ch 132 APs as WPA2-PSK/CCMP; `--json` passes `python3 -m json.tool`. Wildcard probes only (not on DFS 52-144), no deauth.
