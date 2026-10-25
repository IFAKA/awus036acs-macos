# awus036acs-macos

A native, userspace driver for the **Alfa AWUS036ACS** Wi-Fi adapter
(Realtek RTL8811AU/RTL8821AU chipset, USB ID `0bda:0811`) on **macOS, Apple
Silicon**. No kext, no VM, no DriverKit entitlement. It talks to the chip
directly over `libusb` from a normal user process (root is only needed for
the `utun` bridge, see below).

It is a port of the relevant parts of the GPLv2 Linux driver
[aircrack-ng/rtl8812au](https://github.com/aircrack-ng/rtl8812au) to a
macOS/libusb userspace program, written from scratch in C.

## Why this exists

macOS has no first-party driver for this chip on Apple Silicon, and the
vendor kext ([chris1111's build](https://github.com/chris1111/wireless-usb-big-sur-adapter))
is x86_64-only, so it can't load on ARM Macs. Apple's DriverKit path needs a
signed, Apple-provisioned USB transport entitlement that isn't available to
an individual developer outside their program. A userspace libusb driver
sidesteps all of that: it needs no kernel extension, no entitlement, and no
SIP changes.

## Status: works, not yet 1:1 with the original driver

Proven on real hardware (Alfa AWUS036ACS + Apple Silicon Mac, macOS 26):

- Power-on sequence, firmware download (NIC image, RTL8821AU cut B), MAC/BB/
  AGC/RF table bring-up (path A, 1T1R).
- 2.4 GHz monitor-mode RX (`build/monitor`), with `.pcap` output readable by
  `tcpdump`/Wireshark.
- Frame TX and a closed-loop auth proof against a real AP (`build/authtest`).
- Full WPA2-PSK station join: probe/auth/assoc, 4-way handshake (software
  crypto via CommonCrypto), software CCMP encrypt/decrypt.
- DHCP and ARP in userspace, bridged to a `utun` interface — i.e. the Mac
  gets a real IP and routes real internet traffic through the adapter
  (verified with pings to a public host, 0% loss).
- Clean teardown: the adapter detaches without disturbing the Mac's default
  route or other interfaces.

## 1:1 with the original ALFA driver: checklist

Goal: behave like the vendor package "ALFA USB WiFi Driver (Build 0919)"
(Realtek kexts + StatusBarApp 5.0.8, x86_64 only, so it cannot run on Apple
Silicon). Tick a box only when it is verified; the note says how. Pick an
unchecked item and send a PR. Detail and evidence live in [`PLAN.md`](PLAN.md).

One deliberate difference: the original appears as a normal Wi-Fi `en`
interface. That needs an Apple-granted DriverKit entitlement, so this project
bridges to a `utun` interface instead.

- [x] Scan list: SSID, BSSID, channel, RSSI, security, WPS flag, 2.4 + 5 GHz (`awusctl scan`)
- [x] Join WPA2-PSK on 2.4 GHz (air-verified)
- [x] Join WPA2-PSK on 5 GHz incl. DFS channel (air-verified, DFS transmit gate)
- [ ] Join open network (logic and unit tests only, not on air)
- [ ] Join WEP 40/104 (unit vectors only, not on air)
- [ ] WPA1/TKIP and mixed mode (unit tests only, not on air)
- [x] Hidden SSID join (path air-verified; a truly hidden AP is untested)
- [ ] WPA3-SAE (integrated and covered by a software loopback test only, `make test-link-sae`; never on the air, our router is WPA2-only)
- [ ] 802.1X EAP: PEAP, TTLS, TLS, LEAP (integrated: `awusctl join --sec eap`, app Join Other, profiles; covered by a software loopback test only, `make test-link-eap`, loopback not air; we have no Enterprise AP or RADIUS server. PEM files only, no PKCS#12; TLS 1.2 only; see docs/EAP.md)
- [ ] Ad-hoc create/join (create + beacon is air-verified on ch 11: a Mac scan sees the IBSS, interval 100, via `awusctl adhoc create`; SSID text not verified, join and the data plane are not built/tested, see docs/ADHOC.md)
- [ ] WPS push-button and PIN (integrated: `awusctl wps pbc|pin`, covered by software loopback tests only, `make test-link-wps`; never run against a real router)
- [x] Saved profiles, auto-join, auto-reconnect with backoff (air-verified, incl. a real unplug/replug and a real sleep/wake, both rejoined by themselves)
- [x] Wi-Fi on/off and TX power control (air-verified)
- [x] RSSI, link speed and status query (`awusctl status`)
- [x] Country code, 5 GHz channel rules, DFS marking (table is a summary, not legal text)
- [ ] 40/80 MHz, short GI, aggregation and rate adaptation (HT 40 MHz MCS7 SGI air-verified on 5 GHz: ~49 Mbit/s up, ~39-49 down, 10x the legacy baseline; VHT/80 MHz and A-MPDU/block-ack not built)
- [x] LED: solid when connected, blinks on activity, matches the vendor behaviour (checked by eye); known nit: it blinks instead of going off in RF-off
- [ ] Menu-bar app and installer: built, tested against a fake daemon only; not installed or run against hardware
- [ ] DHCP renew/rebind and IPv6 (RA, SLAAC, ping6) air-verified; DNS applied to the interface and root `utun` IPv6 written but untested (needs root)
- [ ] USB mode-switch ("fake CD") handling: eject logic unit-tested; this unit never shows the CD stage, so it is not confirmed on a real stick
- [ ] Long-run stability and root `utun` + default-route mode tested

Other known gaps:

- No Linux-tool compatibility layer (a virtual monitor interface for
  `aircrack-ng`/`airodump-ng`).
- Per-rate TX power, crystal cap, and BB swing are fixed defaults, not read
  from the adapter's efuse.

## The daemon: awusd and awusctl

`build/awusd` is a single-threaded daemon that owns the adapter: hot-plug,
saved profiles, auto-join, auto-reconnect (backoff 1, 2, 4, 8 s, then up to
30 s; after 3 failed tries it re-scans), sleep/wake re-initialisation, DHCP
renew/rebind, RF on/off, TX power, country rules and the LED. `build/awusctl`
is its client (`make awusd` builds both; `awusctl scan|join` still work
directly when no daemon is running).

- Socket: `/var/run/awusd.sock` for root, else `$TMPDIR/awusd.sock`; override
  with `--sock`. Mode 0600, peer uid checked (`--sock-uid UID` lets one more
  user in). One request line per connection, `OK` or `ERR ...` plus
  `key=value` lines.
- Commands: `status`, `scan`, `join`, `leave`, `ping`, `rf on|off|get`,
  `txpower get|set N`, `country get|set CC`, `profile add|list|remove`,
  `autojoin on|off|get`, `quit`. Debug: `debug drop|unplug [ms]|wake|renew|
  rebind|led on|off|auto|failnext N`.
- Profiles: `profiles.json` (0600, clear-text PSK). A clear-text file was
  chosen over the Keychain because the `security` CLI puts the secret on argv
  and shows a GUI prompt, which a daemon cannot answer. Pass keys with
  `--key-env VAR`; keys are never logged.
- Country: a small built-in table (00 ES GB DE FR IT US JP), not the legal
  text of any regulator; check your local rules. Blocked channels (for
  example DFS under `00`) are listened to but never transmitted on, and
  `join` there fails with `channel_blocked_by_country`. A hidden-SSID join's
  own scan may transmit on a blocked channel before that check.
- Root vs link-only: without root there is no utun, so the link (IP via DHCP,
  ping) works but no traffic is bridged. As root, a utun is created;
  `default_route=1` additionally installs two /1 routes through it (untested).
- launchd: `packaging/com.awus.awusd.plist`; `make install-daemon` /
  `uninstall-daemon` (daemon at `/usr/local/libexec/awus/awusd`) print what they would do unless run as root.

## Menu-bar app and installer

`make app` builds `build/AWUS WiFi.app` (Swift, `swiftc` only, ad-hoc signed, `LSUIElement`, so no Dock icon). It
talks to `awusd` over the socket (`/var/run/awusd.sock`; `--sock PATH` or `$AWUS_SOCK` to override). Menu: status line
with signal bars (0-5 from RSSI), networks sorted by signal (lock = secured, check = current, 2.4G/5G tag), click to
join (secured ones ask for the password, with "Remember"), Join Other Network..., Saved Networks (join, auto-join,
remove), Turn Wi-Fi Off/On, Status... (link details, TX power slider, country), About, Quit. WPS and Create Ad-hoc Network
are in the menu (ad-hoc only announces the network for now). Status is polled every 2 s while the menu is closed; the scan refreshes when the
menu opens. If the daemon is not running the menu shows "Start driver...", which explains the sudo command.
`"build/AWUS WiFi.app/Contents/MacOS/AWUS WiFi" --dump-menu` prints the menu as text. For development without the
adapter run `python3 tools/fake_awusd.py` (canned data, never touches USB) and start the app with `--sock`.

`make pkg` builds `build/AWUS-WiFi-Driver.pkg` (unsigned, Apple Silicon): `awusd` in `/usr/local/libexec/awus`,
`awusctl` in `/usr/local/bin`, the app in `/Applications`, a LaunchDaemon for `awusd`, a LaunchAgent that opens the
app at login, and a postinstall that loads the daemon (`launchctl bootstrap system ...`) and lets the installing user
talk to it (`--sock-uid`; one user only). libusb is linked statically, so no Homebrew is needed on the target Mac.
Because the pkg is not signed or notarized, Gatekeeper blocks a double-click: right-click the pkg and choose Open, or
run `xattr -d com.apple.quarantine AWUS-WiFi-Driver.pkg`. Binaries are built for the macOS version of the build machine.

Uninstall: `sudo sh /usr/local/share/awus/uninstall.sh` (or double-click `build/AWUS-Uninstall.command`). It stops the
daemon and app, removes every installed file, and asks before deleting saved networks (`--purge` skips the question).

## Build

Requires Xcode command-line tools and `libusb` (`brew install libusb`).

```sh
make wifi        # station mode: join a WPA2 network and bridge to utun
make monitor      # monitor mode: capture frames to a .pcap
make authtest     # one-shot auth proof against your own AP
make injtest      # injection-rate test against your own AP
```

Binaries land in `build/`. `make clean` removes them.

## Use

All tools operate only on **your own** hardware and **your own** network —
point every `--bssid`/`--ssid` flag at an access point you own or are
authorized to test. There is no scanning-for-others' credentials code path
here, and none should be added.

```sh
# Monitor mode, 2.4 GHz channel 7, 30 seconds, save a pcap:
./build/monitor -c 7 -t 30 -o /tmp/capture.pcap

# Join your own WPA2 network and bridge it to a utun interface (needs sudo
# for the utun device only):
. /tmp/your-env-file   # exports TEST_SSID, TEST_PSK
sudo --preserve-env=TEST_PSK ./build/wifi --tun --ssid "$TEST_SSID" \
    --bssid aa:bb:cc:dd:ee:ff --ch 7 --route
```

See `PLAN.md` for the full build log, register-level notes, and the
reasoning behind each design decision.

## License

GPLv2 (see [`LICENSE`](LICENSE)), because this is derived from the GPLv2
`aircrack-ng/rtl8812au` driver and its firmware/table/power-sequence data.

The 802.1X engine's TLS comes from Mbed TLS (dual Apache-2.0 / GPL-2.0-or-later), used under the
GPL-2.0-or-later option and linked statically; no OpenSSL is included.

## Contributing

Pull requests welcome, especially on the parity checklist in
[`CONTRIBUTING.md`](CONTRIBUTING.md). This only exists because the hardware
deserved to work without a VM — help make it work all the way.
