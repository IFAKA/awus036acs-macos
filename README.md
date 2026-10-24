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

## Status: works, not yet 1:1 with the Linux driver

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

Known gaps — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the checklist:

- The LED is driven by the daemon (verified by register readback; visual confirmation pending).
- 5 GHz is scan/receive-only and lightly tested; 40/80 MHz and WPA3 are
  unimplemented.
- No throughput tuning, no long-session soak testing, no GTK rekey exercised.
- No Linux-tool compatibility layer (e.g. a virtual monitor interface for
  `aircrack-ng`/`airodump-ng` to attach to directly).
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
remove), Turn Wi-Fi Off/On, Status... (link details, TX power slider, country), About, Quit. WPS and Ad-hoc are
present but disabled ("not built yet"). Status is polled every 2 s while the menu is closed; the scan refreshes when the
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

## Contributing

Pull requests welcome, especially on the parity checklist in
[`CONTRIBUTING.md`](CONTRIBUTING.md). This only exists because the hardware
deserved to work without a VM — help make it work all the way.
