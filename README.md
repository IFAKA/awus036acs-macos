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

- The chip's LED never lights (register path known, not wired up).
- 5 GHz is scan/receive-only and lightly tested; 40/80 MHz and WPA3 are
  unimplemented.
- No throughput tuning, no long-session soak testing, no GTK rekey exercised.
- No Linux-tool compatibility layer (e.g. a virtual monitor interface for
  `aircrack-ng`/`airodump-ng` to attach to directly).
- Per-rate TX power, crystal cap, and BB swing are fixed defaults, not read
  from the adapter's efuse.

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
