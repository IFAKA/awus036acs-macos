# Contributing

This driver works end-to-end (WPA2 join, DHCP, routed internet traffic) but
is not yet 1:1 with the upstream Linux driver it's ported from
(`aircrack-ng/rtl8812au`). Below is the gap list, roughly in order of how
much a typical user would miss it. Each item names the file(s) it touches
and what "done" looks like.

## Parity checklist

### LED
The chip's LED is software-controlled via `REG_LEDCFG2` (offset `0x4E`) but
the driver never writes it. Port the Linux driver's LED on/off/blink logic
(`rtl8812au/hal/rtl8821au_led.c` and friends) into a small `led.c`, and call
it from `bringup.c` on power-on and from `sta.c` on link up/down.
**Done when:** the LED lights on power-on like it does on Windows/Linux.

### efuse-derived calibration
Crystal cap, BB swing, and per-rate TX power currently use fixed defaults
(see `phy.c`, search for `RTL_TXPWR_DEFAULT`-style constants). The real chip
stores these per-unit in its efuse. Port the efuse read path
(`rtl8812au/hal/.../rtl8821au_hal_init.c`, `odm_EfuseInit` and the maps it
reads) and apply the values during `rtl_init_phy`.
**Done when:** TX power and RX sensitivity match the Windows driver's
behavior on the same unit, not just "close enough."

### 5 GHz: full support
5 GHz currently works for scan/RX (`monitor --hop5`) but TX/association
there is lightly tested, and 40/80 MHz channel bonding is not implemented at
all (see `phy.c`/`mac.c` for the channel-width register writes the Linux
driver does that aren't ported). **Done when:** `wifi --tun` can join a
5 GHz 80 MHz WPA2 AP as reliably as it joins a 2.4 GHz 20 MHz one.

### WPA3 / SAE
`wpa.c` only implements WPA2-PSK (PBKDF2 + 4-way handshake, CCMP). WPA3 needs
SAE (dragonfly handshake) before the same 4-way handshake flow.
**Done when:** `wifi --tun` can join a WPA3-only AP.

### QoS data frames and GTK rekey
Only non-QoS unicast data frames have been exercised; QoS (802.11e) framing
and a GTK rekey during a live session are unbuilt/untested (`tx.c`, `sta.c`).
**Done when:** a long session survives a GTK rekey without dropping, and
QoS-tagged APs are handled correctly (TID, ack policy).

### Keepalive frames should be real CCMP, not plain
Null-data keepalives sent during an active session are currently plain, not
encrypted CCMP frames (`sta.c`). Real stations encrypt these.
**Done when:** keepalives are indistinguishable (format-wise) from other
encrypted traffic to the AP.

### Throughput and long-session stability
No tuning has been done for sustained throughput (block-ack/aggregation is
unimplemented), and no multi-hour soak test has been run.
**Done when:** `iperf3` numbers are in a reasonable range for this chipset,
and a multi-hour session doesn't drop.

### Linux-tool compatibility
There's no way to point `aircrack-ng`, `airodump-ng`, or `aireplay-ng`
directly at this adapter the way you can on Linux. A reasonable path: a
named-pipe or loopback `pcap` feed from `monitor.c` that those tools can
read live (tools already read from a pipe/FIFO today), plus a documented
injection command (`inject.c`/`injtest.c` already prove TX works).
**Done when:** `airodump-ng` can watch a live capture piped from this driver.

### RSSI accuracy
Current RSSI reporting (`rx.c`) is rough. Port the real Linux driver's
RSSI/EVM calculation if it differs meaningfully.

## Ground rule for any PR touching injection/auth/capture code

Every tool in this repo (`authtest`, `injtest`, `monitor`, `wifi`) is meant
to be run only against networks the operator owns or is authorized to test.
Keep it that way: no feature that only makes sense against someone else's
network (e.g. deauth floods, credential harvesting) belongs here. If you're
unsure whether something crosses that line, open an issue first.

## Workflow

1. Open an issue or claim one of the items above before starting, so two
   people don't duplicate work.
2. Keep PRs scoped to one item from the list where possible — they're
   independent of each other.
3. `PLAN.md` has the register-level notes and reasoning for the existing
   code; read the relevant section before changing a subsystem.
4. Test against your own hardware and your own AP; include what you ran and
   its output in the PR description (this project has no CI with real USB
   hardware attached).
