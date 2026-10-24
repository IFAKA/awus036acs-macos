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
