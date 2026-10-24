// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// bench: goodput measurement over a joined link (no root, no utun). The peer is this Mac's own LAN interface: uplink =
// UDP from our userspace IP stack over the air to a UDP socket on the Mac; downlink = a paced UDP flood from the Mac
// to our lease IP, counted when it arrives through the radio. Our own router only.
#ifndef BENCH_H
#define BENCH_H
#include <stddef.h>
#include <stdint.h>
#include "link.h"

#define BENCH_PORT 54321

// Pure helpers (unit tested). Build an IPv4+UDP packet (UDP checksum 0 = none); the payload starts with a 4-byte
// big-endian sequence number, the rest is a fixed pattern. Returns the IP packet length.
size_t bench_udp_build(uint8_t *out, uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, uint32_t seq, size_t payload_len);
// Parse: 0 ok (dport, seq, payload length filled), -1 not a plain IPv4 UDP packet.
int bench_udp_parse(const uint8_t *ip, size_t len, uint16_t *dport, uint32_t *seq, size_t *payload_len, uint32_t *src);
// Mbit/s from payload bytes and milliseconds.
double bench_mbps(unsigned long long bytes, long ms);
// Find this Mac's IPv4 address on the subnet of `lease_ip`/`mask` (not 127/utun). 0 = none. Host order.
uint32_t bench_find_peer(uint32_t lease_ip, uint32_t mask);

typedef struct {
    double mbps;                    // goodput measured at the receiving end
    unsigned long sent, recv;       // datagrams
    double offered_mbps;            // downlink: target; uplink: what we managed to submit
    unsigned long tx_ok, tx_retry_over, tx_submitted;   // chip TX report deltas (uplink)
    int rx_rate, rx_bw;             // last RX rate / bandwidth code seen from the AP
    int tx_rate;                    // data rate code used
} bench_res_t;

// dir: 1 = uplink (we send), 2 = downlink (the Mac sends at offered_mbps). secs per run. 0 = ok.
int bench_run(link_t *l, uint32_t peer, int dir, int secs, int payload, int offered_mbps, bench_res_t *res);
#endif
