// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// caps: HT (802.11n) / VHT (802.11ac) capability and operation elements of an AP, the elements we send in the
// association request, and the transmit plan (width, sub-channel, highest MCS) that follows from them. Pure functions.
#ifndef CAPS_H
#define CAPS_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int has_ht, has_vht;
    uint16_t ht_cap_info;           // HT Capabilities: bit 1 40 MHz, bit 5 SGI20, bit 6 SGI40, bit 0 LDPC rx
    uint8_t ht_mcs_rx[4];           // AP receive MCS bitmap bytes 0-3 (MCS 0-31)
    int ht_primary;                 // HT Operation: primary channel (0 = not present)
    int ht_sec_off;                 // 0 none, 1 above, 3 below
    int ht_sta_width;               // 1 = the BSS may use 40 MHz
    uint32_t vht_cap_info;          // VHT Capabilities info: bit 4 rx LDPC, bit 5 SGI80
    uint16_t vht_rx_map;            // AP receive MCS map, 2 bits per spatial stream (NSS1 = bits 1:0: 0 = MCS0-7, 1 = 0-8, 2 = 0-9, 3 = none)
    int vht_width;                  // VHT Operation: 0 = 20/40, 1 = 80, 2 = 160, 3 = 80+80
    int vht_seg0, vht_seg1;         // centre channel index of the 80 MHz segment (and the second one)
    int wmm;                        // WMM element present
} ap_caps_t;

void caps_parse(const uint8_t *ies, size_t n, ap_caps_t *c);

typedef enum { MODE_LEGACY = 0, MODE_HT = 1, MODE_VHT = 2 } tx_mode_t;
typedef struct {
    tx_mode_t mode;
    int bw;                         // radio and data width: 0 = 20, 1 = 40, 2 = 80 MHz
    int sc;                         // HT secondary channel offset for 40 MHz (1 above, 3 below), else 0
    int center;                     // centre channel the radio is tuned to
    int max_mcs;                    // highest MCS (HT 0-7, VHT 0-9)
    int sgi;                        // AP accepts a short guard interval at this width
} tx_plan_t;

// Decide how to talk to the AP on `channel`. max_bw caps the width (0/1/2). legacy = force 20 MHz legacy rates. allow_vht = use VHT rates/80 MHz on 5 GHz.
void caps_plan(const ap_caps_t *c, int channel, int max_bw, int legacy, int allow_vht, tx_plan_t *p);

// Elements for the association request. Each returns the bytes written (including id and length).
size_t caps_build_ht_cap(uint8_t *o, int bw40, int channel_2g);
size_t caps_build_vht_cap(uint8_t *o);
size_t caps_build_wmm(uint8_t *o);

// Rate codes passed to the TX path in the same int as the legacy Mbps*10 rates.
#define RATE_HT(mcs)   (1000 + (mcs))        // HT MCS 0-7 (1 spatial stream)
#define RATE_VHT(mcs)  (2000 + (mcs))        // VHT MCS 0-9, 1 spatial stream
#define RATE_IS_HT(r)  ((r) >= 1000 && (r) < 2000)
#define RATE_IS_VHT(r) ((r) >= 2000)
// Approximate PHY rate in kbit/s for a rate code at a width and guard interval (for logs and the rate ladder).
int caps_rate_kbps(int rate, int bw, int sgi);
// Short text for a rate code: "6M", "MCS7", "VHT9".
const char *caps_rate_str(int rate, char *buf, size_t n);
#endif
