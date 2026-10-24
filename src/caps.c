// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <stdio.h>
#include <string.h>
#include "caps.h"

void caps_parse(const uint8_t *p, size_t n, ap_caps_t *c)
{
    const uint8_t *end = p + n;
    memset(c, 0, sizeof *c);
    c->vht_rx_map = 0xFFFF;
    while (p + 2 <= end && p + 2 + p[1] <= end) {
        int id = p[0], l = p[1];
        const uint8_t *b = p + 2;
        if (id == 45 && l >= 26) {                       // HT Capabilities
            c->has_ht = 1; c->ht_cap_info = b[0] | b[1] << 8;
            memcpy(c->ht_mcs_rx, b + 3, 4);
        } else if (id == 61 && l >= 22) {                // HT Operation
            c->ht_primary = b[0]; c->ht_sec_off = b[1] & 3; c->ht_sta_width = (b[1] >> 2) & 1;
        } else if (id == 191 && l >= 12) {               // VHT Capabilities
            c->has_vht = 1;
            c->vht_cap_info = b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24;
            c->vht_rx_map = b[4] | b[5] << 8;
        } else if (id == 192 && l >= 5) {                // VHT Operation
            c->vht_width = b[0]; c->vht_seg0 = b[1]; c->vht_seg1 = b[2];
        } else if (id == 221 && l >= 7 && !memcmp(b, "\x00\x50\xf2\x02", 4)) {
            c->wmm = 1;
        }
        p += 2 + l;
    }
}

// Highest MCS 0-7 the AP receives from the HT bitmap (contiguous from 0), -1 if none.
static int ht_top(const ap_caps_t *c)
{
    int t = -1;
    for (int i = 0; i < 8 && (c->ht_mcs_rx[0] >> i & 1); i++) t = i;
    return t;
}

void caps_plan(const ap_caps_t *c, int channel, int max_bw, int legacy, int allow_vht, tx_plan_t *p)
{
    memset(p, 0, sizeof *p);
    p->center = channel;
    if (legacy || !c->has_ht || ht_top(c) < 0) return;
    p->mode = MODE_HT;
    p->max_mcs = ht_top(c);
    int can40 = c->ht_sta_width && (c->ht_sec_off == 1 || c->ht_sec_off == 3) && (c->ht_cap_info & 2) && max_bw >= 1;
    if (can40) { p->bw = 1; p->sc = c->ht_sec_off; p->center = p->sc == 1 ? channel + 2 : channel - 2; }
    p->sgi = p->bw ? (c->ht_cap_info >> 6 & 1) : (c->ht_cap_info >> 5 & 1);
    int nss1 = c->vht_rx_map & 3;
    if (allow_vht && channel > 14 && c->has_vht && nss1 != 3) {
        p->mode = MODE_VHT;
        p->max_mcs = nss1 == 0 ? 7 : nss1 == 1 ? 8 : 9;
        if (c->vht_width == 1 && can40 && max_bw >= 2) {
            // 80 MHz only when the operation element's segment centre is the centre of the 80 MHz block that holds the primary
            extern int rtl_center_channel(int ch, int bw, int sc, int *idx80);
            int cch = rtl_center_channel(channel, 2, 0, NULL);
            if (cch && cch == c->vht_seg0) { p->bw = 2; p->sc = 0; p->center = cch; }
        }
        p->sgi = p->bw == 2 ? (c->vht_cap_info >> 5 & 1) : p->sgi;
    }
}

size_t caps_build_ht_cap(uint8_t *o, int bw40, int channel_2g)
{
    uint16_t ci = 0x000C | 0x0020;                       // SM power save disabled, SGI20
    if (bw40) { ci |= 0x0002 | 0x0040; if (channel_2g) ci |= 0x1000; }     // 40 MHz, SGI40, DSSS/CCK in 40 MHz (2.4 GHz)
    o[0] = 45; o[1] = 26;
    memset(o + 2, 0, 26);
    o[2] = ci; o[3] = ci >> 8;
    o[4] = 0x03;                                         // A-MPDU: max length exponent 3, no minimum spacing
    o[5] = 0xFF;                                         // RX MCS 0-7
    o[5 + 12] = 0x01;                                    // TX MCS set defined
    return 28;
}

size_t caps_build_vht_cap(uint8_t *o)
{
    uint32_t ci = 0x00000020 | (5u << 23);               // SGI80, max A-MPDU exponent 5
    o[0] = 191; o[1] = 12;
    memset(o + 2, 0, 12);
    o[2] = ci; o[3] = ci >> 8; o[4] = ci >> 16; o[5] = ci >> 24;
    o[6] = 0xFE; o[7] = 0xFF;                            // RX map: NSS1 MCS 0-9, others unsupported
    o[8] = 0xB1; o[9] = 0x01;                            // highest RX rate 433 Mbit/s
    o[10] = 0xFE; o[11] = 0xFF;
    o[12] = 0xB1; o[13] = 0x01;
    return 14;
}

size_t caps_build_wmm(uint8_t *o)
{
    static const uint8_t w[] = {221, 7, 0x00, 0x50, 0xF2, 0x02, 0x00, 0x01, 0x00};
    memcpy(o, w, sizeof w);
    return sizeof w;
}

// 1 spatial stream, 20 MHz, long guard interval, kbit/s (HT MCS0-7, VHT MCS0-8); wider channels scale by data subcarriers (52/108/234)
static const int mcs20[9] = {6500, 13000, 19500, 26000, 39000, 52000, 58500, 65000, 78000};
int caps_rate_kbps(int rate, int bw, int sgi)
{
    long v;
    if (RATE_IS_VHT(rate)) {
        int m = rate - 2000;
        if (m < 0 || m > 9 || bw < 0 || bw > 2) return 0;
        if (m == 9) { if (bw == 0) return 0; v = bw == 1 ? 180000 : 390000; }      // MCS9 is not defined for 20 MHz 1SS
        else v = (long)mcs20[m] * (bw == 0 ? 52 : bw == 1 ? 108 : 234) / 52;
    } else if (RATE_IS_HT(rate)) {
        int m = rate - 1000;
        if (m < 0 || m > 7 || bw < 0 || bw > 1) return 0;
        v = (long)mcs20[m] * (bw == 0 ? 52 : 108) / 52;
    } else return rate * 100;
    return (int)(sgi ? v * 10 / 9 : v);
}

const char *caps_rate_str(int rate, char *b, size_t n)
{
    if (RATE_IS_VHT(rate)) snprintf(b, n, "VHT%d", rate - 2000);
    else if (RATE_IS_HT(rate)) snprintf(b, n, "MCS%d", rate - 1000);
    else snprintf(b, n, rate % 10 ? "%d.%dM" : "%dM", rate % 10 ? rate / 10 : rate / 10, rate % 10 ? rate % 10 : 0);
    return b;
}
