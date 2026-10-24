// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos. Unit test for caps.c (HT/VHT element parsing, transmit plan, our elements, rate codes).
#include <stdio.h>
#include <string.h>
#include "caps.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

// stand-in for phy.c: only the 80 MHz block of channel 132-144 matters here
int rtl_center_channel(int ch, int bw, int sc, int *idx80) { (void)sc; if (idx80) *idx80 = 0; return bw == 2 && ch >= 132 && ch <= 144 ? 138 : 0; }

int main(void)
{
    uint8_t ie[256]; size_t n = 0;
    ie[n++] = 0; ie[n++] = 3; memcpy(ie + n, "abc", 3); n += 3;
    n += caps_build_ht_cap(ie + n, 1, 0);                       // our own HT cap element is a valid AP element too
    ie[n++] = 61; ie[n++] = 22; memset(ie + n, 0, 22); ie[n] = 132; ie[n + 1] = 0x05; n += 22;     // primary 132, secondary above, any width
    n += caps_build_vht_cap(ie + n);
    ie[n++] = 192; ie[n++] = 5; ie[n++] = 1; ie[n++] = 138; ie[n++] = 0; ie[n++] = 0; ie[n++] = 0;  // 80 MHz, segment centre 138
    n += caps_build_wmm(ie + n);
    ap_caps_t c; caps_parse(ie, n, &c);
    CHECK(c.has_ht && c.has_vht && c.wmm);
    CHECK(c.ht_cap_info & 2); CHECK(c.ht_mcs_rx[0] == 0xFF);
    CHECK(c.ht_primary == 132 && c.ht_sec_off == 1 && c.ht_sta_width == 1);
    CHECK((c.vht_rx_map & 3) == 2 && c.vht_width == 1 && c.vht_seg0 == 138);

    tx_plan_t p;
    caps_plan(&c, 132, 2, 0, 1, &p);
    CHECK(p.mode == MODE_VHT && p.bw == 2 && p.center == 138 && p.max_mcs == 9);
    caps_plan(&c, 132, 2, 0, 0, &p);                             // VHT not allowed: HT 40 MHz above
    CHECK(p.mode == MODE_HT && p.bw == 1 && p.sc == 1 && p.center == 134 && p.max_mcs == 7 && p.sgi == 1);
    caps_plan(&c, 132, 0, 0, 0, &p);                             // capped to 20 MHz
    CHECK(p.mode == MODE_HT && p.bw == 0 && p.center == 132);
    caps_plan(&c, 132, 2, 1, 1, &p);                             // legacy forced
    CHECK(p.mode == MODE_LEGACY && p.bw == 0 && p.center == 132);
    c.ht_sec_off = 3; caps_plan(&c, 132, 1, 0, 0, &p);
    CHECK(p.bw == 1 && p.sc == 3 && p.center == 130);
    c.ht_sta_width = 0; caps_plan(&c, 132, 2, 0, 0, &p);         // BSS runs 20 MHz
    CHECK(p.bw == 0);
    ap_caps_t none; caps_parse(ie, 5, &none);                    // only an SSID element
    CHECK(!none.has_ht); caps_plan(&none, 6, 2, 0, 1, &p); CHECK(p.mode == MODE_LEGACY);
    uint8_t trunc[4] = {45, 26, 0, 0}; caps_parse(trunc, sizeof trunc, &none); CHECK(!none.has_ht);   // truncated element ignored

    CHECK(caps_rate_kbps(RATE_HT(7), 0, 0) == 65000);
    CHECK(caps_rate_kbps(RATE_HT(7), 1, 1) == 150000);
    CHECK(caps_rate_kbps(RATE_VHT(9), 2, 1) == 433333);
    CHECK(caps_rate_kbps(60, 0, 0) == 6000);
    char b[16];
    CHECK(!strcmp(caps_rate_str(RATE_HT(3), b, sizeof b), "MCS3"));
    CHECK(!strcmp(caps_rate_str(RATE_VHT(9), b, sizeof b), "VHT9"));
    CHECK(!strcmp(caps_rate_str(60, b, sizeof b), "6M"));
    CHECK(!strcmp(caps_rate_str(55, b, sizeof b), "5.5M"));
    printf(fails ? "test_caps FAILED\n" : "test_caps OK\n");
    return fails != 0;
}
