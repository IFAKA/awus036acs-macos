// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Host test for phy.c / tables.c with a fake register backend (no USB device needed).
// Build + run (from the project root):
//   cc -O2 -Wall -I src $(pkg-config --cflags libusb-1.0) -o /tmp/test_phy src/test_phy.c src/phy.c src/mac.c src/tables.c $(pkg-config --libs libusb-1.0) && /tmp/test_phy
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "rtl.h"
#include "phy.h"
#include "tables.h"

// ---- fake backend: 64 KiB register file, 32-bit aligned model, write log ----
typedef struct { uint16_t addr; uint8_t width; uint32_t val; } wlog_t;
static uint8_t regs[0x10000];
static wlog_t *wlog; static size_t nlog, caplog;
static void logw(uint16_t a, int w, uint32_t v)
{
    if (nlog == caplog) { caplog = caplog ? caplog * 2 : 4096; wlog = realloc(wlog, caplog * sizeof *wlog); }
    wlog[nlog++] = (wlog_t){a, (uint8_t)w, v};
}
uint8_t  rtl_r8 (rtl_t *r, uint16_t a) { (void)r; return regs[a]; }
uint16_t rtl_r16(rtl_t *r, uint16_t a) { (void)r; return (uint16_t)(regs[a] | regs[a + 1] << 8); }
static uint32_t rf_a[256];   // fake RF path A registers behind the 0xC90 / 0x8B0 serial interface
uint32_t rtl_r32(rtl_t *r, uint16_t a)
{
    (void)r;
    if (a == 0xD04 || a == 0xD08) return rf_a[regs[0x8B0]];   // read-back of the address selected in 0x8B0[7:0]
    uint32_t v; memcpy(&v, &regs[a], 4); return v; }
int rtl_w8 (rtl_t *r, uint16_t a, uint8_t v)  { (void)r; regs[a] = v; logw(a, 1, v); return 0; }
int rtl_w16(rtl_t *r, uint16_t a, uint16_t v) { (void)r; memcpy(&regs[a], &v, 2); logw(a, 2, v); return 0; }
int rtl_w32(rtl_t *r, uint16_t a, uint32_t v)
{
    (void)r;
    if (a == 0xC90) rf_a[(v >> 20) & 0xFF] = v & 0xFFFFF;
    memcpy(&regs[a], &v, 4); logw(a, 4, v); return 0; }

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

typedef struct { long n_delay; } cnt_t;
static int emit_count(void *c, uint32_t a, uint32_t d) { (void)d; if (a >= 0xF9 && a <= 0xFE) ((cnt_t *)c)->n_delay++; return 0; }

// Expected counts, derived BY HAND (see report): USB interface (cond 0x200), board type 0, no ext PA/LNA.
//   MAC: 98 entries, no conditions.            BB: 172 entries, no conditions.
//   AGC: 64 common + 58 (ELSE: the 0x20C / 0x40C branches need board bits) + 8 after ENDIF = 130.
//   RF A: 9 common + one body per condition block: where an "EIF 0x...200" exists it matches (USB, board 0),
//         otherwise the ELSE body; plus the tail 102 after the last ENDIF.  Total 279 (see hand tally in the report).
static const long EXPECT[4] = {98, 172, 130, 279};

int main(void)
{
    const uint32_t *tabs[4] = {rtl_tab_mac, rtl_tab_bb, rtl_tab_agc, rtl_tab_rf_a};
    const size_t lens[4] = {rtl_tab_mac_len, rtl_tab_bb_len, rtl_tab_agc_len, rtl_tab_rf_a_len};
    const char *names[4] = {"MAC", "BB", "AGC", "RF_A"};
    for (int cut = 0; cut < 2; cut++)
        for (int t = 0; t < 4; t++) {
            cnt_t c = {0}; long m = 0;
            long n = rtl_cfg_walk(tabs[t], lens[t], (uint8_t)cut, emit_count, &c, &m);
            printf("cut %c %-5s: table words %4zu, cond markers %3ld, writes %4ld (of which delay codes %ld)\n",
                   'A' + cut, names[t], lens[t], m, n, c.n_delay);
            CHECK(n == EXPECT[t]);
        }
    size_t npg; (void)rtl_phy_pg(&npg);
    printf("PG table: %zu entries\n", npg);
    CHECK(npg == 15);

    // full init on the fake device, both cuts
    for (int cut = 0; cut < 2; cut++) {
        memset(regs, 0, sizeof regs); nlog = 0;
        regs[0x454] = 0x00;
        rtl_t r; memset(&r, 0, sizeof r); r.cut = (uint8_t)cut;
        int rc = rtl_init_phy(&r);
        printf("rtl_init_phy cut %c: rc=%d, register writes logged=%zu\n", 'A' + cut, rc, nlog);
        CHECK(rc == 0);
        CHECK(regs[0x100] & 0xC0);                           // MAC TX/RX enabled
        CHECK((rtl_r8(&r, 0x454) & 0x80) == 0);              // 2.4 GHz
        // RF 0x18 on the last LSSI write must carry channel 1
        uint32_t last18 = 0; int found = 0;
        for (size_t i = 0; i < nlog; i++)
            if (wlog[i].addr == 0xC90 && ((wlog[i].val >> 20) & 0xFF) == 0x18) { last18 = wlog[i].val & 0xFFFFF; found = 1; }
        CHECK(found && (last18 & 0xFF) == 1);
    }
    // 5 GHz channel switch flips band bit and sets RF 0x18 channel
    {
        rtl_t r; memset(&r, 0, sizeof r);
        nlog = 0;
        CHECK(rtl_set_channel(&r, 36, 1) == 0);
        CHECK((rtl_r8(&r, 0x454) & 0x80) != 0);
        uint32_t last18 = 0;
        for (size_t i = 0; i < nlog; i++)
            if (wlog[i].addr == 0xC90 && ((wlog[i].val >> 20) & 0xFF) == 0x18) last18 = wlog[i].val & 0xFFFFF;
        CHECK((last18 & 0xFF) == 36);
        CHECK(rtl_set_channel(&r, 0, 1) < 0);
        CHECK(rtl_set_channel(&r, 15, 1) < 0);
        CHECK(rtl_set_channel(&r, 6, 0) < 0);
    }
    // width: centre channels and register fields
    {
        int ix = -1;
        CHECK(rtl_center_channel(6, 0, 0, NULL) == 6);
        CHECK(rtl_center_channel(36, 1, 1, NULL) == 38 && rtl_center_channel(40, 1, 3, NULL) == 38);
        CHECK(rtl_center_channel(1, 1, 0, NULL) == 0);
        CHECK(rtl_center_channel(36, 2, 0, &ix) == 42 && ix == 0);
        CHECK(rtl_center_channel(48, 2, 0, &ix) == 42 && ix == 3);
        CHECK(rtl_center_channel(132, 2, 0, &ix) == 138 && ix == 0);
        CHECK(rtl_center_channel(144, 2, 0, &ix) == 138 && ix == 3);
        CHECK(rtl_center_channel(149, 2, 0, &ix) == 155 && ix == 0);
        CHECK(rtl_center_channel(165, 2, 0, &ix) == 171);
        CHECK(rtl_center_channel(6, 2, 0, &ix) == 0 && rtl_center_channel(34, 2, 0, &ix) == 0 && rtl_center_channel(138, 2, 0, &ix) == 0);
        rtl_t r; memset(&r, 0, sizeof r);
        memset(regs, 0, sizeof regs);
        CHECK(rtl_set_channel_bw(&r, 132, 2, 0) == 0);
        CHECK((regs[0x668] | regs[0x669] << 8) >> 7 == 2);        // 0x668 bits 8:7 = 10 -> 80 MHz
        CHECK(regs[0x483] == (4 | (10 << 4)));                     // primary is the lowest 20 of the lower 40 of the 80
        CHECK(r.bw == 2 && r.center == 138 && r.channel == 132);
        CHECK(rtl_set_channel_bw(&r, 36, 1, 1) == 0);
        CHECK(((regs[0x668] | regs[0x669] << 8) >> 7 & 3) == 1);
        CHECK(regs[0x483] == 2 && r.center == 38);                 // secondary above: primary is the lower 20
        CHECK(rtl_set_channel_bw(&r, 6, 1, 3) == 0 && r.center == 4 && regs[0x483] == 1);
        CHECK(rtl_set_channel_bw(&r, 6, 2, 0) < 0);
        CHECK(rtl_set_channel_bw(&r, 36, 0, 0) == 0 && regs[0x483] == 0 && ((regs[0x668] | regs[0x669] << 8) >> 7 & 3) == 0);
    }
    printf(fails ? "FAILED (%d)\n" : "ALL OK\n", fails);
    return fails != 0;
}
