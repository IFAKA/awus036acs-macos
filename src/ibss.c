// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Ad-hoc (IBSS) create / join. See ibss.h. Register recipe from rtl8812au: start_create_ibss, send_beacon,
// hw_var_set_opmode (_HW_STATE_ADHOC_), ResumeTxBeacon, rtl8812_download_rsvd_page.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ibss.h"
#include "phy.h"
#include "mac.h"
#include "rx.h"
#include "tx.h"

#define REG_CR           0x0100
#define REG_HISR0        0x00B4
#define REG_TDECTRL      0x0208
#define REG_FWHW_TXQ     0x0420
#define REG_TBTT_PROHIBIT 0x0540
#define REG_BCN_CTRL     0x0550
#define REG_DUAL_TSF_RST 0x0553
#define REG_BCN_INTERVAL 0x0554
#define REG_ATIMWND      0x055A
#define REG_BCN_MAX_ERR  0x055D
#define REG_TSFTR        0x0560
#define BCN_EN_TXBCN_RPT BIT(2)
#define BCN_EN_FUNCTION  BIT(3)
#define BCN_DIS_TSF_UDT  BIT(4)
#define BCN_DIS_BCNQ_SUB BIT(1)
#define HISR_TXBCN0OK    BIT(25)
#define HISR_TXBCN0ERR   BIT(26)
#define HISR_BCNDMA0     BIT(20)
#ifndef BIT
#define BIT(n) (1u << (n))
#endif

static long now_ms(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

void ibss_random_addr(uint8_t a[6], uint32_t (*rnd)(void))
{
    for (int i = 0; i < 6; i += 2) { uint32_t v = rnd(); a[i] = (uint8_t)v; a[i + 1] = (uint8_t)(v >> 8); }
    a[0] = (uint8_t)((a[0] & 0xFC) | 0x02);     // unicast, locally administered
}

static int is_zero6(const uint8_t *a) { static const uint8_t z[6]; return !memcmp(a, z, 6); }

int ibss_build_frame(uint8_t *out, size_t cap, const ibss_t *c, int probe_resp, const uint8_t *da)
{
    static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t sl = strlen(c->ssid);
    if (sl > 32 || cap < 24 + 12 + 2 + 32 + 40) return -1;
    int n = 0;
    out[n++] = probe_resp ? 0x50 : 0x80; out[n++] = 0;
    out[n++] = 0; out[n++] = 0;
    memcpy(out + n, probe_resp && da ? da : bcast, 6); n += 6;
    memcpy(out + n, c->mac, 6); n += 6;
    memcpy(out + n, c->bssid, 6); n += 6;
    out[n++] = 0; out[n++] = 0;                                   // sequence (hardware)
    memset(out + n, 0, 8); n += 8;                                // timestamp
    out[n++] = 100; out[n++] = 0;                                 // beacon interval 100 TU
    uint16_t cap_info = 0x0002 | (c->privacy ? 0x0010 : 0);       // IBSS (ESS clear), privacy = WEP
    out[n++] = (uint8_t)cap_info; out[n++] = (uint8_t)(cap_info >> 8);
    out[n++] = 0; out[n++] = (uint8_t)sl; memcpy(out + n, c->ssid, sl); n += (int)sl;
    if (c->channel <= 14) {
        static const uint8_t r1[] = {1, 8, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};   // 1 2 5.5 11 (basic), 6 9 12 18
        memcpy(out + n, r1, sizeof r1); n += sizeof r1;
        out[n++] = 3; out[n++] = 1; out[n++] = (uint8_t)c->channel;                          // DS parameter set
    } else {
        static const uint8_t r5[] = {1, 8, 0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C}; // 6b 9 12b 18 24b 36 48 54
        memcpy(out + n, r5, sizeof r5); n += sizeof r5;
    }
    out[n++] = 6; out[n++] = 2; out[n++] = 0; out[n++] = 0;                                  // IBSS parameter set: ATIM window 0
    if (c->channel <= 14) {
        out[n++] = 42; out[n++] = 1; out[n++] = 0;                                          // ERP information
        static const uint8_t x[] = {50, 4, 0x30, 0x48, 0x60, 0x6C};                         // extended rates 24 36 48 54
        memcpy(out + n, x, sizeof x); n += sizeof x;
    }
    return n;
}

int ibss_parse(const uint8_t *f, int len, ibss_peer_t *pe)
{
    if (len < 36 || ((f[0] & 0xFC) != 0x80 && (f[0] & 0xFC) != 0x50)) return 0;
    uint16_t cap = (uint16_t)(f[34] | f[35] << 8);
    if ((cap & 0x0003) != 0x0002) return 0;
    memset(pe, 0, sizeof *pe);
    memcpy(pe->src, f + 10, 6); memcpy(pe->bssid, f + 16, 6);
    pe->privacy = !!(cap & 0x0010);
    int i = 36, got = 0;
    while (i + 2 <= len) {
        int id = f[i], l = f[i + 1];
        if (i + 2 + l > len) break;
        if (id == 0 && l <= 32) { memcpy(pe->ssid, f + i + 2, (size_t)l); pe->ssid[l] = 0; got = 1; }
        else if (id == 3 && l == 1) pe->channel = f[i + 2];
        i += 2 + l;
    }
    return got;
}

int ibss_probe_req_for(const uint8_t *f, int len, const char *ssid)
{
    if (len < 26 || (f[0] & 0xFC) != 0x40) return 0;
    if (f[24] != 0 || 26 + f[25] > len) return 0;
    return f[25] == 0 || (f[25] == strlen(ssid) && !memcmp(f + 26, ssid, f[25]));
}

void ibss_note(ibss_t *c, const ibss_peer_t *pe)
{
    for (int i = 0; i < c->npeers; i++)
        if (!memcmp(c->peers[i].bssid, pe->bssid, 6) && !strcmp(c->peers[i].ssid, pe->ssid)) { c->peers[i] = *pe; return; }
    if (c->npeers < IBSS_MAX_PEERS) c->peers[c->npeers++] = *pe;
}

// ---------------------------------------------------------------- radio
static uint32_t rnd32(void) { return arc4random(); }

static int set_msr(rtl_t *r, unsigned type) { return rtl_w32(r, REG_CR, (rtl_r32(r, REG_CR) & ~0x30000u) | (type << 16)); }

int ibss_start(rtl_t *r, ibss_t *c, char *err, size_t en)
{
    #define FAIL(...) do { snprintf(err, en, __VA_ARGS__); return -1; } while (0)
    if (!c->ssid[0] || strlen(c->ssid) > 32) FAIL("bad ssid");
    if (c->channel < 1 || c->channel > 165) FAIL("bad channel");
    if (is_zero6(c->mac)) ibss_random_addr(c->mac, rnd32);
    if (!c->join) ibss_random_addr(c->bssid, rnd32);
    else if (is_zero6(c->bssid)) FAIL("join needs the BSSID of the network");
    if (rtl_set_channel(r, c->channel, 1)) FAIL("channel %d: radio refused", c->channel);
    if (rtl_set_sta_addr(r, c->mac, c->bssid)) FAIL("cannot program address");
    if (set_msr(r, 1)) FAIL("cannot set ad-hoc network type");
    int n = ibss_build_frame(c->bcn, sizeof c->bcn, c, 0, NULL);
    if (n < 0) FAIL("beacon does not fit");
    c->bcn_len = n;
    int rate = c->channel <= 14 ? 10 : 60;
    // beacon timing, as SetBeaconRelatedRegisters8812A
    int e = 0;
    e |= rtl_w16(r, REG_BCN_INTERVAL, 100);
    e |= rtl_w8(r, REG_ATIMWND, 0x02);
    e |= rtl_w8(r, REG_BCN_MAX_ERR, 0xFF);
    if (!c->join) e |= rtl_w8(r, REG_DUAL_TSF_RST, BIT(0));         // new network: our TSF starts at 0
    if (e) FAIL("beacon timing registers failed");
    // download the beacon into the beacon page (rtl8812_download_rsvd_page recipe)
    e |= rtl_w8(r, REG_CR + 1, rtl_r8(r, REG_CR + 1) | BIT(0));      // ENSWBCN: the host writes the beacon
    uint8_t bc = rtl_r8(r, REG_BCN_CTRL);
    e |= rtl_w8(r, REG_BCN_CTRL, (uint8_t)((bc & ~BCN_EN_FUNCTION) | BCN_DIS_TSF_UDT));
    e |= rtl_w8(r, REG_FWHW_TXQ + 2, rtl_r8(r, REG_FWHW_TXQ + 2) | BIT(6));    // a live beacon (rsvd-page downloads clear this)
    int valid = 0;
    for (int tries = 0; tries < 10 && !valid && !e; tries++) {
        e |= rtl_w8(r, REG_TDECTRL + 2, rtl_r8(r, REG_TDECTRL + 2) | BIT(0));  // clear BCN_VALID (write 1)
        if (rtl_tx_beacon(r, c->bcn, n, rate)) { snprintf(err, en, "beacon download: USB transmit failed"); e = 1; break; }
        for (int p = 0; p < 20 && !valid; p++) { valid = rtl_r8(r, REG_TDECTRL + 2) & BIT(0); if (!valid) { struct timespec ts = {0, 2000000}; nanosleep(&ts, NULL); } }
    }
    e |= rtl_w8(r, REG_CR + 1, rtl_r8(r, REG_CR + 1) & ~BIT(0));
    if (e && !valid) { if (!err[0]) snprintf(err, en, "beacon download failed"); return -1; }
    if (!valid) FAIL("chip did not take the beacon (BCN_VALID never set)");
    uint8_t ctl = (uint8_t)(BCN_EN_FUNCTION | BCN_DIS_BCNQ_SUB | BCN_EN_TXBCN_RPT | (c->join ? 0 : BCN_DIS_TSF_UDT));
    e |= rtl_w8(r, REG_BCN_CTRL, ctl);
    // ResumeTxBeacon: beacon queue live, TBTT hold time
    e |= rtl_w8(r, REG_FWHW_TXQ + 2, rtl_r8(r, REG_FWHW_TXQ + 2) | BIT(6));
    e |= rtl_w8(r, REG_TBTT_PROHIBIT + 1, 0x80);       // TBTT_PROHIBIT_HOLD_TIME: 4 ms in 32 us units
    e |= rtl_w8(r, REG_TBTT_PROHIBIT + 2, (uint8_t)((rtl_r8(r, REG_TBTT_PROHIBIT + 2) & 0xF0) | 0));
    e |= rtl_w32(r, REG_HISR0, 0xFFFFFFFFu);
    if (e) FAIL("could not start the beacon engine");
    c->on = 1; c->started_ms = now_ms();
    c->beacons_ok = c->beacons_err = c->beacons_dma = c->probe_resp = c->probe_req = c->bcn_heard = 0; c->npeers = 0;
    return 0;
    #undef FAIL
}

void ibss_stop(rtl_t *r, ibss_t *c)
{
    if (!c->on) return;
    rtl_w8(r, REG_FWHW_TXQ + 2, rtl_r8(r, REG_FWHW_TXQ + 2) & ~BIT(6));
    rtl_w16(r, REG_BCN_CTRL, 0x1010);                   // back to the init value
    set_msr(r, 0);
    rtl_set_sta_addr(r, c->mac, NULL);
    set_msr(r, 0);
    c->on = 0;
}

typedef struct { ibss_t *c; rtl_t *r; int seen; } tick_t;

static void on_frame(void *ud, const rtl_frame_t *f)
{
    tick_t *t = ud; ibss_t *c = t->c;
    int len = f->has_fcs ? f->len - 4 : f->len;
    if (len < 24 || f->crc_err) return;
    t->seen++;
    const uint8_t *d = f->data;
    if (ibss_probe_req_for(d, len, c->ssid)) {
        if (c->no_probe_resp) return;
        c->probe_req++;
        uint8_t pr[256];
        int n = ibss_build_frame(pr, sizeof pr, c, 1, d + 10);
        if (n > 0) {
            uint32_t lo = rtl_r32(t->r, REG_TSFTR), hi = rtl_r32(t->r, REG_TSFTR + 4);
            for (int i = 0; i < 4; i++) { pr[24 + i] = (uint8_t)(lo >> (8 * i)); pr[28 + i] = (uint8_t)(hi >> (8 * i)); }
            if (!rtl_tx_frame(t->r, pr, n, c->channel <= 14 ? 10 : 60, 7)) c->probe_resp++;
        }
        return;
    }
    ibss_peer_t pe;
    if (ibss_parse(d, len, &pe)) {
        if (!memcmp(pe.bssid, c->bssid, 6) && memcmp(pe.src, c->mac, 6)) c->bcn_heard++;
        pe.rssi = f->rssi_valid ? f->rssi_dbm : 0; pe.last_ms = now_ms();
        if (!pe.channel) pe.channel = f->channel;
        ibss_note(c, &pe);
    }
}

int ibss_tick(rtl_t *r, ibss_t *c, int ms)
{
    tick_t t = { c, r, 0 };
    long end = now_ms() + ms;
    do {
        long left = end - now_ms();
        int rc = rtl_rx_poll(r, on_frame, &t, left > 50 ? 50 : (int)(left < 1 ? 1 : left));
        if (rc < 0) return rc;
        if (c->on) {                                     // one TXBCN-OK bit per beacon the chip put on the air
            uint32_t h = rtl_r32(r, REG_HISR0);
            if (h & (HISR_TXBCN0OK | HISR_TXBCN0ERR | HISR_BCNDMA0)) {
                c->beacons_ok += !!(h & HISR_TXBCN0OK); c->beacons_err += !!(h & HISR_TXBCN0ERR); c->beacons_dma += !!(h & HISR_BCNDMA0);
                rtl_w32(r, REG_HISR0, h & (HISR_TXBCN0OK | HISR_TXBCN0ERR | HISR_BCNDMA0));
            }
        }
    } while (now_ms() < end);
    return t.seen;
}

typedef struct { const char *ssid; ibss_peer_t pe; int found; } find_t;
static void on_find(void *ud, const rtl_frame_t *f)
{
    find_t *s = ud;
    int len = f->has_fcs ? f->len - 4 : f->len;
    ibss_peer_t pe;
    if (s->found || f->crc_err || !ibss_parse(f->data, len, &pe)) return;
    if (s->ssid && strcmp(s->ssid, pe.ssid)) return;
    s->pe = pe; s->found = 1;
    if (!s->pe.channel) s->pe.channel = f->channel;
    s->pe.rssi = f->rssi_valid ? f->rssi_dbm : 0;
}

int ibss_find(rtl_t *r, int channel, const char *ssid, int ms, ibss_peer_t *pe)
{
    if (rtl_set_channel(r, channel, 1)) return -1;
    find_t s = { ssid, {{0}}, 0 };
    long end = now_ms() + ms;
    while (!s.found && now_ms() < end) { if (rtl_rx_poll(r, on_find, &s, 50) < 0) return -1; }
    if (s.found) *pe = s.pe;
    return s.found;
}
