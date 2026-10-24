// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sta.h"
#include "mac.h"
#include "phy.h"
#include "tx.h"
#include "wep.h"

static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }

void sta_init(sta_t *s, rtl_t *r, const char *ssid, const uint8_t *bssid, int channel)
{
    memset(s, 0, sizeof *s);
    s->r = r;
    snprintf(s->ssid, sizeof s->ssid, "%s", ssid ? ssid : "");
    if (bssid) { memcpy(s->bssid, bssid, 6); s->have_bssid = 1; }
    s->channel = channel;
    s->rate = channel > 14 ? 60 : 10;
    s->eapol_keyinfo = -1;
    s->last_status = -1;
    s->mac[0] = 0x02;
    for (int i = 1; i < 6; i++) s->mac[i] = rand() & 0xFF;
    rtl_set_sta_addr(r, s->mac, s->have_bssid ? s->bssid : NULL);
}

static void put_hdr(uint8_t *f, uint8_t fc0, const uint8_t *a1, const uint8_t *a2, const uint8_t *a3)
{
    memset(f, 0, 24);
    f[0] = fc0;
    memcpy(f + 4, a1, 6); memcpy(f + 10, a2, 6); memcpy(f + 16, a3, 6);
}

int sta_is_dfs(int ch) { return ch >= 52 && ch <= 144; }

int sta_set_channel(sta_t *s, int ch)
{
    int rc = rtl_set_channel(s->r, ch, 1);
    if (rc) return rc;
    s->channel = ch;
    s->rate = ch > 14 ? 60 : 10;            // management rate: 6 Mbps OFDM on 5 GHz (CCK does not exist there), 1 Mbps CCK on 2.4 GHz
    s->beacon_ms = 0;                       // a beacon heard on another channel proves nothing here
    return 0;
}

// ---- RX handling ----
typedef struct { sta_t *s; sta_data_cb cb; void *ud; } rxctx_t;

static void parse_ies(sta_t *s, const uint8_t *p, const uint8_t *end)
{
    while (p + 2 <= end && p + 2 + p[1] <= end) {
        int n = p[1];
        if (p[0] == 1 && n <= 16) { memcpy(s->rates, p + 2, n); s->nrates = n; }
        else if (p[0] == 50 && n <= 16) { memcpy(s->xrates, p + 2, n); s->nxrates = n; }
        else if (p[0] == 48 && n + 2 <= (int)sizeof s->rsn) { memcpy(s->rsn, p, n + 2); s->rsn_len = n + 2; }
        else if (p[0] == 221 && n >= 4 && !memcmp(p + 2, "\x00\x50\xf2\x01", 4) && n + 2 <= (int)sizeof s->wpa_ie) { memcpy(s->wpa_ie, p, n + 2); s->wpa_ie_len = n + 2; }
        p += 2 + n;
    }
}

static void on_frame(void *ud, const rtl_frame_t *f)
{
    rxctx_t *x = ud;
    sta_t *s = x->s;
    if (f->crc_err || !f->has_fcs || f->len < 24 + 4) return;
    const uint8_t *d = f->data;
    int len = f->len - 4;                   // strip FCS
    int type = (d[0] >> 2) & 3, sub = d[0] >> 4;
    const uint8_t *a1 = d + 4, *a2 = d + 10;
    if (s->have_bssid && !memcmp(a2, s->bssid, 6) && (type == 0 || type == 2)) {      // anything transmitted by our AP
        s->last_rx_ms = now_ms(); s->rx_ap_frames++;
        if (f->rssi_valid) { s->rssi_avg = s->rssi_n ? (s->rssi_avg * 7 + f->rssi_dbm - 4) / 8 : f->rssi_dbm; s->rssi_n++; }
        s->rx_rate = f->rate;
    }
    if (type == 0) {
        int tome = !memcmp(a1, s->mac, 6);
        int frombss = s->have_bssid && !memcmp(a2, s->bssid, 6);
        if ((sub == 5 || sub == 8) && len >= 36) {          // probe resp / beacon
            const uint8_t *ie = d + 36, *end = d + len;
            char ss[33] = ""; const uint8_t *p = ie; int have_ssid = 0, ssid_len = 0;
            while (p + 2 <= end && p + 2 + p[1] <= end) {
                if (p[0] == 0 && p[1] <= 32) { memcpy(ss, p + 2, p[1]); ss[p[1]] = 0; ssid_len = p[1]; have_ssid = 1; break; }
                p += 2 + p[1];
            }
            if (!have_ssid) return;
            if (s->have_bssid && !frombss) return;
            int match = !strcmp(ss, s->ssid);
            if (s->hidden) {
                // a hidden network's Beacons carry an empty or zeroed SSID: believe them only from a BSSID we were told;
                // otherwise only a Probe Response addressed to us (it carries the real SSID) counts.
                int blank = ssid_len == 0 || ss[0] == 0;
                if (blank) match = s->have_bssid && frombss;
                else if (sub == 8 && !s->have_bssid) match = 0;
                else if (sub == 5 && !tome && !s->have_bssid) match = 0;
            }
            if (!match) return;
            if (!s->have_bssid) { memcpy(s->bssid, a2, 6); s->have_bssid = 1; rtl_set_sta_addr(s->r, s->mac, s->bssid); }
            s->ap_cap = d[34] | d[35] << 8;
            s->rssi = f->rssi_dbm;
            s->nrates = s->nxrates = 0; s->rsn_len = s->wpa_ie_len = 0;
            parse_ies(s, ie, end);
            s->ies_len = (int)(end - ie) < (int)sizeof s->ies ? (int)(end - ie) : (int)sizeof s->ies;
            memcpy(s->ies, ie, s->ies_len);
            s->ap_seen = 1;
            if (sub == 8) s->beacon_ms = now_ms();
        } else if (sub == 11 && tome && frombss && len >= 30) {   // auth (transaction 2 or 4)
            s->auth_rx_algo = d[24] | d[25] << 8;
            s->auth_status = d[28] | d[29] << 8;
            s->challenge_len = 0;
            if (len >= 32 + 128 && d[30] == 16 && d[31] == 128) { memcpy(s->challenge, d + 32, 128); s->challenge_len = 128; }
            s->auth_got = d[26] | d[27] << 8;
        } else if (sub == 1 && tome && frombss && len >= 30) {    // assoc response
            s->assoc_status = d[26] | d[27] << 8;
            s->aid = (d[28] | d[29] << 8) & 0x3FFF;
            s->assoc_got = 1;
        } else if ((sub == 12 || sub == 10) && frombss && len >= 26 && (tome || (a1[0] & 1))) {   // deauth / disassoc
            int reason = d[24] | d[25] << 8;
            if (sub == 12) { s->deauth_seen++; s->deauth_reason = reason; }
            else { s->disassoc_seen++; s->disassoc_reason = reason; }
            s->associated = 0;
        }
        return;
    }
    if (type != 2 || !s->have_bssid) return;
    // data: from-DS only (byte1 & 3 == 2); addr1 = DA, addr2 = BSSID
    if ((d[1] & 3) != 2 || memcmp(a2, s->bssid, 6)) return;
    int group = a1[0] & 1;
    if (!group && memcmp(a1, s->mac, 6)) return;
    int qos = sub & 8, hl = 24 + (qos ? 2 : 0) + ((d[1] & 0x80) ? 4 : 0);
    if (len < hl) return;
    if (sub & 4) return;                    // null / qos-null: no payload
    s->data_rx++;
    if (group) s->group_rx++;
    if (d[1] & 0x40) {
        s->prot_rx++;
        if (len >= hl + 8 && (d[hl + 3] & 0x20)) s->prot_extiv++;
    } else if (len >= hl + 8 + 7 && !memcmp(d + hl, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8)) {
        const uint8_t *e = d + hl + 8;     // EAPOL: ver, type, len(2), key descr type, key info (BE)
        if (e[1] == 3) { s->eapol_rx++; s->eapol_keyinfo = e[6] << 8 | e[7]; }
    }
    if (x->cb) x->cb(x->ud, d, len, f);
}

void sta_poll(sta_t *s, int ms, sta_data_cb cb, void *ud)
{
    rxctx_t x = { s, cb ? cb : s->def_cb, cb ? ud : s->def_ud };
    long end = now_ms() + ms;
    do {
        long left = end - now_ms();
        if (left < 1) left = 1;
        s->in_rx++;
        int rc = rtl_rx_poll(s->r, on_frame, &x, left > 30 ? 30 : (int)left);
        s->in_rx--;
        if (rc < 0) break;
    } while (now_ms() < end);
}

// DFS transmit rule (the regulatory "no transmission before the channel is known to be in use by an AP" idea, applied to a
// client): on channels 52-144 this station sends NOTHING unless a Beacon from the AP we are talking to was received within
// the last DFS_BEACON_MS. Radar detection is not implemented here, so we only ever follow an AP that is already beaconing
// there. When called from the join steps (scan/auth/assoc, not from an RX callback and not yet associated) the gate may wait
// up to DFS_WAIT_MS listening for that beacon; everywhere else (inside RX callbacks, after association) it only checks,
// because polling there would re-enter the receive path. Returns 0 = may transmit, 3 = refused (counted in dfs_refused).
#define DFS_BEACON_MS 1000
#define DFS_WAIT_MS   1500
static int tx_gate(sta_t *s, int may_poll)
{
    if (!sta_is_dfs(s->channel)) return 0;
    if (s->beacon_ms && now_ms() - s->beacon_ms <= DFS_BEACON_MS) return 0;
    if (may_poll && !s->in_rx && !s->associated) {
        long end = now_ms() + DFS_WAIT_MS;
        while (now_ms() < end) {
            sta_poll(s, 50, NULL, NULL);
            if (s->beacon_ms && now_ms() - s->beacon_ms <= DFS_BEACON_MS) return 0;
        }
    }
    s->dfs_refused++;
    return 3;
}

static int tx_mgmt(sta_t *s, const uint8_t *fr, int n, int rate, int retries, int may_poll)
{
    int g = tx_gate(s, may_poll);
    if (g) return g;
    return rtl_tx_frame(s->r, fr, n, rate, retries) ? 2 : 0;
}

// ---- management exchanges ----
int sta_scan(sta_t *s, int timeout_ms)
{
    uint8_t fr[128];
    static const uint8_t bc[6] = {255, 255, 255, 255, 255, 255};
    put_hdr(fr, 0x40, s->have_bssid ? s->bssid : bc, s->mac, s->have_bssid ? s->bssid : bc);
    int n = 24, sl = strlen(s->ssid);
    fr[n++] = 0; fr[n++] = sl; memcpy(fr + n, s->ssid, sl); n += sl;
    static const uint8_t sr[] = {1, 4, 0x82, 0x84, 0x8b, 0x96};
    static const uint8_t er[] = {50, 8, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c};
    static const uint8_t sr5[] = {1, 8, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c};     // 5 GHz: OFDM rates only
    if (s->channel > 14) { memcpy(fr + n, sr5, sizeof sr5); n += sizeof sr5; }
    else { memcpy(fr + n, sr, sizeof sr); n += sizeof sr; memcpy(fr + n, er, sizeof er); n += sizeof er; }
    long end = now_ms() + timeout_ms;
    s->dfs_refused = 0;
    while (now_ms() < end && !s->ap_seen) {
        // On a DFS channel this stays passive (no probe) until the AP's Beacon was heard, see tx_gate.
        int rc = tx_mgmt(s, fr, n, s->rate, 3, 0);
        if (rc && rc != 3) return 2;
        sta_poll(s, 250, NULL, NULL);
    }
    return s->ap_seen ? 0 : 1;
}

// Wait for transaction `seq` of our auth exchange (an error status from the AP, e.g. 13 = algorithm not supported, is accepted
// for any algorithm number: some APs echo 0, some 1).
static int auth_reply_ok(const sta_t *s, int seq) { return s->auth_got == seq && (s->auth_rx_algo == s->auth_algo || s->auth_status != 0); }

static int sta_auth_shared(sta_t *s)
{
    uint8_t fr[24 + 4 + 6 + 2 + 128 + 4 + 8];
    uint8_t one[30], body[6 + 2 + 128];
    put_hdr(one, 0xB0, s->bssid, s->mac, s->bssid);
    one[24] = 1; one[25] = 0; one[26] = 1; one[27] = 0; one[28] = one[29] = 0;
    s->auth_got = 0;
    for (int a = 0; a < 5 && !auth_reply_ok(s, 2); a++) {
        if (tx_mgmt(s, one, sizeof one, s->rate, 7, 1) == 2) return 2;
        sta_poll(s, 300, NULL, NULL);
    }
    if (!auth_reply_ok(s, 2)) { s->last_status = -1; return 1; }
    s->last_status = s->auth_status;
    if (s->auth_status != 0) return 1;
    if (s->challenge_len != 128) { s->last_status = 15; return 1; }          // no challenge text: treat as challenge failure
    body[0] = 1; body[1] = 0; body[2] = 3; body[3] = 0; body[4] = body[5] = 0; body[6] = 16; body[7] = 128;
    memcpy(body + 8, s->challenge, 128);
    put_hdr(fr, 0xB0, s->bssid, s->mac, s->bssid);
    fr[1] = 0x40;                                                            // Protected Frame: the body is WEP encrypted
    uint8_t iv[3]; wep_next_iv(&s->wep_iv, iv);
    int n = wep_encrypt(s->wep_key, s->wep_key_len, s->wep_keyid, iv, body, sizeof body, fr + 24);
    if (n < 0) return 2;
    s->auth_got = 0;
    for (int a = 0; a < 5 && !auth_reply_ok(s, 4); a++) {
        if (tx_mgmt(s, fr, 24 + n, s->rate, 7, 1) == 2) return 2;
        sta_poll(s, 300, NULL, NULL);
    }
    if (!auth_reply_ok(s, 4)) { s->last_status = -1; return 1; }
    s->last_status = s->auth_status;
    return s->auth_status != 0;
}

int sta_auth(sta_t *s)
{
    uint8_t fr[30];
    if (s->auth_algo == 1) return sta_auth_shared(s);
    put_hdr(fr, 0xB0, s->bssid, s->mac, s->bssid);
    fr[24] = fr[25] = 0; fr[26] = 1; fr[27] = 0; fr[28] = fr[29] = 0;
    s->auth_got = 0;
    for (int a = 0; a < 5 && !auth_reply_ok(s, 2); a++) {
        if (tx_mgmt(s, fr, sizeof fr, s->rate, 7, 1) == 2) return 2;
        sta_poll(s, 300, NULL, NULL);
    }
    if (!auth_reply_ok(s, 2)) { s->last_status = -1; return 1; }
    s->last_status = s->auth_status;
    return s->auth_status != 0;
}

int sta_assoc(sta_t *s)
{
    uint8_t fr[256];
    put_hdr(fr, 0x00, s->bssid, s->mac, s->bssid);
    int n = 24;
    uint16_t cap = 0x0001;                              // ESS
    cap |= s->ap_cap & (0x0010 | 0x0020 | 0x0400);      // privacy, short preamble, short slot as the AP has them
    fr[n++] = cap; fr[n++] = cap >> 8;
    fr[n++] = 10; fr[n++] = 0;                          // listen interval
    int sl = strlen(s->ssid);
    fr[n++] = 0; fr[n++] = sl; memcpy(fr + n, s->ssid, sl); n += sl;
    if (s->nrates) { fr[n++] = 1; fr[n++] = s->nrates; memcpy(fr + n, s->rates, s->nrates); n += s->nrates; }
    if (s->nxrates) { fr[n++] = 50; fr[n++] = s->nxrates; memcpy(fr + n, s->xrates, s->nxrates); n += s->nxrates; }
    if (s->sec_ie_len) { memcpy(fr + n, s->sec_ie, s->sec_ie_len); n += s->sec_ie_len; }
    s->assoc_got = 0;
    for (int a = 0; a < 5 && !s->assoc_got; a++) {
        if (tx_mgmt(s, fr, n, s->rate, 7, 1) == 2) return 2;
        sta_poll(s, 400, NULL, NULL);
    }
    if (!s->assoc_got) { s->last_status = -1; return 1; }
    s->last_status = s->assoc_status;
    if (s->assoc_status == 0) s->associated = 1;
    return s->assoc_status != 0;
}

int sta_send_data(sta_t *s, const uint8_t dst[6], const uint8_t *body, int blen, int prot, int rate)
{
    uint8_t fr[2400];
    if (blen < 0 || blen > 2200) return -2;
    put_hdr(fr, 0x08, s->bssid, s->mac, dst);
    fr[1] = 0x01 | (prot ? 0x40 : 0);                   // to-DS (+ Protected as given by caller)
    memcpy(fr + 24, body, blen);
    if (tx_gate(s, 0)) return -3;
    return rtl_tx_data(s->r, fr, 24 + blen, rate, 7);
}

int sta_send_null(sta_t *s)
{
    uint8_t fr[24];
    put_hdr(fr, 0x48, s->bssid, s->mac, s->bssid);      // null function (subtype 4)
    fr[1] = 0x01;                                       // to-DS, PM=0
    if (tx_gate(s, 0)) return -3;
    return rtl_tx_data(s->r, fr, 24, 60, 7);
}

int sta_deauth(sta_t *s, int reason)
{
    uint8_t fr[26];
    put_hdr(fr, 0xC0, s->bssid, s->mac, s->bssid);
    fr[24] = reason; fr[25] = reason >> 8;
    s->associated = 0;
    return tx_mgmt(s, fr, sizeof fr, s->rate, 3, 0);
}
