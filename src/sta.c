#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sta.h"
#include "mac.h"
#include "tx.h"

static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }

void sta_init(sta_t *s, rtl_t *r, const char *ssid, const uint8_t *bssid, int channel)
{
    memset(s, 0, sizeof *s);
    s->r = r;
    snprintf(s->ssid, sizeof s->ssid, "%s", ssid ? ssid : "");
    if (bssid) { memcpy(s->bssid, bssid, 6); s->have_bssid = 1; }
    s->channel = channel;
    s->rate = 10;
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

// ---- RX handling ----
typedef struct { sta_t *s; sta_data_cb cb; void *ud; } rxctx_t;

static void parse_ies(sta_t *s, const uint8_t *p, const uint8_t *end)
{
    while (p + 2 <= end && p + 2 + p[1] <= end) {
        int n = p[1];
        if (p[0] == 1 && n <= 16) { memcpy(s->rates, p + 2, n); s->nrates = n; }
        else if (p[0] == 50 && n <= 16) { memcpy(s->xrates, p + 2, n); s->nxrates = n; }
        else if (p[0] == 48 && n + 2 <= (int)sizeof s->rsn) { memcpy(s->rsn, p, n + 2); s->rsn_len = n + 2; }
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
    if (type == 0) {
        int tome = !memcmp(a1, s->mac, 6);
        int frombss = s->have_bssid && !memcmp(a2, s->bssid, 6);
        if ((sub == 5 || sub == 8) && len >= 36) {          // probe resp / beacon
            const uint8_t *ie = d + 36, *end = d + len;
            char ss[33] = ""; const uint8_t *p = ie; int have_ssid = 0;
            while (p + 2 <= end && p + 2 + p[1] <= end) {
                if (p[0] == 0 && p[1] <= 32) { memcpy(ss, p + 2, p[1]); ss[p[1]] = 0; have_ssid = 1; break; }
                p += 2 + p[1];
            }
            if (!have_ssid || strcmp(ss, s->ssid)) return;
            if (s->have_bssid && !frombss) return;
            if (!s->have_bssid) { memcpy(s->bssid, a2, 6); s->have_bssid = 1; rtl_set_sta_addr(s->r, s->mac, s->bssid); }
            s->ap_cap = d[34] | d[35] << 8;
            s->rssi = f->rssi_dbm;
            s->nrates = s->nxrates = 0; s->rsn_len = 0;
            parse_ies(s, ie, end);
            s->ap_seen = 1;
        } else if (sub == 11 && tome && frombss && len >= 30) {   // auth
            if ((d[24] | d[25] << 8) == 0 && (d[26] | d[27] << 8) == 2) { s->auth_status = d[28] | d[29] << 8; s->auth_got = 1; }
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
    rxctx_t x = { s, cb, ud };
    long end = now_ms() + ms;
    do {
        long left = end - now_ms();
        if (left < 1) left = 1;
        if (rtl_rx_poll(s->r, on_frame, &x, left > 30 ? 30 : (int)left) < 0) break;
    } while (now_ms() < end);
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
    memcpy(fr + n, sr, sizeof sr); n += sizeof sr;
    static const uint8_t er[] = {50, 8, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c};
    memcpy(fr + n, er, sizeof er); n += sizeof er;
    long end = now_ms() + timeout_ms;
    while (now_ms() < end && !s->ap_seen) {
        if (rtl_tx_frame(s->r, fr, n, 10, 3)) return 2;
        sta_poll(s, 250, NULL, NULL);
    }
    return s->ap_seen ? 0 : 1;
}

int sta_auth(sta_t *s)
{
    uint8_t fr[30];
    put_hdr(fr, 0xB0, s->bssid, s->mac, s->bssid);
    fr[24] = fr[25] = 0; fr[26] = 1; fr[27] = 0; fr[28] = fr[29] = 0;
    s->auth_got = 0;
    for (int a = 0; a < 5 && !s->auth_got; a++) {
        if (rtl_tx_frame(s->r, fr, sizeof fr, s->rate, 7)) return 2;
        sta_poll(s, 300, NULL, NULL);
    }
    if (!s->auth_got) { s->last_status = -1; return 1; }
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
    static const uint8_t rsn[] = {48, 20, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 2, 0, 0};
    memcpy(fr + n, rsn, sizeof rsn); n += sizeof rsn;
    s->assoc_got = 0;
    for (int a = 0; a < 5 && !s->assoc_got; a++) {
        if (rtl_tx_frame(s->r, fr, n, s->rate, 7)) return 2;
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
    return rtl_tx_data(s->r, fr, 24 + blen, rate, 7);
}

int sta_send_null(sta_t *s)
{
    uint8_t fr[24];
    put_hdr(fr, 0x48, s->bssid, s->mac, s->bssid);      // null function (subtype 4)
    fr[1] = 0x01;                                       // to-DS, PM=0
    return rtl_tx_data(s->r, fr, 24, 60, 7);
}
