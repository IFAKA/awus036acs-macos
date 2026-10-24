// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Station join library: see link.h. The code was lifted out of wifi.c (stage 5B/5C) so that build/wifi and
// `awusctl join` share one join path.
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "link.h"
#include "phy.h"
#include "scanparse.h"
#include "tun.h"
#include "tkip.h"
#include "wep.h"

#define ECHO_ID 0x4157

long link_now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }
#define now_ms link_now_ms

static void LOGF(link_t *l, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[%6ldms] ", now_ms() - l->t0);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}
#define LOG(...) LOGF(l, __VA_ARGS__)
#define SAY(...) do { if (l->out) fprintf(l->out, __VA_ARGS__); } while (0)

static void hexs(const uint8_t *p, int n) { for (int i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]); }

const char *link_sec_str(link_sec_t s)
{
    switch (s) {
    case LINK_SEC_AUTO: return "auto";
    case LINK_SEC_OPEN: return "open";
    case LINK_SEC_WEP: return "wep";
    case LINK_SEC_WEP_SHARED: return "wep-shared";
    case LINK_SEC_WPA: return "wpa";
    case LINK_SEC_WPA2: return "wpa2";
    }
    return "?";
}

const char *link_cipher_str(int c)
{
    switch (c) {
    case LINK_CIPHER_NONE: return "none";
    case LINK_CIPHER_WEP: return "WEP";
    case LINK_CIPHER_TKIP: return "TKIP";
    case LINK_CIPHER_CCMP: return "CCMP";
    }
    return "?";
}

void link_ipstr(char *b, size_t n, uint32_t a) { snprintf(b, n, "%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255); }

// ---- handshake ----
static void send_eapol(link_t *l, const uint8_t *eapol, size_t n, const char *what)
{
    uint8_t body[8 + 512];
    static const uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    memcpy(body, llc, 8); memcpy(body + 8, eapol, n);
    int rc = sta_send_data(&l->s, l->s.bssid, body, 8 + (int)n, 0, l->hs_rate);
    LOG("tx EAPOL %s len=%zu rate=%d rc=%d", what, n, l->hs_rate, rc);
}

static void handle_eapol(link_t *l, const uint8_t *e, size_t el)
{
    uint8_t out[512]; size_t ol = 0; int ev = 0;
    eapol_key_t k;
    if (l->sec != LINK_SEC_WPA2 && l->sec != LINK_SEC_WPA) return;        // nobody asked for a handshake
    if (eapol_key_parse(e, el, &k) == 0) {
        LOG("rx EAPOL key_info=0x%04x replay=%llu kdlen=%zu", k.info, (unsigned long long)k.replay, k.key_data_len);
        if ((k.info & EAPOL_KEY_PAIRWISE) && !(k.info & EAPOL_KEY_MIC)) {
            l->m1_count++; if (l->m1_count == 1) l->t_m1 = now_ms();
            if (l->m1_count > 1) { l->hs_rate = (l->m1_count % 2 || l->s.channel > 14) ? 60 : 10;      /* no CCK (10) on 5 GHz */ LOG("M1 retransmit #%d -> reply rate %d", l->m1_count, l->hs_rate); }
        }
    } else LOG("rx EAPOL malformed len=%zu", el);
    int rc = wpa_rx_eapol(&l->w, e, el, out, &ol, &ev);
    if (rc) { LOG("wpa_rx_eapol rejected rc=%d", rc); return; }
    if (ev & WPA_EV_PTK) {
        const uint8_t *beacon_ie = l->sec == LINK_SEC_WPA ? l->s.wpa_ie : l->s.rsn;
        size_t beacon_len = l->sec == LINK_SEC_WPA ? (size_t)l->s.wpa_ie_len : (size_t)l->s.rsn_len;
        if (l->w.ap_rsn_len != beacon_len || memcmp(l->w.ap_rsn, beacon_ie, l->w.ap_rsn_len)) {
            l->rsn_mismatch = 1;
            LOG("security IE in M3 differs from probe response; refusing (not sending M4)");
            LOG("probe ie:  "); hexs(beacon_ie, (int)beacon_len); fputc('\n', stderr);
            LOG("m3 rsn:    "); hexs(l->w.ap_rsn, l->w.ap_rsn_len); fputc('\n', stderr);
            return;
        }
    }
    const char *what = (k.info & EAPOL_KEY_PAIRWISE) ? ((k.info & EAPOL_KEY_MIC) ? "M4" : "M2") : "G2";
    if (ol) send_eapol(l, out, ol, what);
    if (ev & WPA_EV_PTK) {                 // install the TK only after M4 went out
        l->tk_ready = 1; l->tx_pn = 1; memset(l->rx_pn, 0, sizeof l->rx_pn);
        if (l->pw_cipher == LINK_CIPHER_TKIP) { memcpy(l->mic_rx, l->w.ptk + 48, 8); memcpy(l->mic_tx, l->w.ptk + 56, 8); }
        LOG("PTK installed (TK%s)", l->pw_cipher == LINK_CIPHER_TKIP ? " + Michael keys" : "");
    }
    if (ev & WPA_EV_GTK) {
        size_t gl; int gid;
        const uint8_t *g = wpa_get_gtk(&l->w, &gl, &gid);
        if (g && ((gl == 16 && l->grp_cipher == LINK_CIPHER_CCMP) || (gl == 32 && l->grp_cipher == LINK_CIPHER_TKIP))) {
            memcpy(l->gk[gid & 3].tk, g, 16);
            if (gl == 32) memcpy(l->gk[gid & 3].mic_rx, g + 16, 8);     // the AP's transmit Michael key
            l->gk[gid & 3].have = 1; l->gk[gid & 3].pn = 0; LOG("GTK installed id=%d (%s)", gid, link_cipher_str(l->grp_cipher));
        } else LOG("GTK unusable len=%zu for group cipher %s", gl, link_cipher_str(l->grp_cipher));
    }
    if (l->w.state == 2 && (l->gk[0].have + l->gk[1].have + l->gk[2].have + l->gk[3].have) && !l->handshake_done) {
        l->handshake_done = 1; l->t_hs = now_ms();
        LOG("handshake complete");
    }
}

// ---- data RX ----
static void on_data(void *ud, const uint8_t *d, int len, const rtl_frame_t *f)
{
    link_t *l = ud;
    (void)f;
    int sub = d[0] >> 4, qos = (sub & 8) != 0, ht = (d[1] & 0x80) != 0;
    int hl = 24 + (qos ? 2 : 0) + (ht ? 4 : 0);
    if (len < hl + 8) return;
    const uint8_t *a1 = d + 4, *a3 = d + 16;
    int group = a1[0] & 1;
    if (!(d[1] & 0x40)) {
        if (!memcmp(d + hl, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8)) { handle_eapol(l, d + hl + 8, len - hl - 8); return; }
        if (l->pw_cipher == LINK_CIPHER_NONE && l->grp_cipher == LINK_CIPHER_NONE) {      // open network: plain data
            if (group && !memcmp(a3, l->s.mac, 6)) return;
            l->st_dec_ok++;
            net_rx(&l->n, d + hl, len - hl, now_ms(), &l->ops);
            return;
        }
        l->st_clear_drop++;
        return;
    }
    if (group && !memcmp(a3, l->s.mac, 6)) return;             // our own broadcast reflected by the AP
    if (l->pw_cipher == LINK_CIPHER_WEP) {                      // WEP: one key for unicast and group, IV | keyid | data | ICV
        uint8_t plain[2400]; int kid = -1;
        if (len - hl > (int)sizeof plain) return;
        if (((d[hl + 3] >> 6) & 3) != l->s.wep_keyid) { l->st_no_key++; return; }
        int pl = wep_decrypt(l->s.wep_key, l->s.wep_key_len, d + hl, len - hl, plain, &kid);
        if (pl < 0) { l->st_dec_fail++; if (l->st_dec_fail <= 8) LOG("wep decrypt FAIL fc=%02x%02x len=%d rc=%d", d[0], d[1], len, pl); return; }
        l->st_dec_ok++;
        net_rx(&l->n, plain, pl, now_ms(), &l->ops);
        return;
    }
    const uint8_t *key; int kid = (d[hl + 3] >> 6) & 3;
    uint64_t *lastpn;
    int tid = qos ? (d[24] & 0x0F) : 0;
    if (group) {
        if (!l->gk[kid].have) { l->st_no_key++; return; }
        key = l->gk[kid].tk; lastpn = &l->gk[kid].pn;
    } else {
        key = wpa_get_tk(&l->w);
        if (!key || !l->tk_ready) { l->st_no_key++; return; }
        lastpn = &l->rx_pn[tid];
    }
    uint8_t plain[2400]; uint64_t pn = 0; int k2 = 0, pl;
    if (len - hl > (int)sizeof plain) return;
    if ((group ? l->grp_cipher : l->pw_cipher) == LINK_CIPHER_TKIP) {
        const uint8_t *mk = group ? l->gk[kid].mic_rx : l->mic_rx;
        pl = tkip_decrypt(key, mk, d + 10, a1, a3, tid, d + hl, len - hl, plain, &pn, &k2);
        if (pl < 0) {
            l->st_dec_fail++;
            if (l->st_dec_fail <= 8) { LOG("tkip decrypt FAIL fc=%02x%02x len=%d group=%d kid=%d tid=%d rc=%d", d[0], d[1], len, group, kid, tid, pl); }
            return;
        }
    } else {
        pl = ccmp_decrypt(key, d, 24 + (qos ? 2 : 0), d + hl, len - hl, plain, &pn, &k2);
        if (pl < 0) {
            l->st_dec_fail++;
            if (l->st_dec_fail <= 8) { LOG("ccmp decrypt FAIL fc=%02x%02x len=%d hl=%d group=%d kid=%d tid=%d", d[0], d[1], len, hl, group, kid, tid); }
            return;
        }
    }
    if (pn <= *lastpn) { l->st_replay++; LOG("replay reject pn=%llu last=%llu", (unsigned long long)pn, (unsigned long long)*lastpn); return; }
    *lastpn = pn;
    l->st_dec_ok++;
    net_rx(&l->n, plain, pl, now_ms(), &l->ops);
}

// ---- data TX ----
static void ops_tx(void *ctx, const uint8_t dst[6], const uint8_t *payload, size_t len)
{
    link_t *l = ctx;
    uint8_t hdr[24] = {0}, out[2400];
    if (len > 1700) return;
    if (l->pw_cipher == LINK_CIPHER_NONE) {
        if (sta_send_data(&l->s, dst, payload, (int)len, 0, l->data_rate)) LOG("data tx failed");
        return;
    }
    if (l->pw_cipher == LINK_CIPHER_WEP) {
        uint8_t iv[3];
        wep_next_iv(&l->s.wep_iv, iv);
        int n = wep_encrypt(l->s.wep_key, l->s.wep_key_len, l->s.wep_keyid, iv, payload, len, out);
        if (n < 0) return;
        l->st_tx_enc++;
        int rc = sta_send_data(&l->s, dst, out, n, 1, l->data_rate);
        if (rc) LOG("data tx rc=%d", rc);
        return;
    }
    if (!l->tk_ready) return;
    hdr[0] = 0x08; hdr[1] = 0x41;
    memcpy(hdr + 4, l->s.bssid, 6); memcpy(hdr + 10, l->s.mac, 6); memcpy(hdr + 16, dst, 6);
    int n = l->pw_cipher == LINK_CIPHER_TKIP
        ? tkip_encrypt(wpa_get_tk(&l->w), l->mic_tx, l->s.mac, dst, l->s.mac, 0, l->tx_pn++, 0, payload, len, out)
        : ccmp_encrypt(wpa_get_tk(&l->w), hdr, 24, l->tx_pn++, 0, payload, len, out);
    if (n < 0) return;
    l->st_tx_enc++;
    int rc = sta_send_data(&l->s, dst, out, n, 1, l->data_rate);
    if (rc) LOG("data tx rc=%d", rc);
}

static void ops_to_tun(void *ctx, const uint8_t *p, size_t len)
{
    link_t *l = ctx;
    if (l->tun_fd >= 0) {
        if (tun_write(l->tun_fd, p, len) == 0) l->st_tun_rx++; else l->st_tun_drop++;
        return;
    }
    if (len < 28 || (p[0] >> 4) != 4) return;
    int ihl = (p[0] & 15) * 4;
    if (p[9] == 17 && l->udp_rx && (size_t)ihl + 8 <= len) {      // bench hook: UDP datagram for us
        size_t ul = (size_t)p[ihl + 4] << 8 | p[ihl + 5];
        if (ul < 8 || ul - 8 > len - ihl - 8) return;
        size_t pl = ul - 8;
        uint32_t seq = pl >= 4 ? (uint32_t)p[ihl + 8] << 24 | p[ihl + 9] << 16 | p[ihl + 10] << 8 | p[ihl + 11] : 0;
        l->udp_rx(l->udp_ud, p[ihl + 2] << 8 | p[ihl + 3], p + ihl + 8, pl, seq, (uint32_t)p[12] << 24 | p[13] << 16 | p[14] << 8 | p[15]);
        return;
    }
    if (p[9] != 1 || (size_t)ihl + 8 > len) return;
    const uint8_t *ic = p + ihl;
    if (ic[0] != 0) return;
    int id = ic[4] << 8 | ic[5], seq = ic[6] << 8 | ic[7];
    if (id != ECHO_ID || seq < 0 || seq >= LINK_PING_MAX || l->ping_got[seq]) return;
    l->ping_got[seq] = 1; l->ping_rtt[seq] = now_ms() - l->ping_sent_at[seq];
    LOG("echo reply seq=%d rtt=%ldms", seq, l->ping_rtt[seq]);
}

static void ops_lease(void *ctx, const net_lease_t *nl, int up)
{
    link_t *l = ctx;
    if (up) { l->lease_ip = nl->ip; LOG("lease up ip=%08x gw=%08x", nl->ip, nl->gw); }
    else LOG("lease down");
}

// ---- main loop helpers ----
int link_pump(link_t *l, int ms)
{
    long end = now_ms() + ms;
    int dseen = l->s.deauth_seen + l->s.disassoc_seen;
    do {
        sta_poll(&l->s, 20, NULL, NULL);
        if (l->s.deauth_seen + l->s.disassoc_seen != dseen) return -1;
        if (l->stop && *l->stop) return -1;
        if (l->handshake_done) {
            net_tick(&l->n, now_ms(), &l->ops);
            if (now_ms() >= l->t_next_null) { l->t_next_null = now_ms() + 15000; int rc = sta_send_null(&l->s); LOG("keepalive null rc=%d", rc); }
        }
    } while (now_ms() < end);
    return 0;
}

static void send_ping(link_t *l, int seq)
{
    uint8_t p[20 + 8 + 32] = {0};
    p[0] = 0x45; p[2] = 0; p[3] = sizeof p; p[4] = 0x70; p[5] = seq; p[8] = 64; p[9] = 1;
    p[12] = l->lease_ip >> 24; p[13] = l->lease_ip >> 16; p[14] = l->lease_ip >> 8; p[15] = l->lease_ip;
    p[16] = l->ping_target >> 24; p[17] = l->ping_target >> 16; p[18] = l->ping_target >> 8; p[19] = l->ping_target;
    uint16_t c = net_cksum(p, 20); p[10] = c >> 8; p[11] = c;
    uint8_t *ic = p + 20;
    ic[0] = 8; ic[4] = ECHO_ID >> 8; ic[5] = ECHO_ID & 0xFF; ic[6] = seq >> 8; ic[7] = seq;
    for (int i = 0; i < 32; i++) ic[8 + i] = 0x41 + i;
    c = net_cksum(ic, 40); ic[2] = c >> 8; ic[3] = c;
    l->ping_sent_at[seq] = now_ms();
    int rc = net_tx_ip(&l->n, p, sizeof p, now_ms(), &l->ops);
    LOG("ping seq=%d tx rc=%d", seq, rc);
}

static int wait_echo(link_t *l, int seq, int ms)
{
    long end = now_ms() + ms;
    while (now_ms() < end && !l->ping_got[seq]) if (link_pump(l, 20) < 0) return -1;
    return l->ping_got[seq] ? 0 : 1;
}

int link_ping(link_t *l, uint32_t target, int count, link_ping_t *res)
{
    memset(res, 0, sizeof *res);
    if (count < 1 || count > LINK_PING_MAX) count = 6;
    l->ping_target = target;
    memset(l->ping_got, 0, sizeof l->ping_got);
    send_ping(l, 0);
    int w = wait_echo(l, 0, 3000);
    if (w) return w;
    res->sent = 1; res->recv = 1; res->first_rtt_ms = l->ping_rtt[0];
    long sum = l->ping_rtt[0];
    for (int seq = 1; seq < count; seq++) {
        send_ping(l, seq); res->sent++;
        if (wait_echo(l, seq, 1000) == 0) { res->recv++; sum += l->ping_rtt[seq]; }
        else if (l->s.deauth_seen) break;
        if (link_pump(l, 200) < 0) break;
    }
    res->avg_rtt_ms = res->recv ? sum / res->recv : -1;
    return 0;
}

// ---- join (scan, auth, assoc, 4-way, DHCP). On failure sets fail_step/fail_reason and returns -1. ----
static int jfail(link_t *l, const char *step, const char *reason)
{
    snprintf(l->fail_step, sizeof l->fail_step, "%s", step);
    snprintf(l->fail_reason, sizeof l->fail_reason, "%s", reason);
    return -1;
}

static int jfail_status(link_t *l, const char *step)
{
    char b[40];
    if (l->s.dfs_refused) return jfail(l, step, "dfs_no_beacon (not transmitting on a DFS channel without a beacon from the AP in the last second)");
    if (l->s.last_status < 0) return jfail(l, step, "timeout");
    snprintf(b, sizeof b, "status=%d", l->s.last_status);
    return jfail(l, step, b);
}

// Cipher suite type byte (1 WEP40, 2 TKIP, 4 CCMP, 5 WEP104) of a group cipher to LINK_CIPHER_*, or -1 if we cannot do it.
static int group_cipher(int suite)
{
    return suite == 4 ? LINK_CIPHER_CCMP : suite == 2 ? LINK_CIPHER_TKIP : -1;
}

// Our RSN IE (WPA2) or WPA vendor IE (WPA1) for the association request and message 2: one pairwise cipher, PSK AKM.
// The group cipher must be the one the AP announced, or the AP drops us in message 2/3.
static size_t build_sec_ie(uint8_t *o, int wpa1, int pw, int grp)
{
    const uint8_t oui[3] = {0x00, wpa1 ? 0x50 : 0x0F, wpa1 ? 0xF2 : 0xAC};
    int g = grp == LINK_CIPHER_TKIP ? 2 : 4, p = pw == LINK_CIPHER_TKIP ? 2 : 4;
    size_t n = 0;
    if (wpa1) { o[n++] = 0xDD; o[n++] = 22; o[n++] = 0x00; o[n++] = 0x50; o[n++] = 0xF2; o[n++] = 1; }
    else { o[n++] = 48; o[n++] = 20; }
    o[n++] = 1; o[n++] = 0;                                              // version 1
    memcpy(o + n, oui, 3); o[n + 3] = (uint8_t)g; n += 4;                // group cipher
    o[n++] = 1; o[n++] = 0;                                              // one pairwise cipher
    memcpy(o + n, oui, 3); o[n + 3] = (uint8_t)p; n += 4;
    o[n++] = 1; o[n++] = 0;                                              // one AKM: PSK
    memcpy(o + n, oui, 3); o[n + 3] = 2; n += 4;
    if (!wpa1) { o[n++] = 0; o[n++] = 0; }                               // RSN capabilities (WPA1 has none)
    return n;
}

// Decide security, ciphers and our association security element from what the AP advertised. 0 or -1 (jfail set).
static int resolve_security(link_t *l)
{
    sta_t *s = &l->s;
    scan_ap_t ap;
    scan_parse_ie(s->ies, s->ies_len, &ap);
    link_sec_t want = l->cfg.sec;
    int rsn_psk = ap.rsn && (ap.rsn_akm & SCAN_AKM_PSK) && s->rsn_len;
    int wpa_psk = ap.wpa1 && (ap.wpa_akm & SCAN_AKM_PSK) && s->wpa_ie_len;
    // Usable RSN: PSK, a pairwise cipher we have (CCMP preferred, else TKIP), a group cipher we have.
    int rsn_ok = rsn_psk && (ap.rsn_cipher & (SCAN_CIPHER_CCMP | SCAN_CIPHER_TKIP)) && group_cipher(ap.rsn_group) >= 0;
    int wpa_ok = wpa_psk && (ap.wpa_cipher & SCAN_CIPHER_TKIP) && ap.wpa_group == 2;
    if (want == LINK_SEC_AUTO) {
        if (rsn_ok) want = LINK_SEC_WPA2;
        else if (!ap.rsn && wpa_ok) want = LINK_SEC_WPA;
        else if (ap.rsn || ap.wpa1) return jfail(l, "scan", "unsupported_security");
        else if (s->ap_cap & 0x0010) want = LINK_SEC_WEP;
        else want = LINK_SEC_OPEN;
    }
    l->sec = want;
    s->sec_ie_len = 0;
    switch (want) {
    case LINK_SEC_OPEN:
        if (ap.rsn || ap.wpa1 || (s->ap_cap & 0x0010)) return jfail(l, "scan", "ap_is_not_open");
        l->pw_cipher = l->grp_cipher = LINK_CIPHER_NONE;
        break;
    case LINK_SEC_WEP:
    case LINK_SEC_WEP_SHARED:
        if (ap.rsn || ap.wpa1) return jfail(l, "scan", "ap_is_not_wep");
        if (!(s->ap_cap & 0x0010)) return jfail(l, "scan", "ap_has_no_privacy_bit");
        if (!l->cfg.key || wep_parse_key(l->cfg.key, s->wep_key, &s->wep_key_len)) return jfail(l, "scan", "bad_wep_key (5/13 ASCII chars or 10/26 hex digits)");
        if (l->cfg.wep_keyid < 0 || l->cfg.wep_keyid > 3) return jfail(l, "scan", "bad_wep_keyid");
        s->wep_keyid = l->cfg.wep_keyid;
        s->auth_algo = want == LINK_SEC_WEP_SHARED;
        l->pw_cipher = l->grp_cipher = LINK_CIPHER_WEP;
        break;
    case LINK_SEC_WPA2:
        if (!s->rsn_len) return jfail(l, "scan", "ap_has_no_rsn_ie");
        if (!rsn_psk) return jfail(l, "scan", "ap_rsn_not_psk");
        if (!rsn_ok) return jfail(l, "scan", "unsupported_cipher");
        l->pw_cipher = (ap.rsn_cipher & SCAN_CIPHER_CCMP) ? LINK_CIPHER_CCMP : LINK_CIPHER_TKIP;
        l->grp_cipher = group_cipher(ap.rsn_group);
        s->sec_ie_len = (int)build_sec_ie(s->sec_ie, 0, l->pw_cipher, l->grp_cipher);
        break;
    case LINK_SEC_WPA:
        if (!s->wpa_ie_len) return jfail(l, "scan", "ap_has_no_wpa_ie");
        if (!wpa_psk) return jfail(l, "scan", "ap_wpa_not_psk");
        if (!wpa_ok) return jfail(l, "scan", "unsupported_cipher");
        l->pw_cipher = l->grp_cipher = LINK_CIPHER_TKIP;
        s->sec_ie_len = (int)build_sec_ie(s->sec_ie, 1, l->pw_cipher, l->grp_cipher);
        break;
    default:
        return jfail(l, "scan", "unsupported_security");
    }
    LOG("security: %s pairwise=%s group=%s", link_sec_str(l->sec), link_cipher_str(l->pw_cipher), link_cipher_str(l->grp_cipher));
    return 0;
}

// Find the AP when no channel was given: 2.4 GHz non-overlapping first, then the rest of 2.4, then 5 GHz non-DFS, then DFS
// (passive: sta_scan does not transmit there until the AP's Beacon was heard). Sets l->cfg.channel. 0 or -1.
static int find_channel(link_t *l)
{
    static const int order[] = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13,
                                36, 40, 44, 48, 149, 153, 157, 161, 165,
                                52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144};
    for (unsigned i = 0; i < sizeof order / sizeof order[0] && !(l->stop && *l->stop); i++) {
        int ch = order[i];
        if (sta_set_channel(&l->s, ch)) continue;
        l->s.ap_seen = 0;
        if (sta_scan(&l->s, sta_is_dfs(ch) ? 1300 : 700) == 0) { l->cfg.channel = ch; LOG("found the AP on channel %d", ch); return 0; }
    }
    return -1;
}

static int join_once(link_t *l)
{
    char b[200];
    sta_t *s = &l->s;
    // fresh state for every attempt
    l->handshake_done = l->rsn_mismatch = l->tk_ready = l->m1_count = 0;
    memset(l->gk, 0, sizeof l->gk);
    memset(l->rx_pn, 0, sizeof l->rx_pn); l->tx_pn = 1; l->hs_rate = l->cfg.hs_rate ? l->cfg.hs_rate : 60;
    s->deauth_seen = s->disassoc_seen = 0; s->associated = 0; s->ap_seen = 0;
    if (!l->cfg.channel && find_channel(l)) return jfail(l, "scan", "no_probe_response");
    if (s->ap_seen == 0 && sta_scan(s, 4000)) return jfail(l, "scan", "no_probe_response");
    LOG("ap bssid=%02x:%02x:%02x:%02x:%02x:%02x rssi=%d", s->bssid[0], s->bssid[1], s->bssid[2], s->bssid[3], s->bssid[4], s->bssid[5], s->rssi);
    if (resolve_security(l)) return -1;
    int keyed = l->sec == LINK_SEC_WPA2 || l->sec == LINK_SEC_WPA;
    if (keyed) {
        if (!l->cfg.key) return jfail(l, "scan", "no_passphrase");
        wpa_init_ex(&l->w, l->cfg.key, (const uint8_t *)s->ssid, strlen(s->ssid), s->bssid, s->mac, s->sec_ie, (size_t)s->sec_ie_len,
                    l->pw_cipher == LINK_CIPHER_TKIP, l->sec == LINK_SEC_WPA);
    }
    net_init(&l->n, s->mac);
    int arc = sta_auth(s);
    if (arc && l->sec == LINK_SEC_WEP && s->auth_algo == 0 && s->last_status == 13) {     // AP wants shared-key auth
        LOG("open-system auth refused with status 13: trying shared-key");
        s->auth_algo = 1;
        arc = sta_auth(s);
    }
    if (arc) return jfail_status(l, "auth");
    if (sta_assoc(s)) return jfail_status(l, "assoc");
    l->t_assoc = now_ms();
    LOG("associated aid=%d (elapsed counted from here)", s->aid);
    SAY("assoc aid=%d\n", s->aid);

    long end;
    if (keyed) {
        int dseen = s->deauth_seen + s->disassoc_seen;
        end = now_ms() + 10000;
        while (now_ms() < end && !l->handshake_done && !l->rsn_mismatch && !(l->stop && *l->stop) && s->deauth_seen + s->disassoc_seen == dseen)
            sta_poll(s, 50, NULL, NULL);
        if (l->stop && *l->stop) return jfail(l, "interrupted", "signal");
        if (l->rsn_mismatch) return jfail(l, "handshake", "rsn_ie_mismatch");
        if (s->deauth_seen + s->disassoc_seen != dseen) {
            snprintf(b, sizeof b, "ap_%s reason=%d m1_seen=%d state=%d", s->deauth_seen ? "deauth" : "disassoc", s->deauth_seen ? s->deauth_reason : s->disassoc_reason, l->m1_count, l->w.state);
            return jfail(l, "handshake", b);
        }
        if (!l->handshake_done) {
            snprintf(b, sizeof b, "timeout m1_seen=%d state=%d eapol_rx=%lu", l->m1_count, l->w.state, s->eapol_rx);
            return jfail(l, "handshake", b);
        }
        SAY("handshake ok: M1 rx at %ldms, M4 tx at %ldms (since start)\n", l->t_m1 - l->t0, l->t_hs - l->t0);
    } else {
        l->handshake_done = 1; l->t_hs = now_ms();         // no key handshake: the link is usable as soon as we are associated
    }
    l->t_next_null = now_ms() + 15000;

    net_dhcp_start(&l->n, now_ms(), &l->ops);
    end = now_ms() + 20000;
    while (now_ms() < end && !l->n.configured) if (link_pump(l, 20) < 0) break;
    if (l->stop && *l->stop) return jfail(l, "interrupted", "signal");
    if (s->deauth_seen + s->disassoc_seen) { snprintf(b, sizeof b, "ap_deauth reason=%d", s->deauth_seen ? s->deauth_reason : s->disassoc_reason); return jfail(l, "dhcp", b); }
    if (!l->n.configured) {
        snprintf(b, sizeof b, "timeout dec_ok=%lu dec_fail=%lu tx_enc=%lu", l->st_dec_ok, l->st_dec_fail, l->st_tx_enc);
        return jfail(l, "dhcp", b);
    }
    return 0;
}

int link_rejoin(link_t *l) { return join_once(l); }

// Whole-join retry: up to 3 attempts, 1 s apart, on scan/auth/assoc/handshake failures. Not retried: DHCP, RSN mismatch, no RSN IE, signals.
int link_join(rtl_t *r, const link_cfg_t *cfg, link_t *l)
{
    l->r = r;
    l->cfg = *cfg;
    if (!l->cfg.data_rate) l->cfg.data_rate = 60;
    l->data_rate = l->cfg.data_rate;
    sta_init(&l->s, r, cfg->ssid, cfg->bssid, cfg->channel);
    l->s.hidden = cfg->hidden;
    if (cfg->channel && r->channel != cfg->channel && sta_set_channel(&l->s, cfg->channel)) { jfail(l, "channel", "set_channel_failed"); return -1; }
    l->s.def_cb = on_data; l->s.def_ud = l;
    LOG("sa=%02x:%02x:%02x:%02x:%02x:%02x", l->s.mac[0], l->s.mac[1], l->s.mac[2], l->s.mac[3], l->s.mac[4], l->s.mac[5]);
    for (int a = 1; a <= 3 && !(l->stop && *l->stop); a++) {
        if (join_once(l) == 0) return 0;
        const char *st = l->fail_step, *re = l->fail_reason;
        int retryable = !strcmp(st, "scan") ? !strcmp(re, "no_probe_response")
                      : (!strcmp(st, "auth") || !strcmp(st, "assoc"))
                      || (!strcmp(st, "handshake") && strcmp(re, "rsn_ie_mismatch"));
        SAY("join attempt %d/3 failed: %s %s\n", a, st, re);
        if (a == 3 || !retryable) return -1;
        sleep(1);
    }
    return -1;
}

void link_init(link_t *l, rtl_t *r)
{
    memset(l, 0, sizeof *l);
    l->r = r;
    l->tun_fd = -1;
    l->t0 = now_ms();
    l->ops = (net_ops_t){ .ctx = l, .tx = ops_tx, .to_tun = ops_to_tun, .lease = ops_lease };
}

void link_leave(link_t *l)
{
    if (l->s.associated || l->s.have_bssid) sta_deauth(&l->s, 3);
}
