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
    if (l->sec != LINK_SEC_WPA2) return;        // nobody asked for a handshake
    if (eapol_key_parse(e, el, &k) == 0) {
        LOG("rx EAPOL key_info=0x%04x replay=%llu kdlen=%zu", k.info, (unsigned long long)k.replay, k.key_data_len);
        if ((k.info & EAPOL_KEY_PAIRWISE) && !(k.info & EAPOL_KEY_MIC)) {
            l->m1_count++; if (l->m1_count == 1) l->t_m1 = now_ms();
            if (l->m1_count > 1) { l->hs_rate = (l->m1_count % 2) ? 60 : 10; LOG("M1 retransmit #%d -> reply rate %d", l->m1_count, l->hs_rate); }
        }
    } else LOG("rx EAPOL malformed len=%zu", el);
    int rc = wpa_rx_eapol(&l->w, e, el, out, &ol, &ev);
    if (rc) { LOG("wpa_rx_eapol rejected rc=%d", rc); return; }
    if (ev & WPA_EV_PTK) {
        if (l->w.ap_rsn_len != (size_t)l->s.rsn_len || memcmp(l->w.ap_rsn, l->s.rsn, l->w.ap_rsn_len)) {
            l->rsn_mismatch = 1;
            LOG("RSN IE in M3 differs from probe response; refusing (not sending M4)");
            LOG("probe rsn: "); hexs(l->s.rsn, l->s.rsn_len); fputc('\n', stderr);
            LOG("m3 rsn:    "); hexs(l->w.ap_rsn, l->w.ap_rsn_len); fputc('\n', stderr);
            return;
        }
    }
    const char *what = (k.info & EAPOL_KEY_PAIRWISE) ? ((k.info & EAPOL_KEY_MIC) ? "M4" : "M2") : "G2";
    if (ol) send_eapol(l, out, ol, what);
    if (ev & WPA_EV_PTK) {                 // install the TK only after M4 went out
        l->tk_ready = 1; l->tx_pn = 1; memset(l->rx_pn, 0, sizeof l->rx_pn);
        LOG("PTK installed (TK)");
    }
    if (ev & WPA_EV_GTK) {
        size_t gl; int gid;
        const uint8_t *g = wpa_get_gtk(&l->w, &gl, &gid);
        if (g && gl == 16) { memcpy(l->gk[gid & 3].tk, g, 16); l->gk[gid & 3].have = 1; l->gk[gid & 3].pn = 0; LOG("GTK installed id=%d", gid); }
        else LOG("GTK unusable len=%zu", gl);
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
    uint8_t plain[2400]; uint64_t pn = 0; int k2 = 0;
    if (len - hl > (int)sizeof plain) return;
    int pl = ccmp_decrypt(key, d, 24 + (qos ? 2 : 0), d + hl, len - hl, plain, &pn, &k2);
    if (pl < 0) {
        l->st_dec_fail++;
        if (l->st_dec_fail <= 8) { LOG("ccmp decrypt FAIL fc=%02x%02x len=%d hl=%d group=%d kid=%d tid=%d", d[0], d[1], len, hl, group, kid, tid); }
        return;
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
    if (!l->tk_ready) return;
    hdr[0] = 0x08; hdr[1] = 0x41;
    memcpy(hdr + 4, l->s.bssid, 6); memcpy(hdr + 10, l->s.mac, 6); memcpy(hdr + 16, dst, 6);
    int n = ccmp_encrypt(wpa_get_tk(&l->w), hdr, 24, l->tx_pn++, 0, payload, len, out);
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
    if (l->s.last_status < 0) return jfail(l, step, "timeout");
    snprintf(b, sizeof b, "status=%d", l->s.last_status);
    return jfail(l, step, b);
}

static const uint8_t our_rsn_ccmp[] = {48, 20, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 2, 0, 0};

// Decide security, ciphers and our association security element from what the AP advertised. 0 or -1 (jfail set).
static int resolve_security(link_t *l)
{
    sta_t *s = &l->s;
    scan_ap_t ap;
    scan_parse_ie(s->ies, s->ies_len, &ap);
    link_sec_t want = l->cfg.sec;
    int have_psk_rsn = ap.rsn && (ap.rsn_akm & SCAN_AKM_PSK);
    if (want == LINK_SEC_AUTO) {
        if (have_psk_rsn && (ap.rsn_cipher & SCAN_CIPHER_CCMP)) want = LINK_SEC_WPA2;
        else if (ap.rsn || ap.wpa1) return jfail(l, "scan", "unsupported_security");
        else if (s->ap_cap & 0x0010) return jfail(l, "scan", "unsupported_security wep");
        else want = LINK_SEC_OPEN;
    }
    l->sec = want;
    s->sec_ie_len = 0;
    switch (want) {
    case LINK_SEC_OPEN:
        if (ap.rsn || ap.wpa1 || (s->ap_cap & 0x0010)) return jfail(l, "scan", "ap_is_not_open");
        l->pw_cipher = l->grp_cipher = LINK_CIPHER_NONE;
        break;
    case LINK_SEC_WPA2:
        if (!s->rsn_len) return jfail(l, "scan", "ap_has_no_rsn_ie");
        if (!have_psk_rsn) return jfail(l, "scan", "ap_rsn_not_psk");
        if (!(ap.rsn_cipher & SCAN_CIPHER_CCMP) || ap.rsn_group != 4) return jfail(l, "scan", "unsupported_cipher");
        l->pw_cipher = l->grp_cipher = LINK_CIPHER_CCMP;
        memcpy(s->sec_ie, our_rsn_ccmp, sizeof our_rsn_ccmp); s->sec_ie_len = sizeof our_rsn_ccmp;
        break;
    default:
        return jfail(l, "scan", "unsupported_security");
    }
    LOG("security: %s pairwise=%s group=%s", link_sec_str(l->sec), link_cipher_str(l->pw_cipher), link_cipher_str(l->grp_cipher));
    return 0;
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
    if (sta_scan(s, 4000)) return jfail(l, "scan", "no_probe_response");
    LOG("ap bssid=%02x:%02x:%02x:%02x:%02x:%02x rssi=%d", s->bssid[0], s->bssid[1], s->bssid[2], s->bssid[3], s->bssid[4], s->bssid[5], s->rssi);
    if (resolve_security(l)) return -1;
    if (l->sec == LINK_SEC_WPA2) wpa_init(&l->w, l->cfg.key, (const uint8_t *)s->ssid, strlen(s->ssid), s->bssid, s->mac, s->sec_ie, s->sec_ie_len);
    net_init(&l->n, s->mac);
    if (sta_auth(s)) return jfail_status(l, "auth");
    if (sta_assoc(s)) return jfail_status(l, "assoc");
    l->t_assoc = now_ms();
    LOG("associated aid=%d (elapsed counted from here)", s->aid);
    SAY("assoc aid=%d\n", s->aid);

    long end;
    if (l->sec == LINK_SEC_WPA2) {
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
