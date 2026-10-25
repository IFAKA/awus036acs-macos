// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_link_sae.c - WPA3-SAE + PMF through the real link.c / sta.c join path against a fake AP in the same process.
 *
 * THIS IS A SOFTWARE LOOPBACK, NOT AN AIR TEST. No radio is used (sta_io hooks replace the USB transmit / receive), the
 * "AP" below is written by us from the same engines (sae.c, wpa3.c) the station uses, so it proves the call sequence and
 * the frame plumbing in link.c (SAE commit/confirm before association, RSN IE with AKM 8 / MFPC / MFPR / PMKID / RSNXE,
 * the AKM 8 4-way handshake with AES-CMAC MIC, CCMP data both ways, protected Deauth / Disassoc / SA Query, BIP broadcast
 * with the IGTK, transition-mode choice) but it can NOT prove interoperability with a real WPA3 access point.
 *
 * Build / run: make test-link-sae */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "link.h"
#include "sta.h"
#include "wpa.h"
#include "wpa3.h"
#include "sae.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

/* ---------------- the fake AP ---------------- */
#define QN 32
typedef struct { uint8_t d[700]; int n; } qf_t;
static struct {
    qf_t q[QN]; int qh, qt;
    uint8_t bssid[6], sta[6];
    const char *ssid, *pw;
    int h2e, with_psk_akm, mfpr, refuse_assoc;
    uint8_t rsn[64]; int rsn_len;
    sae_t sae; int sae_init, sae_commit_built, sae_ok;
    uint8_t sta_rsn[96]; int sta_rsn_len, sta_has_rsnxe, assoc_seen, assoc_pmkid_ok, assoc_akm8, assoc_mfpc, assoc_mfpr;
    uint8_t pmk[32], ptk[48], anonce[32]; int m2_ok, m4_ok, have_ptk;
    uint64_t tx_pn, rx_mgmt_pn;
    int data_rx_ok, last_payload_len; uint8_t last_payload[200];
    int sa_query_resp_ok, leave_deauth_ok, auth_frames;
    uint8_t gtk[16], igtk[16];
} ap;

static const uint8_t LLC_EAPOL[8] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x88, 0x8E};

static void qpush(const uint8_t *f, int n)
{
    qf_t *e = &ap.q[ap.qt % QN];
    if (n > (int)sizeof e->d - 4) return;
    memcpy(e->d, f, n); e->n = n; ap.qt++;
}

static void mkhdr(uint8_t *h, uint8_t fc0, uint8_t fc1)
{
    memset(h, 0, 24);
    h[0] = fc0; h[1] = fc1;
    memcpy(h + 4, ap.sta, 6); memcpy(h + 10, ap.bssid, 6); memcpy(h + 16, ap.bssid, 6);
}

static void send_mgmt(uint8_t fc0, const uint8_t *body, int bl)
{
    uint8_t f[700];
    mkhdr(f, fc0, 0);
    memcpy(f + 24, body, bl);
    qpush(f, 24 + bl);
}

static void send_eapol(const uint8_t *e, int n)
{
    uint8_t f[700];
    mkhdr(f, 0x08, 0x02);
    memcpy(f + 24, LLC_EAPOL, 8); memcpy(f + 32, e, n);
    qpush(f, 32 + n);
}

static void ap_build_rsn(void)
{
    uint8_t *o = ap.rsn; int n = 0;
    o[n++] = 48; o[n++] = 0;
    o[n++] = 1; o[n++] = 0;
    memcpy(o + n, "\x00\x0f\xac\x04", 4); n += 4;                 /* group CCMP */
    o[n++] = 1; o[n++] = 0; memcpy(o + n, "\x00\x0f\xac\x04", 4); n += 4;   /* pairwise CCMP */
    if (ap.with_psk_akm) { o[n++] = 2; o[n++] = 0; memcpy(o + n, "\x00\x0f\xac\x02", 4); n += 4; memcpy(o + n, "\x00\x0f\xac\x08", 4); n += 4; }
    else { o[n++] = 1; o[n++] = 0; memcpy(o + n, "\x00\x0f\xac\x08", 4); n += 4; }
    o[n++] = ap.mfpr ? 0xC0 : 0x80; o[n++] = 0;                    /* RSN capabilities: MFPC (bit 7), MFPR (bit 6) */
    o[1] = (uint8_t)(n - 2);
    ap.rsn_len = n;
}

static void ap_probe_resp(void)
{
    uint8_t b[300]; int n = 0;
    memset(b, 0, 8); n = 8;
    b[n++] = 0x64; b[n++] = 0;                                      /* beacon interval */
    b[n++] = 0x11; b[n++] = 0x00;                                   /* ESS + privacy */
    b[n++] = 0; b[n++] = (uint8_t)strlen(ap.ssid); memcpy(b + n, ap.ssid, strlen(ap.ssid)); n += (int)strlen(ap.ssid);
    memcpy(b + n, "\x01\x04\x82\x84\x8b\x96", 6); n += 6;
    memcpy(b + n, "\x03\x01\x06", 3); n += 3;
    memcpy(b + n, ap.rsn, ap.rsn_len); n += ap.rsn_len;
    if (ap.h2e) { memcpy(b + n, "\xf4\x01\x20", 3); n += 3; }
    send_mgmt(0x50, b, n);
}

static const uint8_t *find_ie(const uint8_t *p, int len, int id, int *n)
{
    const uint8_t *e = p + len;
    while (p + 2 <= e && p + 2 + p[1] <= e) { if (p[0] == id) { *n = p[1]; return p; } p += 2 + p[1]; }
    return NULL;
}

static void ap_send_m1(void)
{
    uint8_t e[256];
    for (int i = 0; i < 32; i++) ap.anonce[i] = (uint8_t)(0x90 + i);
    int n = eapol_key_build(e, sizeof e, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK, 16, 1, ap.anonce, NULL, 0, NULL);
    send_eapol(e, n);
}

static void ap_send_m3(void)
{
    uint8_t kd[200], wr[216], e[512]; size_t kl = 0;
    memcpy(kd, ap.rsn, ap.rsn_len); kl = ap.rsn_len;
    kd[kl++] = 0xdd; kd[kl++] = 6 + 16; kd[kl++] = 0; kd[kl++] = 0x0f; kd[kl++] = 0xac; kd[kl++] = 1; kd[kl++] = 2 | 4; kd[kl++] = 0;
    memcpy(kd + kl, ap.gtk, 16); kl += 16;
    kd[kl++] = 0xdd; kd[kl++] = 4 + 2 + 6 + 16; kd[kl++] = 0; kd[kl++] = 0x0f; kd[kl++] = 0xac; kd[kl++] = 9; kd[kl++] = 4; kd[kl++] = 0;
    for (int i = 0; i < 6; i++) kd[kl++] = (uint8_t)(i + 1);
    memcpy(kd + kl, ap.igtk, 16); kl += 16;
    kd[kl++] = 0xdd; while (kl % 8) kd[kl++] = 0;
    aes_wrap(ap.ptk + 16, kd, kl, wr);
    uint16_t m3 = EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | EAPOL_KEY_MIC | EAPOL_KEY_INSTALL | EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPTED;
    int n = eapol_key_build(e, sizeof e, m3, 16, 2, ap.anonce, wr, kl + 8, NULL);
    wpa3_eapol_mic(ap.ptk, e, (size_t)n, e + 4 + 77);
    send_eapol(e, n);
}

static void ap_rx_eapol(const uint8_t *e, int n)
{
    eapol_key_t k;
    if (eapol_key_parse(e, n, &k)) return;
    if (!ap.have_ptk) {                                              /* M2 */
        wpa3_ptk(ap.pmk, ap.bssid, ap.sta, ap.anonce, k.nonce, ap.ptk);
        ap.have_ptk = 1;
        ap.m2_ok = wpa3_eapol_verify_mic(ap.ptk, e, k.frame_len) == 0 && (k.info & 7) == 0 &&
                   k.key_data_len == (size_t)ap.sta_rsn_len && !memcmp(k.key_data, ap.sta_rsn, ap.sta_rsn_len);
        if (ap.m2_ok) ap_send_m3();
    } else if (!ap.m4_ok) {                                          /* M4 */
        ap.m4_ok = wpa3_eapol_verify_mic(ap.ptk, e, k.frame_len) == 0 && k.replay == 2;
    }
}

static void ap_rx_auth(const uint8_t *f, int n)
{
    const uint8_t *b = f + 24; int bl = n - 24, seq = b[2] | b[3] << 8;
    ap.auth_frames++;
    memcpy(ap.sta, f + 10, 6);
    if ((b[0] | b[1] << 8) != 3) return;
    uint8_t out[600]; int m;
    if (!ap.sae_init) {
        sae_init(&ap.sae, (const uint8_t *)ap.pw, strlen(ap.pw), ap.bssid, ap.sta, (const uint8_t *)ap.ssid, strlen(ap.ssid), NULL, ap.h2e);
        ap.sae_init = 1;
    }
    if (seq == 1) {
        if (ap.sae.state >= 2) return;                               /* a retransmitted commit: ignore */
        if (!ap.sae_commit_built) { m = sae_build_commit(&ap.sae, out, sizeof out); ap.sae_commit_built = 1; (void)m; }
        if (sae_process_commit(&ap.sae, b, (size_t)bl)) return;
        m = sae_build_commit(&ap.sae, out, sizeof out); send_mgmt(0xB0, out, m);
        m = sae_build_confirm(&ap.sae, out, sizeof out); send_mgmt(0xB0, out, m);
    } else if (seq == 2) {
        if (sae_process_confirm(&ap.sae, b, (size_t)bl) == 0) { ap.sae_ok = 1; memcpy(ap.pmk, sae_get_pmk(&ap.sae), 32); }
    }
}

static void ap_rx_assoc(const uint8_t *f, int n)
{
    int l;
    const uint8_t *rsn = find_ie(f + 28, n - 28, 48, &l);
    ap.assoc_seen++;
    ap.sta_has_rsnxe = find_ie(f + 28, n - 28, 244, &l) != NULL;
    if (rsn) {
        int rl = rsn[1];
        memcpy(ap.sta_rsn, rsn, rl + 2); ap.sta_rsn_len = rl + 2;
        ap.assoc_akm8 = !memcmp(rsn + 16, "\x00\x0f\xac\x08", 4);       /* version 2, group 4, count 2, pairwise 4, count 2 -> AKM at 14 */
        ap.assoc_mfpc = (rsn[20] & 0x80) != 0; ap.assoc_mfpr = (rsn[20] & 0x40) != 0;
        const uint8_t *pm = ap.sae_ok ? sae_get_pmkid(&ap.sae) : NULL;
        ap.assoc_pmkid_ok = pm && rl + 2 >= 24 + 16 && rsn[22] == 1 && !memcmp(rsn + 24, pm, 16);
    }
    uint8_t b[8] = {0x11, 0x00, ap.refuse_assoc ? 1 : 0, 0, 1, 0xC0};
    send_mgmt(0x10, b, 6);
    if (!ap.refuse_assoc && ap.sae_ok) ap_send_m1();
}

static int io_tx(void *ud, const uint8_t *f, int n, int is_data)
{
    (void)ud;
    int type = (f[0] >> 2) & 3, sub = f[0] >> 4;
    if (n < 24) return 0;
    if (type == 0) {
        if (sub == 4) ap_probe_resp();
        else if (sub == 11) ap_rx_auth(f, n);
        else if (sub == 0) ap_rx_assoc(f, n);
        else if ((sub == 12 || sub == 13) && (f[1] & 0x40) && ap.have_ptk) {
            uint8_t body[64]; uint64_t pn;
            int bl = wpa3_mgmt_unprotect(ap.ptk + 32, f, n, body, &pn);
            if (sub == 13 && bl == 4 && body[0] == 8 && body[1] == 1 && body[2] == 0x12 && body[3] == 0x34) ap.sa_query_resp_ok = 1;
            if (sub == 12 && bl == 2 && body[0] == 3) ap.leave_deauth_ok = 1;
        }
        return 0;
    }
    if (type == 2 && is_data) {
        if (f[1] & 0x40) {
            uint8_t pl[300]; uint64_t pn;
            int pln = ccmp_decrypt(ap.ptk + 32, f, 24, f + 24, n - 24, pl, &pn, NULL);
            if (pln > 0) { ap.data_rx_ok++; ap.last_payload_len = pln < 200 ? pln : 200; memcpy(ap.last_payload, pl, ap.last_payload_len); }
        } else if (n > 32 && !memcmp(f + 24, LLC_EAPOL, 8)) ap_rx_eapol(f + 32, n - 32);
    }
    return 0;
}

static int io_poll(void *ud, rtl_frame_cb cb, void *cbud, int ms)
{
    (void)ud; (void)ms;
    int cnt = 0;
    while (ap.qh != ap.qt) {
        uint8_t buf[704]; qf_t *e = &ap.q[ap.qh % QN];
        memcpy(buf, e->d, e->n); memset(buf + e->n, 0, 4);
        rtl_frame_t f = { .data = buf, .len = e->n + 4, .has_fcs = 1, .rssi_valid = 1, .rssi_dbm = -40, .rate = 4, .channel = 6 };
        ap.qh++;
        cb(cbud, &f);
        cnt++;
    }
    if (!cnt) usleep(300);
    return cnt;
}

static const sta_io_t IO = { io_tx, io_poll, NULL };

static void ap_reset(const char *pw, int h2e, int psk_akm, int mfpr)
{
    memset(&ap, 0, sizeof ap);
    memcpy(ap.bssid, "\x02\xaa\xbb\xcc\xdd\x01", 6);
    ap.ssid = "LoopNet"; ap.pw = pw; ap.h2e = h2e; ap.with_psk_akm = psk_akm; ap.mfpr = mfpr;
    for (int i = 0; i < 16; i++) { ap.gtk[i] = (uint8_t)(0x70 + i); ap.igtk[i] = (uint8_t)(0x60 + i); }
    ap.tx_pn = 1;
    ap_build_rsn();
}

static void pump(link_t *l, int ms) { link_pump(l, ms); }

/* AP -> STA unicast CCMP data */
static void ap_send_data(const uint8_t *payload, int pl)
{
    uint8_t f[700], out[600];
    mkhdr(f, 0x08, 0x42);
    int n = ccmp_encrypt(ap.ptk + 32, f, 24, ap.tx_pn++, 0, payload, pl, out);
    memcpy(f + 24, out, n);
    qpush(f, 24 + n);
}

static void ap_send_mgmt_prot(uint8_t fc0, const uint8_t *body, int bl, uint64_t pn, const uint8_t *tk, uint8_t *keep, int *keepn)
{
    uint8_t h[24], out[200];
    mkhdr(h, fc0, 0);
    int n = wpa3_mgmt_protect(tk, h, body, bl, pn, 0, out, sizeof out);
    qpush(out, n);
    if (keep) { memcpy(keep, out, n); *keepn = n; }
}

/* ---------------- scenarios ---------------- */
static link_t L;
static rtl_t R;

static int do_join(link_cfg_t *cfg)
{
    memset(&R, 0, sizeof R); R.channel = 6;
    link_init(&L, &R);
    L.out = NULL;
    return link_join(&R, cfg, &L);
}

static void scenario_sae_full(const char *name, int h2e, int psk_akm, int mfpr)
{
    printf("scenario: %s\n", name);
    ap_reset("correct horse", h2e, psk_akm, mfpr);
    link_cfg_t cfg = { .ssid = "LoopNet", .channel = 6, .sec = LINK_SEC_AUTO, .key = "correct horse", .legacy = 1, .no_dhcp = 1 };
    CHECK(do_join(&cfg) == 0);
    if (L.fail_step[0]) printf("  join failed: %s %s\n", L.fail_step, L.fail_reason);
    CHECK(L.sec == LINK_SEC_SAE && L.pw_cipher == LINK_CIPHER_CCMP && L.grp_cipher == LINK_CIPHER_CCMP);
    CHECK(ap.sae_ok && ap.assoc_seen == 1);
    CHECK(ap.assoc_akm8 && ap.assoc_mfpc && ap.assoc_pmkid_ok);
    CHECK(ap.assoc_mfpr == (mfpr || !psk_akm));                     /* MFPR when the AP demands it, always on a SAE-only AP */
    CHECK(ap.sta_has_rsnxe == h2e);
    CHECK(ap.m2_ok && ap.m4_ok);
    CHECK(L.handshake_done && L.tk_ready && L.w3.state == 2);
    CHECK(L.gk[2].have && memcmp(L.gk[2].tk, ap.gtk, 16) == 0);
    CHECK(L.have_igtk && L.igtk_id == 4 && memcmp(L.igtk, ap.igtk, 16) == 0);
    CHECK(L.s.pmf_active == 1);
    CHECK(link_tk(&L) && memcmp(link_tk(&L), ap.ptk + 32, 16) == 0);

    /* data AP -> STA decrypts */
    uint8_t pay[40] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x06};
    unsigned long ok0 = L.st_dec_ok;
    ap_send_data(pay, sizeof pay);
    pump(&L, 60);
    CHECK(L.st_dec_ok == ok0 + 1 && L.st_dec_fail == 0);
    /* data STA -> AP encrypts with the right TK */
    int rx0 = ap.data_rx_ok;
    uint8_t up[30] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00, 1, 2, 3, 4, 5};
    L.ops.tx(&L, ap.bssid, up, sizeof up);
    CHECK(ap.data_rx_ok == rx0 + 1 && ap.last_payload_len == (int)sizeof up && !memcmp(ap.last_payload, up, sizeof up));

    /* PMF */
    uint8_t rsn0[2] = {7, 0}, keep[200]; int kn = 0;
    unsigned long d0 = L.s.pmf_dropped;
    uint8_t h[24]; mkhdr(h, 0xC0, 0); { uint8_t f[40]; memcpy(f, h, 24); f[24] = 7; f[25] = 0; qpush(f, 26); }   /* unprotected Deauth */
    pump(&L, 40);
    CHECK(L.s.deauth_seen == 0 && L.s.pmf_dropped == d0 + 1 && L.s.associated);
    uint8_t wrongtk[16]; memset(wrongtk, 0x55, 16);
    ap_send_mgmt_prot(0xC0, rsn0, 2, ap.tx_pn++, wrongtk, NULL, NULL);                                           /* forged protected Deauth */
    pump(&L, 40);
    CHECK(L.s.deauth_seen == 0 && L.s.pmf_dropped == d0 + 2);
    uint8_t sq[4] = {8, 0, 0x12, 0x34};
    ap_send_mgmt_prot(0xD0, sq, 4, ap.tx_pn++, ap.ptk + 32, NULL, NULL);                                         /* SA Query request */
    pump(&L, 40);
    CHECK(ap.sa_query_resp_ok && L.st_sa_query == 1);
    uint8_t rsn4[2] = {4, 0};
    ap_send_mgmt_prot(0xC0, rsn4, 2, ap.tx_pn++, ap.ptk + 32, keep, &kn);                                        /* genuine Deauth */
    pump(&L, 40);
    CHECK(L.s.deauth_seen == 1 && L.s.deauth_reason == 4);
    qpush(keep, kn);                                                                                             /* replay of it */
    pump(&L, 40);
    CHECK(L.s.deauth_seen == 1 && L.s.pmf_dropped == d0 + 3);
    /* broadcast Disassoc/Deauth with BIP */
    {
        uint8_t bh[24] = {0xC0, 0}, body[2] = {5, 0}, ipn[6] = {1, 2, 3, 4, 5, 7}, out[100], fr[200];
        memset(bh + 4, 0xff, 6); memcpy(bh + 10, ap.bssid, 6); memcpy(bh + 16, ap.bssid, 6);
        int n = wpa3_bip_protect(ap.igtk, 4, ipn, bh, body, 2, out, sizeof out);
        memcpy(fr, bh, 24); memcpy(fr + 24, out, n);
        fr[24 + n - 1] ^= 1; qpush(fr, 24 + n); fr[24 + n - 1] ^= 1;      /* bad MIC first */
        pump(&L, 40);
        CHECK(L.s.deauth_seen == 1);
        qpush(fr, 24 + n);
        pump(&L, 40);
        CHECK(L.s.deauth_seen == 2 && L.s.deauth_reason == 5);
        qpush(fr, 24 + n);                                                   /* BIP replay */
        pump(&L, 40);
        CHECK(L.s.deauth_seen == 2);
    }
    link_leave(&L);
    CHECK(ap.leave_deauth_ok);
}

static void scenario_wrong_pw(void)
{
    printf("scenario: wrong passphrase\n");
    ap_reset("another password", 1, 0, 0);
    link_cfg_t cfg = { .ssid = "LoopNet", .channel = 6, .sec = LINK_SEC_AUTO, .key = "correct horse", .legacy = 1, .no_dhcp = 1 };
    CHECK(do_join(&cfg) == -1);
    printf("  fail: %s / %s\n", L.fail_step, L.fail_reason);
    CHECK(!strcmp(L.fail_step, "auth") && strstr(L.fail_reason, "sae_confirm"));
    CHECK(ap.assoc_seen == 0 && !L.handshake_done);
}

static void scenario_transition_prefer_psk(void)
{
    printf("scenario: transition AP, prefer_sae off -> WPA2-PSK is chosen\n");
    ap_reset("correct horse", 1, 1, 0);
    ap.refuse_assoc = 1;                       /* the fake AP has no PSK 4-way; we only look at the choice */
    link_cfg_t cfg = { .ssid = "LoopNet", .channel = 6, .sec = LINK_SEC_AUTO, .key = "correct horse", .legacy = 1, .no_dhcp = 1, .prefer_psk = 1 };
    CHECK(do_join(&cfg) == -1);
    CHECK(L.sec == LINK_SEC_WPA2);
    CHECK(ap.sae_init == 0);                   /* no SAE frame was sent */
}

static void scenario_sae_only_vs_wpa2(void)
{
    printf("scenario: SAE-only AP, security forced to wpa2\n");
    ap_reset("correct horse", 1, 0, 0);
    link_cfg_t cfg = { .ssid = "LoopNet", .channel = 6, .sec = LINK_SEC_WPA2, .key = "correct horse", .legacy = 1, .no_dhcp = 1 };
    CHECK(do_join(&cfg) == -1);
    CHECK(!strcmp(L.fail_step, "scan") && !strcmp(L.fail_reason, "ap_rsn_not_psk"));
}

int main(void)
{
    srand(7);
    sta_io = &IO;
    scenario_sae_full("SAE-only AP, H2E, PMF required", 1, 0, 1);
    scenario_sae_full("SAE-only AP, hunting-and-pecking", 0, 0, 1);
    scenario_sae_full("WPA2/WPA3 transition AP, prefer SAE (default)", 1, 1, 0);
    scenario_wrong_pw();
    scenario_sae_only_vs_wpa2();
    scenario_transition_prefer_psk();
    printf("test_link_sae (software loopback, not an air test): %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
