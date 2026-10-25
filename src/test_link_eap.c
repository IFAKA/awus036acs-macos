// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_link_eap.c - WPA2-Enterprise (802.1X) through the real link.c / sta.c join path against a fake AP in the same process.
 *
 * THIS IS A SOFTWARE LOOPBACK, NOT AN AIR TEST. No radio is used (sta_io hooks replace the USB transmit / receive). The "AP" is
 * written here: it answers open-system auth and association, then relays EAP over EAPOL to the test authenticator of
 * src/eap_testauth.h (a TLS 1.2 server + PEAP / TTLS / EAP-TLS inner logic written by us, certificates made with the openssl CLI),
 * and after EAP-Success runs the authenticator side of the 4-way with PMK = MSK[0..32). It proves the call sequence and the
 * plumbing in link.c (RSN IE with AKM 1 / 5 and MFPC / MFPR, EAPOL-Start and EAP over EAPOL, PMK into the 4-way, key descriptor
 * versions 2 and 3, CCMP data, PMF), and wrong-password / wrong-CA failures. It can NOT prove interoperability with a real RADIUS
 * server or a real Enterprise access point.
 *
 * Build / run: make test-link-eap */
#include "eap_testauth.h"
#include "link.h"
#include "sta.h"
#include "wpa.h"
#include "wpa3.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

/* ---------------- the fake AP ---------------- */
#define QN 64
typedef struct { uint8_t d[1400]; int n; } qf_t;
static struct {
    qf_t q[QN]; int qh, qt;
    uint8_t bssid[6], sta[6];
    const char *ssid;
    int akm1, akm5, mfpc, mfpr, pmf;               /* what the AP offers; pmf = what we expect the station to use */
    uint8_t rsn[64]; int rsn_len;
    auth_t *a;
    int assoc_seen, assoc_akm, assoc_mfpc, assoc_mfpr, eapol_start_seen, eap_resp_seen, ident_ok;
    char identity[64];
    int eap_done, eap_failed, eap_stuck;
    uint8_t pmk[32], ptk[48], anonce[32]; int have_pmk, m1_sent, m2_ok, m4_ok, have_ptk;
    uint64_t tx_pn;
    int data_rx_ok, last_payload_len; uint8_t last_payload[200];
    int leave_deauth_ok, leave_deauth_plain;
    uint8_t gtk[16], igtk[16];
} ap;

static const uint8_t LLC_EAPOL[8] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x88, 0x8E};

static void qpush(const uint8_t *f, int n)
{
    qf_t *e = &ap.q[ap.qt % QN];
    if (n > (int)sizeof e->d - 4) { printf("fake AP: frame too big (%d)\n", n); exit(2); }
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
    uint8_t f[1400];
    mkhdr(f, 0x08, 0x02);
    memcpy(f + 24, LLC_EAPOL, 8); memcpy(f + 32, e, n);
    qpush(f, 32 + n);
}

static void send_eap(const uint8_t *eap, size_t n)       /* EAP packet -> EAPOL-wrapped -> data frame */
{
    uint8_t fr[2100];
    size_t m = eap_eapol_wrap(fr, eap, n);
    send_eapol(fr, (int)m);
}

static void ap_build_rsn(void)
{
    uint8_t *o = ap.rsn; int n = 0;
    o[n++] = 48; o[n++] = 0;
    o[n++] = 1; o[n++] = 0;
    memcpy(o + n, "\x00\x0f\xac\x04", 4); n += 4;                 /* group CCMP */
    o[n++] = 1; o[n++] = 0; memcpy(o + n, "\x00\x0f\xac\x04", 4); n += 4;   /* pairwise CCMP */
    o[n++] = (uint8_t)(ap.akm1 + ap.akm5); o[n++] = 0;
    if (ap.akm1) { memcpy(o + n, "\x00\x0f\xac\x01", 4); n += 4; }
    if (ap.akm5) { memcpy(o + n, "\x00\x0f\xac\x05", 4); n += 4; }
    o[n++] = (uint8_t)((ap.mfpc ? 0x80 : 0) | (ap.mfpr ? 0x40 : 0)); o[n++] = 0;
    o[1] = (uint8_t)(n - 2);
    ap.rsn_len = n;
}

static void ap_probe_resp(void)
{
    uint8_t b[300]; int n = 0;
    memset(b, 0, 8); n = 8;
    b[n++] = 0x64; b[n++] = 0;
    b[n++] = 0x11; b[n++] = 0x00;
    b[n++] = 0; b[n++] = (uint8_t)strlen(ap.ssid); memcpy(b + n, ap.ssid, strlen(ap.ssid)); n += (int)strlen(ap.ssid);
    memcpy(b + n, "\x01\x04\x82\x84\x8b\x96", 6); n += 6;
    memcpy(b + n, "\x03\x01\x06", 3); n += 3;
    memcpy(b + n, ap.rsn, ap.rsn_len); n += ap.rsn_len;
    send_mgmt(0x50, b, n);
}

static const uint8_t *find_ie(const uint8_t *p, int len, int id, int *n)
{
    const uint8_t *e = p + len;
    while (p + 2 <= e && p + 2 + p[1] <= e) { if (p[0] == id) { *n = p[1]; return p; } p += 2 + p[1]; }
    return NULL;
}

/* ---- key handshake, authenticator side. AKM 1: descriptor version 2, SHA-1 PRF, HMAC-SHA1 MIC. AKM 5: version 3, SHA-256 KDF, CMAC. */
static int ap_akm(void) { return ap.assoc_akm; }
static uint16_t ap_ver(void) { return ap_akm() == 1 ? 2 : 3; }
static void ap_mic(const uint8_t *e, size_t n, uint8_t mic[16])
{
    if (ap_akm() == 1) eapol_key_mic(ap.ptk, e, n, mic); else wpa3_eapol_mic(ap.ptk, e, n, mic);
}
static int ap_mic_ok(const uint8_t *e, size_t n)
{
    return ap_akm() == 1 ? eapol_key_verify_mic(ap.ptk, e, n) == 0 : wpa3_eapol_verify_mic(ap.ptk, e, n) == 0;
}

static void ap_send_m1(void)
{
    uint8_t e[256];
    for (int i = 0; i < 32; i++) ap.anonce[i] = (uint8_t)(0x90 + i);
    int n = eapol_key_build(e, sizeof e, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | ap_ver(), 16, 1, ap.anonce, NULL, 0, NULL);
    send_eapol(e, n);
    ap.m1_sent = 1;
}

static void ap_send_m3(void)
{
    uint8_t kd[200], wr[216], e[512]; size_t kl = 0;
    memcpy(kd, ap.rsn, ap.rsn_len); kl = ap.rsn_len;
    kd[kl++] = 0xdd; kd[kl++] = 6 + 16; kd[kl++] = 0; kd[kl++] = 0x0f; kd[kl++] = 0xac; kd[kl++] = 1; kd[kl++] = 2 | 4; kd[kl++] = 0;
    memcpy(kd + kl, ap.gtk, 16); kl += 16;
    if (ap.pmf) {
        kd[kl++] = 0xdd; kd[kl++] = 4 + 2 + 6 + 16; kd[kl++] = 0; kd[kl++] = 0x0f; kd[kl++] = 0xac; kd[kl++] = 9; kd[kl++] = 4; kd[kl++] = 0;
        for (int i = 0; i < 6; i++) kd[kl++] = (uint8_t)(i + 1);
        memcpy(kd + kl, ap.igtk, 16); kl += 16;
    }
    kd[kl++] = 0xdd; while (kl % 8) kd[kl++] = 0;
    aes_wrap(ap.ptk + 16, kd, kl, wr);
    uint16_t m3 = EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | EAPOL_KEY_MIC | EAPOL_KEY_INSTALL | EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPTED | ap_ver();
    int n = eapol_key_build(e, sizeof e, m3, 16, 2, ap.anonce, wr, kl + 8, NULL);
    uint8_t mic[16];
    ap_mic(e, (size_t)n, mic);
    memcpy(e + 4 + 77, mic, 16);
    send_eapol(e, n);
}

static void ap_rx_key(const uint8_t *e, int n)
{
    eapol_key_t k;
    if (!ap.have_pmk || eapol_key_parse(e, n, &k)) return;
    if (!ap.have_ptk) {                                              /* M2 */
        if (ap_akm() == 1) wpa_ptk(ap.pmk, ap.bssid, ap.sta, ap.anonce, k.nonce, ap.ptk);
        else wpa3_ptk(ap.pmk, ap.bssid, ap.sta, ap.anonce, k.nonce, ap.ptk);
        ap.have_ptk = 1;
        ap.m2_ok = ap_mic_ok(e, k.frame_len) && (k.info & 7) == ap_ver() &&
                   k.key_data_len == (size_t)ap.rsn_len + 0 + 0 ? 0 : 0;
        ap.m2_ok = ap_mic_ok(e, k.frame_len) && (k.info & 7) == ap_ver();
        if (ap.m2_ok) ap_send_m3();
    } else if (!ap.m4_ok) {                                          /* M4 */
        ap.m4_ok = ap_mic_ok(e, k.frame_len) && k.replay == 2;
    }
}

/* ---- EAP: packet from the station */
static void ap_rx_eap(const uint8_t *pkt, size_t pl)
{
    uint8_t out[2048]; size_t ol = 0;
    if (pl >= 5 && pkt[4] == EAP_TYPE_IDENTITY && pkt[0] == EAP_CODE_RESPONSE && !ap.eap_resp_seen) {
        size_t il = pl - 5 < sizeof ap.identity - 1 ? pl - 5 : sizeof ap.identity - 1;
        memcpy(ap.identity, pkt + 5, il); ap.identity[il] = 0;
    }
    if (pl >= 5 && pkt[0] == EAP_CODE_RESPONSE) ap.eap_resp_seen++;
    int k = a_rx(ap.a, pkt, pl, out, &ol);
    if (k == 0 && ol) send_eap(out, ol);
    else if (k == 1) {                                               /* EAP-Success: both sides now have the MSK */
        send_eap(out, ol);
        memcpy(ap.pmk, ap.a->msk, 32); ap.have_pmk = 1; ap.eap_done = 1;
        ap_send_m1();
    } else if (k == 2) { send_eap(out, ol); ap.eap_failed = 1; }
    else if (k < 0 && k != -2) ap.eap_stuck = 1;
}

static void ap_rx_eapol(const uint8_t *e, int n)
{
    const uint8_t *pkt; size_t pl;
    if (n < 4) return;
    if (e[1] == 1) {                                                 /* EAPOL-Start: (re)send the Identity request */
        ap.eapol_start_seen++;
        if (!ap.eap_resp_seen) { uint8_t req[5] = {EAP_CODE_REQUEST, 0x41, 0, 5, EAP_TYPE_IDENTITY}; send_eap(req, 5); }
        return;
    }
    if (e[1] == 0 && eap_eapol_unwrap(e, (size_t)n, &pkt, &pl) == 0) { ap_rx_eap(pkt, pl); return; }
    if (e[1] == 3) ap_rx_key(e, n);
}

static void ap_rx_assoc(const uint8_t *f, int n)
{
    int l;
    const uint8_t *rsn = find_ie(f + 28, n - 28, 48, &l);
    ap.assoc_seen++;
    if (rsn && rsn[1] >= 20) {
        ap.assoc_akm = rsn[19];
        ap.assoc_mfpc = (rsn[20] & 0x80) != 0; ap.assoc_mfpr = (rsn[20] & 0x40) != 0;
    }
    uint8_t b[8] = {0x11, 0x00, 0, 0, 1, 0xC0};
    send_mgmt(0x10, b, 6);
    /* Identity request, as an Enterprise AP does right after association */
    ap.a->id = 0x40;
    uint8_t req[5] = {EAP_CODE_REQUEST, ++ap.a->id, 0, 5, EAP_TYPE_IDENTITY};
    send_eap(req, 5);
}

static int io_tx(void *ud, const uint8_t *f, int n, int is_data)
{
    (void)ud;
    int type = (f[0] >> 2) & 3, sub = f[0] >> 4;
    if (n < 24) return 0;
    if (type == 0) {
        if (sub == 4) ap_probe_resp();
        else if (sub == 11) { memcpy(ap.sta, f + 10, 6); uint8_t b[6] = {0, 0, 2, 0, 0, 0}; send_mgmt(0xB0, b, 6); }   /* open system, success */
        else if (sub == 0) ap_rx_assoc(f, n);
        else if (sub == 12) {
            if (f[1] & 0x40) {
                uint8_t body[64]; uint64_t pn;
                int bl = ap.have_ptk ? wpa3_mgmt_unprotect(ap.ptk + 32, f, n, body, &pn) : -1;
                if (bl == 2 && body[0] == 3) ap.leave_deauth_ok = 1;
            } else ap.leave_deauth_plain = 1;
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
        uint8_t buf[1404]; qf_t *e = &ap.q[ap.qh % QN];
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

static void ap_reset(int akm1, int akm5, int mfpc, int mfpr, int method, int inner, const char *user, const char *pass)
{
    if (ap.a) a_free(ap.a);
    memset(&ap, 0, sizeof ap);
    memcpy(ap.bssid, "\x02\xaa\xbb\xcc\xdd\x02", 6);
    ap.ssid = "CorpNet"; ap.akm1 = akm1; ap.akm5 = akm5; ap.mfpc = mfpc; ap.mfpr = mfpr;
    ap.pmf = mfpc || mfpr || (!akm1 && akm5);
    for (int i = 0; i < 16; i++) { ap.gtk[i] = (uint8_t)(0x70 + i); ap.igtk[i] = (uint8_t)(0x60 + i); }
    ap.tx_pn = 1;
    ap_build_rsn();
    ap.a = a_new(method, inner, user, pass);
    if (!a_start_tls(ap.a) && method != EAP_TYPE_LEAP) { printf("authenticator TLS setup failed\n"); exit(2); }
}

static void ap_send_data(const uint8_t *payload, int pl)
{
    uint8_t f[700], out[600];
    mkhdr(f, 0x08, 0x42);
    int n = ccmp_encrypt(ap.ptk + 32, f, 24, ap.tx_pn++, 0, payload, pl, out);
    memcpy(f + 24, out, n);
    qpush(f, 24 + n);
}

static void ap_send_mgmt_prot(uint8_t fc0, const uint8_t *body, int bl, uint64_t pn, const uint8_t *tk)
{
    uint8_t h[24], out[200];
    mkhdr(h, fc0, 0);
    int n = wpa3_mgmt_protect(tk, h, body, bl, pn, 0, out, sizeof out);
    qpush(out, n);
}

/* ---------------- scenarios ---------------- */
static link_t L;
static rtl_t R;
static char P_CA[300], P_CA2[300], P_CERT[300], P_KEY[300];

static int do_join(link_cfg_t *cfg)
{
    memset(&R, 0, sizeof R); R.channel = 6;
    link_init(&L, &R);
    L.out = NULL;
    return link_join(&R, cfg, &L);
}

static link_cfg_t base_cfg(int method, int inner)
{
    link_cfg_t c = { .ssid = "CorpNet", .channel = 6, .sec = LINK_SEC_EAP, .key = "correct horse", .legacy = 1, .no_dhcp = 1 };
    c.eap_identity = "alice"; c.eap_anon = "anonymous"; c.eap_method = method; c.eap_inner = inner;
    c.eap_ca_file = P_CA;
    if (method == EAP_TYPE_TLS) { c.eap_cert_file = P_CERT; c.eap_key_file = P_KEY; c.key = NULL; }
    return c;
}

/* A successful join: checks the EAP part, the 4-way, data both ways and (when PMF) protected management frames. */
static void check_success(const char *name, int expect_akm, int expect_pmf)
{
    if (L.fail_step[0]) printf("  %s: join failed: %s %s\n", name, L.fail_step, L.fail_reason);
    CHECK(L.sec == LINK_SEC_EAP && L.pw_cipher == LINK_CIPHER_CCMP && L.grp_cipher == LINK_CIPHER_CCMP);
    CHECK(ap.assoc_seen == 1 && ap.assoc_akm == expect_akm);
    CHECK(ap.assoc_mfpc == expect_pmf && ap.assoc_mfpr == ap.mfpr);
    CHECK(ap.eap_done && !ap.eap_failed && !ap.eap_stuck);
    CHECK(ap.eap_resp_seen >= 2);
    CHECK(ap.m2_ok && ap.m4_ok);
    CHECK(L.handshake_done && L.tk_ready && L.w3.state == 2 && L.w3.akm == expect_akm);
    CHECK(L.eap == NULL && L.eap_state == 2);
    CHECK(L.gk[2].have && memcmp(L.gk[2].tk, ap.gtk, 16) == 0);
    CHECK(L.have_igtk == expect_pmf && (!expect_pmf || (L.igtk_id == 4 && memcmp(L.igtk, ap.igtk, 16) == 0)));
    CHECK(L.s.pmf_active == expect_pmf);
    CHECK(link_tk(&L) && memcmp(link_tk(&L), ap.ptk + 32, 16) == 0);
    CHECK(memcmp(L.w3.pmk, ap.a->msk, 32) == 0);                      /* PMK = MSK[0..32) on both sides */

    uint8_t pay[40] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x06};
    unsigned long ok0 = L.st_dec_ok;
    ap_send_data(pay, sizeof pay);
    link_pump(&L, 60);
    CHECK(L.st_dec_ok == ok0 + 1 && L.st_dec_fail == 0);
    int rx0 = ap.data_rx_ok;
    uint8_t up[30] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00, 1, 2, 3, 4, 5};
    L.ops.tx(&L, ap.bssid, up, sizeof up);
    CHECK(ap.data_rx_ok == rx0 + 1 && ap.last_payload_len == (int)sizeof up && !memcmp(ap.last_payload, up, sizeof up));

    uint8_t h[24], f[40];
    mkhdr(h, 0xC0, 0); memcpy(f, h, 24); f[24] = 7; f[25] = 0;
    qpush(f, 26);                                                      /* an unprotected Deauth from the AP */
    link_pump(&L, 40);
    if (expect_pmf) {
        CHECK(L.s.deauth_seen == 0 && L.s.pmf_dropped == 1 && L.s.associated);   /* PMF: dropped */
        uint8_t rsn4[2] = {4, 0};
        ap_send_mgmt_prot(0xC0, rsn4, 2, ap.tx_pn++, ap.ptk + 32);
        link_pump(&L, 40);
        CHECK(L.s.deauth_seen == 1 && L.s.deauth_reason == 4);        /* the protected one is honoured */
    } else {
        CHECK(L.s.deauth_seen == 1 && L.s.deauth_reason == 7 && L.s.pmf_dropped == 0);   /* no PMF: accepted */
    }
}

static void scenario_ok(const char *name, int method, int inner, int akm1, int akm5, int mfpc, int mfpr, int expect_akm, int auto_sec, int frag)
{
    printf("scenario: %s\n", name);
    ap_reset(akm1, akm5, mfpc, mfpr, method, inner, "alice", "correct horse");
    if (frag) ap.a->frag = (size_t)frag;
    link_cfg_t cfg = base_cfg(method, inner);
    if (auto_sec) cfg.sec = LINK_SEC_AUTO;
    CHECK(do_join(&cfg) == 0);
    check_success(name, expect_akm, ap.pmf);
    CHECK(!strcmp(ap.identity, method == EAP_TYPE_TLS ? "alice" : "anonymous"));    /* the outer identity is the anonymous one */
    if (method == EAP_TYPE_TLS) CHECK(L.sec == LINK_SEC_EAP);
    link_leave(&L);
    CHECK(ap.pmf ? ap.leave_deauth_ok : ap.leave_deauth_plain);
}

static void scenario_fail(const char *name, int method, int inner, const char *ap_pass, const char *client_ca, int insecure, const char *want_step)
{
    printf("scenario: %s\n", name);
    ap_reset(1, 0, 0, 0, method, inner, "alice", ap_pass);
    link_cfg_t cfg = base_cfg(method, inner);
    cfg.eap_ca_file = client_ca; cfg.eap_insecure_skip_verify = insecure;
    int rc = do_join(&cfg);
    printf("  %s / %s\n", L.fail_step, L.fail_reason);
    if (want_step == NULL) {
        CHECK(rc == 0 && L.handshake_done);
        return;
    }
    CHECK(rc == -1 && !strcmp(L.fail_step, want_step));
    CHECK(ap.assoc_seen == 1);                          /* not retried: a rejected login must not hammer the AP */
    CHECK(!L.handshake_done && !L.tk_ready && !ap.m1_sent && !ap.m2_ok);
    CHECK(L.eap == NULL);
}

int main(void)
{
    srand(7);
    make_certs();
    snprintf(P_CA, sizeof P_CA, "%s/ca.pem", g_dir); snprintf(P_CA2, sizeof P_CA2, "%s/ca2.pem", g_dir);
    snprintf(P_CERT, sizeof P_CERT, "%s/cli.pem", g_dir); snprintf(P_KEY, sizeof P_KEY, "%s/cli.key", g_dir);
    sta_io = &IO;

    scenario_ok("PEAP / MS-CHAPv2, AKM 1, no PMF (explicit sec eap)", EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2, 1, 0, 0, 0, 1, 0, 0);
    scenario_ok("PEAP / MS-CHAPv2, AKM 1, AUTO picks 802.1X from the scan, small TLS fragments", EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2, 1, 0, 0, 0, 1, 1, 200);
    scenario_ok("TTLS / PAP, AKM 1, AP offers PMF (capable)", EAP_TYPE_TTLS, EAP_INNER_PAP, 1, 0, 1, 0, 1, 0, 0);
    scenario_ok("TTLS / MS-CHAPv2, AKM 5 only (802.1X-SHA256, PMF)", EAP_TYPE_TTLS, EAP_INNER_MSCHAPV2, 0, 1, 0, 0, 5, 0, 0);
    scenario_ok("EAP-TLS (PEM client certificate), AP offers AKM 1 and 5, PMF required", EAP_TYPE_TLS, EAP_INNER_MSCHAPV2, 1, 1, 1, 1, 1, 0, 0);

    scenario_fail("PEAP wrong password", EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2, "another password", P_CA, 0, "eap");
    scenario_fail("TTLS / PAP wrong password", EAP_TYPE_TTLS, EAP_INNER_PAP, "another password", P_CA, 0, "eap");
    scenario_fail("TTLS / MS-CHAPv2 wrong password", EAP_TYPE_TTLS, EAP_INNER_MSCHAPV2, "another password", P_CA, 0, "eap");
    scenario_fail("PEAP, server certificate not signed by our CA", EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2, "correct horse", P_CA2, 0, "eap");
    scenario_fail("PEAP, wrong CA but insecure_skip_verify", EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2, "correct horse", P_CA2, 1, NULL);

    printf("scenario: configuration errors stop before the AP is touched\n");
    {
        ap_reset(1, 0, 0, 0, EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2, "alice", "correct horse");
        link_cfg_t c = base_cfg(EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2);
        c.sec = LINK_SEC_AUTO; c.eap_identity = NULL;
        CHECK(do_join(&c) == -1 && !strcmp(L.fail_step, "config") && !strcmp(L.fail_reason, "no_eap_identity") && ap.assoc_seen == 0);
        c = base_cfg(EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2); c.eap_ca_file = "/nonexistent/ca.pem";
        CHECK(do_join(&c) == -1 && !strcmp(L.fail_step, "config") && strstr(L.fail_reason, "cannot_read_ca_file") && ap.assoc_seen == 0);
        c = base_cfg(EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2); c.eap_ca_file = NULL;      /* no CA and no insecure flag */
        CHECK(do_join(&c) == -1 && !strcmp(L.fail_step, "config") && ap.assoc_seen == 0);
        c = base_cfg(EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2); c.key = NULL;
        CHECK(do_join(&c) == -1 && !strcmp(L.fail_reason, "no_eap_password") && ap.assoc_seen == 0);
    }
    printf("scenario: an 802.1X AP is not joined as WPA2-PSK / SAE\n");
    {
        ap_reset(1, 0, 0, 0, EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2, "alice", "correct horse");
        link_cfg_t c = base_cfg(EAP_TYPE_PEAP, EAP_INNER_MSCHAPV2); c.sec = LINK_SEC_WPA2;
        CHECK(do_join(&c) == -1 && !strcmp(L.fail_reason, "ap_rsn_not_psk"));
    }

    rm_certs();
    printf("test_link_eap (software loopback, not an air test): %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
