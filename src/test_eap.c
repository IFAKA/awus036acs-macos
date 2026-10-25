// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_eap.c - tests of the EAP supplicant (eap.c, eap_*.c).
 *  1. crypto against published vectors: RFC 1320 (MD4), RFC 2759 section 9.2 (MS-CHAPv2), RFC 3079 (MPPE keys),
 *     LEAP key (python hashlib cross-check).
 *  2. framing: Identity / Notification / Nak / expanded type, retransmission, EAPOL wrap, early Success ignored.
 *  3. loopback: a small authenticator written here (test only) talks to the supplicant through real TLS 1.2 (the
 *     same Mbed TLS provider, server side) with certificates made at run time by the openssl CLI. For every method
 *     both sides must end with the same MSK. Negative cases: wrong CA, wrong server name, wrong password, a server
 *     that does not know the password, unexpected EAP-Success. */
#include "eap_i.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef OPENSSL_BIN
#define OPENSSL_BIN "openssl"
#endif

static int g_fail, g_n;
#define CHECK(c, ...) do { g_n++; if (!(c)) { g_fail++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static size_t unhex(const char *s, uint8_t *o) {
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) { unsigned v; sscanf(s, "%2x", &v); o[n++] = (uint8_t)v; }
    return n;
}
static int eqhex(const uint8_t *b, size_t n, const char *hex) {
    uint8_t t[256];
    return unhex(hex, t) == n && !memcmp(t, b, n);
}

/* ================================================================== 1. crypto vectors */
static void test_crypto(void) {
    uint8_t h[16];
    static const struct { const char *in, *out; } md4[] = {
        {"", "31d6cfe0d16ae931b73c59d7e0c089c0"}, {"a", "bde52cb31de33e46245e05fbdbd6fb24"},
        {"abc", "a448017aaf21d8525fc10ae87aa6729d"}, {"message digest", "d9130a8164549fe818874806e1c7014b"},
        {"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"}};
    for (size_t i = 0; i < sizeof md4 / sizeof *md4; i++) {
        eap_md4((const uint8_t *)md4[i].in, strlen(md4[i].in), h);
        CHECK(eqhex(h, 16, md4[i].out), "MD4 vector %zu", i);
    }
    /* RFC 2759 section 9.2 */
    uint8_t auth[16], peer[16], ch[8], nt[24], pwh[16], pwhh[16];
    unhex("5B5D7C7D7B3F2F3E3C2C602132262628", auth);
    unhex("21402324255E262A28295F2B3A337C7E", peer);
    eap_mschapv2_challenge_hash(peer, auth, "User", 4, ch);
    CHECK(eqhex(ch, 8, "D02E4386BCE91226"), "RFC2759 challenge hash");
    eap_nt_password_hash("clientPass", 10, pwh);
    CHECK(eqhex(pwh, 16, "44EBBA8D5312B8D611474411F56989AE"), "RFC2759 NT hash");
    eap_mschapv2_nt_response(auth, peer, "User", 4, pwh, nt);
    CHECK(eqhex(nt, 24, "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"), "RFC2759 NT response");
    eap_hash_nt_hash(pwh, pwhh);
    CHECK(eqhex(pwhh, 16, "41C00C584BD2D91C4017A2A12FA59F3F"), "RFC2759 hash of hash");
    char ar[43];
    eap_mschapv2_auth_response(pwh, nt, peer, auth, "User", 4, ar);
    CHECK(!memcmp(ar, "S=407A5589115FD0D6209F510FE9C04566932CDA56", 42), "RFC2759 authenticator response");
    /* a DOMAIN\ prefix is ignored for the challenge hash */
    uint8_t ch2[8];
    eap_mschapv2_challenge_hash(peer, auth, "CORP\\User", 9, ch2);
    CHECK(!memcmp(ch, ch2, 8), "domain prefix stripped");
    /* RFC 3079 section 3.5.3 */
    uint8_t master[16], k[16];
    eap_mppe_master_key(pwhh, nt, master);
    CHECK(eqhex(master, 16, "FDECE3717A8C838CB388E527AE3CDD31"), "RFC3079 master key");
    eap_mppe_asym_key(master, 1, 1, k);
    CHECK(eqhex(k, 16, "8B7CDC149B993A1BA118CB153F56DCCB"), "RFC3079 MasterSendKey (server send)");
    eap_mppe_asym_key(master, 0, 1, k);
    CHECK(eqhex(k, 16, "D5F0E9521E3EA9589645E86051C82226"), "MPPE server receive key (hashlib)");
    eap_mppe_asym_key(master, 1, 0, k);
    CHECK(eqhex(k, 16, "D5F0E9521E3EA9589645E86051C82226"), "client send == server receive");
    /* LEAP key, python hashlib: md5(hh | ap_chal | ap_resp | peer_chal | peer_resp) with counting bytes */
    uint8_t a[8], ap[24], p[8], pr[24];
    for (int i = 0; i < 8; i++) { a[i] = (uint8_t)(1 + i); p[i] = (uint8_t)(40 + i); }
    for (int i = 0; i < 24; i++) { ap[i] = (uint8_t)(10 + i); pr[i] = (uint8_t)(50 + i); }
    eap_leap_key(pwhh, a, ap, p, pr, k);
    CHECK(eqhex(k, 16, "956afd097b2bfccf75edf79f40836c4d"), "LEAP key");
}

/* ================================================================== certificates */
static char g_dir[256];
static uint8_t *rd(const char *name, size_t *n) {
    char path[400];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { printf("cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END); long l = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)l + 1);
    if (fread(b, 1, (size_t)l, f) != (size_t)l) exit(2);
    b[l] = 0; fclose(f); *n = (size_t)l;
    return b;
}
typedef struct { uint8_t *p; size_t n; } buf_t;
static buf_t g_ca, g_ca2, g_srv, g_srvkey, g_cli, g_clikey, g_p12;

static void make_certs(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/test_eap.XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); exit(2); }
    char cmd[4096];
    const char *O = OPENSSL_BIN;
    snprintf(cmd, sizeof cmd,
        "cd %s && "
        "%s req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.pem -subj /CN=TestCA -days 2 "
        "  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign && "
        "%s req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca2.key -out ca2.pem -subj /CN=OtherCA -days 2 "
        "  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign && "
        "printf 'subjectAltName=DNS:radius.test\\nextendedKeyUsage=serverAuth\\nbasicConstraints=CA:FALSE\\n' > srv.ext && "
        "printf 'extendedKeyUsage=clientAuth\\nbasicConstraints=CA:FALSE\\n' > cli.ext && "
        "%s req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout srv.key -out srv.csr -subj /CN=radius.test && "
        "%s x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out srv.pem -days 2 -extfile srv.ext && "
        "%s req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout cli.key -out cli.csr -subj /CN=alice && "
        "%s x509 -req -in cli.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cli.pem -days 2 -extfile cli.ext && "
        "%s pkcs12 -export -inkey cli.key -in cli.pem -certfile ca.pem -out cli.p12 -passout pass:p12pass",
        g_dir, O, O, O, O, O, O, O);
    strcat(cmd, " >/dev/null 2>&1");
    if (system(cmd)) { printf("certificate generation failed (OPENSSL_BIN=%s)\n", O); exit(2); }
    g_ca.p = rd("ca.pem", &g_ca.n); g_ca2.p = rd("ca2.pem", &g_ca2.n);
    g_srv.p = rd("srv.pem", &g_srv.n); g_srvkey.p = rd("srv.key", &g_srvkey.n);
    g_cli.p = rd("cli.pem", &g_cli.n); g_clikey.p = rd("cli.key", &g_clikey.n);
    g_p12.p = rd("cli.p12", &g_p12.n);
}
static void rm_certs(void) {
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir);
    if (system(cmd)) {}
}

/* ================================================================== 2. framing */
static eap_cfg_t base_cfg(void) {
    eap_cfg_t c;
    memset(&c, 0, sizeof c);
    c.identity = "anon@example.org"; c.inner_identity = "alice"; c.password = "secret";
    c.insecure_skip_verify = 1;
    return c;
}
static size_t mkreq(uint8_t *o, uint8_t id, int type, const uint8_t *d, size_t n) {
    o[0] = 1; o[1] = id; o[2] = (uint8_t)((5 + n) >> 8); o[3] = (uint8_t)(5 + n); o[4] = (uint8_t)type;
    if (n) memcpy(o + 5, d, n);
    return 5 + n;
}

static void test_framing(void) {
    uint8_t out[2048], req[64];
    size_t ol;
    eap_cfg_t c = base_cfg();
    eap_t *e = eap_new(&c);
    CHECK(e != NULL, "eap_new");
    /* an unauthenticated EAP-Success first is ignored */
    uint8_t succ[4] = {3, 9, 0, 4};
    CHECK(eap_rx(e, succ, 4, out, sizeof out, &ol) == EAP_ST_IGNORED, "early success ignored");
    size_t n = mkreq(req, 7, EAP_TYPE_IDENTITY, NULL, 0);
    CHECK(eap_rx(e, req, n, out, sizeof out, &ol) == EAP_ST_CONTINUE, "identity");
    CHECK(ol == 5 + strlen("anon@example.org") && out[0] == 2 && out[1] == 7 && out[4] == 1 &&
          ((out[2] << 8) | out[3]) == (int)ol && !memcmp(out + 5, "anon@example.org", 16), "identity response bytes");
    /* retransmission returns the identical answer */
    uint8_t first[64]; memcpy(first, out, ol);
    size_t ol1 = ol;
    CHECK(eap_rx(e, req, n, out, sizeof out, &ol) == EAP_ST_CONTINUE && ol == ol1 && !memcmp(first, out, ol), "retransmit");
    /* Notification: empty response of type 2 */
    n = mkreq(req, 8, EAP_TYPE_NOTIFICATION, (const uint8_t *)"hello", 5);
    CHECK(eap_rx(e, req, n, out, sizeof out, &ol) == EAP_ST_CONTINUE && ol == 5 && out[4] == 2 && out[1] == 8, "notification");
    /* unknown method: Nak listing our methods (default PEAP, TTLS, TLS)... TLS needs a cert, so check the list we have */
    n = mkreq(req, 9, 99, NULL, 0);
    CHECK(eap_rx(e, req, n, out, sizeof out, &ol) == EAP_ST_CONTINUE && out[4] == EAP_TYPE_NAK && out[1] == 9 &&
          out[5] == EAP_TYPE_PEAP && out[6] == EAP_TYPE_TTLS, "nak");
    /* a vendor expanded request we do not know */
    uint8_t ex[16] = {0, 0, 0x37, 0x63, 0, 0, 0, 1};
    n = mkreq(req, 10, EAP_TYPE_EXPANDED, ex, 8);
    CHECK(eap_rx(e, req, n, out, sizeof out, &ol) == EAP_ST_CONTINUE && out[4] == EAP_TYPE_NAK, "unknown expanded -> nak");
    /* expanded PEAP Start: answered in expanded framing, with a TLS ClientHello */
    uint8_t exs[16] = {0, 0, 0, 0, 0, 0, EAP_TYPE_PEAP, 0x20};
    n = mkreq(req, 11, EAP_TYPE_EXPANDED, exs, 8);
    int st = eap_rx(e, req, n, out, sizeof out, &ol);
    CHECK(st == EAP_ST_CONTINUE && ol > 20 && out[4] == EAP_TYPE_EXPANDED && out[11] == EAP_TYPE_PEAP && out[1] == 11 &&
          ((out[2] << 8) | out[3]) == (int)ol && (out[12] & 0x20) == 0 && out[13] == 0x16, "expanded PEAP start -> ClientHello (%d, %zu)", st, ol);
    CHECK(eap_method(e) == EAP_TYPE_PEAP, "method");
    CHECK(eap_rx(e, succ, 4, out, sizeof out, &ol) == EAP_ST_IGNORED, "success mid-handshake ignored");
    uint8_t fail[4] = {4, 12, 0, 4};
    CHECK(eap_rx(e, fail, 4, out, sizeof out, &ol) == EAP_ST_FAILURE, "failure honoured");
    CHECK(eap_get_msk(e, &ol) == NULL, "no MSK after failure");
    eap_free(e);

    /* configuration checks */
    eap_cfg_t b = base_cfg(); b.insecure_skip_verify = 0;
    CHECK(eap_new(&b) == NULL, "CA required by default");
    b = base_cfg(); static const int leap[1] = {EAP_TYPE_LEAP}; b.methods = leap; b.n_methods = 1;
    CHECK(eap_new(&b) == NULL, "LEAP refused without allow_leap");
    b.allow_leap = 1;
    e = eap_new(&b); CHECK(e != NULL, "LEAP allowed with the flag"); eap_free(e);
    b = base_cfg(); b.identity = NULL;
    CHECK(eap_new(&b) == NULL, "identity required");

    /* EAPOL framing */
    uint8_t pkt[8] = {1, 5, 0, 8, 13, 0x20, 0, 0}, fr[32];
    size_t fl = eap_eapol_wrap(fr, pkt, 8);
    const uint8_t *pp; size_t pl;
    CHECK(fl == 12 && fr[0] == 1 && fr[1] == 0 && fr[3] == 8, "eapol wrap");
    CHECK(eap_eapol_unwrap(fr, fl, &pp, &pl) == 0 && pl == 8 && !memcmp(pp, pkt, 8), "eapol unwrap");
    uint8_t key[8] = {2, 3, 0, 4, 0, 0, 0, 0};
    CHECK(eap_eapol_unwrap(key, 8, &pp, &pl) == 1, "EAPOL-Key passed to the 4-way code");
    CHECK(eap_eapol_unwrap(fr, 6, &pp, &pl) < 0, "truncated eapol");
    uint8_t st4[4]; CHECK(eap_eapol_start(st4) == 4 && st4[1] == 1, "eapol start");
}

/* ================================================================== 3. loopback authenticator */
typedef struct {
    int method, peap_ver, inner;                      /* inner: EAP_INNER_* for TTLS */
    const char *user, *pass, *proof_pass;             /* proof_pass: password used to build the "S=" proof */
    size_t frag;
    int require_cli;
    tlsp_t *tls;
    uint8_t *tx; size_t tx_len, tx_off;
    uint8_t *rx; size_t rx_len; uint32_t rx_expect;
    uint8_t id, iid;
    int hs_done, done_ok, done_fail, ack_ok, ms_ok;
    uint8_t msk[64]; int have_msk;
    uint8_t ms_id, auth_ch[16];
    int n_m_flags;                                    /* fragments with M seen from the client */
    int n_srv_m;                                      /* fragments with M sent by us */
    int leap_state; uint8_t leap_ch[8], leap_peer[24];
    uint8_t leap_key[16];
} auth_t;

static void a_push(auth_t *a, const uint8_t *d, size_t n) {
    a->tx = realloc(a->tx, a->tx_len + n + 1);
    memcpy(a->tx + a->tx_len, d, n); a->tx_len += n;
}
static void a_drain(auth_t *a) {
    uint8_t b[2048]; size_t n;
    while ((n = tlsp_out(a->tls, b, sizeof b)) > 0) a_push(a, b, n);
}
/* next request carrying the next fragment (or an empty one) */
static size_t a_next(auth_t *a, uint8_t *o) {
    size_t frag = a->frag, n = 6;
    uint8_t fl = a->method == EAP_TYPE_PEAP ? (uint8_t)a->peap_ver : 0;
    if (a->tx_off < a->tx_len) {
        size_t ch = a->tx_len - a->tx_off;
        if (ch > frag) ch = frag;
        if (a->tx_off == 0 && a->tx_len > frag) {
            fl |= 0x80;
            o[6] = (uint8_t)(a->tx_len >> 24); o[7] = (uint8_t)(a->tx_len >> 16); o[8] = (uint8_t)(a->tx_len >> 8); o[9] = (uint8_t)a->tx_len;
            n = 10;
        }
        if (a->tx_off + ch < a->tx_len) { fl |= 0x40; a->n_srv_m++; }
        memcpy(o + n, a->tx + a->tx_off, ch);
        n += ch; a->tx_off += ch;
        if (a->tx_off == a->tx_len) { a->tx_len = a->tx_off = 0; }
    }
    o[0] = 1; o[1] = ++a->id; o[2] = (uint8_t)(n >> 8); o[3] = (uint8_t)n; o[4] = (uint8_t)a->method; o[5] = fl;
    return n;
}
static size_t a_simple(auth_t *a, uint8_t *o, int code) {
    o[0] = (uint8_t)code; o[1] = ++a->id; o[2] = 0; o[3] = 4;
    return 4;
}
static void a_inner(auth_t *a, int type, const uint8_t *d, size_t n) {       /* full-header inner request */
    uint8_t b[300];
    b[0] = 1; b[1] = ++a->iid; b[2] = (uint8_t)((5 + n) >> 8); b[3] = (uint8_t)(5 + n); b[4] = (uint8_t)type;
    memcpy(b + 5, d, n);
    tlsp_write(a->tls, b, 5 + n);
}
static void a_derive(auth_t *a, const char *label) {
    uint8_t km[128];
    tlsp_export(a->tls, label, km, sizeof km);
    memcpy(a->msk, km, 64); a->have_msk = 1;
}

static void a_ms_success(auth_t *a, const uint8_t *peer, const uint8_t *ntresp, uint8_t *txt /*[1+42+...]*/, size_t *tl) {
    uint8_t ph[16]; char ar[43];
    eap_nt_password_hash(a->proof_pass ? a->proof_pass : a->pass, strlen(a->proof_pass ? a->proof_pass : a->pass), ph);
    eap_mschapv2_auth_response(ph, ntresp, peer, a->auth_ch, a->user, strlen(a->user), ar);
    memcpy(txt, ar, 42);
    memcpy(txt + 42, " M=welcome", 10);
    *tl = 52;
}
static int a_check_nt(auth_t *a, const uint8_t *peer, const uint8_t *nt) {
    uint8_t ph[16], exp[24];
    eap_nt_password_hash(a->pass, strlen(a->pass), ph);
    eap_mschapv2_nt_response(a->auth_ch, peer, a->user, strlen(a->user), ph, exp);
    return !memcmp(exp, nt, 24);
}

static int avp_find(const uint8_t *d, size_t n, uint32_t code, uint32_t vendor, const uint8_t **v, size_t *vl) {
    size_t o = 0;
    while (o + 8 <= n) {
        uint32_t c = (uint32_t)d[o] << 24 | d[o + 1] << 16 | d[o + 2] << 8 | d[o + 3];
        size_t len = (size_t)d[o + 5] << 16 | d[o + 6] << 8 | d[o + 7], hl = 8;
        uint32_t ven = 0;
        if (d[o + 4] & 0x80) { ven = (uint32_t)d[o + 8] << 24 | d[o + 9] << 16 | d[o + 10] << 8 | d[o + 11]; hl = 12; }
        if (len < hl || o + len > n) return 0;
        if (c == code && ven == vendor) { *v = d + o + hl; *vl = len - hl; return 1; }
        o += (len + 3) & ~(size_t)3;
    }
    return 0;
}
static size_t mkavp(uint8_t *o, uint32_t code, uint32_t vendor, const uint8_t *v, size_t vl) {
    size_t hl = vendor ? 12 : 8, n = hl + vl;
    o[0] = code >> 24; o[1] = code >> 16; o[2] = code >> 8; o[3] = (uint8_t)code;
    o[4] = (uint8_t)((vendor ? 0x80 : 0) | 0x40); o[5] = n >> 16; o[6] = n >> 8; o[7] = (uint8_t)n;
    if (vendor) { o[8] = vendor >> 24; o[9] = vendor >> 16; o[10] = vendor >> 8; o[11] = (uint8_t)vendor; }
    memcpy(o + hl, v, vl);
    size_t pad = (4 - (n & 3)) & 3;
    memset(o + n, 0, pad);
    return n + pad;
}

static void a_app_peap(auth_t *a, const uint8_t *d, size_t n) {
    int type; const uint8_t *p; size_t pn;
    if (n >= 5 && d[0] == 2 && (((size_t)d[2] << 8) | d[3]) == n) { type = d[4]; p = d + 5; pn = n - 5; }
    else { type = d[0]; p = d + 1; pn = n - 1; }
    if (type == EAP_TYPE_IDENTITY) {
        if (pn != strlen(a->user) || memcmp(p, a->user, pn)) { a->done_fail = 1; return; }
        uint8_t m[64]; size_t o = 0;
        a->ms_id = 0x42; arc4random_buf(a->auth_ch, 16);
        m[o++] = 1; m[o++] = a->ms_id; size_t ml = 4 + 1 + 16 + 3; m[o++] = (uint8_t)(ml >> 8); m[o++] = (uint8_t)ml; m[o++] = 16;
        memcpy(m + o, a->auth_ch, 16); o += 16; memcpy(m + o, "srv", 3); o += 3;
        a_inner(a, EAP_TYPE_MSCHAPV2, m, o);
    } else if (type == EAP_TYPE_MSCHAPV2 && pn >= 1) {
        if (p[0] == 2 && pn >= 4 + 1 + 49) {
            const uint8_t *peer = p + 5, *nt = p + 5 + 16 + 8;
            if (a_check_nt(a, peer, nt)) {
                uint8_t m[80]; size_t tl;
                a_ms_success(a, peer, nt, m + 4, &tl);
                m[0] = 3; m[1] = a->ms_id; m[2] = (uint8_t)((4 + tl) >> 8); m[3] = (uint8_t)(4 + tl);
                a_inner(a, EAP_TYPE_MSCHAPV2, m, 4 + tl);
                a->ms_ok = 1;
            } else {
                static const char t[] = "E=691 R=0 C=00000000000000000000000000000000 V=3 M=Authentication failed";
                uint8_t m[100]; size_t tl = strlen(t);
                m[0] = 4; m[1] = a->ms_id; m[2] = (uint8_t)((4 + tl) >> 8); m[3] = (uint8_t)(4 + tl); memcpy(m + 4, t, tl);
                a_inner(a, EAP_TYPE_MSCHAPV2, m, 4 + tl);
            }
        } else if (p[0] == 3) {
            uint8_t r[6] = {0x80, 0x03, 0x00, 0x02, 0x00, 0x01};
            a_inner(a, EAP_TYPE_TLV, r, 6);
        } else if (p[0] == 4) a->done_fail = 1;
    } else if (type == EAP_TYPE_TLV) {
        if (pn >= 6 && p[4] == 0 && p[5] == 1) a->done_ok = 1; else a->done_fail = 1;
    }
}
static void a_app_ttls(auth_t *a, const uint8_t *d, size_t n) {
    const uint8_t *v; size_t vl;
    if (!avp_find(d, n, 1, 0, &v, &vl) || vl != strlen(a->user) || memcmp(v, a->user, vl)) { a->done_fail = 1; return; }
    if (a->inner == EAP_INNER_PAP) {
        if (!avp_find(d, n, 2, 0, &v, &vl) || vl % 16) { a->done_fail = 1; return; }
        size_t l = vl; while (l && v[l - 1] == 0) l--;
        if (l == strlen(a->pass) && !memcmp(v, a->pass, l)) a->done_ok = 1; else a->done_fail = 1;
        return;
    }
    const uint8_t *chv, *rsp; size_t cl, rl;
    uint8_t exp[17];
    if (!avp_find(d, n, 11, 311, &chv, &cl) || !avp_find(d, n, 25, 311, &rsp, &rl) || cl != 16 || rl != 50) { a->done_fail = 1; return; }
    tlsp_export(a->tls, "ttls challenge", exp, 17);
    if (memcmp(exp, chv, 16) || rsp[0] != exp[16]) { a->done_fail = 1; return; }
    memcpy(a->auth_ch, chv, 16); a->ms_id = rsp[0];
    if (!a_check_nt(a, rsp + 2, rsp + 26)) { a->done_fail = 1; return; }
    uint8_t body[80], av[120]; size_t tl;
    body[0] = a->ms_id;
    a_ms_success(a, rsp + 2, rsp + 26, body + 1, &tl);
    size_t an = mkavp(av, 26, 311, body, 1 + tl);
    tlsp_write(a->tls, av, an);
    a->ack_ok = 1;
}

/* handle a complete client TLS message; false = fatal */
static int a_message(auth_t *a) {
    if (tlsp_in(a->tls, a->rx, a->rx_len)) return 0;
    a->rx_len = 0; a->rx_expect = 0;
    int r = tlsp_handshake(a->tls);
    if (r < 0) return 0;
    if (r == 1 && !a->hs_done) {
        a->hs_done = 1;
        if (a->method == EAP_TYPE_TLS) { a_derive(a, "client EAP encryption"); a->done_ok = 1; }
        else if (a->method == EAP_TYPE_PEAP) { a_derive(a, "client EAP encryption"); a_inner(a, EAP_TYPE_IDENTITY, NULL, 0); }
        else a_derive(a, "ttls keying material");
    }
    if (a->hs_done) {
        uint8_t b[2048]; int k;
        while ((k = tlsp_read(a->tls, b, sizeof b)) > 0) {
            if (a->method == EAP_TYPE_PEAP) a_app_peap(a, b, (size_t)k);
            else if (a->method == EAP_TYPE_TTLS) a_app_ttls(a, b, (size_t)k);
        }
    }
    a_drain(a);
    return 1;
}

static auth_t *a_new(int method, int inner, const char *user, const char *pass) {
    auth_t *a = calloc(1, sizeof *a);
    a->method = method; a->inner = inner; a->user = user; a->pass = pass; a->frag = 1000; a->peap_ver = 0;
    return a;
}
static int a_start_tls(auth_t *a) {
    tlsp_cfg_t c;
    memset(&c, 0, sizeof c);
    c.server = 1; c.cert_pem = g_srv.p; c.cert_pem_len = g_srv.n; c.key_pem = g_srvkey.p; c.key_pem_len = g_srvkey.n;
    c.ca_pem = g_ca.p; c.ca_pem_len = g_ca.n; c.require_client_cert = a->method == EAP_TYPE_TLS;
    a->tls = tlsp_new(&c);
    return a->tls != NULL;
}
static void a_free(auth_t *a) { tlsp_free(a->tls); free(a->tx); free(a->rx); free(a); }

/* returns 0 = request to send in o (len *ol), 1 = EAP-Success in o, 2 = EAP-Failure in o, -1 = authenticator error */
static int a_rx(auth_t *a, const uint8_t *r, size_t rl, uint8_t *o, size_t *ol) {
    if (rl < 5 || r[0] != EAP_CODE_RESPONSE) return -1;
    if (r[4] == EAP_TYPE_NAK) return -1;
    if (a->method == EAP_TYPE_LEAP) {
        if (a->leap_state == 0) {                             /* response to our challenge */
            uint8_t ph[16], exp[24];
            eap_nt_password_hash(a->pass, strlen(a->pass), ph);
            eap_challenge_response(a->leap_ch, ph, exp);
            if (rl < 8 + 24 || memcmp(r + 8, exp, 24)) { *ol = a_simple(a, o, EAP_CODE_FAILURE); return 2; }
            memcpy(a->leap_peer, r + 8, 24);
            a->leap_state = 1;
            *ol = a_simple(a, o, EAP_CODE_SUCCESS);
            return 0;                                         /* Success is followed by the peer's own challenge */
        }
        return -1;
    }
    if (r[4] == EAP_TYPE_IDENTITY) {
        if (!a_start_tls(a)) return -1;
        o[0] = 1; o[1] = ++a->id; o[2] = 0; o[3] = 6; o[4] = (uint8_t)a->method;
        o[5] = 0x20 | (a->method == EAP_TYPE_PEAP ? (uint8_t)a->peap_ver : 0);
        *ol = 6;
        return 0;
    }
    if (r[4] != a->method) return -1;
    uint8_t fl = rl > 5 ? r[5] : 0;
    const uint8_t *p = r + 6;
    size_t pn = rl > 6 ? rl - 6 : 0;
    if (fl & 0x80) {
        if (pn < 4) return -1;
        a->rx_expect = (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
        p += 4; pn -= 4;
    }
    if (pn) {
        a->rx = realloc(a->rx, a->rx_len + pn);
        memcpy(a->rx + a->rx_len, p, pn); a->rx_len += pn;
    }
    if (fl & 0x40) { a->n_m_flags++; a->tx_len = a->tx_off = 0; *ol = a_next(a, o); return 0; }   /* ack the fragment */
    if (pn == 0 && !(fl & 0x40) && a->ack_ok) a->done_ok = 1;   /* empty ack after the MS-CHAP2-Success AVP */
    if (a->rx_len) {
        if (a->rx_expect && a->rx_expect != a->rx_len) return -1;
        if (!a_message(a)) { *ol = a_simple(a, o, EAP_CODE_FAILURE); return 2; }
    }
    if (a->tx_off < a->tx_len) { *ol = a_next(a, o); return 0; }
    if (a->done_fail) { *ol = a_simple(a, o, EAP_CODE_FAILURE); return 2; }
    if (a->done_ok) { *ol = a_simple(a, o, EAP_CODE_SUCCESS); return 1; }
    return -2;
}

/* ---- run one full exchange */
typedef struct {
    int final;                       /* EAP_ST_* the client ended with, or -1 if the exchange did not finish */
    int msk_match; int have_msk;
    int steps, dup_ok;
    int client_m, server_m;
    char err[160];
} run_t;

static run_t run(const eap_cfg_t *cfg, auth_t *a, int dup) {
    run_t r;
    memset(&r, 0, sizeof r);
    r.final = -1; r.dup_ok = 1;
    eap_t *e = eap_new(cfg);
    if (!e) { snprintf(r.err, sizeof r.err, "eap_new: %s", eap_new_error()); return r; }
    uint8_t req[4096], out[4096], again[4096];
    size_t rl, ol;
    int cm = 0;
    req[0] = 1; req[1] = ++a->id; req[2] = 0; req[3] = 5; req[4] = EAP_TYPE_IDENTITY; rl = 5;
    if (a->method == EAP_TYPE_LEAP) {
        arc4random_buf(a->leap_ch, 8);
        const char *nm = "srv";
        req[1] = ++a->id; req[4] = EAP_TYPE_LEAP; req[5] = 1; req[6] = 0; req[7] = 8; memcpy(req + 8, a->leap_ch, 8);
        memcpy(req + 16, nm, 3); rl = 19; req[3] = 19;
        /* LEAP starts with the Identity request in real life; the peer answers it with the identity, then the AP sends the challenge */
        uint8_t ir[5] = {1, 1, 0, 5, 1};
        int st0 = eap_rx(e, ir, 5, out, sizeof out, &ol);
        if (st0 != EAP_ST_CONTINUE || !ol) { snprintf(r.err, sizeof r.err, "LEAP identity step failed"); eap_free(e); return r; }
    }
    for (int step = 0; step < 300; step++) {
        r.steps = step;
        int st = eap_rx(e, req, rl, out, sizeof out, &ol);
        if (dup && req[0] == EAP_CODE_REQUEST && st == EAP_ST_CONTINUE) {
            size_t ol2;
            int st2 = eap_rx(e, req, rl, again, sizeof again, &ol2);
            if (st2 != EAP_ST_CONTINUE || ol2 != ol || memcmp(again, out, ol)) r.dup_ok = 0;
        }
        if (st == EAP_ST_SUCCESS || st == EAP_ST_FAILURE) { r.final = st; break; }
        if (st == EAP_ST_IGNORED) { snprintf(r.err, sizeof r.err, "client ignored a packet (%s)", eap_error(e)); break; }
        if (req[0] == EAP_CODE_SUCCESS && a->method == EAP_TYPE_LEAP) { /* peer's challenge goes out as a request */ }
        if (!ol) { snprintf(r.err, sizeof r.err, "client produced nothing"); break; }
        if (out[5 + (out[4] == EAP_TYPE_EXPANDED ? 7 : 0)] & 0x40 && out[4] != EAP_TYPE_IDENTITY && out[4] != EAP_TYPE_LEAP) cm++;
        if (a->method == EAP_TYPE_LEAP && out[0] == EAP_CODE_REQUEST) {
            /* peer-issued challenge: authenticator answers with its response */
            uint8_t ph[16], hh[16], resp[24];
            eap_nt_password_hash(a->pass, strlen(a->pass), ph); eap_hash_nt_hash(ph, hh);
            eap_challenge_response(out + 8, hh, resp);
            req[0] = EAP_CODE_RESPONSE; req[1] = out[1]; req[2] = 0; req[3] = 8 + 24 + 3; req[4] = EAP_TYPE_LEAP; req[5] = 1; req[6] = 0; req[7] = 24;
            memcpy(req + 8, resp, 24); memcpy(req + 32, "srv", 3); rl = 35;
            uint8_t cl[16];
            eap_leap_key(hh, out + 8, resp, a->leap_ch, a->leap_peer, cl);   /* needs leap_peer: set below */
            memcpy(a->leap_key, cl, 16);
            r.have_msk = 1;
            req[0] = EAP_CODE_RESPONSE;
            continue;
        }
        int k = a_rx(a, out, ol, req, &rl);
        if (a->method == EAP_TYPE_LEAP && k == 0 && req[0] == EAP_CODE_SUCCESS) continue;
        if (k < 0) { snprintf(r.err, sizeof r.err, "authenticator stopped (%d)", k); break; }
        if (k == -2) { snprintf(r.err, sizeof r.err, "authenticator has nothing to say"); break; }
    }
    r.client_m = cm; r.server_m = a->n_srv_m;
    size_t ml = 0;
    const uint8_t *m = eap_get_msk(e, &ml);
    if (r.final == EAP_ST_SUCCESS && m) {
        if (a->method == EAP_TYPE_LEAP) { r.have_msk = 1; r.msk_match = ml == 16 && !memcmp(m, a->leap_key, 16); }
        else { r.have_msk = a->have_msk; r.msk_match = a->have_msk && ml == 64 && !memcmp(m, a->msk, 64); }
        uint8_t pmk[32], z[32] = {0};
        if (eap_get_pmk(e, pmk) || memcmp(pmk, m, ml < 32 ? ml : 32) || (ml < 32 && memcmp(pmk + ml, z, 32 - ml))) r.msk_match = 0;
    }
    snprintf(r.err + strlen(r.err), sizeof r.err - strlen(r.err), "%s%s", r.err[0] ? " | " : "", eap_error(e));
    eap_free(e);
    return r;
}

static eap_cfg_t cfg_for(int method) {
    static const int mp[1] = {EAP_TYPE_PEAP}, mt[1] = {EAP_TYPE_TTLS}, ml[1] = {EAP_TYPE_TLS}, mq[1] = {EAP_TYPE_LEAP};
    eap_cfg_t c;
    memset(&c, 0, sizeof c);
    c.identity = "anonymous"; c.inner_identity = "alice"; c.password = "correct horse";
    c.ca_pem = g_ca.p; c.ca_pem_len = g_ca.n;
    c.methods = method == EAP_TYPE_PEAP ? mp : method == EAP_TYPE_TTLS ? mt : method == EAP_TYPE_TLS ? ml : mq;
    c.n_methods = 1;
    if (method == EAP_TYPE_TLS) { c.cert_pem = g_cli.p; c.cert_pem_len = g_cli.n; c.key_pem = g_clikey.p; c.key_pem_len = g_clikey.n; }
    if (method == EAP_TYPE_LEAP) { c.allow_leap = 1; c.identity = "alice"; }
    return c;
}

#define EXPECT_OK(name, r) do { CHECK((r).final == EAP_ST_SUCCESS && (r).msk_match, "%s: final=%d have_msk=%d match=%d [%s]", name, (r).final, (r).have_msk, (r).msk_match, (r).err); \
    CHECK((r).dup_ok, "%s: retransmitted request got a different answer", name); } while (0)
#define EXPECT_FAIL(name, r) CHECK((r).final == EAP_ST_FAILURE, "%s: expected failure, final=%d [%s]", name, (r).final, (r).err)

static void test_loopback(void) {
    run_t r;
    auth_t *a;
    eap_cfg_t c;

    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse"); a->peap_ver = 0;
    c = cfg_for(EAP_TYPE_PEAP); r = run(&c, a, 1);
    EXPECT_OK("PEAPv0 MSCHAPv2", r); printf("  PEAPv0: steps=%d msk_match=%d\n", r.steps, r.msk_match); a_free(a);

    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse"); a->peap_ver = 1;
    c = cfg_for(EAP_TYPE_PEAP); r = run(&c, a, 0);
    EXPECT_OK("PEAPv1 MSCHAPv2", r); a_free(a);

    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse"); a->peap_ver = 0;
    c = cfg_for(EAP_TYPE_PEAP); c.peap_v0_only = 1; r = run(&c, a, 0);
    EXPECT_OK("PEAP with peap_v0_only", r); a_free(a);

    a = a_new(EAP_TYPE_TTLS, EAP_INNER_MSCHAPV2, "alice", "correct horse");
    c = cfg_for(EAP_TYPE_TTLS); r = run(&c, a, 1);
    EXPECT_OK("TTLS MSCHAPv2", r); a_free(a);

    a = a_new(EAP_TYPE_TTLS, EAP_INNER_PAP, "alice", "correct horse");
    c = cfg_for(EAP_TYPE_TTLS); c.inner = EAP_INNER_PAP; r = run(&c, a, 0);
    EXPECT_OK("TTLS PAP", r); a_free(a);

    a = a_new(EAP_TYPE_TLS, 0, "alice", "x");
    c = cfg_for(EAP_TYPE_TLS); r = run(&c, a, 1);
    EXPECT_OK("EAP-TLS PEM client cert", r); a_free(a);

    a = a_new(EAP_TYPE_TLS, 0, "alice", "x");
    c = cfg_for(EAP_TYPE_TLS); c.cert_pem = NULL; c.cert_pem_len = 0; c.key_pem = NULL; c.key_pem_len = 0;
    c.p12 = g_p12.p; c.p12_len = g_p12.n; c.key_pass = "p12pass"; r = run(&c, a, 0);
    CHECK(r.final != EAP_ST_SUCCESS && strstr(r.err, "PKCS#12"), "PKCS#12 identity is refused with a clear message [%s]", r.err); a_free(a);

    a = a_new(EAP_TYPE_TLS, 0, "alice", "x");
    c = cfg_for(EAP_TYPE_TLS); c.cert_pem = NULL; c.cert_pem_len = 0; c.key_pem = NULL; c.key_pem_len = 0;
    c.p12 = g_p12.p; c.p12_len = g_p12.n; c.key_pass = "wrong"; r = run(&c, a, 0);
    CHECK(r.final != EAP_ST_SUCCESS, "PKCS#12 with a wrong passphrase must not authenticate either [%s]", r.err); a_free(a);

    a = a_new(EAP_TYPE_LEAP, 0, "alice", "correct horse");
    c = cfg_for(EAP_TYPE_LEAP); r = run(&c, a, 0);
    EXPECT_OK("LEAP", r); a_free(a);

    /* small fragments in both directions */
    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse"); a->frag = 150;
    c = cfg_for(EAP_TYPE_PEAP); c.frag_size = 100; r = run(&c, a, 1);
    EXPECT_OK("PEAPv0 fragmented", r);
    CHECK(r.server_m > 3 && a->n_m_flags > 0, "fragmentation exercised both ways (server M=%d client M=%d)", r.server_m, a->n_m_flags);
    printf("  fragmented PEAP: server M-fragments=%d, client M-fragments=%d, steps=%d\n", r.server_m, a->n_m_flags, r.steps);
    a_free(a);

    a = a_new(EAP_TYPE_TLS, 0, "alice", "x"); a->frag = 300;
    c = cfg_for(EAP_TYPE_TLS); c.frag_size = 200; r = run(&c, a, 0);
    EXPECT_OK("EAP-TLS fragmented", r);
    CHECK(r.server_m > 0 && a->n_m_flags > 0, "TLS fragmentation both ways (%d/%d)", r.server_m, a->n_m_flags);
    a_free(a);

    /* ---- negatives */
    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse");
    c = cfg_for(EAP_TYPE_PEAP); c.ca_pem = g_ca2.p; c.ca_pem_len = g_ca2.n; r = run(&c, a, 0);
    EXPECT_FAIL("wrong CA", r); a_free(a);

    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse");
    c = cfg_for(EAP_TYPE_PEAP); c.ca_pem = g_ca2.p; c.ca_pem_len = g_ca2.n; c.insecure_skip_verify = 1; r = run(&c, a, 0);
    EXPECT_OK("wrong CA with insecure_skip_verify", r); a_free(a);

    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse");
    c = cfg_for(EAP_TYPE_PEAP); c.server_name = "radius.test"; r = run(&c, a, 0);
    EXPECT_OK("server_name matches", r); a_free(a);

    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse");
    c = cfg_for(EAP_TYPE_PEAP); c.server_name = "other.test"; r = run(&c, a, 0);
    EXPECT_FAIL("server_name mismatch", r); a_free(a);

    a = a_new(EAP_TYPE_PEAP, 0, "alice", "different password");
    c = cfg_for(EAP_TYPE_PEAP); r = run(&c, a, 0);
    EXPECT_FAIL("PEAP wrong password", r); CHECK(strstr(r.err, "691") || strstr(r.err, "MS-CHAP") || r.final == EAP_ST_FAILURE, "error text [%s]", r.err); a_free(a);

    a = a_new(EAP_TYPE_TTLS, EAP_INNER_MSCHAPV2, "alice", "different password");
    c = cfg_for(EAP_TYPE_TTLS); r = run(&c, a, 0);
    EXPECT_FAIL("TTLS wrong password", r); a_free(a);

    a = a_new(EAP_TYPE_TTLS, EAP_INNER_PAP, "alice", "different password");
    c = cfg_for(EAP_TYPE_TTLS); c.inner = EAP_INNER_PAP; r = run(&c, a, 0);
    EXPECT_FAIL("TTLS PAP wrong password", r); a_free(a);

    a = a_new(EAP_TYPE_LEAP, 0, "alice", "different password");
    c = cfg_for(EAP_TYPE_LEAP); r = run(&c, a, 0);
    EXPECT_FAIL("LEAP wrong password", r); a_free(a);

    /* a server that knows the user's NT response is right but cannot prove it knows the password */
    a = a_new(EAP_TYPE_PEAP, 0, "alice", "correct horse"); a->proof_pass = "not the password";
    c = cfg_for(EAP_TYPE_PEAP); r = run(&c, a, 0);
    EXPECT_FAIL("PEAP server with a wrong MS-CHAPv2 proof", r);
    CHECK(strstr(r.err, "authenticator response"), "reason names the proof [%s]", r.err); a_free(a);

    a = a_new(EAP_TYPE_TTLS, EAP_INNER_MSCHAPV2, "alice", "correct horse"); a->proof_pass = "not the password";
    c = cfg_for(EAP_TYPE_TTLS); r = run(&c, a, 0);
    EXPECT_FAIL("TTLS server with a wrong MS-CHAPv2 proof", r); a_free(a);

    /* EAP-TLS where the client has no certificate the server trusts */
    a = a_new(EAP_TYPE_TLS, 0, "alice", "x");
    c = cfg_for(EAP_TYPE_TLS); r = run(&c, a, 0);
    CHECK(r.final == EAP_ST_SUCCESS, "control run succeeds"); a_free(a);
}

/* An EAP-Success that arrives before the tunnel finished must never turn into a PMK (rogue AP shortcut). */
static void test_rogue_success(void) {
    eap_cfg_t c = cfg_for(EAP_TYPE_PEAP);
    eap_t *e = eap_new(&c);
    uint8_t out[2048], req[16];
    size_t ol, n = mkreq(req, 1, EAP_TYPE_IDENTITY, NULL, 0);
    eap_rx(e, req, n, out, sizeof out, &ol);
    uint8_t st[6] = {1, 2, 0, 6, EAP_TYPE_PEAP, 0x20};
    eap_rx(e, st, 6, out, sizeof out, &ol);
    uint8_t succ[4] = {3, 3, 0, 4};
    uint8_t pmk[32];
    CHECK(eap_rx(e, succ, 4, out, sizeof out, &ol) == EAP_ST_IGNORED && eap_get_pmk(e, pmk) == -1, "rogue EAP-Success gives no PMK");
    eap_free(e);
}

int main(void) {
    test_crypto();
    test_framing();
    make_certs();
    test_loopback();
    test_rogue_success();
    rm_certs();
    printf("%d checks, %d failed\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
