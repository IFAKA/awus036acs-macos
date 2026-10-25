// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_testauth.h - TEST ONLY. Test certificates (made with the openssl CLI) and a small EAP authenticator (the "RADIUS server" side:
 * TLS 1.2 server through eap_tlsp, PEAP/MS-CHAPv2, TTLS MS-CHAPv2 or PAP, EAP-TLS, LEAP). Shared by test_eap.c (talks to the
 * supplicant directly) and test_link_eap.c (talks through link.c and a fake AP). Header-only on purpose, like wps_testreg.h. */
#ifndef EAP_TESTAUTH_H
#define EAP_TESTAUTH_H
#include "eap_i.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#pragma GCC diagnostic ignored "-Wunused-function"

#ifndef OPENSSL_BIN
#define OPENSSL_BIN "openssl"
#endif

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


#endif
