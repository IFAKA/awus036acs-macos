// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_ttls.c - EAP-TTLS v0 (RFC 5281) with MS-CHAPv2 or PAP in the tunnel, carried as Diameter AVPs (RFC 5281 10,
 * MS-CHAP AVPs from RFC 2548). MSK = TLS-PRF(..., "ttls keying material")[0..64); the MS-CHAPv2 authenticator
 * challenge and ident are TLS-PRF(..., "ttls challenge")[0..17). */
#include "eap_i.h"
#include <ctype.h>
#include <string.h>

#define VENDOR_MS 311
#define AVP_USER_NAME 1
#define AVP_USER_PASSWORD 2
#define MS_CHAP_ERROR 2
#define MS_CHAP_CHALLENGE 11
#define MS_CHAP2_RESPONSE 25
#define MS_CHAP2_SUCCESS 26

static size_t avp(uint8_t *o, uint32_t code, uint32_t vendor, const uint8_t *v, size_t vl) {
    size_t hl = vendor ? 12 : 8, n = hl + vl;
    o[0] = (uint8_t)(code >> 24); o[1] = (uint8_t)(code >> 16); o[2] = (uint8_t)(code >> 8); o[3] = (uint8_t)code;
    o[4] = (uint8_t)((vendor ? 0x80 : 0) | 0x40);                 /* V (if vendor) and M */
    o[5] = (uint8_t)(n >> 16); o[6] = (uint8_t)(n >> 8); o[7] = (uint8_t)n;
    if (vendor) { o[8] = (uint8_t)(vendor >> 24); o[9] = (uint8_t)(vendor >> 16); o[10] = (uint8_t)(vendor >> 8); o[11] = (uint8_t)vendor; }
    memcpy(o + hl, v, vl);
    size_t pad = (4 - (n & 3)) & 3;
    memset(o + n, 0, pad);
    return n + pad;
}

static int ttls_start(eap_t *e, uint8_t f) { (void)f; e->flags_ver = 0; return 0; }

static int ttls_established(eap_t *e) {
    if (eap_derive_msk(e, "ttls keying material")) return -1;
    uint8_t buf[512], *o = buf;
    const char *u = e->cfg.inner_identity;
    size_t ul = strlen(u);
    if (ul > 200) { eap_set_err(e, "inner identity too long"); return -1; }
    o += avp(o, AVP_USER_NAME, 0, (const uint8_t *)u, ul);
    if (e->cfg.inner == EAP_INNER_PAP) {
        size_t pl = strlen(e->cfg.password), padded = pl ? (pl + 15) & ~(size_t)15 : 16;
        uint8_t pw[128];
        if (padded > 128) { eap_set_err(e, "PAP password too long"); return -1; }
        memset(pw, 0, sizeof pw); memcpy(pw, e->cfg.password, pl);
        o += avp(o, AVP_USER_PASSWORD, 0, pw, padded);
        e->phase2_ok = 1;                               /* success is the outer EAP-Success */
    } else {
        uint8_t ch[17], resp[50];
        if (tlsp_export(e->tls, "ttls challenge", ch, sizeof ch)) { eap_set_err(e, "ttls challenge export failed"); return -1; }
        memcpy(e->ms_auth_ch, ch, 16); e->ms_ident = ch[16];
        arc4random_buf(e->ms_peer_ch, 16);
        eap_nt_password_hash(e->cfg.password, strlen(e->cfg.password), e->ms_pwhash);
        eap_mschapv2_nt_response(e->ms_auth_ch, e->ms_peer_ch, u, ul, e->ms_pwhash, e->ms_nt);
        resp[0] = e->ms_ident; resp[1] = 0;
        memcpy(resp + 2, e->ms_peer_ch, 16); memset(resp + 18, 0, 8); memcpy(resp + 26, e->ms_nt, 24);
        o += avp(o, MS_CHAP_CHALLENGE, VENDOR_MS, e->ms_auth_ch, 16);
        o += avp(o, MS_CHAP2_RESPONSE, VENDOR_MS, resp, 50);
        e->ms_state = 1;
    }
    e->ttls_sent = 1;
    return eap_tun_send(e, buf, (size_t)(o - buf));
}

static int ttls_app(eap_t *e, const uint8_t *d, size_t n) {
    size_t o = 0;
    while (o + 8 <= n) {
        uint32_t code = (uint32_t)d[o] << 24 | (uint32_t)d[o + 1] << 16 | (uint32_t)d[o + 2] << 8 | d[o + 3];
        uint8_t fl = d[o + 4];
        size_t len = (size_t)d[o + 5] << 16 | (size_t)d[o + 6] << 8 | d[o + 7], hl = 8;
        uint32_t vendor = 0;
        if (fl & 0x80) {
            if (o + 12 > n) return -1;
            vendor = (uint32_t)d[o + 8] << 24 | (uint32_t)d[o + 9] << 16 | (uint32_t)d[o + 10] << 8 | d[o + 11];
            hl = 12;
        }
        if (len < hl || o + len > n) { eap_set_err(e, "TTLS: malformed AVP"); return -1; }
        const uint8_t *v = d + o + hl;
        size_t vl = len - hl;
        if (vendor == VENDOR_MS && code == MS_CHAP2_SUCCESS) {
            char want[43];
            int ok = e->ms_state == 1 && vl >= 1 + 42 && v[0] == e->ms_ident;
            if (ok) {
                eap_mschapv2_auth_response(e->ms_pwhash, e->ms_nt, e->ms_peer_ch, e->ms_auth_ch, e->cfg.inner_identity,
                                           strlen(e->cfg.inner_identity), want);
                uint8_t diff = 0;
                for (int i = 0; i < 42; i++) diff |= (uint8_t)(toupper(v[1 + i]) ^ (uint8_t)want[i]);
                ok = diff == 0;
            }
            if (!ok) { e->ms_state = 3; eap_set_err(e, "TTLS: MS-CHAP2-Success does not verify"); return -1; }
            e->ms_state = 2; e->phase2_ok = 1;
        } else if (vendor == VENDOR_MS && code == MS_CHAP_ERROR) {
            char txt[100];
            size_t m = vl > 1 ? vl - 1 : 0;
            if (m > 90) m = 90;
            memcpy(txt, v + 1, m); txt[m] = 0;
            e->ms_state = 3;
            eap_set_err(e, "TTLS MS-CHAP error: %s", txt);
            return -1;
        }
        o += (len + 3) & ~(size_t)3;
    }
    return 0;
}

const eap_tlsm_t eap_ttls_m = { EAP_TYPE_TTLS, "ttls keying material", ttls_start, ttls_established, ttls_app };
