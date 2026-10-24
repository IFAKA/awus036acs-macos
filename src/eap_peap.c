// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_peap.c - PEAP v0 / v1 with an EAP-MSCHAPv2 inner method (draft-josefsson-pppext-eap-tls-eap-06, MS-PEAP).
 * Phase 2 packets: v1 carries full EAP headers; v0 omits Code/Id/Length from our responses (and accepts both forms in
 * requests, as FreeRADIUS sends a full-header Identity request and EAP-TLV packets). The MSK is
 * TLS-PRF(..., "client EAP encryption")[0..64). Crypto-binding TLVs from the server are ignored (not verified).
 * An EAP-Success is accepted once the server has proved knowledge of the password (valid MS-CHAPv2 "S=" value). */
#include "eap_i.h"
#include <ctype.h>
#include <string.h>

static int peap_start(eap_t *e, uint8_t srv_flags) {
    int v = srv_flags & 7;
    if (v > 1) v = 1;
    if (e->cfg.peap_v0_only) v = 0;
    e->peap_ver = v;
    e->flags_ver = (uint8_t)v;
    return 0;
}

static int peap_established(eap_t *e) { return eap_derive_msk(e, "client EAP encryption"); }

/* ---- EAP-MSCHAPv2 peer (inner). d = MS-CHAPv2 packet after the EAP type byte. resp gets the type byte + body. */
static int mschapv2(eap_t *e, const uint8_t *d, size_t n, uint8_t *resp, size_t *rl) {
    if (n < 4) return -1;
    size_t mslen = (size_t)d[2] << 8 | d[3];
    if (mslen > n || mslen < 4) return -1;
    switch (d[0]) {
    case 1: {                                              /* Challenge */
        if (mslen < 5 + 16 || d[4] != 16) return -1;
        memcpy(e->ms_auth_ch, d + 5, 16);
        e->ms_ident = d[1];
        arc4random_buf(e->ms_peer_ch, 16);
        eap_nt_password_hash(e->cfg.password, strlen(e->cfg.password), e->ms_pwhash);
        const char *u = e->cfg.inner_identity;
        size_t ul = strlen(u);
        eap_mschapv2_nt_response(e->ms_auth_ch, e->ms_peer_ch, u, ul, e->ms_pwhash, e->ms_nt);
        size_t o = 0, ml = 4 + 1 + 49 + ul;
        resp[o++] = EAP_TYPE_MSCHAPV2; resp[o++] = 2; resp[o++] = e->ms_ident;
        resp[o++] = (uint8_t)(ml >> 8); resp[o++] = (uint8_t)ml; resp[o++] = 49;
        memcpy(resp + o, e->ms_peer_ch, 16); o += 16;
        memset(resp + o, 0, 8); o += 8;
        memcpy(resp + o, e->ms_nt, 24); o += 24;
        resp[o++] = 0;
        memcpy(resp + o, u, ul); o += ul;
        *rl = o;
        e->ms_state = 1;
        return 0;
    }
    case 3: {                                              /* Success: "S=<40 hex> M=<text>" */
        char want[43];
        size_t ul = strlen(e->cfg.inner_identity);
        int ok = e->ms_state == 1 && mslen >= 4 + 42;
        if (ok) {
            eap_mschapv2_auth_response(e->ms_pwhash, e->ms_nt, e->ms_peer_ch, e->ms_auth_ch, e->cfg.inner_identity, ul, want);
            uint8_t diff = 0;
            for (int i = 0; i < 42; i++) diff |= (uint8_t)(toupper(d[4 + i]) ^ (uint8_t)want[i]);
            ok = diff == 0;
        }
        resp[0] = EAP_TYPE_MSCHAPV2;
        if (ok) { resp[1] = 3; e->ms_state = 2; e->phase2_ok = 1; }
        else { resp[1] = 4; e->ms_state = 3; eap_set_err(e, "MS-CHAPv2: server authenticator response is wrong"); }
        *rl = 2;
        return 0;
    }
    case 4: {                                              /* Failure: "E=691 R=0 C=... V=3 M=..." */
        size_t m = mslen - 4;
        if (m > 100) m = 100;
        char txt[110];
        memcpy(txt, d + 4, m); txt[m] = 0;
        eap_set_err(e, "MS-CHAPv2 failure: %s", txt);
        e->ms_state = 3;
        resp[0] = EAP_TYPE_MSCHAPV2; resp[1] = 4; *rl = 2;
        return 0;
    }
    }
    return -1;
}

/* ---- phase 2 */
static int peap_app(eap_t *e, const uint8_t *in, size_t n) {
    uint8_t reply[600], *r = reply;
    size_t rl = 0, off = 0;
    int code = EAP_CODE_REQUEST, type;
    uint8_t id = e->cur_id;
    const uint8_t *p = in;
    size_t pn = n;
    if (n >= 4 && in[0] >= 1 && in[0] <= 4 && (((size_t)in[2] << 8) | in[3]) == n) {   /* full EAP header */
        code = in[0]; id = in[1]; p = in + 4; pn = n - 4;
    }
    if (code == EAP_CODE_SUCCESS) { return 0; }             /* PEAPv1: tunnelled EAP-Success; outer Success decides */
    if (code == EAP_CODE_FAILURE) { e->ms_state = 3; eap_set_err(e, "PEAP: tunnelled EAP-Failure"); return -1; }
    if (code != EAP_CODE_REQUEST || pn < 1) { eap_set_err(e, "PEAP: bad inner packet"); return -1; }
    type = p[0];
    r += 4;                                                 /* room for a header, filled in below */
    if (type == EAP_TYPE_IDENTITY) {
        size_t il = strlen(e->cfg.inner_identity);
        if (il > 200) il = 200;
        r[0] = EAP_TYPE_IDENTITY; memcpy(r + 1, e->cfg.inner_identity, il); rl = 1 + il;
    } else if (type == EAP_TYPE_MSCHAPV2) {
        if (mschapv2(e, p + 1, pn - 1, r, &rl)) { eap_set_err(e, "PEAP: bad MS-CHAPv2 packet"); return -1; }
    } else if (type == EAP_TYPE_TLV) {
        int result = 0;
        size_t o = 1;
        while (o + 4 <= pn) {
            unsigned t = ((unsigned)p[o] << 8 | p[o + 1]) & 0x3fff;
            size_t l = (size_t)p[o + 2] << 8 | p[o + 3];
            if (o + 4 + l > pn) return -1;
            if (t == 3 && l == 2) result = p[o + 4] << 8 | p[o + 5];
            o += 4 + l;
        }
        if (result == 1 && e->ms_state != 2) { eap_set_err(e, "PEAP: server reports success without proving itself"); return -1; }
        if (result == 2) { e->ms_state = 3; eap_set_err(e, "PEAP: server says authentication failed"); }
        if (!result) { eap_set_err(e, "PEAP: TLV without Result"); return -1; }
        r[0] = EAP_TYPE_TLV; r[1] = 0x80; r[2] = 0x03; r[3] = 0; r[4] = 2; r[5] = (uint8_t)(result >> 8); r[6] = (uint8_t)result;
        rl = 7;
        if (result == 1) e->phase2_ok = 1;
        id = e->cur_id;
    } else {                                                /* Nak: we only do MS-CHAPv2 inside */
        r[0] = EAP_TYPE_NAK; r[1] = EAP_TYPE_MSCHAPV2; rl = 2;
    }
    if (e->peap_ver == 0 && type != EAP_TYPE_TLV) { off = 4; }       /* headerless response */
    else {
        reply[0] = EAP_CODE_RESPONSE; reply[1] = id; reply[2] = (uint8_t)((rl + 4) >> 8); reply[3] = (uint8_t)(rl + 4);
    }
    return eap_tun_send(e, reply + off, rl + (off ? 0 : 4));
}

const eap_tlsm_t eap_peap_m = { EAP_TYPE_PEAP, "client EAP encryption", peap_start, peap_established, peap_app };
