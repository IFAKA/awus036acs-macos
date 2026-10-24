// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_leap.c - Cisco LEAP. INSECURE: the exchange is an NT-hash challenge/response in the clear, so a passive
 * capture lets anybody run a dictionary attack at billions of guesses per second (ASLEAP). Only enabled by
 * eap_cfg_t.allow_leap. Flow (mirrors hostap eap_leap.c): AP Request(8-byte challenge) -> our Response(24 bytes);
 * AP EAP-Success -> our Request(8-byte challenge of our own); AP Response(24 bytes) -> verified: done. */
#include "eap_i.h"
#include <string.h>

static void pwhash(eap_t *e, uint8_t h[16]) { eap_nt_password_hash(e->cfg.password, strlen(e->cfg.password), h); }

enum { L_WAIT_CHAL = 0, L_WAIT_SUCCESS = 1, L_WAIT_RESP = 2, L_DONE = 3 };

static size_t put(uint8_t *o, int code, uint8_t id, const uint8_t *val, size_t vl, const char *name) {
    size_t nl = strlen(name), n = 0;
    o[n++] = (uint8_t)code; o[n++] = id; n += 2;
    o[n++] = EAP_TYPE_LEAP; o[n++] = 1; o[n++] = 0; o[n++] = (uint8_t)vl;
    memcpy(o + n, val, vl); n += vl;
    memcpy(o + n, name, nl); n += nl;
    o[2] = (uint8_t)(n >> 8); o[3] = (uint8_t)n;
    return n;
}

int eap_leap_rx(eap_t *e, const uint8_t *pkt, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    int code = pkt[0];
    uint8_t id = pkt[1], h[16], hh[16];
    *out_len = 0;
    if (cap < 128 + strlen(e->cfg.identity)) return EAP_ST_IGNORED;
    if (code == EAP_CODE_REQUEST && e->leap_state == L_WAIT_CHAL) {
        if (len < 8 + 1 || pkt[4] != EAP_TYPE_LEAP || pkt[5] != 1 || pkt[7] != 8 || len < 8 + 8) return EAP_ST_IGNORED;
        memcpy(e->leap_ap_ch, pkt + 8, 8);              /* challenge the AP gave us (hostap: "peer_challenge") */
        pwhash(e, h);
        eap_challenge_response(e->leap_ap_ch, h, e->leap_peer_resp);
        *out_len = put(out, EAP_CODE_RESPONSE, id, e->leap_peer_resp, 24, e->cfg.identity);
        e->leap_state = L_WAIT_SUCCESS;
        return EAP_ST_CONTINUE;
    }
    if (code == EAP_CODE_SUCCESS && e->leap_state == L_WAIT_SUCCESS) {
        arc4random_buf(e->leap_peer_ch, 8);              /* our own challenge to the AP */
        *out_len = put(out, EAP_CODE_REQUEST, id, e->leap_peer_ch, 8, e->cfg.identity);
        e->leap_state = L_WAIT_RESP;
        return EAP_ST_CONTINUE;
    }
    if (code == EAP_CODE_RESPONSE && e->leap_state == L_WAIT_RESP) {
        if (len < 8 + 24 || pkt[4] != EAP_TYPE_LEAP || pkt[5] != 1 || pkt[7] != 24) return EAP_ST_IGNORED;
        uint8_t exp[24], d = 0;
        memcpy(e->leap_ap_resp, pkt + 8, 24);
        pwhash(e, h); eap_hash_nt_hash(h, hh);
        eap_challenge_response(e->leap_peer_ch, hh, exp);
        for (int i = 0; i < 24; i++) d |= exp[i] ^ e->leap_ap_resp[i];
        if (d) { e->state = 2; eap_set_err(e, "LEAP: AP failed the mutual authentication"); return EAP_ST_FAILURE; }
        eap_leap_key(hh, e->leap_peer_ch, e->leap_ap_resp, e->leap_ap_ch, e->leap_peer_resp, e->msk);
        e->msk_len = 16; e->key_ok = e->phase2_ok = 1; e->leap_state = L_DONE; e->state = 1;
        return EAP_ST_SUCCESS;
    }
    return EAP_ST_IGNORED;
}
