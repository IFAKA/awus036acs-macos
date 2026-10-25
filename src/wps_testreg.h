// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wps_testreg.h - the in-memory WPS REGISTRAR used by tests only (src/test_wps.c and src/test_link_wps.c). Written by the same
 * author from the same reading of the spec as src/wps.c: it proves the two halves agree, not that a real AP agrees.
 * Header-only on purpose; needs wps.h, <stdio.h>, <stdlib.h>, <string.h> included first. */
#ifndef WPS_TESTREG_H
#define WPS_TESTREG_H
#include "bignum_dh.h"
/* also needs a CHECK(cond) macro in scope */

/* deterministic "random" bytes (xorshift64*) so runs are reproducible */
static uint64_t rs = 0x9E3779B97F4A7C15ull;
static void det_rand(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; b[i] = (uint8_t)((rs * 0x2545F4914F6CDD1Dull) >> 56); }
}

/* ---------------------------------------------------------------- in-memory registrar (test only) */
typedef struct {
    const char *pin_msg;         /* password used for the R-Hashes it sends */
    const char *pin_ver;         /* password used to check the E-Hashes it receives (differs only in the split-PIN test) */
    int m2d, corrupt_m4, bad_pk;
    uint16_t pwid;
    const char *ssid, *key; uint16_t auth, encr;
    uint8_t priv[192], pkr[192], pke[192], ne[16], nr[16], mac[6], rs1[16], rs2[16], eh1[32], eh2[32];
    wps_keys_t k; uint8_t psk1[16], psk2[16], vpsk1[16], vpsk2[16];
    uint8_t prev[WPS_MAX_MSG]; size_t prev_len;
    int stage;                   /* 0 want M1, 1 M3, 2 M5, 3 M7, 4 Done, 5 registered, -1 refused */
    uint16_t nack_err;
    uint8_t msg[13][WPS_MAX_MSG]; size_t msg_len[13];   /* transcript by message type */
} reg_t;

static void reg_init(reg_t *r, const char *pin) {
    memset(r, 0, sizeof *r);
    r->pin_msg = r->pin_ver = pin; r->pwid = 0xFFFF;
    r->ssid = "MyTestNet"; r->key = "correct horse battery"; r->auth = WPS_AUTH_WPA2PSK; r->encr = WPS_ENCR_AES;
    det_rand(r->priv, 192); det_rand(r->nr, 16); det_rand(r->rs1, 16); det_rand(r->rs2, 16);
    dh_public(r->priv, r->pkr);
}
static void reg_log(reg_t *r, const uint8_t *m, size_t n) {
    uint8_t t = 0; wps_tlv_get8(m, n, WPS_ATTR_MSG_TYPE, &t);
    if (t < 13 && n <= WPS_MAX_MSG) { memcpy(r->msg[t], m, n); r->msg_len[t] = n; }
}
static int reg_auth_ok(reg_t *r, const uint8_t *m, size_t n) {
    uint8_t a[8];
    if (n < 12) return 0;
    wps_authenticator(r->k.auth, r->prev, r->prev_len, m, n - 12, a);
    return memcmp(a, m + n - 8, 8) == 0 && m[n - 12] == 0x10 && m[n - 11] == 0x05;
}
static void reg_seal_auth(reg_t *r, wps_buf_t *b) {
    uint8_t a[8]; wps_authenticator(r->k.auth, r->prev, r->prev_len, b->p, b->len, a);
    wps_put(b, WPS_ATTR_AUTHENTICATOR, a, 8);
    memcpy(r->prev, b->p, b->len); r->prev_len = b->len;
}
static int reg_nack(reg_t *r, uint16_t err, uint8_t *out, size_t cap) {
    wps_buf_t b; wps_buf_init(&b, out, cap);
    wps_put8(&b, WPS_ATTR_VERSION, 0x10); wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_NACK);
    wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, r->ne, 16); wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, r->nr, 16);
    wps_put16(&b, WPS_ATTR_CONFIG_ERROR, err);
    r->stage = -1; r->nack_err = err;
    return (int)b.len;
}
/* encrypted-settings message from registrar: type, inner TLVs, optional extra plain attrs already in b */
static int reg_enc_msg(reg_t *r, uint8_t type, const uint8_t *inner, size_t il, int with_hashes, uint8_t *out, size_t cap) {
    uint8_t iv[16], enc[512];
    det_rand(iv, 16);
    int n = wps_encr_seal(&r->k, iv, inner, il, enc, sizeof enc);
    if (type == WPS_MSG_M4 && r->corrupt_m4) enc[n - 3] ^= 0x55;
    wps_buf_t b; wps_buf_init(&b, out, cap);
    wps_put8(&b, WPS_ATTR_VERSION, 0x10); wps_put8(&b, WPS_ATTR_MSG_TYPE, type);
    wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, r->ne, 16);
    if (with_hashes) {
        uint8_t h1[32], h2[32];
        wps_hash(r->k.auth, r->rs1, r->psk1, r->pke, r->pkr, h1);
        wps_hash(r->k.auth, r->rs2, r->psk2, r->pke, r->pkr, h2);
        wps_put(&b, WPS_ATTR_R_HASH1, h1, 32); wps_put(&b, WPS_ATTR_R_HASH2, h2, 32);
    }
    wps_put(&b, WPS_ATTR_ENCR_SETTINGS, enc, (size_t)n);
    wps_put_vendor_v2(&b);
    reg_seal_auth(r, &b);
    return (int)b.len;
}
static void put_tlv(uint8_t *d, size_t *n, uint16_t t, const void *v, size_t l) {
    d[*n] = (uint8_t)(t >> 8); d[*n + 1] = (uint8_t)t; d[*n + 2] = (uint8_t)(l >> 8); d[*n + 3] = (uint8_t)l;
    if (l) memcpy(d + *n + 4, v, l);
    *n += 4 + l;
}

/* process one enrollee message; returns reply length, 0 for none */
static int reg_rx(reg_t *r, const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    uint8_t mt = 0; wps_tlv_get8(in, len, WPS_ATTR_MSG_TYPE, &mt);
    reg_log(r, in, len);
    if (mt == WPS_MSG_NACK) { r->stage = -1; return 0; }
    if (mt == WPS_MSG_ACK) return 0;
    if (mt == WPS_MSG_DONE) { r->stage = r->stage == 4 ? 5 : -1; return 0; }
    wps_buf_t b;
    if (mt == WPS_MSG_M1 && r->stage == 0) {
        uint16_t pw;
        CHECK(wps_tlv_check(in, len) == 0);
        CHECK(!wps_tlv_get(in, len, WPS_ATTR_ENROLLEE_NONCE, r->ne, 16));
        CHECK(!wps_tlv_get(in, len, WPS_ATTR_MAC, r->mac, 6));
        CHECK(!wps_tlv_get(in, len, WPS_ATTR_PUBLIC_KEY, r->pke, 192));
        CHECK(!wps_tlv_get16(in, len, WPS_ATTR_DEV_PWID, &pw));
        if (r->pwid == 0xFFFF) r->pwid = pw;
        if (r->bad_pk) { memset(r->pkr, 0, 192); r->pkr[191] = 1; }
        if (r->m2d) {
            wps_buf_init(&b, out, cap);
            wps_put8(&b, WPS_ATTR_VERSION, 0x10); wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_M2D);
            wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, r->ne, 16); wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, r->nr, 16);
            wps_put16(&b, WPS_ATTR_CONFIG_ERROR, 0); wps_put16(&b, WPS_ATTR_DEV_PWID, 0);
            return (int)b.len;
        }
        uint8_t shared[192];
        CHECK(dh_shared(r->priv, r->pke, shared) == 0);
        wps_derive_keys(shared, r->ne, r->mac, r->nr, &r->k);
        wps_psk(r->k.auth, r->pin_msg, r->psk1, r->psk2);
        wps_psk(r->k.auth, r->pin_ver, r->vpsk1, r->vpsk2);
        memcpy(r->prev, in, len); r->prev_len = len;
        uint8_t uuid_r[16]; det_rand(uuid_r, 16);
        wps_buf_init(&b, out, cap);
        wps_put8(&b, WPS_ATTR_VERSION, 0x10); wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_M2);
        wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, r->ne, 16); wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, r->nr, 16);
        wps_put(&b, WPS_ATTR_UUID_R, uuid_r, 16); wps_put(&b, WPS_ATTR_PUBLIC_KEY, r->pkr, 192);
        wps_put16(&b, WPS_ATTR_AUTH_FLAGS, 0x3F); wps_put16(&b, WPS_ATTR_ENCR_FLAGS, 0x0F); wps_put8(&b, 0x100D, 1);
        wps_put16(&b, WPS_ATTR_CONFIG_METHODS, 0x0188);
        wps_put(&b, WPS_ATTR_MANUFACTURER, "TestAP", 6); wps_put(&b, WPS_ATTR_MODEL_NAME, "T1", 2);
        wps_put(&b, WPS_ATTR_MODEL_NUMBER, "1", 1); wps_put(&b, WPS_ATTR_SERIAL, "0001", 4);
        wps_put(&b, WPS_ATTR_PRIMARY_DEVTYPE, "\x00\x06\x00\x50\xF2\x04\x00\x01", 8);
        wps_put(&b, WPS_ATTR_DEV_NAME, "TestAP", 6); wps_put8(&b, WPS_ATTR_RF_BANDS, 3);
        wps_put16(&b, WPS_ATTR_ASSOC_STATE, 0); wps_put16(&b, WPS_ATTR_CONFIG_ERROR, 0); wps_put16(&b, WPS_ATTR_DEV_PWID, r->pwid);
        wps_put_vendor_v2(&b);
        reg_seal_auth(r, &b);
        r->stage = 1; return (int)b.len;
    }
    if (mt == WPS_MSG_M3 && r->stage == 1) {
        uint8_t nr[16];
        if (!reg_auth_ok(r, in, len) || wps_tlv_get(in, len, WPS_ATTR_REGISTRAR_NONCE, nr, 16) || memcmp(nr, r->nr, 16))
            return reg_nack(r, 0, out, cap);
        CHECK(!wps_tlv_get(in, len, WPS_ATTR_E_HASH1, r->eh1, 32) && !wps_tlv_get(in, len, WPS_ATTR_E_HASH2, r->eh2, 32));
        memcpy(r->prev, in, len); r->prev_len = len;
        uint8_t inner[20]; size_t n = 0; put_tlv(inner, &n, WPS_ATTR_R_SNONCE1, r->rs1, 16);
        r->stage = 2; return reg_enc_msg(r, WPS_MSG_M4, inner, n, 1, out, cap);
    }
    if (mt == WPS_MSG_M5 && r->stage == 2) {
        uint8_t pl[128], es[16], h[32];
        if (!reg_auth_ok(r, in, len)) return reg_nack(r, 0, out, cap);
        size_t el; const uint8_t *enc = wps_tlv_find(in, len, WPS_ATTR_ENCR_SETTINGS, &el);
        int pn = enc ? wps_encr_open(&r->k, enc, el, pl, sizeof pl) : -1;
        if (pn < 0 || wps_tlv_get(pl, (size_t)pn, WPS_ATTR_E_SNONCE1, es, 16)) return reg_nack(r, WPS_CFG_DECRYPTION_FAILURE, out, cap);
        wps_hash(r->k.auth, es, r->vpsk1, r->pke, r->pkr, h);
        if (memcmp(h, r->eh1, 32)) return reg_nack(r, WPS_CFG_PIN_AUTH_FAILURE, out, cap);
        memcpy(r->prev, in, len); r->prev_len = len;
        uint8_t inner[20]; size_t n = 0; put_tlv(inner, &n, WPS_ATTR_R_SNONCE2, r->rs2, 16);
        r->stage = 3; return reg_enc_msg(r, WPS_MSG_M6, inner, n, 0, out, cap);
    }
    if (mt == WPS_MSG_M7 && r->stage == 3) {
        uint8_t pl[128], es[16], h[32];
        if (!reg_auth_ok(r, in, len)) return reg_nack(r, 0, out, cap);
        size_t el; const uint8_t *enc = wps_tlv_find(in, len, WPS_ATTR_ENCR_SETTINGS, &el);
        int pn = enc ? wps_encr_open(&r->k, enc, el, pl, sizeof pl) : -1;
        if (pn < 0 || wps_tlv_get(pl, (size_t)pn, WPS_ATTR_E_SNONCE2, es, 16)) return reg_nack(r, WPS_CFG_DECRYPTION_FAILURE, out, cap);
        wps_hash(r->k.auth, es, r->vpsk2, r->pke, r->pkr, h);
        if (memcmp(h, r->eh2, 32)) return reg_nack(r, WPS_CFG_PIN_AUTH_FAILURE, out, cap);
        memcpy(r->prev, in, len); r->prev_len = len;
        uint8_t cred[256], inner[300]; size_t cn = 0, n = 0; uint8_t idx = 1, ty[2];
        put_tlv(cred, &cn, WPS_ATTR_NET_INDEX, &idx, 1);
        put_tlv(cred, &cn, WPS_ATTR_SSID, r->ssid, strlen(r->ssid));
        ty[0] = (uint8_t)(r->auth >> 8); ty[1] = (uint8_t)r->auth; put_tlv(cred, &cn, WPS_ATTR_AUTH_TYPE, ty, 2);
        ty[0] = (uint8_t)(r->encr >> 8); ty[1] = (uint8_t)r->encr; put_tlv(cred, &cn, WPS_ATTR_ENCR_TYPE, ty, 2);
        put_tlv(cred, &cn, WPS_ATTR_NET_KEY, r->key, strlen(r->key));
        put_tlv(cred, &cn, WPS_ATTR_MAC, "\xAA\xBB\xCC\xDD\xEE\x01", 6);
        put_tlv(inner, &n, WPS_ATTR_CRED, cred, cn);
        r->stage = 4; return reg_enc_msg(r, WPS_MSG_M8, inner, n, 0, out, cap);
    }
    return 0;
}

#endif
