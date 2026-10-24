// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wps.c - WPS 2.0 enrollee. See wps.h. */
#include "wps.h"
#include "bignum_dh.h"
#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ small helpers */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}
static void wipe(void *p, size_t n) { memset_s(p, n, 0, n); }
static void be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static void rnd(const wps_cfg_t *c, uint8_t *b, size_t n) {
    if (c->rand_fn) c->rand_fn(b, n); else arc4random_buf(b, n);
}
static void hmac256(const uint8_t *key, size_t klen, const uint8_t *d1, size_t n1, const uint8_t *d2, size_t n2,
                    const uint8_t *d3, size_t n3, const uint8_t *d4, size_t n4, uint8_t out[32]) {
    CCHmacContext c;
    CCHmacInit(&c, kCCHmacAlgSHA256, key, klen);
    if (n1) CCHmacUpdate(&c, d1, n1);
    if (n2) CCHmacUpdate(&c, d2, n2);
    if (n3) CCHmacUpdate(&c, d3, n3);
    if (n4) CCHmacUpdate(&c, d4, n4);
    CCHmacFinal(&c, out);
}

/* ------------------------------------------------------------------ TLV */
void wps_buf_init(wps_buf_t *b, uint8_t *p, size_t cap) { b->p = p; b->cap = cap; b->len = 0; b->err = 0; }
void wps_put(wps_buf_t *b, uint16_t type, const void *v, size_t n) {
    if (b->err || n > 0xFFFF || b->len + 4 + n > b->cap) { b->err = 1; return; }
    be16(b->p + b->len, type); be16(b->p + b->len + 2, (uint16_t)n);
    if (n) memcpy(b->p + b->len + 4, v, n);
    b->len += 4 + n;
}
void wps_put8(wps_buf_t *b, uint16_t type, uint8_t v) { wps_put(b, type, &v, 1); }
void wps_put16(wps_buf_t *b, uint16_t type, uint16_t v) { uint8_t t[2]; be16(t, v); wps_put(b, type, t, 2); }
void wps_put_vendor_v2(wps_buf_t *b) {
    static const uint8_t v[] = {0x00, 0x37, 0x2A, 0x00, 0x01, 0x20};   /* WFA SMI, subelement 0 (Version2), len 1, 2.0 */
    wps_put(b, WPS_ATTR_VENDOR_EXT, v, sizeof v);
}
int wps_tlv_check(const uint8_t *buf, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (len - i < 4) return -1;
        size_t n = rd16(buf + i + 2);
        if (n > len - i - 4) return -1;
        i += 4 + n;
    }
    return 0;
}
const uint8_t *wps_tlv_find(const uint8_t *buf, size_t len, uint16_t type, size_t *vlen) {
    size_t i = 0;
    while (len - i >= 4 && i <= len) {
        size_t n = rd16(buf + i + 2);
        if (n > len - i - 4) return NULL;
        if (rd16(buf + i) == type) { if (vlen) *vlen = n; return buf + i + 4; }
        i += 4 + n;
    }
    return NULL;
}
int wps_tlv_get(const uint8_t *buf, size_t len, uint16_t type, void *out, size_t want) {
    size_t n; const uint8_t *v = wps_tlv_find(buf, len, type, &n);
    if (!v || n != want) return -1;
    memcpy(out, v, n); return 0;
}
int wps_tlv_get16(const uint8_t *buf, size_t len, uint16_t type, uint16_t *out) {
    uint8_t t[2]; if (wps_tlv_get(buf, len, type, t, 2)) return -1;
    *out = rd16(t); return 0;
}
int wps_tlv_get8(const uint8_t *buf, size_t len, uint16_t type, uint8_t *out) { return wps_tlv_get(buf, len, type, out, 1); }

/* ------------------------------------------------------------------ PIN */
int wps_pin_checksum(uint32_t pin) {
    uint32_t acc = 0;
    pin *= 10;
    acc += 3 * ((pin / 10000000) % 10);
    acc += (pin / 1000000) % 10;
    acc += 3 * ((pin / 100000) % 10);
    acc += (pin / 10000) % 10;
    acc += 3 * ((pin / 1000) % 10);
    acc += (pin / 100) % 10;
    acc += 3 * ((pin / 10) % 10);
    return (int)((10 - acc % 10) % 10);
}
int wps_pin_valid(const char *pin) {
    size_t n = pin ? strlen(pin) : 0;
    if (n != 4 && n != 8) return 0;
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) { if (pin[i] < '0' || pin[i] > '9') return 0; v = v * 10 + (uint32_t)(pin[i] - '0'); }
    if (n == 4) return 1;
    return wps_pin_checksum(v / 10) == (int)(v % 10);
}
int wps_pin_generate(uint32_t seven, char out[9]) {
    if (seven >= 10000000) return -1;
    uint32_t v = seven * 10 + (uint32_t)wps_pin_checksum(seven);
    for (int i = 7; i >= 0; i--) { out[i] = (char)('0' + v % 10); v /= 10; }
    out[8] = 0;
    return 0;
}

/* ------------------------------------------------------------------ keys */
void wps_kdk(const uint8_t dhkey[32], const uint8_t n1[16], const uint8_t mac_e[6], const uint8_t n2[16], uint8_t kdk[32]) {
    hmac256(dhkey, 32, n1, 16, mac_e, 6, n2, 16, NULL, 0, kdk);
}
void wps_kdf(const uint8_t kdk[32], uint8_t *out, size_t outlen) {
    static const char label[] = "Wi-Fi Easy and Secure Key Derivation";
    uint32_t bits = (uint32_t)(outlen * 8);
    uint8_t ib[4], bb[4], h[32];
    for (size_t pos = 0, i = 1; pos < outlen; pos += 32, i++) {
        ib[0] = (uint8_t)(i >> 24); ib[1] = (uint8_t)(i >> 16); ib[2] = (uint8_t)(i >> 8); ib[3] = (uint8_t)i;
        bb[0] = (uint8_t)(bits >> 24); bb[1] = (uint8_t)(bits >> 16); bb[2] = (uint8_t)(bits >> 8); bb[3] = (uint8_t)bits;
        hmac256(kdk, 32, ib, 4, (const uint8_t *)label, sizeof label - 1, bb, 4, NULL, 0, h);
        size_t c = outlen - pos < 32 ? outlen - pos : 32;
        memcpy(out + pos, h, c);
    }
    wipe(h, sizeof h);
}
void wps_derive_keys(const uint8_t shared[192], const uint8_t n1[16], const uint8_t mac_e[6], const uint8_t n2[16], wps_keys_t *k) {
    uint8_t dhkey[32], kdk[32], okm[80];
    CC_SHA256(shared, 192, dhkey);
    wps_kdk(dhkey, n1, mac_e, n2, kdk);
    wps_kdf(kdk, okm, sizeof okm);
    memcpy(k->auth, okm, 32); memcpy(k->kwk, okm + 32, 16); memcpy(k->emsk, okm + 48, 32);
    wipe(dhkey, sizeof dhkey); wipe(kdk, sizeof kdk); wipe(okm, sizeof okm);
}
void wps_psk(const uint8_t authkey[32], const char *pin, uint8_t psk1[16], uint8_t psk2[16]) {
    size_t n = strlen(pin), l1 = (n + 1) / 2, l2 = n - l1;
    uint8_t h[32];
    hmac256(authkey, 32, (const uint8_t *)pin, l1, NULL, 0, NULL, 0, NULL, 0, h);
    memcpy(psk1, h, 16);
    hmac256(authkey, 32, (const uint8_t *)pin + l1, l2, NULL, 0, NULL, 0, NULL, 0, h);
    memcpy(psk2, h, 16);
    wipe(h, sizeof h);
}
void wps_hash(const uint8_t authkey[32], const uint8_t snonce[16], const uint8_t psk[16], const uint8_t pke[192],
              const uint8_t pkr[192], uint8_t out[32]) {
    CCHmacContext c;
    CCHmacInit(&c, kCCHmacAlgSHA256, authkey, 32);
    CCHmacUpdate(&c, snonce, 16); CCHmacUpdate(&c, psk, 16);
    CCHmacUpdate(&c, pke, 192); CCHmacUpdate(&c, pkr, 192);
    CCHmacFinal(&c, out);
}
void wps_authenticator(const uint8_t authkey[32], const uint8_t *prev, size_t prev_len, const uint8_t *cur, size_t cur_len, uint8_t out[8]) {
    uint8_t h[32];
    hmac256(authkey, 32, prev, prev_len, cur, cur_len, NULL, 0, NULL, 0, h);
    memcpy(out, h, 8);
}
int wps_encr_seal(const wps_keys_t *k, const uint8_t iv[16], const uint8_t *plain, size_t plen, uint8_t *out, size_t cap) {
    uint8_t tmp[WPS_MAX_MSG];
    if (plen + 12 > sizeof tmp - 16 || 16 + ((plen + 12) / 16 + 1) * 16 > cap) return WPS_ERR_SPACE;
    memcpy(tmp, plain, plen);
    uint8_t h[32];
    hmac256(k->auth, 32, plain, plen, NULL, 0, NULL, 0, NULL, 0, h);
    be16(tmp + plen, WPS_ATTR_KWA); be16(tmp + plen + 2, 8); memcpy(tmp + plen + 4, h, 8);
    memcpy(out, iv, 16);
    size_t moved = 0;
    if (CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, k->kwk, 16, iv, tmp, plen + 12, out + 16, cap - 16, &moved))
        return WPS_ERR_BAD;
    wipe(tmp, sizeof tmp);
    return (int)(16 + moved);
}
int wps_encr_open(const wps_keys_t *k, const uint8_t *in, size_t len, uint8_t *plain, size_t cap) {
    uint8_t tmp[WPS_MAX_MSG];
    if (len < 32 || (len - 16) % 16 || len - 16 > sizeof tmp) return WPS_ERR_BAD;
    size_t moved = 0;
    if (CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, k->kwk, 16, in, in + 16, len - 16, tmp, sizeof tmp, &moved))
        return WPS_ERR_BAD;
    int rc = WPS_ERR_BAD;
    if (moved >= 12 && moved - 12 <= cap) {
        size_t pl = moved - 12; uint8_t h[32];
        hmac256(k->auth, 32, tmp, pl, NULL, 0, NULL, 0, NULL, 0, h);
        if (rd16(tmp + pl) == WPS_ATTR_KWA && rd16(tmp + pl + 2) == 8 && ct_eq(tmp + pl + 4, h, 8)) {
            memcpy(plain, tmp, pl); rc = (int)pl;
        }
    }
    wipe(tmp, sizeof tmp);
    return rc;
}
void wps_uuid_from_mac(const uint8_t mac[6], uint8_t uuid[16]) {
    static const char ns[] = "AWUS036ACS-WPS-UUID-E";
    uint8_t in[sizeof ns + 6], h[32];
    memcpy(in, ns, sizeof ns); memcpy(in + sizeof ns, mac, 6);
    CC_SHA256(in, sizeof in, h);
    memcpy(uuid, h, 16);
    uuid[6] = (uint8_t)((uuid[6] & 0x0F) | 0x50);   /* name-based, version 5 layout */
    uuid[8] = (uint8_t)((uuid[8] & 0x3F) | 0x80);
}

/* ------------------------------------------------------------------ message pieces */
#define VERSION_BYTE 0x10
static const uint8_t DEVTYPE[8] = {0x00, 0x01, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x01};   /* Computer / PC */
#define CFG_METHODS 0x2388      /* virtual display PIN | keypad | virtual push button */
#define OS_VERSION  0x80000001u

static void copy_str(char *dst, size_t cap, const char *src, const char *def) {
    const char *s = src ? src : def;
    size_t n = strlen(s); if (n >= cap) n = cap - 1;
    memcpy(dst, s, n); dst[n] = 0;
}
static void put_str(wps_buf_t *b, uint16_t t, const char *s) { wps_put(b, t, s, strlen(s)); }
static void put32(wps_buf_t *b, uint16_t t, uint32_t v) {
    uint8_t x[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    wps_put(b, t, x, 4);
}
static int fin(const wps_buf_t *b) { return b->err ? WPS_ERR_SPACE : (int)b->len; }

int wps_enrollee_init(wps_enrollee_t *e, const wps_cfg_t *cfg) {
    memset(e, 0, sizeof *e);
    e->cfg = *cfg;
    e->pbc = cfg->pin == NULL;
    if (cfg->pin) {
        if (!wps_pin_valid(cfg->pin)) return WPS_ERR_PIN;
        strncpy(e->pin, cfg->pin, WPS_PIN_MAX);
    } else strcpy(e->pin, "00000000");
    copy_str(e->manufacturer, sizeof e->manufacturer, cfg->manufacturer, "ALFA");
    copy_str(e->model_name, sizeof e->model_name, cfg->model_name, "AWUS036ACS");
    copy_str(e->model_number, sizeof e->model_number, cfg->model_number, "AWUS036ACS");
    copy_str(e->serial, sizeof e->serial, cfg->serial, "12345678");
    copy_str(e->device_name, sizeof e->device_name, cfg->device_name, "AWUS036ACS");
    e->cfg.pin = NULL; e->cfg.manufacturer = e->cfg.model_name = e->cfg.model_number = e->cfg.serial = e->cfg.device_name = NULL; /* copied above */
    e->state = WPS_ST_IDLE;
    return 0;
}
void wps_enrollee_clear(wps_enrollee_t *e) { wipe(e, sizeof *e); }

static uint16_t pwid(const wps_enrollee_t *e) { return e->pbc ? WPS_DEVPW_PBC : WPS_DEVPW_PIN; }

static void set_prev(wps_enrollee_t *e, const uint8_t *m, size_t n) { memcpy(e->prev, m, n); e->prev_len = n; }

int wps_enrollee_start(wps_enrollee_t *e, uint8_t *out, size_t cap) {
    if (e->state != WPS_ST_IDLE) return WPS_ERR_STATE;
    rnd(&e->cfg, e->ne, 16);
    rnd(&e->cfg, e->priv, sizeof e->priv);
    e->priv[0] |= 0x80;
    if (dh_public(e->priv, e->pke)) return WPS_ERR_KEY;
    wps_buf_t b; wps_buf_init(&b, out, cap);
    wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
    wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_M1);
    wps_put(&b, WPS_ATTR_UUID_E, e->cfg.uuid, 16);
    wps_put(&b, WPS_ATTR_MAC, e->cfg.mac, 6);
    wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, e->ne, 16);
    wps_put(&b, WPS_ATTR_PUBLIC_KEY, e->pke, 192);
    wps_put16(&b, WPS_ATTR_AUTH_FLAGS, WPS_AUTH_OPEN | WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK);
    wps_put16(&b, WPS_ATTR_ENCR_FLAGS, WPS_ENCR_NONE | WPS_ENCR_WEP | WPS_ENCR_TKIP | WPS_ENCR_AES);
    wps_put8(&b, WPS_ATTR_CONN_TYPE_FLAGS, 0x01);
    wps_put16(&b, WPS_ATTR_CONFIG_METHODS, CFG_METHODS);
    wps_put8(&b, WPS_ATTR_WPS_STATE, 0x01);
    put_str(&b, WPS_ATTR_MANUFACTURER, e->manufacturer);
    put_str(&b, WPS_ATTR_MODEL_NAME, e->model_name);
    put_str(&b, WPS_ATTR_MODEL_NUMBER, e->model_number);
    put_str(&b, WPS_ATTR_SERIAL, e->serial);
    wps_put(&b, WPS_ATTR_PRIMARY_DEVTYPE, DEVTYPE, 8);
    put_str(&b, WPS_ATTR_DEV_NAME, e->device_name);
    wps_put8(&b, WPS_ATTR_RF_BANDS, 0x03);
    wps_put16(&b, WPS_ATTR_ASSOC_STATE, 0);
    wps_put16(&b, WPS_ATTR_CONFIG_ERROR, 0);
    wps_put16(&b, WPS_ATTR_DEV_PWID, pwid(e));
    put32(&b, WPS_ATTR_OS_VERSION, OS_VERSION);
    wps_put_vendor_v2(&b);
    if (b.err) return WPS_ERR_SPACE;
    set_prev(e, b.p, b.len);
    e->state = WPS_ST_WAIT_M2;
    return fin(&b);
}

static int build_nack(wps_enrollee_t *e, uint16_t cfg_error, wps_fail_t why, uint8_t *out, size_t cap) {
    wps_buf_t b; wps_buf_init(&b, out, cap);
    wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
    wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_NACK);
    wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, e->ne, 16);
    wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, e->nr, 16);      /* zeros before M2 */
    wps_put16(&b, WPS_ATTR_CONFIG_ERROR, cfg_error);
    e->state = WPS_ST_FAILED; e->fail = why; e->cfg_error = cfg_error;
    return fin(&b);
}

/* message ends with Authenticator (12 bytes); check HMAC over prev || message-without-it */
static int verify_auth(const wps_enrollee_t *e, const uint8_t *in, size_t len) {
    if (len < 12 || rd16(in + len - 12) != WPS_ATTR_AUTHENTICATOR || rd16(in + len - 10) != 8) return 0;
    uint8_t a[8];
    wps_authenticator(e->keys.auth, e->prev, e->prev_len, in, len - 12, a);
    return ct_eq(a, in + len - 8, 8);
}
static void finish_msg_auth(wps_enrollee_t *e, wps_buf_t *b) {
    uint8_t a[8];
    wps_authenticator(e->keys.auth, e->prev, e->prev_len, b->p, b->len, a);
    wps_put(b, WPS_ATTR_AUTHENTICATOR, a, 8);
}
/* build "Mx" with RegistrarNonce + Encrypted Settings(inner TLV) + vendor ext + authenticator */
static int build_enc_msg(wps_enrollee_t *e, uint8_t type, uint16_t inner_t, const uint8_t snonce[16], uint8_t *out, size_t cap) {
    uint8_t inner[20], iv[16], enc[96];
    be16(inner, inner_t); be16(inner + 2, 16); memcpy(inner + 4, snonce, 16);
    rnd(&e->cfg, iv, 16);
    int n = wps_encr_seal(&e->keys, iv, inner, 20, enc, sizeof enc);
    if (n < 0) return n;
    wps_buf_t b; wps_buf_init(&b, out, cap);
    wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
    wps_put8(&b, WPS_ATTR_MSG_TYPE, type);
    wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, e->nr, 16);
    wps_put(&b, WPS_ATTR_ENCR_SETTINGS, enc, (size_t)n);
    wps_put_vendor_v2(&b);
    if (b.err) return WPS_ERR_SPACE;
    finish_msg_auth(e, &b);
    if (b.err) return WPS_ERR_SPACE;
    set_prev(e, b.p, b.len);
    return fin(&b);
}

static int cred_from(const uint8_t *p, size_t n, wps_cred_t *c) {
    memset(c, 0, sizeof *c);
    c->key_index = 1;
    size_t l; const uint8_t *v;
    if (!(v = wps_tlv_find(p, n, WPS_ATTR_SSID, &l)) || l < 1 || l > 32) return -1;
    memcpy(c->ssid, v, l); c->ssid_len = l;
    if (wps_tlv_get16(p, n, WPS_ATTR_AUTH_TYPE, &c->auth_type)) return -1;
    if (wps_tlv_get16(p, n, WPS_ATTR_ENCR_TYPE, &c->encr_type)) return -1;
    if ((v = wps_tlv_find(p, n, WPS_ATTR_NET_KEY, &l))) {
        if (l > 64) return -1;
        memcpy(c->key, v, l); c->key_len = l; c->key[l] = 0;
    }
    uint8_t ki; if (!wps_tlv_get8(p, n, WPS_ATTR_NET_KEY_INDEX, &ki)) c->key_index = ki;
    wps_tlv_get(p, n, WPS_ATTR_MAC, c->mac, 6);
    if (c->key_len == 64) {
        int hex = 1;
        for (size_t i = 0; i < 64; i++) { uint8_t ch = c->key[i]; if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) hex = 0; }
        c->key_is_hex_psk = hex;
    }
    return 0;
}

int wps_enrollee_rx(wps_enrollee_t *e, const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    if (e->state == WPS_ST_IDLE || e->state == WPS_ST_DONE || e->state == WPS_ST_FAILED) return WPS_ERR_STATE;
    if (len > WPS_MAX_MSG || wps_tlv_check(in, len)) return WPS_ERR_BAD;
    uint8_t mt, nonce[16], ver;
    if (wps_tlv_get8(in, len, WPS_ATTR_MSG_TYPE, &mt) || wps_tlv_get8(in, len, WPS_ATTR_VERSION, &ver)) return WPS_ERR_BAD;
    if (wps_tlv_get(in, len, WPS_ATTR_ENROLLEE_NONCE, nonce, 16) || !ct_eq(nonce, e->ne, 16)) return WPS_ERR_IGNORE;

    if (mt == WPS_MSG_NACK) {
        uint16_t err = 0; wps_tlv_get16(in, len, WPS_ATTR_CONFIG_ERROR, &err);
        e->state = WPS_ST_FAILED; e->fail = WPS_FAIL_AP_NACK; e->cfg_error = err;
        return 0;
    }
    if (e->state == WPS_ST_WAIT_M2 || e->state == WPS_ST_M2D) {
        if (mt == WPS_MSG_M2D) {
            wps_buf_t b; wps_buf_init(&b, out, cap);
            wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
            wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_ACK);
            wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, e->ne, 16);
            uint8_t rn[16];
            if (!wps_tlv_get(in, len, WPS_ATTR_REGISTRAR_NONCE, rn, 16)) memcpy(e->nr, rn, 16);
            wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, e->nr, 16);
            e->state = WPS_ST_M2D;
            return fin(&b);
        }
        if (mt != WPS_MSG_M2) return WPS_ERR_IGNORE;
        uint8_t pkr[192], nr[16]; uint16_t apw;
        if (wps_tlv_get(in, len, WPS_ATTR_REGISTRAR_NONCE, nr, 16) || wps_tlv_get(in, len, WPS_ATTR_PUBLIC_KEY, pkr, 192))
            return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_BAD_MSG, out, cap);
        memcpy(e->nr, nr, 16);
        uint8_t shared[192];
        if (dh_shared(e->priv, pkr, shared)) return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_BAD_KEY, out, cap);
        memcpy(e->pkr, pkr, 192);
        wps_derive_keys(shared, e->ne, e->cfg.mac, e->nr, &e->keys);
        wipe(shared, sizeof shared);
        if (!verify_auth(e, in, len)) return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_AUTHENTICATOR, out, cap);
        if (wps_tlv_get16(in, len, WPS_ATTR_DEV_PWID, &apw) || apw != pwid(e))
            return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_PWID_MISMATCH, out, cap);
        set_prev(e, in, len);
        wps_psk(e->keys.auth, e->pin, e->psk1, e->psk2);
        rnd(&e->cfg, e->es1, 16); rnd(&e->cfg, e->es2, 16);
        uint8_t h1[32], h2[32];
        wps_hash(e->keys.auth, e->es1, e->psk1, e->pke, e->pkr, h1);
        wps_hash(e->keys.auth, e->es2, e->psk2, e->pke, e->pkr, h2);
        wps_buf_t b; wps_buf_init(&b, out, cap);
        wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
        wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_M3);
        wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, e->nr, 16);
        wps_put(&b, WPS_ATTR_E_HASH1, h1, 32);
        wps_put(&b, WPS_ATTR_E_HASH2, h2, 32);
        wps_put_vendor_v2(&b);
        if (b.err) return WPS_ERR_SPACE;
        finish_msg_auth(e, &b);
        if (b.err) return WPS_ERR_SPACE;
        set_prev(e, b.p, b.len);
        e->state = WPS_ST_WAIT_M4;
        return fin(&b);
    }

    /* M4 / M6 / M8: Registrar nonce must match, Authenticator and Encrypted Settings must verify */
    uint8_t want = e->state == WPS_ST_WAIT_M4 ? WPS_MSG_M4 : e->state == WPS_ST_WAIT_M6 ? WPS_MSG_M6 : WPS_MSG_M8;
    if (mt != want) return WPS_ERR_IGNORE;
    if (!verify_auth(e, in, len)) return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_AUTHENTICATOR, out, cap);
    size_t el; const uint8_t *enc = wps_tlv_find(in, len, WPS_ATTR_ENCR_SETTINGS, &el);
    uint8_t plain[WPS_MAX_MSG];
    int pl = enc ? wps_encr_open(&e->keys, enc, el, plain, sizeof plain) : WPS_ERR_BAD;
    if (pl < 0 || wps_tlv_check(plain, (size_t)pl)) {
        wipe(plain, sizeof plain);
        return build_nack(e, WPS_CFG_DECRYPTION_FAILURE, WPS_FAIL_DECRYPT, out, cap);
    }
    int rc;
    if (want == WPS_MSG_M4 || want == WPS_MSG_M6) {
        int first = want == WPS_MSG_M4;
        uint8_t rs[16], rh[32], chk[32];
        if (wps_tlv_get(plain, (size_t)pl, first ? WPS_ATTR_R_SNONCE1 : WPS_ATTR_R_SNONCE2, rs, 16)) {
            wipe(plain, sizeof plain);
            return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_BAD_MSG, out, cap);
        }
        if (first) {      /* both R-Hashes arrive in M4; R-Hash2 is checked when its nonce arrives in M6 */
            if (wps_tlv_get(in, len, WPS_ATTR_R_HASH1, e->rhash1, 32) || wps_tlv_get(in, len, WPS_ATTR_R_HASH2, e->rhash2, 32)) {
                wipe(plain, sizeof plain);
                return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_BAD_MSG, out, cap);
            }
        }
        memcpy(rh, first ? e->rhash1 : e->rhash2, 32);
        wps_hash(e->keys.auth, rs, first ? e->psk1 : e->psk2, e->pke, e->pkr, chk);
        if (!ct_eq(chk, rh, 32)) {
            wipe(plain, sizeof plain);
            return build_nack(e, WPS_CFG_PIN_AUTH_FAILURE, WPS_FAIL_PIN_AUTH, out, cap);
        }
        set_prev(e, in, len);
        rc = build_enc_msg(e, first ? WPS_MSG_M5 : WPS_MSG_M7, first ? WPS_ATTR_E_SNONCE1 : WPS_ATTR_E_SNONCE2,
                           first ? e->es1 : e->es2, out, cap);
        if (rc >= 0) e->state = first ? WPS_ST_WAIT_M6 : WPS_ST_WAIT_M8;
    } else {
        /* M8: credential(s), either wrapped in a Credential attribute or flat */
        size_t cl; const uint8_t *cv = wps_tlv_find(plain, (size_t)pl, WPS_ATTR_CRED, &cl);
        wps_cred_t cred;
        int bad = cv ? (wps_tlv_check(cv, cl) || cred_from(cv, cl, &cred)) : cred_from(plain, (size_t)pl, &cred);
        wipe(plain, sizeof plain);
        if (bad) return build_nack(e, WPS_CFG_NO_ERROR, WPS_FAIL_BAD_CRED, out, cap);
        e->cred = cred; e->have_cred = 1;
        wps_buf_t b; wps_buf_init(&b, out, cap);
        wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
        wps_put8(&b, WPS_ATTR_MSG_TYPE, WPS_MSG_DONE);
        wps_put(&b, WPS_ATTR_ENROLLEE_NONCE, e->ne, 16);
        wps_put(&b, WPS_ATTR_REGISTRAR_NONCE, e->nr, 16);
        e->state = WPS_ST_DONE;
        return fin(&b);
    }
    wipe(plain, sizeof plain);
    return rc;
}

/* ------------------------------------------------------------------ EAPOL / EAP-WSC */
int wps_eap_start_frame(uint8_t *out, size_t cap) {
    if (cap < 4) return WPS_ERR_SPACE;
    out[0] = 1; out[1] = 1; out[2] = 0; out[3] = 0;     /* EAPOL v1, type Start, length 0 */
    return 4;
}
int wps_eap_build(uint8_t *out, size_t cap, int code, uint8_t id, int op, uint8_t flags, int have_msglen, uint16_t msglen,
                  const uint8_t *data, size_t dlen) {
    size_t eap = 4 + 1 + 3 + 4 + 2 + (have_msglen ? 2 : 0) + dlen;
    if (4 + eap > cap || eap > 0xFFFF) return WPS_ERR_SPACE;
    uint8_t *p = out;
    *p++ = 1; *p++ = 0; be16(p, (uint16_t)eap); p += 2;
    *p++ = (uint8_t)code; *p++ = id; be16(p, (uint16_t)eap); p += 2;
    *p++ = 254; *p++ = 0x00; *p++ = 0x37; *p++ = 0x2A; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 1;
    *p++ = (uint8_t)op; *p++ = (uint8_t)(flags | (have_msglen ? WPS_FLAG_LEN : 0));
    if (have_msglen) { be16(p, msglen); p += 2; }
    if (dlen) memcpy(p, data, dlen);
    return (int)(4 + eap);
}
int wps_eap_build_identity(uint8_t *out, size_t cap, int code, uint8_t id, const char *identity) {
    size_t n = identity ? strlen(identity) : 0, eap = 5 + n;
    if (4 + eap > cap) return WPS_ERR_SPACE;
    out[0] = 1; out[1] = 0; be16(out + 2, (uint16_t)eap);
    out[4] = (uint8_t)code; out[5] = id; be16(out + 6, (uint16_t)eap); out[8] = 1;
    if (n) memcpy(out + 9, identity, n);
    return (int)(4 + eap);
}

int wps_eap_init(wps_eap_t *s, const wps_cfg_t *cfg) {
    memset(s, 0, sizeof *s);
    int rc = wps_enrollee_init(&s->en, cfg);
    s->frag_size = cfg->frag_size ? cfg->frag_size : 1398;
    if (s->frag_size < 16 || s->frag_size > 1398) s->frag_size = cfg->frag_size < 16 ? 16 : 1398;
    return rc;
}
void wps_eap_clear(wps_eap_t *s) { wipe(s, sizeof *s); }
int wps_eap_result(const wps_eap_t *s) { return s->en.state == WPS_ST_DONE ? 1 : s->en.state == WPS_ST_FAILED ? -1 : 0; }

static int op_for(const uint8_t *m, size_t n) {
    uint8_t t = 0; wps_tlv_get8(m, n, WPS_ATTR_MSG_TYPE, &t);
    return t == WPS_MSG_ACK ? WPS_OP_ACK : t == WPS_MSG_NACK ? WPS_OP_NACK : t == WPS_MSG_DONE ? WPS_OP_DONE : WPS_OP_MSG;
}
/* next fragment (or the whole message) of the pending outgoing message */
static int send_chunk(wps_eap_t *s, uint8_t id, uint8_t *out, size_t cap) {
    size_t remain = s->tx_len - s->tx_off;
    size_t chunk = remain > s->frag_size ? s->frag_size : remain;
    int first_frag = s->tx_off == 0 && remain > s->frag_size;
    int n = wps_eap_build(out, cap, 2, id, s->tx_op, remain > chunk ? WPS_FLAG_MORE : 0, first_frag, (uint16_t)s->tx_len,
                          s->tx + s->tx_off, chunk);
    if (n > 0) { s->tx_off += chunk; if (s->tx_off >= s->tx_len) s->tx_len = s->tx_off = 0; }
    return n;
}
static int send_msg(wps_eap_t *s, uint8_t id, const uint8_t *m, size_t n, uint8_t *out, size_t cap) {
    if (n > sizeof s->tx) return WPS_ERR_SPACE;
    memcpy(s->tx, m, n); s->tx_len = n; s->tx_off = 0; s->tx_op = (uint8_t)op_for(m, n);
    return send_chunk(s, id, out, cap);
}

static int eap_rx(wps_eap_t *s, const uint8_t *f, size_t len, uint8_t *out, size_t cap, uint8_t *id_out, int *is_req) {
    *is_req = 0;
    if (len < 4 || f[1] != 0) return 0;                          /* only EAP packets */
    size_t blen = rd16(f + 2);
    if (blen < 4 || blen > len - 4) return WPS_ERR_BAD;
    const uint8_t *eap = f + 4; uint8_t code = eap[0], id = eap[1]; size_t elen = rd16(eap + 2);
    if (elen < 4 || elen > blen) return WPS_ERR_BAD;
    if (code == 4) {
        wps_state_t st = s->en.state;
        if (st != WPS_ST_DONE && st != WPS_ST_FAILED && st != WPS_ST_M2D) { s->en.state = WPS_ST_FAILED; s->en.fail = WPS_FAIL_EAP_FAILURE; }
        return 0;
    }
    if (code != 1 || elen < 5) return 0;
    *is_req = 1; *id_out = id;
    if (s->have_id && id == s->last_id && s->last_resp_len) {    /* retransmitted request: same answer */
        if (s->last_resp_len > cap) return WPS_ERR_SPACE;
        memcpy(out, s->last_resp, s->last_resp_len); *is_req = 0;
        return (int)s->last_resp_len;
    }
    s->have_id = 1; s->last_id = id; s->last_resp_len = 0;
    uint8_t type = eap[4];
    if (type == 1) return wps_eap_build_identity(out, cap, 2, id, "WFA-SimpleConfig-Enrollee-1-0");
    if (type != 254) {                                           /* legacy Nak asking for the expanded type */
        if (cap < 10) return WPS_ERR_SPACE;
        out[0] = 1; out[1] = 0; be16(out + 2, 6); out[4] = 2; out[5] = id; be16(out + 6, 6); out[8] = 3; out[9] = 254;
        return 10;
    }
    static const uint8_t wfa[7] = {0x00, 0x37, 0x2A, 0, 0, 0, 1};   /* SMI 0x372A (WFA), vendor type 1 (SimpleConfig) */
    if (elen < 13 || memcmp(eap + 5, wfa, 7)) return 0;
    if (elen < 14) return WPS_ERR_BAD;
    uint8_t op = eap[12], flags = eap[13];
    const uint8_t *d = eap + 14; size_t dl = elen - 14;
    if (op == WPS_OP_START) {
        if (s->en.state != WPS_ST_IDLE) return 0;
        uint8_t m1[WPS_MAX_MSG];
        int n = wps_enrollee_start(&s->en, m1, sizeof m1);
        return n < 0 ? n : send_msg(s, id, m1, (size_t)n, out, cap);
    }
    if (op == WPS_OP_FRAG_ACK) return s->tx_len > s->tx_off ? send_chunk(s, id, out, cap) : 0;
    if (op != WPS_OP_MSG && op != WPS_OP_ACK && op != WPS_OP_NACK) return 0;
    if (flags & WPS_FLAG_LEN) {
        if (dl < 2) return WPS_ERR_BAD;
        size_t total = rd16(d); d += 2; dl -= 2;
        if (total > WPS_MAX_MSG) return WPS_ERR_BAD;
        s->rx_total = total; s->rx_len = 0; s->rx_active = 1;
    }
    if (s->rx_active) {
        if (s->rx_len + dl > s->rx_total) { s->rx_active = 0; return WPS_ERR_BAD; }
        memcpy(s->rx + s->rx_len, d, dl); s->rx_len += dl;
        if (flags & WPS_FLAG_MORE) return wps_eap_build(out, cap, 2, id, WPS_OP_FRAG_ACK, 0, 0, 0, NULL, 0);
        s->rx_active = 0;
        if (s->rx_len != s->rx_total) return WPS_ERR_BAD;
        d = s->rx; dl = s->rx_len;
    } else if (flags & WPS_FLAG_MORE) return WPS_ERR_BAD;       /* continuation without a start */
    uint8_t m[WPS_MAX_MSG];
    int n = wps_enrollee_rx(&s->en, d, dl, m, sizeof m);
    if (n <= 0) return n == WPS_ERR_IGNORE || n == WPS_ERR_STATE ? 0 : n;
    return send_msg(s, id, m, (size_t)n, out, cap);
}

int wps_eap_rx(wps_eap_t *s, const uint8_t *f, size_t len, uint8_t *out, size_t cap) {
    uint8_t id = 0; int req = 0;
    int n = eap_rx(s, f, len, out, cap, &id, &req);
    if (n > 0 && req && (size_t)n <= sizeof s->last_resp) { memcpy(s->last_resp, out, (size_t)n); s->last_resp_len = (size_t)n; }
    return n;
}

/* ------------------------------------------------------------------ probe / association request IEs */
static int wrap_ie(wps_buf_t *attrs, uint8_t *out, size_t cap) {
    if (attrs->err || attrs->len > 251 || attrs->len + 6 > cap) return WPS_ERR_SPACE;
    memmove(out + 6, out, attrs->len);
    out[0] = 0xDD; out[1] = (uint8_t)(attrs->len + 4); out[2] = 0x00; out[3] = 0x50; out[4] = 0xF2; out[5] = 0x04;
    return (int)(attrs->len + 6);
}
int wps_build_probe_req_ie(const wps_cfg_t *c, uint8_t *out, size_t cap) {
    if (cap < 8) return WPS_ERR_SPACE;
    if (c->pin && !wps_pin_valid(c->pin)) return WPS_ERR_PIN;
    wps_buf_t b; wps_buf_init(&b, out, cap - 6);                 /* attributes first, then shifted behind the IE header */
    wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
    wps_put8(&b, WPS_ATTR_REQUEST_TYPE, 1);                      /* Enrollee */
    wps_put16(&b, WPS_ATTR_CONFIG_METHODS, CFG_METHODS);
    wps_put(&b, WPS_ATTR_UUID_E, c->uuid, 16);
    wps_put(&b, WPS_ATTR_PRIMARY_DEVTYPE, DEVTYPE, 8);
    wps_put8(&b, WPS_ATTR_RF_BANDS, 0x03);
    wps_put16(&b, WPS_ATTR_ASSOC_STATE, 0);
    wps_put16(&b, WPS_ATTR_CONFIG_ERROR, 0);
    wps_put16(&b, WPS_ATTR_DEV_PWID, c->pin ? WPS_DEVPW_PIN : WPS_DEVPW_PBC);
    put_str(&b, WPS_ATTR_MANUFACTURER, c->manufacturer ? c->manufacturer : "ALFA");
    put_str(&b, WPS_ATTR_MODEL_NAME, c->model_name ? c->model_name : "AWUS036ACS");
    put_str(&b, WPS_ATTR_MODEL_NUMBER, c->model_number ? c->model_number : "AWUS036ACS");
    put_str(&b, WPS_ATTR_DEV_NAME, c->device_name ? c->device_name : "AWUS036ACS");
    put32(&b, WPS_ATTR_OS_VERSION, OS_VERSION);
    wps_put_vendor_v2(&b);
    return wrap_ie(&b, out, cap);
}
int wps_build_assoc_req_ie(uint8_t *out, size_t cap) {
    if (cap < 8) return WPS_ERR_SPACE;
    wps_buf_t b; wps_buf_init(&b, out, cap - 6);
    wps_put8(&b, WPS_ATTR_VERSION, VERSION_BYTE);
    wps_put8(&b, WPS_ATTR_REQUEST_TYPE, 1);
    wps_put_vendor_v2(&b);
    return wrap_ie(&b, out, cap);
}

/* ------------------------------------------------------------------ AP side info from Beacon / Probe Response */
static void ap_str(const uint8_t *a, size_t n, uint16_t t, char *dst) {
    size_t l; const uint8_t *v = wps_tlv_find(a, n, t, &l);
    if (!v) return;
    if (l > 32) l = 32;
    memcpy(dst, v, l); dst[l] = 0;
}
int wps_ap_parse(const uint8_t *ies, size_t len, wps_ap_info_t *o) {
    uint8_t bssid[6]; memcpy(bssid, o->bssid, 6);
    memset(o, 0, sizeof *o); memcpy(o->bssid, bssid, 6);
    uint8_t a[1024]; size_t al = 0; int found = 0;
    for (size_t i = 0; i < len;) {
        if (len - i < 2 || (size_t)ies[i + 1] > len - i - 2) return -1;
        size_t n = ies[i + 1];
        if (ies[i] == 0xDD && n >= 4 && !memcmp(ies + i + 2, "\x00\x50\xF2\x04", 4)) {
            if (al + n - 4 > sizeof a) return -1;
            memcpy(a + al, ies + i + 6, n - 4); al += n - 4; found = 1;
        }
        i += 2 + n;
    }
    if (!found) return 0;
    if (wps_tlv_check(a, al)) return -1;
    o->present = 1;
    wps_tlv_get8(a, al, WPS_ATTR_VERSION, &o->version);
    uint8_t v8;
    if (!wps_tlv_get8(a, al, WPS_ATTR_WPS_STATE, &v8)) o->wps_state = v8;
    if (!wps_tlv_get8(a, al, WPS_ATTR_AP_SETUP_LOCKED, &v8)) o->ap_setup_locked = v8 != 0;
    if (!wps_tlv_get8(a, al, WPS_ATTR_SELECTED_REG, &v8)) o->selected_registrar = v8 != 0;
    wps_tlv_get16(a, al, WPS_ATTR_DEV_PWID, &o->dev_pwid);
    wps_tlv_get16(a, al, WPS_ATTR_SELREG_METHODS, &o->selreg_methods);
    wps_tlv_get16(a, al, WPS_ATTR_CONFIG_METHODS, &o->cfg_methods);
    if (!wps_tlv_get(a, al, WPS_ATTR_UUID_E, o->uuid, 16)) o->have_uuid = 1;
    ap_str(a, al, WPS_ATTR_DEV_NAME, o->device_name);
    ap_str(a, al, WPS_ATTR_MANUFACTURER, o->manufacturer);
    ap_str(a, al, WPS_ATTR_MODEL_NAME, o->model_name);
    size_t vl; const uint8_t *vx = wps_tlv_find(a, al, WPS_ATTR_VENDOR_EXT, &vl);
    if (vx && vl >= 3 && !memcmp(vx, "\x00\x37\x2A", 3)) {         /* WFA subelements: id, len, value */
        for (size_t i = 3; i + 2 <= vl && i + 2 + vx[i + 1] <= vl; i += 2 + vx[i + 1])
            if (vx[i] == 0 && vx[i + 1] == 1) o->version2 = vx[i + 2];
    }
    return 1;
}
wps_ap_reason_t wps_ap_check(const wps_ap_info_t *ap, wps_mode_t mode) {
    if (!ap->present) return WPS_AP_NO_WPS;
    if (ap->ap_setup_locked) return WPS_AP_LOCKED;
    if (mode == WPS_MODE_PBC && !(ap->selected_registrar && ap->dev_pwid == WPS_DEVPW_PBC)) return WPS_AP_PBC_INACTIVE;
    return WPS_AP_OK;
}
const char *wps_ap_reason_str(wps_ap_reason_t r) {
    switch (r) {
    case WPS_AP_OK: return "ok";
    case WPS_AP_NO_WPS: return "AP does not advertise WPS";
    case WPS_AP_LOCKED: return "AP setup is locked (too many failed PIN attempts); wait or unlock on the router";
    case WPS_AP_PBC_INACTIVE: return "no push-button window open on this AP; press its WPS button first";
    case WPS_AP_PIN_WRONG_MODE: return "AP is not accepting a PIN";
    }
    return "?";
}
int wps_pbc_pick(const wps_ap_info_t *aps, size_t n, int *count) {
    int found = -1; int cnt = 0;
    for (size_t i = 0; i < n; i++) {
        if (wps_ap_check(&aps[i], WPS_MODE_PBC) != WPS_AP_OK) continue;
        int dup = 0;
        for (size_t j = 0; j < i && !dup; j++) {
            if (wps_ap_check(&aps[j], WPS_MODE_PBC) != WPS_AP_OK) continue;
            if (aps[i].have_uuid && aps[j].have_uuid) dup = !memcmp(aps[i].uuid, aps[j].uuid, 16);
            else dup = !memcmp(aps[i].bssid, aps[j].bssid, 6);
        }
        if (dup) continue;
        cnt++; if (found < 0) found = (int)i;
    }
    if (count) *count = cnt;
    return cnt > 1 ? -2 : found;
}

/* ------------------------------------------------------------------ self rate limit */
int64_t wps_limiter_check(const wps_limiter_t *l, uint64_t now) {
    if (l->blocked) return -1;
    return now >= l->next_ok ? 0 : (int64_t)(l->next_ok - now);
}
void wps_limiter_record(wps_limiter_t *l, uint64_t now, int success) {
    if (success) { l->fails = 0; l->next_ok = now; return; }
    l->fails++;
    uint64_t d = 30;
    for (int i = 1; i < l->fails && d < 3600; i++) d *= 2;
    if (d > 3600) d = 3600;
    l->next_ok = now + d;
    if (l->fails >= 5) l->blocked = 1;
}
void wps_limiter_reset(wps_limiter_t *l) { memset(l, 0, sizeof *l); }
