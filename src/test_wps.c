// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_wps.c - tests for src/wps.c and src/bignum_dh.c. Prints "WPS TEST OK" and exits 0 on success.
 *
 * INDEPENDENT CROSS-CHECK: the VEC[] table (DH public keys, DHKey, KDK, AuthKey/KeyWrapKey/EMSK, PSK1/2, E/R-Hash, an
 *   Authenticator and a sealed Encrypted Settings blob) was produced by tools/wps_check.py, which uses only python
 *   hashlib/hmac/pow and the openssl CLI for AES-128-CBC (the `cryptography` package is not installed here). It also
 *   rebuilds the prime from the RFC 3526 formula using pi computed in python. `make test-wps` additionally runs
 *   `wps_check.py transcript` on the M1..M8 transcript this test writes, re-verifying every Authenticator, KWA, E/R-Hash
 *   and the credential with no C code involved.
 * PUBLISHED: PIN checksum 12345670 (WSC spec / widely used example), 4^13 mod 497 = 445 (textbook), Fermat 2^(p-1) = 1.
 * SELF-CONSISTENCY ONLY: the in-memory registrar below is written by the same author from the same reading of the spec,
 *   so the M1..M8 loopback proves the two halves agree with each other and with the python check, not with a real AP.
 *   Never run against a real AP/registrar. */
#include "wps.h"
#include "bignum_dh.h"
#include <CommonCrypto/CommonCrypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void unhex(const char *s, uint8_t *o) { for (; s[0] && s[1]; s += 2, o++) { unsigned v; sscanf(s, "%2x", &v); *o = (uint8_t)v; } }
static void tohex(const uint8_t *b, size_t n, char *o) { for (size_t i = 0; i < n; i++) snprintf(o + 2 * i, 3, "%02x", b[i]); }
static int eqhex(const uint8_t *b, size_t n, const char *hex) {
    uint8_t t[512]; if (strlen(hex) != 2 * n) return 0;
    unhex(hex, t); return memcmp(b, t, n) == 0;
}

/* deterministic "random" bytes (xorshift64*) so runs are reproducible */
static uint64_t rs = 0x9E3779B97F4A7C15ull;
static void det_rand(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; b[i] = (uint8_t)((rs * 0x2545F4914F6CDD1Dull) >> 56); }
}

static const struct { const char *name; const char *hex; } VEC[] = {
    {"p_sha", "64fcc83ec403930bf18393dbc883ccaa1fbb08ac876f77f7aa99748ca945019b"},
    {"pke_sha", "2ba7342521090958a37aa7fa585f215b6e811feec7cecc654c44c56c3d6a984d"},
    {"pkr_sha", "36d5324fd2cb7689b79c73077e7a2eb5fb02c80c2d28b23afe54e938b0e2ed9a"},
    {"shared_sha", "9409cd2f6f7ef9e591226621fff13300828c99c54116520c5ef6065784ce7366"},
    {"dhkey", "9409cd2f6f7ef9e591226621fff13300828c99c54116520c5ef6065784ce7366"},
    {"kdk", "6367a0a560d4d2ed01612d900628dc8746d9d7a9f4e8d4b85348b0559c7ad01a"},
    {"auth", "e64f08f6a73ad0a71691a80ce4fe9a4bfd52f89b6d26fc627a7c9ad8eb3e474c"},
    {"kwk", "d5de0293a7bf3ba98dfeea0b42dccd29"},
    {"emsk", "ddae369033b12ac6d0d61d3f583e50f090618a705821c882e4e9ee6ce9a95855"},
    {"psk1", "fe64e578410a7c24c001b247b3ec120a"},
    {"psk2", "5f69be11d591288c702196c74b155601"},
    {"ehash1", "4108ac014668db9d229881f441b12ee15358ab2a1020ae25a78ee3e57de049ba"},
    {"ehash2", "3f01b7908fd0a7995f0257700b23f09b4192cc03b13d97e99ff661743684c836"},
    {"rhash1", "13a3e79973f2e44366e741dededaecc0e7dd3ed694fdb15b2d65cec38fb0a4e1"},
    {"authenticator", "d6b9e6846afdaf8d"},
    {"seal", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf9f1ef8bff47a4f5bd92fa8ed41aade309e96a70ddfce7b15d0b2af2a36cc8fab659cf22dccf0d959e3d75d0e15bc4f49"},
    {"pbc_psk1", "15df2671b7ffc119b9395592f62c408c"},
};
static const char *vec(const char *name) {
    for (size_t i = 0; i < sizeof VEC / sizeof VEC[0]; i++) if (!strcmp(VEC[i].name, name)) return VEC[i].hex;
    printf("FAIL no vector %s\n", name); fails++; return "";
}
#define CHECK_VEC(buf, n, name) do { if (!eqhex(buf, n, vec(name))) { char h_[600]; tohex(buf, n, h_); printf("FAIL vector %s: got %s\n", name, h_); fails++; } } while (0)

/* ---------------------------------------------------------------- PIN */
static void test_pin(void) {
    CHECK(wps_pin_checksum(1234567) == 0);
    CHECK(wps_pin_valid("12345670"));
    CHECK(!wps_pin_valid("12345678"));
    CHECK(wps_pin_checksum(4626484) == 8 && wps_pin_valid("46264848"));
    CHECK(wps_pin_valid("00000000"));
    CHECK(wps_pin_valid("1234"));                          /* 4-digit PINs have no checksum */
    CHECK(!wps_pin_valid("123") && !wps_pin_valid("123456789") && !wps_pin_valid("1234567a") && !wps_pin_valid("") && !wps_pin_valid(NULL));
    char p[9];
    CHECK(wps_pin_generate(1234567, p) == 0 && !strcmp(p, "12345670"));
    CHECK(wps_pin_generate(10000000, p) == -1);
    for (uint32_t i = 0; i < 20000; i += 7) { wps_pin_generate(i * 499 % 10000000, p); CHECK(wps_pin_valid(p)); }
    /* every single-digit change to a valid PIN is caught by the checksum except none: a one-digit error never validates */
    int caught = 0, tot = 0;
    for (int pos = 0; pos < 8; pos++) for (char d = '0'; d <= '9'; d++) {
        char q[9]; strcpy(q, "12345670"); if (q[pos] == d) continue;
        q[pos] = d; tot++; caught += !wps_pin_valid(q);
    }
    CHECK(caught == tot);
}

/* ---------------------------------------------------------------- bignum / DH */
static void test_bignum(void) {
    uint8_t b[4] = {0, 0, 0, 4}, e[1] = {13}, m[4] = {0, 0, 0x01, 0xF1}, o[4];   /* 4^13 mod 497 = 445 */
    CHECK(bn_modexp(b, e, 1, m, 4, o) == 0 && o[2] == 0x01 && o[3] == 0xBD && !o[0] && !o[1]);
    uint8_t zero[1] = {0};
    CHECK(bn_modexp(b, zero, 1, m, 4, o) == 0 && o[3] == 1 && !o[2]);                   /* x^0 = 1 */
    uint8_t m128[16] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x61}; /* 2^128-159, the largest 128-bit prime */
    uint8_t g[16] = {0}, em[16], r[16];
    g[15] = 2; memset(em, 0xFF, 16); em[15] = 0x60;                                      /* p-1 */
    CHECK(bn_modexp(g, em, 16, m128, 16, r) == 0 && r[15] == 1 && !memcmp(r, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 15));
    CHECK(bn_modexp(g, em, 16, m128, 15, r) == -1);                                     /* size not multiple of 4 */
    uint8_t even[4] = {0, 0, 0, 10}; CHECK(bn_modexp(b, e, 1, even, 4, o) == -1);

    uint8_t sha[32]; CC_SHA256(DH_GROUP5_P, DH_LEN, sha);
    CHECK_VEC(sha, 32, "p_sha");                                                        /* prime == RFC 3526 formula */
    uint8_t pm1[DH_LEN], one[DH_LEN], g192[DH_LEN] = {0}, res[DH_LEN];
    memcpy(pm1, DH_GROUP5_P, DH_LEN); pm1[DH_LEN - 1]--;
    g192[DH_LEN - 1] = 2;
    CHECK(bn_modexp(g192, pm1, DH_LEN, DH_GROUP5_P, DH_LEN, res) == 0);                 /* Fermat: 2^(p-1) = 1 */
    memset(one, 0, sizeof one); one[DH_LEN - 1] = 1;
    CHECK(!memcmp(res, one, DH_LEN));

    uint8_t pa[DH_LEN], pb[DH_LEN], A[DH_LEN], B[DH_LEN], s1[DH_LEN], s2[DH_LEN];
    for (int t = 0; t < 4; t++) {
        det_rand(pa, DH_LEN); det_rand(pb, DH_LEN);
        CHECK(dh_public(pa, A) == 0 && dh_public(pb, B) == 0);
        CHECK(dh_shared(pa, B, s1) == 0 && dh_shared(pb, A, s2) == 0 && !memcmp(s1, s2, DH_LEN));
        CHECK(memcmp(s1, A, DH_LEN) && memcmp(s1, B, DH_LEN));
    }
    uint8_t bad[DH_LEN] = {0};
    CHECK(dh_shared(pa, bad, s1) == -1);                              /* 0 */
    bad[DH_LEN - 1] = 1; CHECK(dh_shared(pa, bad, s1) == -1);         /* 1 */
    CHECK(dh_shared(pa, pm1, s1) == -1);                              /* p-1 */
    CHECK(dh_shared(pa, DH_GROUP5_P, s1) == -1);                      /* p */
    memset(bad, 0xFF, DH_LEN); CHECK(dh_shared(pa, bad, s1) == -1);   /* > p */
    memset(bad, 0, DH_LEN); CHECK(dh_public(bad, A) == -1);
}

/* ---------------------------------------------------------------- python-generated vectors */
static void test_vectors(void) {
    uint8_t pe[192], pr[192], pke[192], pkr[192], shared[192], sha[32];
    for (int i = 0; i < 192; i++) { pe[i] = (uint8_t)(i * 37 + 11); pr[i] = (uint8_t)(i * 91 + 5); }
    CHECK(dh_public(pe, pke) == 0 && dh_public(pr, pkr) == 0);
    CC_SHA256(pke, 192, sha); CHECK_VEC(sha, 32, "pke_sha");
    CC_SHA256(pkr, 192, sha); CHECK_VEC(sha, 32, "pkr_sha");
    CHECK(dh_shared(pe, pkr, shared) == 0);
    CC_SHA256(shared, 192, sha); CHECK_VEC(sha, 32, "shared_sha"); CHECK_VEC(sha, 32, "dhkey");
    uint8_t n1[16], n2[16], es1[16], es2[16], rs1[16], iv[16], mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    for (int i = 0; i < 16; i++) { n1[i] = (uint8_t)(1 + i); n2[i] = (uint8_t)(0xA1 + i); es1[i] = (uint8_t)(0x30 + i);
        es2[i] = (uint8_t)(0x50 + i); rs1[i] = (uint8_t)(0x70 + i); iv[i] = (uint8_t)(0xC0 + i); }
    uint8_t kdk[32]; wps_kdk(sha, n1, mac, n2, kdk); CHECK_VEC(kdk, 32, "kdk");
    wps_keys_t k; wps_derive_keys(shared, n1, mac, n2, &k);
    CHECK_VEC(k.auth, 32, "auth"); CHECK_VEC(k.kwk, 16, "kwk"); CHECK_VEC(k.emsk, 32, "emsk");
    uint8_t psk1[16], psk2[16], h[32];
    wps_psk(k.auth, "12345670", psk1, psk2); CHECK_VEC(psk1, 16, "psk1"); CHECK_VEC(psk2, 16, "psk2");
    wps_hash(k.auth, es1, psk1, pke, pkr, h); CHECK_VEC(h, 32, "ehash1");
    wps_hash(k.auth, es2, psk2, pke, pkr, h); CHECK_VEC(h, 32, "ehash2");
    wps_hash(k.auth, rs1, psk1, pke, pkr, h); CHECK_VEC(h, 32, "rhash1");
    wps_psk(k.auth, "00000000", psk1, psk2); CHECK_VEC(psk1, 16, "pbc_psk1");
    uint8_t a8[8]; wps_authenticator(k.auth, (const uint8_t *)"prev-message", 12, (const uint8_t *)"current-message", 15, a8);
    CHECK_VEC(a8, 8, "authenticator");
    uint8_t inner[20] = {0x10, 0x16, 0x00, 0x10}, enc[96], pl[64];
    memcpy(inner + 4, es1, 16);
    int n = wps_encr_seal(&k, iv, inner, 20, enc, sizeof enc);
    CHECK(n == 64); if (n > 0) CHECK_VEC(enc, (size_t)n, "seal");
    CHECK(wps_encr_open(&k, enc, 64, pl, sizeof pl) == 20 && !memcmp(pl, inner, 20));
    enc[40] ^= 1; CHECK(wps_encr_open(&k, enc, 64, pl, sizeof pl) < 0);       /* tamper */
    enc[40] ^= 1; enc[3] ^= 0x80;                                             /* flip a bit in the IV */
    int r = wps_encr_open(&k, enc, 64, pl, sizeof pl);
    CHECK(r < 0);                                                             /* CBC: IV bit flip garbles plaintext block 1; KWA catches it */
    enc[3] ^= 0x80;
    wps_keys_t k2 = k; k2.auth[0] ^= 1; CHECK(wps_encr_open(&k2, enc, 64, pl, sizeof pl) < 0);   /* wrong AuthKey: KWA fails */
    k2 = k; k2.kwk[0] ^= 1; CHECK(wps_encr_open(&k2, enc, 64, pl, sizeof pl) < 0);
    CHECK(wps_encr_open(&k, enc, 63, pl, sizeof pl) < 0 && wps_encr_open(&k, enc, 16, pl, sizeof pl) < 0);
}

/* ---------------------------------------------------------------- TLV */
static void test_tlv(void) {
    uint8_t buf[256]; wps_buf_t b; wps_buf_init(&b, buf, sizeof buf);
    wps_put8(&b, 0x1022, 4); wps_put16(&b, 0x1012, 0x0004); wps_put(&b, 0x1045, "net", 3); wps_put(&b, 0x1027, NULL, 0);
    wps_put8(&b, 0x1022, 9);                                           /* duplicate: first wins */
    CHECK(!b.err && b.len == 5 + 6 + 7 + 4 + 5);
    CHECK(wps_tlv_check(buf, b.len) == 0);
    uint8_t v8; uint16_t v16; size_t l;
    CHECK(wps_tlv_get8(buf, b.len, 0x1022, &v8) == 0 && v8 == 4);
    CHECK(wps_tlv_get16(buf, b.len, 0x1012, &v16) == 0 && v16 == 4);
    CHECK(wps_tlv_get16(buf, b.len, 0x1022, &v16) == -1);              /* wrong length */
    CHECK(wps_tlv_find(buf, b.len, 0x1045, &l) && l == 3 && !memcmp(wps_tlv_find(buf, b.len, 0x1045, &l), "net", 3));
    CHECK(wps_tlv_find(buf, b.len, 0x1027, &l) && l == 0);
    CHECK(wps_tlv_find(buf, b.len, 0x9999, &l) == NULL);
    for (size_t cut = 1; cut < b.len; cut++) { if (wps_tlv_check(buf, cut) == 0) continue; CHECK(wps_tlv_find(buf, cut, 0x9999, &l) == NULL); }
    CHECK(wps_tlv_check(buf, b.len - 1) == -1 && wps_tlv_check(buf, 3) == -1 && wps_tlv_check(buf, 0) == 0);
    uint8_t small[8]; wps_buf_init(&b, small, sizeof small); wps_put(&b, 1, "abcdefgh", 8); CHECK(b.err);
    uint8_t lie[] = {0x10, 0x22, 0xFF, 0xFF, 1}; CHECK(wps_tlv_check(lie, 5) == -1 && wps_tlv_find(lie, 5, 0x1022, &l) == NULL);
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

/* ---------------------------------------------------------------- EAP-level access point (test only) */
typedef struct { uint8_t id; int log_idx; uint8_t seen_nack[WPS_MAX_MSG]; size_t seen_nack_len; int frames; } ap_t;

static int ap_send_frags(wps_eap_t *s, ap_t *ap, int op, const uint8_t *msg, size_t n, size_t frag, uint8_t *resp) {
    size_t off = 0; int rl = 0;
    do {
        size_t rem = n - off, chunk = rem > frag ? frag : rem;
        int first = off == 0 && rem > frag;
        uint8_t f[WPS_EAP_MAX_FRAME];
        int fl = wps_eap_build(f, sizeof f, 1, ++ap->id, op, rem > chunk ? WPS_FLAG_MORE : 0, first, (uint16_t)n, msg + off, chunk);
        CHECK(fl > 0); ap->frames++;
        rl = wps_eap_rx(s, f, (size_t)fl, resp, WPS_EAP_MAX_FRAME);
        off += chunk;
        if (off < n) { CHECK(rl > 0 && resp[4 + 12] == WPS_OP_FRAG_ACK && resp[5] == ap->id); }
    } while (off < n);
    return rl;
}
/* reassemble the enrollee's message that starts with resp (a frame) ; returns message length, sets *op; 0 = no reply */
static int ap_collect(wps_eap_t *s, ap_t *ap, uint8_t *resp, int rl, uint8_t *msg, int *op) {
    if (rl <= 0) return 0;
    size_t have = 0, total = 0;
    for (;;) {
        CHECK(resp[0] == 1 && resp[1] == 0 && resp[4] == 2 && resp[5] == ap->id);           /* EAP Response, our id */
        CHECK(resp[8] == 254 && !memcmp(resp + 9, "\x00\x37\x2A\0\0\0\1", 7));
        size_t elen = (size_t)(resp[6] << 8 | resp[7]); CHECK(4 + elen == (size_t)rl);
        uint8_t o = resp[4 + 12], fl = resp[4 + 13]; const uint8_t *d = resp + 4 + 14; size_t dl = elen - 14;
        *op = o;
        if (fl & WPS_FLAG_LEN) { total = (size_t)(d[0] << 8 | d[1]); d += 2; dl -= 2; have = 0; }
        memcpy(msg + have, d, dl); have += dl;
        if (!(fl & WPS_FLAG_MORE)) { if (total) CHECK(have == total); return (int)have; }
        uint8_t f[64];
        int n = wps_eap_build(f, sizeof f, 1, ++ap->id, WPS_OP_FRAG_ACK, 0, 0, 0, NULL, 0);
        ap->frames++;
        rl = wps_eap_rx(s, f, (size_t)n, resp, WPS_EAP_MAX_FRAME);
        CHECK(rl > 0); if (rl <= 0) return 0;
    }
}
/* drive a full session; returns wps_eap_result */
static int run_session(wps_eap_t *s, reg_t *r, ap_t *ap, size_t ap_frag) {
    memset(ap, 0, sizeof *ap);
    uint8_t resp[WPS_EAP_MAX_FRAME], f[WPS_EAP_MAX_FRAME], msg[WPS_MAX_MSG], out[WPS_MAX_MSG];
    uint8_t st[4]; CHECK(wps_eap_start_frame(st, 4) == 4 && !memcmp(st, "\1\1\0\0", 4));
    int fl = wps_eap_build_identity(f, sizeof f, 1, ++ap->id, "");
    int rl = wps_eap_rx(s, f, (size_t)fl, resp, sizeof resp);
    CHECK(rl > 9 && resp[4] == 2 && resp[8] == 1 && rl - 9 == 29 && !memcmp(resp + 9, "WFA-SimpleConfig-Enrollee-1-0", 29));
    rl = ap_send_frags(s, ap, WPS_OP_START, NULL, 0, ap_frag, resp);
    int op = 0;
    for (int guard = 0; guard < 30; guard++) {
        int n = ap_collect(s, ap, resp, rl, msg, &op);
        if (n <= 0) break;
        int on = reg_rx(r, msg, (size_t)n, out, sizeof out);
        if (on <= 0) break;
        reg_log(r, out, (size_t)on);
        uint8_t t = 0; wps_tlv_get8(out, (size_t)on, WPS_ATTR_MSG_TYPE, &t);
        rl = ap_send_frags(s, ap, t == WPS_MSG_NACK ? WPS_OP_NACK : WPS_OP_MSG, out, (size_t)on, ap_frag, resp);
    }
    ++ap->id;                                                              /* EAP-Failure ends the exchange */
    f[0] = 1; f[1] = 0; f[2] = 0; f[3] = 4; f[4] = 4; f[5] = ap->id; f[6] = 0; f[7] = 4;
    wps_eap_rx(s, f, 8, resp, sizeof resp);
    return wps_eap_result(s);
}

static uint16_t nack_err_of(const wps_eap_t *s) { return s->en.cfg_error; }

static void fill_cfg(wps_cfg_t *c, const char *pin, size_t frag) {
    memset(c, 0, sizeof *c);
    static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(c->mac, mac, 6); wps_uuid_from_mac(mac, c->uuid);
    c->pin = pin; c->rand_fn = det_rand; c->frag_size = frag;
}

static wps_eap_t *S; static reg_t *R;

static void test_success(const char *name, const char *pin, size_t efrag, size_t afrag, int transcript) {
    wps_cfg_t cfg; ap_t ap; fill_cfg(&cfg, pin, efrag);
    CHECK(wps_eap_init(S, &cfg) == 0);
    reg_init(R, pin ? pin : "00000000");
    int res = run_session(S, R, &ap, afrag);
    if (res != 1) printf("  [%s] result %d state %d fail %d reg stage %d\n", name, res, S->en.state, S->en.fail, R->stage);
    CHECK(res == 1);
    CHECK(S->en.state == WPS_ST_DONE && S->en.have_cred && R->stage == 5);
    CHECK(S->en.cred.ssid_len == strlen(R->ssid) && !memcmp(S->en.cred.ssid, R->ssid, S->en.cred.ssid_len));
    CHECK(S->en.cred.auth_type == R->auth && S->en.cred.encr_type == R->encr);
    CHECK(S->en.cred.key_len == strlen(R->key) && !strcmp((char *)S->en.cred.key, R->key));
    CHECK(!memcmp(S->en.cred.mac, "\xAA\xBB\xCC\xDD\xEE\x01", 6));
    CHECK(R->msg_len[WPS_MSG_M1] && R->msg_len[WPS_MSG_M7]);
    if (afrag < 200) CHECK(ap.frames > 12);               /* fragmentation really happened */
    if (transcript) {
        const char *path = getenv("WPS_TRANSCRIPT");
        if (path) {
            FILE *fp = fopen(path, "w");
            static char hx[2 * WPS_MAX_MSG + 1];
            if (fp) {
                tohex(S->en.priv, 192, hx); fprintf(fp, "PRIV_E %s\n", hx);
                fprintf(fp, "PIN %s\nMAC 001122334455\n", pin ? pin : "00000000");
                for (int i = 1; i <= 8; i++) {
                    uint8_t t = (uint8_t)(i <= 2 ? i + 3 : i + 4);   /* message type of Mi (M2D is 6) */
                    tohex(R->msg[t], R->msg_len[t], hx);
                    fprintf(fp, "M%d %s\n", i, hx);
                }
                fclose(fp);
            }
        }
    }
    printf("  ok: %s (frames %d)\n", name, ap.frames);
}

/* run to completion and return; used by the failure tests */
static int run_fail(const char *epin, reg_t *prep, size_t frag) {
    wps_cfg_t cfg; ap_t ap; fill_cfg(&cfg, epin, frag);
    CHECK(wps_eap_init(S, &cfg) == 0);
    return run_session(S, prep, &ap, frag ? frag : 1398);
}

static void test_wrong_pin(void) {
    char right[9], wrong[9], half[9];
    wps_pin_generate(1234567, right);            /* 12345670 */
    wps_pin_generate(7654321, wrong);
    wps_pin_generate(1234999, half);             /* same first half "1234", different second half */
    /* 1: wrong first half: enrollee refuses at M4 (R-Hash1) and NACKs with Device Password Auth Failure */
    reg_init(R, wrong);
    CHECK(run_fail(right, R, 0) == -1);
    CHECK(S->en.state == WPS_ST_FAILED && S->en.fail == WPS_FAIL_PIN_AUTH && nack_err_of(S) == WPS_CFG_PIN_AUTH_FAILURE);
    CHECK(R->stage == -1 && R->nack_err == 0 && R->msg_len[WPS_MSG_M5] == 0);       /* registrar got the NACK, never M5 */
    CHECK(!S->en.have_cred);
    /* 2: first half right, second wrong: passes M4, enrollee refuses at M6 (R-Hash2) */
    reg_init(R, half);
    CHECK(run_fail(right, R, 0) == -1);
    CHECK(S->en.fail == WPS_FAIL_PIN_AUTH && nack_err_of(S) == WPS_CFG_PIN_AUTH_FAILURE);
    CHECK(R->msg_len[WPS_MSG_M5] > 0 && R->msg_len[WPS_MSG_M7] == 0 && !S->en.have_cred);
    /* 3: registrar side check: a registrar that sent matching R-Hashes (so M4/M6 pass) but verifies with another PIN
     * rejects E-Hash1 at M5 and E-Hash2 at M7 with config error 18, and the enrollee reports the AP NACK */
    reg_init(R, right); R->pin_ver = wrong;
    CHECK(run_fail(right, R, 0) == -1);
    CHECK(R->stage == -1 && R->nack_err == WPS_CFG_PIN_AUTH_FAILURE && R->msg_len[WPS_MSG_M7] == 0);
    CHECK(S->en.fail == WPS_FAIL_AP_NACK && nack_err_of(S) == WPS_CFG_PIN_AUTH_FAILURE && !S->en.have_cred);
    reg_init(R, right); R->pin_ver = half;
    CHECK(run_fail(right, R, 0) == -1);
    CHECK(R->nack_err == WPS_CFG_PIN_AUTH_FAILURE && R->msg_len[WPS_MSG_M5] > 0 && R->msg_len[WPS_MSG_M7] > 0 && R->msg_len[WPS_MSG_M8] == 0);
    CHECK(S->en.fail == WPS_FAIL_AP_NACK && !S->en.have_cred);
    /* 4: a PBC enrollee against a PIN registrar (and vice versa): password id mismatch, NACK with no error code */
    reg_init(R, right); R->pwid = WPS_DEVPW_PIN;
    CHECK(run_fail(NULL, R, 0) == -1);
    CHECK(S->en.fail == WPS_FAIL_PWID_MISMATCH && nack_err_of(S) == WPS_CFG_NO_ERROR);
    /* 5: PBC but the AP's registrar has a PIN other than 00000000 (hash mismatch) */
    reg_init(R, right);
    CHECK(run_fail(NULL, R, 0) == -1 && S->en.fail == WPS_FAIL_PIN_AUTH);
    printf("  ok: wrong PIN cases\n");
}

static void test_protocol_faults(void) {
    char pin[9]; wps_pin_generate(1234567, pin);
    /* M2D */
    reg_init(R, pin); R->m2d = 1;
    CHECK(run_fail(pin, R, 0) == 0 && S->en.state == WPS_ST_M2D && S->en.fail == WPS_FAIL_NONE);
    /* corrupt Encrypted Settings in M4 (valid Authenticator): decrypt failure NACK, config error 2 */
    reg_init(R, pin); R->corrupt_m4 = 1;
    CHECK(run_fail(pin, R, 0) == -1 && S->en.fail == WPS_FAIL_DECRYPT && nack_err_of(S) == WPS_CFG_DECRYPTION_FAILURE);
    /* registrar sends an invalid DH public key (1) */
    reg_init(R, pin); R->bad_pk = 1;
    CHECK(run_fail(pin, R, 0) == -1 && S->en.fail == WPS_FAIL_BAD_KEY);

    /* message-level: tampered M2 Authenticator, wrong nonce, replayed/out-of-order, garbage */
    wps_cfg_t cfg; fill_cfg(&cfg, pin, 0);
    wps_enrollee_t *e = malloc(sizeof *e); reg_t *rg = R;
    uint8_t m1[WPS_MAX_MSG], m2[WPS_MAX_MSG], o[WPS_MAX_MSG];
    CHECK(wps_enrollee_init(e, &cfg) == 0);
    CHECK(wps_enrollee_rx(e, m1, 10, o, sizeof o) == WPS_ERR_STATE);                    /* before start */
    int n1 = wps_enrollee_start(e, m1, sizeof m1); CHECK(n1 > 300);
    CHECK(wps_enrollee_start(e, m1, sizeof m1) == WPS_ERR_STATE);
    reg_init(rg, pin);
    int n2 = reg_rx(rg, m1, (size_t)n1, m2, sizeof m2); CHECK(n2 > 0);
    CHECK(wps_enrollee_rx(e, m2, 7, o, sizeof o) == WPS_ERR_BAD);                       /* truncated */
    uint8_t bad[WPS_MAX_MSG]; memcpy(bad, m2, (size_t)n2);
    size_t l; uint8_t *ne = (uint8_t *)wps_tlv_find(bad, (size_t)n2, WPS_ATTR_ENROLLEE_NONCE, &l); ne[0] ^= 1;
    CHECK(wps_enrollee_rx(e, bad, (size_t)n2, o, sizeof o) == WPS_ERR_IGNORE && e->state == WPS_ST_WAIT_M2);   /* other session */
    memcpy(bad, m2, (size_t)n2); bad[n2 - 1] ^= 1;
    int nn = wps_enrollee_rx(e, bad, (size_t)n2, o, sizeof o);
    CHECK(nn > 0 && e->state == WPS_ST_FAILED && e->fail == WPS_FAIL_AUTHENTICATOR);
    uint8_t mt = 0; wps_tlv_get8(o, (size_t)nn, WPS_ATTR_MSG_TYPE, &mt); CHECK(mt == WPS_MSG_NACK);
    CHECK(wps_enrollee_rx(e, m2, (size_t)n2, o, sizeof o) == WPS_ERR_STATE);            /* finished sessions are dead */
    /* M4 arriving while waiting for M2 is ignored; a PIN-less mode flags */
    CHECK(wps_enrollee_init(e, &cfg) == 0); wps_enrollee_start(e, m1, sizeof m1);
    reg_init(rg, pin); n2 = reg_rx(rg, m1, (size_t)(n1 = (int)(e->prev_len)), m2, sizeof m2);
    uint8_t fake[40]; wps_buf_t fb; wps_buf_init(&fb, fake, sizeof fake);
    wps_put8(&fb, WPS_ATTR_VERSION, 0x10); wps_put8(&fb, WPS_ATTR_MSG_TYPE, WPS_MSG_M4); wps_put(&fb, WPS_ATTR_ENROLLEE_NONCE, e->ne, 16);
    CHECK(wps_enrollee_rx(e, fake, fb.len, o, sizeof o) == WPS_ERR_IGNORE && e->state == WPS_ST_WAIT_M2);
    /* AP NACK carrying its own config error */
    wps_buf_init(&fb, fake, sizeof fake);
    wps_put8(&fb, WPS_ATTR_VERSION, 0x10); wps_put8(&fb, WPS_ATTR_MSG_TYPE, WPS_MSG_NACK); wps_put(&fb, WPS_ATTR_ENROLLEE_NONCE, e->ne, 16);
    wps_put16(&fb, WPS_ATTR_CONFIG_ERROR, WPS_CFG_SETUP_LOCKED);
    CHECK(wps_enrollee_rx(e, fake, fb.len, o, sizeof o) == 0 && e->state == WPS_ST_FAILED && e->cfg_error == WPS_CFG_SETUP_LOCKED);
    wps_enrollee_clear(e); CHECK(e->priv[0] == 0 && e->state == 0);
    free(e);
    /* bad PINs are refused at init */
    cfg.pin = "12345678"; CHECK(wps_enrollee_init(S ? &S->en : NULL, &cfg) == WPS_ERR_PIN);
    cfg.pin = "abcd"; CHECK(wps_eap_init(S, &cfg) == WPS_ERR_PIN);
    printf("  ok: protocol fault cases\n");
}

static void test_eap_layer(void) {
    char pin[9]; wps_pin_generate(1234567, pin);
    wps_cfg_t cfg; fill_cfg(&cfg, pin, 100);
    CHECK(wps_eap_init(S, &cfg) == 0);
    uint8_t f[WPS_EAP_MAX_FRAME], r1[WPS_EAP_MAX_FRAME], r2[WPS_EAP_MAX_FRAME];
    int n = wps_eap_build_identity(f, sizeof f, 1, 7, "");
    int a = wps_eap_rx(S, f, (size_t)n, r1, sizeof r1);
    int b = wps_eap_rx(S, f, (size_t)n, r2, sizeof r2);                                  /* retransmitted request */
    CHECK(a > 0 && a == b && !memcmp(r1, r2, (size_t)a));
    n = wps_eap_build(f, sizeof f, 1, 8, WPS_OP_START, 0, 0, 0, NULL, 0);
    a = wps_eap_rx(S, f, (size_t)n, r1, sizeof r1);
    CHECK(a > 0 && (r1[4 + 13] & (WPS_FLAG_LEN | WPS_FLAG_MORE)) == (WPS_FLAG_LEN | WPS_FLAG_MORE));   /* M1 does not fit in 100 */
    size_t total = (size_t)(r1[4 + 14] << 8 | r1[4 + 15]); CHECK(total > 300 && total < 600);
    CHECK(a == 4 + 4 + 1 + 3 + 4 + 2 + 2 + 100);
    b = wps_eap_rx(S, f, (size_t)n, r2, sizeof r2);                                      /* duplicate Start: identical reply */
    CHECK(b == a && !memcmp(r1, r2, (size_t)a));
    n = wps_eap_build(f, sizeof f, 1, 9, WPS_OP_FRAG_ACK, 0, 0, 0, NULL, 0);
    a = wps_eap_rx(S, f, (size_t)n, r1, sizeof r1);
    CHECK(a > 0 && r1[4 + 12] == WPS_OP_MSG && (r1[4 + 13] & WPS_FLAG_LEN) == 0 && (r1[4 + 13] & WPS_FLAG_MORE));
    /* foreign EAP method gets a Nak for the expanded type; garbage is dropped; short frames are errors */
    uint8_t md5[] = {1, 0, 0, 6, 1, 10, 0, 6, 4, 0};
    a = wps_eap_rx(S, md5, sizeof md5, r1, sizeof r1);
    CHECK(a == 10 && r1[8] == 3 && r1[9] == 254);
    uint8_t nonEap[] = {1, 1, 0, 0};
    CHECK(wps_eap_rx(S, nonEap, 4, r1, sizeof r1) == 0);
    uint8_t shortf[] = {1, 0, 0, 40, 1, 1, 0, 40};
    CHECK(wps_eap_rx(S, shortf, sizeof shortf, r1, sizeof r1) == WPS_ERR_BAD);
    /* EAP-Failure before the exchange finished fails the session */
    uint8_t fail[] = {1, 0, 0, 4, 4, 11, 0, 4};
    CHECK(wps_eap_rx(S, fail, sizeof fail, r1, sizeof r1) == 0 && wps_eap_result(S) == -1 && S->en.fail == WPS_FAIL_EAP_FAILURE);
    /* oversize announced message */
    CHECK(wps_eap_init(S, &cfg) == 0);
    uint8_t d[4] = {0xFF, 0xFF, 0, 0};
    n = wps_eap_build(f, sizeof f, 1, 3, WPS_OP_MSG, WPS_FLAG_MORE, 1, 0xFFFF, d, 4);
    CHECK(wps_eap_rx(S, f, (size_t)n, r1, sizeof r1) == WPS_ERR_BAD);
    wps_eap_clear(S);
    printf("  ok: EAP framing\n");
}

/* ---------------------------------------------------------------- IEs */
static void test_ies(void) {
    wps_cfg_t cfg; fill_cfg(&cfg, NULL, 0);
    uint8_t ie[256]; wps_ap_info_t ap; memset(&ap, 0, sizeof ap);
    int n = wps_build_probe_req_ie(&cfg, ie, sizeof ie);
    CHECK(n > 60 && n <= 257 && ie[0] == 0xDD && ie[1] == n - 2 && !memcmp(ie + 2, "\x00\x50\xF2\x04", 4));
    const uint8_t *a = ie + 6; size_t al = (size_t)n - 6;
    CHECK(wps_tlv_check(a, al) == 0);
    uint16_t v16; uint8_t v8; size_t l;
    CHECK(!wps_tlv_get16(a, al, WPS_ATTR_DEV_PWID, &v16) && v16 == WPS_DEVPW_PBC);
    CHECK(!wps_tlv_get8(a, al, WPS_ATTR_REQUEST_TYPE, &v8) && v8 == 1 && !wps_tlv_get8(a, al, WPS_ATTR_VERSION, &v8) && v8 == 0x10);
    CHECK(!wps_tlv_get(a, al, WPS_ATTR_UUID_E, ap.uuid, 16) && !memcmp(ap.uuid, cfg.uuid, 16));
    CHECK(wps_tlv_find(a, al, WPS_ATTR_DEV_NAME, &l) && l == 10 && !memcmp(wps_tlv_find(a, al, WPS_ATTR_DEV_NAME, &l), "AWUS036ACS", 10));
    CHECK(wps_tlv_find(a, al, WPS_ATTR_MANUFACTURER, &l) && l == 4 && !memcmp(wps_tlv_find(a, al, WPS_ATTR_MANUFACTURER, &l), "ALFA", 4));
    CHECK(!wps_tlv_get16(a, al, WPS_ATTR_CONFIG_METHODS, &v16) && (v16 & 0x0280) == 0x0280 && (v16 & 0x0100));
    CHECK(!wps_tlv_get(a, al, WPS_ATTR_PRIMARY_DEVTYPE, ap.uuid, 8));
    CHECK(wps_ap_parse(ie, (size_t)n, &ap) == 1 && ap.version2 == 0x20 && ap.dev_pwid == WPS_DEVPW_PBC);
    cfg.pin = "12345670";
    n = wps_build_probe_req_ie(&cfg, ie, sizeof ie);
    CHECK(wps_ap_parse(ie, (size_t)n, &ap) == 1 && ap.dev_pwid == WPS_DEVPW_PIN);
    cfg.pin = "12345678"; CHECK(wps_build_probe_req_ie(&cfg, ie, sizeof ie) == WPS_ERR_PIN);
    CHECK(wps_build_probe_req_ie(&cfg, ie, 5) < 0);
    n = wps_build_assoc_req_ie(ie, sizeof ie);
    CHECK(n == 6 + 5 + 5 + 10 && ie[0] == 0xDD && !wps_tlv_get8(ie + 6, (size_t)n - 6, WPS_ATTR_REQUEST_TYPE, &v8));
    CHECK(wps_build_assoc_req_ie(ie, 6) < 0);
    /* M1 built by the state machine carries the same device info as the probe request */
    cfg.pin = NULL;
    wps_enrollee_t *e = malloc(sizeof *e); uint8_t m1[WPS_MAX_MSG];
    wps_enrollee_init(e, &cfg); int m = wps_enrollee_start(e, m1, sizeof m1); CHECK(m > 0 && wps_tlv_check(m1, (size_t)m) == 0);
    CHECK(!wps_tlv_get16(m1, (size_t)m, WPS_ATTR_DEV_PWID, &v16) && v16 == 4);
    CHECK(!wps_tlv_get8(m1, (size_t)m, WPS_ATTR_MSG_TYPE, &v8) && v8 == WPS_MSG_M1);
    CHECK(wps_tlv_find(m1, (size_t)m, WPS_ATTR_AUTHENTICATOR, &l) == NULL);              /* M1 has no Authenticator */
    wps_enrollee_clear(e); free(e);
}

static int mk_beacon(uint8_t *out, int locked, int sel, uint16_t pwid, const uint8_t *uuid, int split, uint8_t ssid_c) {
    uint8_t a[200]; wps_buf_t b; wps_buf_init(&b, a, sizeof a);
    wps_put8(&b, WPS_ATTR_VERSION, 0x10); wps_put8(&b, WPS_ATTR_WPS_STATE, 2);
    if (locked >= 0) wps_put8(&b, WPS_ATTR_AP_SETUP_LOCKED, (uint8_t)locked);
    wps_put8(&b, WPS_ATTR_SELECTED_REG, (uint8_t)sel);
    if (sel) { wps_put16(&b, WPS_ATTR_DEV_PWID, pwid); wps_put16(&b, WPS_ATTR_SELREG_METHODS, 0x0188); }
    if (uuid) wps_put(&b, WPS_ATTR_UUID_E, uuid, 16);
    wps_put(&b, WPS_ATTR_DEV_NAME, "HomeAP", 6);
    wps_put_vendor_v2(&b);
    size_t o = 0;
    out[o++] = 0; out[o++] = 1; out[o++] = ssid_c;                                       /* SSID IE first */
    if (!split) { out[o++] = 0xDD; out[o++] = (uint8_t)(4 + b.len); memcpy(out + o, "\x00\x50\xF2\x04", 4); memcpy(out + o + 4, a, b.len); o += 4 + b.len; }
    else for (size_t off = 0; off < b.len; off += 30) {
        size_t c = b.len - off < 30 ? b.len - off : 30;
        out[o++] = 0xDD; out[o++] = (uint8_t)(4 + c); memcpy(out + o, "\x00\x50\xF2\x04", 4); memcpy(out + o + 4, a + off, c); o += 4 + c;
    }
    out[o++] = 0xDD; out[o++] = 5; memcpy(out + o, "\x00\x50\xF2\x01\x01", 5); o += 5;   /* unrelated vendor IE (WPA) */
    return (int)o;
}

static void test_ap_info(void) {
    uint8_t ie[512], u1[16], u2[16]; wps_ap_info_t ap[4];
    memset(ap, 0, sizeof ap); memset(u1, 1, 16); memset(u2, 2, 16);
    int n = mk_beacon(ie, 0, 1, WPS_DEVPW_PBC, u1, 0, 'x');
    CHECK(wps_ap_parse(ie, (size_t)n, &ap[0]) == 1 && ap[0].present && ap[0].version == 0x10 && ap[0].version2 == 0x20);
    CHECK(ap[0].wps_state == 2 && !ap[0].ap_setup_locked && ap[0].selected_registrar && ap[0].dev_pwid == 4 && ap[0].selreg_methods == 0x0188);
    CHECK(ap[0].have_uuid && !memcmp(ap[0].uuid, u1, 16) && !strcmp(ap[0].device_name, "HomeAP"));
    CHECK(wps_ap_check(&ap[0], WPS_MODE_PBC) == WPS_AP_OK && wps_ap_check(&ap[0], WPS_MODE_PIN) == WPS_AP_OK);
    /* same attributes split over several WSC elements */
    n = mk_beacon(ie, 0, 1, WPS_DEVPW_PBC, u1, 1, 'x');
    CHECK(wps_ap_parse(ie, (size_t)n, &ap[1]) == 1 && ap[1].dev_pwid == 4 && ap[1].have_uuid && ap[1].version2 == 0x20 && !strcmp(ap[1].device_name, "HomeAP"));
    /* locked */
    n = mk_beacon(ie, 1, 1, WPS_DEVPW_PBC, u1, 0, 'x'); wps_ap_parse(ie, (size_t)n, &ap[2]);
    CHECK(ap[2].ap_setup_locked && wps_ap_check(&ap[2], WPS_MODE_PBC) == WPS_AP_LOCKED && wps_ap_check(&ap[2], WPS_MODE_PIN) == WPS_AP_LOCKED);
    CHECK(strstr(wps_ap_reason_str(WPS_AP_LOCKED), "locked"));
    /* idle (no PBC window) */
    n = mk_beacon(ie, -1, 0, 0, NULL, 0, 'x'); wps_ap_parse(ie, (size_t)n, &ap[3]);
    CHECK(wps_ap_check(&ap[3], WPS_MODE_PBC) == WPS_AP_PBC_INACTIVE && wps_ap_check(&ap[3], WPS_MODE_PIN) == WPS_AP_OK && !ap[3].have_uuid);
    /* PIN window selected on the AP, not PBC */
    wps_ap_info_t pinw = ap[0]; pinw.dev_pwid = 0;
    CHECK(wps_ap_check(&pinw, WPS_MODE_PBC) == WPS_AP_PBC_INACTIVE);
    /* no WSC IE, malformed IE list */
    uint8_t plain[] = {0, 3, 'a', 'b', 'c'}; wps_ap_info_t none; memset(&none, 0, sizeof none);
    CHECK(wps_ap_parse(plain, sizeof plain, &none) == 0 && wps_ap_check(&none, WPS_MODE_PBC) == WPS_AP_NO_WPS);
    uint8_t trunc[] = {0xDD, 20, 0, 0x50}; CHECK(wps_ap_parse(trunc, sizeof trunc, &none) == -1);

    /* pick / overlap */
    wps_ap_info_t set[3]; int cnt;
    memset(set, 0, sizeof set);
    for (int i = 0; i < 3; i++) set[i].bssid[5] = (uint8_t)(i + 1);
    n = mk_beacon(ie, 0, 1, 4, u1, 0, 'a'); wps_ap_parse(ie, (size_t)n, &set[0]);
    n = mk_beacon(ie, -1, 0, 0, u2, 0, 'b'); wps_ap_parse(ie, (size_t)n, &set[1]);
    n = mk_beacon(ie, 0, 1, 4, u1, 0, 'c'); wps_ap_parse(ie, (size_t)n, &set[2]);     /* same router, other band */
    CHECK(wps_pbc_pick(set, 3, &cnt) == 0 && cnt == 1);                                /* one active registrar (two bands) */
    n = mk_beacon(ie, 0, 1, 4, u2, 0, 'b'); wps_ap_parse(ie, (size_t)n, &set[1]);     /* a second router pressed */
    CHECK(wps_pbc_pick(set, 3, &cnt) == -2 && cnt == 2);                               /* session overlap */
    set[1].ap_setup_locked = 1;                                                        /* locked ones do not count */
    CHECK(wps_pbc_pick(set, 3, &cnt) == 0 && cnt == 1);
    set[0].selected_registrar = 0; set[2].selected_registrar = 0;
    CHECK(wps_pbc_pick(set, 3, &cnt) == -1 && cnt == 0);
    /* beacons carry no UUID: fall back to distinct BSSIDs */
    memset(set, 0, sizeof set);
    for (int i = 0; i < 2; i++) { set[i].bssid[5] = (uint8_t)(i + 1); n = mk_beacon(ie, 0, 1, 4, NULL, 0, 'a'); wps_ap_parse(ie, (size_t)n, &set[i]); }
    CHECK(wps_pbc_pick(set, 2, &cnt) == -2 && cnt == 2);
    printf("  ok: AP WSC IE\n");
}

static void test_limiter(void) {
    wps_limiter_t l; wps_limiter_reset(&l);
    CHECK(wps_limiter_check(&l, 100) == 0);
    wps_limiter_record(&l, 100, 0); CHECK(wps_limiter_check(&l, 100) == 30 && wps_limiter_check(&l, 129) == 1 && wps_limiter_check(&l, 130) == 0);
    wps_limiter_record(&l, 130, 0); CHECK(wps_limiter_check(&l, 130) == 60);
    wps_limiter_record(&l, 200, 0); CHECK(wps_limiter_check(&l, 200) == 120);
    wps_limiter_record(&l, 400, 0); CHECK(wps_limiter_check(&l, 400) == 240 && l.fails == 4 && !l.blocked);
    wps_limiter_record(&l, 700, 0); CHECK(wps_limiter_check(&l, 100000) == -1);            /* fifth failure: blocked until reset */
    wps_limiter_reset(&l); CHECK(wps_limiter_check(&l, 0) == 0);
    wps_limiter_record(&l, 10, 0); wps_limiter_record(&l, 50, 1); CHECK(l.fails == 0 && wps_limiter_check(&l, 50) == 0);
    for (int i = 0; i < 4; i++) wps_limiter_record(&l, 0, 0);
    CHECK(wps_limiter_check(&l, 0) == 240);
}

static void test_uuid(void) {
    uint8_t m1[6] = {1, 2, 3, 4, 5, 6}, m2[6] = {1, 2, 3, 4, 5, 7}, u1[16], u2[16], u3[16];
    wps_uuid_from_mac(m1, u1); wps_uuid_from_mac(m2, u2); wps_uuid_from_mac(m1, u3);
    CHECK(!memcmp(u1, u3, 16) && memcmp(u1, u2, 16) && (u1[6] >> 4) == 5 && (u1[8] >> 6) == 2);
}


/* mutated / random input must never crash (ASAN+UBSAN build) and never produce a credential */
static void test_fuzz(void) {
    char pin[9]; wps_pin_generate(1234567, pin);
    wps_cfg_t cfg; fill_cfg(&cfg, pin, 0);
    wps_enrollee_t *e = malloc(sizeof *e); reg_t *rg = R;
    uint8_t m1[WPS_MAX_MSG], m2[WPS_MAX_MSG], bad[WPS_MAX_MSG], o[WPS_MAX_MSG], r[4];
    int cred = 0;
    for (int it = 0; it < 3000; it++) {
        wps_enrollee_init(e, &cfg);
        int n1 = wps_enrollee_start(e, m1, sizeof m1);
        reg_init(rg, pin);
        int n2 = reg_rx(rg, m1, (size_t)n1, m2, sizeof m2);
        memcpy(bad, m2, (size_t)n2);
        det_rand(r, 4);
        int flips = 1 + r[0] % 3;
        for (int f = 0; f < flips; f++) { det_rand(r, 4); bad[(r[0] << 8 | r[1]) % (size_t)n2] ^= (uint8_t)(1u << (r[2] % 8)); }
        size_t len = (it % 5 == 0) ? (size_t)((r[3] * 7) % (size_t)n2) : (size_t)n2;
        wps_enrollee_rx(e, bad, len, o, sizeof o);
        cred += e->have_cred;
    }
    CHECK(cred == 0);
    wps_eap_t *s = S; uint8_t f[300], resp[WPS_EAP_MAX_FRAME];
    for (int it = 0; it < 5000; it++) {
        wps_eap_init(s, &cfg);
        det_rand(f, sizeof f);
        if (it & 1) { f[0] = 1; f[1] = 0; f[2] = 0; f[3] = (uint8_t)(rs % 200); f[4] = 1; f[7] = f[3]; f[8] = 254; memcpy(f + 9, "\x00\x37\x2A\0\0\0\1", 7); f[16] = (uint8_t)(1 + it % 6); }
        wps_eap_rx(s, f, (size_t)(it % 300), resp, sizeof resp);
    }
    wps_enrollee_clear(e); free(e);
    printf("  ok: mutated input\n");
}

int main(void) {
    S = malloc(sizeof *S); R = malloc(sizeof *R);
    printf("PIN\n"); test_pin();
    printf("bignum / DH\n"); test_bignum();
    printf("python-generated vectors\n"); test_vectors();
    printf("TLV\n"); test_tlv();
    printf("uuid\n"); test_uuid();
    printf("loopback enrollee <-> registrar over EAP-WSC\n");
    test_success("PBC, single frames", NULL, 0, 1398, 0);
    test_success("PIN 12345670, single frames (transcript)", "12345670", 0, 1398, 1);
    test_success("PIN, 100-byte fragments both ways", "12345670", 100, 100, 0);
    test_success("PBC, 64-byte fragments", NULL, 64, 64, 0);
    test_success("PIN 4 digits", "1234", 0, 1398, 0);
    {   /* mixed credential shapes: open network with empty key, 64-hex PSK */
        wps_cfg_t cfg; ap_t ap; fill_cfg(&cfg, NULL, 0);
        wps_eap_init(S, &cfg); reg_init(R, "00000000"); R->ssid = "OpenNet"; R->key = ""; R->auth = WPS_AUTH_OPEN; R->encr = WPS_ENCR_NONE;
        CHECK(run_session(S, R, &ap, 1398) == 1 && S->en.cred.key_len == 0 && S->en.cred.auth_type == WPS_AUTH_OPEN && !S->en.cred.key_is_hex_psk);
        const char *hexpsk = "0123456789abcdefABCDEF0123456789abcdef0123456789abcdef0123456789";
        wps_eap_init(S, &cfg); reg_init(R, "00000000"); R->key = hexpsk; R->auth = 0x22; R->encr = 0x0C;
        CHECK(run_session(S, R, &ap, 1398) == 1 && S->en.cred.key_is_hex_psk && S->en.cred.key_len == 64 && S->en.cred.auth_type == 0x22);
        printf("  ok: open / raw-PSK credentials\n");
    }
    printf("robustness\n"); test_fuzz();
    printf("failures\n"); test_wrong_pin(); test_protocol_faults(); test_eap_layer();
    printf("IEs\n"); test_ies(); test_ap_info(); test_limiter();
    free(S); free(R);
    if (fails) { printf("WPS TEST FAILED (%d)\n", fails); return 1; }
    printf("WPS TEST OK\n");
    return 0;
}
