// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_mschap.c - see eap_mschap.h. Test vectors: RFC 1320 appendix A.5, RFC 2759 section 9.2, RFC 3079 appendix. */
#include "eap_mschap.h"
#include <CommonCrypto/CommonCrypto.h>
#include <string.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"   /* CC_MD5: needed by LEAP */

/* ---------------------------------------------------------------- MD4 */
#define ROL(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
static void md4_block(uint32_t st[4], const uint8_t blk[64]) {
    uint32_t X[16], a = st[0], b = st[1], c = st[2], d = st[3];
    for (int i = 0; i < 16; i++)
        X[i] = (uint32_t)blk[4 * i] | (uint32_t)blk[4 * i + 1] << 8 | (uint32_t)blk[4 * i + 2] << 16 | (uint32_t)blk[4 * i + 3] << 24;
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
    static const int s1[4] = {3, 7, 11, 19}, s2[4] = {3, 5, 9, 13}, s3[4] = {3, 9, 11, 15};
    static const int o2[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    static const int o3[16] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
    uint32_t v[4] = {a, b, c, d};                       /* v[(0 - i) & 3] is the register being updated */
    for (int i = 0; i < 16; i++) {
        int r = (4 - (i & 3)) & 3;                      /* a,d,c,b rotation */
        uint32_t *A = &v[r], *B = &v[(r + 1) & 3], *C = &v[(r + 2) & 3], *D = &v[(r + 3) & 3];
        *A = ROL(*A + F(*B, *C, *D) + X[i], s1[i & 3]);
    }
    for (int i = 0; i < 16; i++) {
        int r = (4 - (i & 3)) & 3;
        uint32_t *A = &v[r], *B = &v[(r + 1) & 3], *C = &v[(r + 2) & 3], *D = &v[(r + 3) & 3];
        *A = ROL(*A + G(*B, *C, *D) + X[o2[i]] + 0x5a827999u, s2[i & 3]);
    }
    for (int i = 0; i < 16; i++) {
        int r = (4 - (i & 3)) & 3;
        uint32_t *A = &v[r], *B = &v[(r + 1) & 3], *C = &v[(r + 2) & 3], *D = &v[(r + 3) & 3];
        *A = ROL(*A + H(*B, *C, *D) + X[o3[i]] + 0x6ed9eba1u, s3[i & 3]);
    }
    st[0] += v[0]; st[1] += v[1]; st[2] += v[2]; st[3] += v[3];
}

void eap_md4(const uint8_t *in, size_t len, uint8_t out[16]) {
    uint32_t st[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    size_t i = 0;
    for (; i + 64 <= len; i += 64) md4_block(st, in + i);
    uint8_t tail[128] = {0};
    size_t rem = len - i;
    if (rem) memcpy(tail, in + i, rem);
    tail[rem] = 0x80;
    size_t tl = rem < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int k = 0; k < 8; k++) tail[tl - 8 + k] = (uint8_t)(bits >> (8 * k));
    md4_block(st, tail);
    if (tl == 128) md4_block(st, tail + 64);
    for (int k = 0; k < 4; k++) for (int j = 0; j < 4; j++) out[4 * k + j] = (uint8_t)(st[k] >> (8 * j));
}

void eap_md5(const uint8_t *in, size_t len, uint8_t out[16]) { CC_MD5(in, (CC_LONG)len, out); }
void eap_sha1(const uint8_t *in, size_t len, uint8_t out[20]) { CC_SHA1(in, (CC_LONG)len, out); }

/* ---------------------------------------------------------------- NT hash */
void eap_nt_password_hash(const char *pw, size_t n, uint8_t out[16]) {
    uint8_t u[2 * 256 * 2];                              /* UTF-16LE; a UTF-8 byte yields at most 2 bytes */
    size_t ul = 0, i = 0;
    if (n > 256) n = 256;
    while (i < n) {
        uint32_t c = (uint8_t)pw[i];
        int extra = 0;
        if (c >= 0xf0) { c &= 0x07; extra = 3; } else if (c >= 0xe0) { c &= 0x0f; extra = 2; }
        else if (c >= 0xc0) { c &= 0x1f; extra = 1; }
        i++;
        while (extra-- > 0 && i < n) c = (c << 6) | ((uint8_t)pw[i++] & 0x3f);
        if (c >= 0x10000) {
            c -= 0x10000;
            uint32_t hi = 0xd800 + (c >> 10), lo = 0xdc00 + (c & 0x3ff);
            u[ul++] = (uint8_t)hi; u[ul++] = (uint8_t)(hi >> 8); u[ul++] = (uint8_t)lo; u[ul++] = (uint8_t)(lo >> 8);
        } else { u[ul++] = (uint8_t)c; u[ul++] = (uint8_t)(c >> 8); }
    }
    eap_md4(u, ul, out);
}
void eap_hash_nt_hash(const uint8_t h[16], uint8_t out[16]) { eap_md4(h, 16, out); }

/* ---------------------------------------------------------------- DES via CommonCrypto */
static void des_ecb(const uint8_t key7[7], const uint8_t in[8], uint8_t out[8]) {
    uint8_t k[8];
    k[0] = key7[0];
    k[1] = (uint8_t)((key7[0] << 7) | (key7[1] >> 1));
    k[2] = (uint8_t)((key7[1] << 6) | (key7[2] >> 2));
    k[3] = (uint8_t)((key7[2] << 5) | (key7[3] >> 3));
    k[4] = (uint8_t)((key7[3] << 4) | (key7[4] >> 4));
    k[5] = (uint8_t)((key7[4] << 3) | (key7[5] >> 5));
    k[6] = (uint8_t)((key7[5] << 2) | (key7[6] >> 6));
    k[7] = (uint8_t)(key7[6] << 1);
    for (int i = 0; i < 8; i++) {                        /* odd parity in the low bit (CommonCrypto ignores it, keep it correct) */
        uint8_t b = k[i] & 0xfe, p = b;
        p ^= p >> 4; p ^= p >> 2; p ^= p >> 1;
        k[i] = (uint8_t)(b | ((p & 1) ^ 1));
    }
    size_t moved = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, k, 8, NULL, in, 8, out, 8, &moved);
}

void eap_challenge_response(const uint8_t ch[8], const uint8_t h[16], uint8_t out[24]) {
    uint8_t z[21];
    memset(z, 0, 21); memcpy(z, h, 16);
    des_ecb(z, ch, out); des_ecb(z + 7, ch, out + 8); des_ecb(z + 14, ch, out + 16);
}

/* ---------------------------------------------------------------- MS-CHAPv2 */
void eap_mschapv2_challenge_hash(const uint8_t peer_ch[16], const uint8_t auth_ch[16], const char *user, size_t ulen,
                                 uint8_t out[8]) {
    for (size_t i = ulen; i > 0; i--)
        if (user[i - 1] == '\\') { user += i; ulen -= i; break; }
    CC_SHA1_CTX c;
    uint8_t d[20];
    CC_SHA1_Init(&c);
    CC_SHA1_Update(&c, peer_ch, 16); CC_SHA1_Update(&c, auth_ch, 16); CC_SHA1_Update(&c, user, (CC_LONG)ulen);
    CC_SHA1_Final(d, &c);
    memcpy(out, d, 8);
}

void eap_mschapv2_nt_response(const uint8_t auth_ch[16], const uint8_t peer_ch[16], const char *user, size_t ulen,
                              const uint8_t pw_hash[16], uint8_t out[24]) {
    uint8_t ch[8];
    eap_mschapv2_challenge_hash(peer_ch, auth_ch, user, ulen, ch);
    eap_challenge_response(ch, pw_hash, out);
}

void eap_mschapv2_auth_response(const uint8_t pw_hash[16], const uint8_t nt_resp[24], const uint8_t peer_ch[16],
                                const uint8_t auth_ch[16], const char *user, size_t ulen, char out[43]) {
    static const char M1[] = "Magic server to client signing constant";
    static const char M2[] = "Pad to make it do more than one iteration";
    uint8_t hh[16], dig[20], chal[8], fin[20];
    eap_hash_nt_hash(pw_hash, hh);
    CC_SHA1_CTX c;
    CC_SHA1_Init(&c); CC_SHA1_Update(&c, hh, 16); CC_SHA1_Update(&c, nt_resp, 24); CC_SHA1_Update(&c, M1, sizeof M1 - 1);
    CC_SHA1_Final(dig, &c);
    eap_mschapv2_challenge_hash(peer_ch, auth_ch, user, ulen, chal);
    CC_SHA1_Init(&c); CC_SHA1_Update(&c, dig, 20); CC_SHA1_Update(&c, chal, 8); CC_SHA1_Update(&c, M2, sizeof M2 - 1);
    CC_SHA1_Final(fin, &c);
    out[0] = 'S'; out[1] = '=';
    for (int i = 0; i < 20; i++) { out[2 + 2 * i] = "0123456789ABCDEF"[fin[i] >> 4]; out[3 + 2 * i] = "0123456789ABCDEF"[fin[i] & 15]; }
    out[42] = 0;
}

/* ---------------------------------------------------------------- MPPE (RFC 3079) */
void eap_mppe_master_key(const uint8_t hh[16], const uint8_t nt_resp[24], uint8_t master[16]) {
    static const char M1[] = "This is the MPPE Master Key";
    uint8_t d[20];
    CC_SHA1_CTX c;
    CC_SHA1_Init(&c); CC_SHA1_Update(&c, hh, 16); CC_SHA1_Update(&c, nt_resp, 24); CC_SHA1_Update(&c, M1, sizeof M1 - 1);
    CC_SHA1_Final(d, &c);
    memcpy(master, d, 16);
}

void eap_mppe_asym_key(const uint8_t master[16], int is_send, int is_server, uint8_t key[16]) {
    static const char M2[] = "On the client side, this is the send key; on the server side, it is the receive key.";
    static const char M3[] = "On the client side, this is the receive key; on the server side, it is the send key.";
    const char *s = is_send ? (is_server ? M3 : M2) : (is_server ? M2 : M3);
    uint8_t pad1[40], pad2[40], d[20];
    memset(pad1, 0, sizeof pad1); memset(pad2, 0xf2, sizeof pad2);
    CC_SHA1_CTX c;
    CC_SHA1_Init(&c); CC_SHA1_Update(&c, master, 16); CC_SHA1_Update(&c, pad1, 40);
    CC_SHA1_Update(&c, s, (CC_LONG)strlen(s)); CC_SHA1_Update(&c, pad2, 40);
    CC_SHA1_Final(d, &c);
    memcpy(key, d, 16);
}

/* ---------------------------------------------------------------- LEAP */
void eap_leap_key(const uint8_t hh[16], const uint8_t ap_chal[8], const uint8_t ap_resp[24],
                  const uint8_t peer_chal[8], const uint8_t peer_resp[24], uint8_t key[16]) {
    uint8_t buf[16 + 8 + 24 + 8 + 24];
    memcpy(buf, hh, 16); memcpy(buf + 16, ap_chal, 8); memcpy(buf + 24, ap_resp, 24);
    memcpy(buf + 48, peer_chal, 8); memcpy(buf + 56, peer_resp, 24);
    CC_MD5(buf, sizeof buf, key);
}
