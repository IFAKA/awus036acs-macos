// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* bignum_dh.c - see bignum_dh.h. */
#include "bignum_dh.h"
#include <string.h>

#define MAXL 48

const uint8_t DH_GROUP5_P[DH_LEN] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/* big-endian bytes -> little-endian 32-bit limbs */
static void to_limbs(const uint8_t *be, size_t nbytes, uint32_t *l) {
    size_t n = nbytes / 4;
    for (size_t i = 0; i < n; i++) {
        const uint8_t *p = be + nbytes - 4 * (i + 1);
        l[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
}
static void from_limbs(const uint32_t *l, size_t nbytes, uint8_t *be) {
    size_t n = nbytes / 4;
    for (size_t i = 0; i < n; i++) {
        uint8_t *p = be + nbytes - 4 * (i + 1);
        p[0] = (uint8_t)(l[i] >> 24); p[1] = (uint8_t)(l[i] >> 16); p[2] = (uint8_t)(l[i] >> 8); p[3] = (uint8_t)l[i];
    }
}
/* a >= b ? */
static int ge(const uint32_t *a, const uint32_t *b, size_t n) {
    for (size_t i = n; i-- > 0;) { if (a[i] != b[i]) return a[i] > b[i]; }
    return 1;
}
static void sub(uint32_t *a, const uint32_t *b, size_t n) {
    int64_t br = 0;
    for (size_t i = 0; i < n; i++) {
        int64_t d = (int64_t)a[i] - b[i] - br;
        br = d < 0; a[i] = (uint32_t)d;
    }
}

/* Montgomery product (CIOS): r = a*b*2^-(32n) mod m. a, b < m. */
static void mont_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *m, uint32_t n0, size_t n) {
    uint32_t t[MAXL + 2];
    memset(t, 0, sizeof t);
    for (size_t i = 0; i < n; i++) {
        uint64_t c = 0;
        for (size_t j = 0; j < n; j++) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * b[i];
            t[j] = (uint32_t)c; c >>= 32;
        }
        c += t[n]; t[n] = (uint32_t)c; t[n + 1] = (uint32_t)(c >> 32);
        uint32_t q = t[0] * n0;
        c = ((uint64_t)t[0] + (uint64_t)q * m[0]) >> 32;
        for (size_t j = 1; j < n; j++) {
            c += (uint64_t)t[j] + (uint64_t)q * m[j];
            t[j - 1] = (uint32_t)c; c >>= 32;
        }
        c += t[n]; t[n - 1] = (uint32_t)c; t[n] = t[n + 1] + (uint32_t)(c >> 32);
    }
    if (t[n] || ge(t, m, n)) sub(t, m, n);
    memcpy(r, t, n * sizeof(uint32_t));
}

int bn_modexp(const uint8_t *base, const uint8_t *exp, size_t elen, const uint8_t *mod, size_t nbytes, uint8_t *out) {
    if (nbytes < 4 || nbytes > DH_LEN || (nbytes & 3) || !(mod[nbytes - 1] & 1) || !(mod[0] | mod[1] | mod[2] | mod[3])) return -1;
    size_t n = nbytes / 4;
    uint32_t m[MAXL], b[MAXL], r[MAXL], bm[MAXL], r2[MAXL], one[MAXL];
    to_limbs(mod, nbytes, m); to_limbs(base, nbytes, b);
    if (ge(b, m, n)) return -1;
    /* n0 = -m^-1 mod 2^32 by Newton iteration */
    uint32_t inv = m[0];
    for (int i = 0; i < 5; i++) inv *= 2 - m[0] * inv;
    uint32_t n0 = (uint32_t)(0u - inv);
    /* R^2 mod m by doubling 1 for 2*32*n steps (R mod m is the value after 32*n steps) */
    memset(r2, 0, sizeof r2); r2[0] = 1;
    if (ge(r2, m, n)) return -1;
    for (size_t i = 0; i < 64 * n; i++) {
        uint32_t carry = 0;
        for (size_t j = 0; j < n; j++) { uint32_t v = r2[j]; r2[j] = v << 1 | carry; carry = v >> 31; }
        if (carry || ge(r2, m, n)) sub(r2, m, n);
    }
    memset(one, 0, sizeof one); one[0] = 1;
    mont_mul(bm, b, r2, m, n0, n);            /* base in Montgomery form */
    mont_mul(r, one, r2, m, n0, n);           /* 1 in Montgomery form */
    for (size_t i = 0; i < elen; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            mont_mul(r, r, r, m, n0, n);
            if ((exp[i] >> bit) & 1) mont_mul(r, r, bm, m, n0, n);
        }
    }
    mont_mul(r, r, one, m, n0, n);            /* leave Montgomery form */
    from_limbs(r, nbytes, out);
    return 0;
}

int dh_public(const uint8_t priv[DH_LEN], uint8_t pub[DH_LEN]) {
    uint8_t g[DH_LEN] = {0}, z = 0;
    g[DH_LEN - 1] = 2;
    for (int i = 0; i < DH_LEN; i++) z |= priv[i];
    if (!z) return -1;
    return bn_modexp(g, priv, DH_LEN, DH_GROUP5_P, DH_LEN, pub);
}

int dh_shared(const uint8_t priv[DH_LEN], const uint8_t peer[DH_LEN], uint8_t out[DH_LEN]) {
    uint8_t pm1[DH_LEN], z = 0;
    memcpy(pm1, DH_GROUP5_P, DH_LEN); pm1[DH_LEN - 1] -= 1;      /* p-1 (p is odd, low byte 0xFF) */
    /* peer must satisfy 1 < peer < p-1 */
    uint8_t hi = 0;
    for (int i = 0; i < DH_LEN - 1; i++) hi |= peer[i];
    if (!hi && peer[DH_LEN - 1] <= 1) return -1;
    if (memcmp(peer, pm1, DH_LEN) >= 0) return -1;
    for (int i = 0; i < DH_LEN; i++) z |= priv[i];
    if (!z) return -1;
    return bn_modexp(peer, priv, DH_LEN, DH_GROUP5_P, DH_LEN, out);
}
