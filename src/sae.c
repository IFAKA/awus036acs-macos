// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* sae.c - WPA3-Personal SAE, group 19 (P-256). See sae.h.
 *
 * SECURITY NOTE: the big-number and curve code below is small and self-contained (8x32-bit limbs, Montgomery
 * multiplication for the field, Jacobian points). It is NOT hardened against side channels: scalar multiplication
 * branches on secret bits, point addition has special-case branches, and the hunting-and-pecking loop runs a
 * minimum of 40 iterations but is not branch-free. A local attacker who can time this process could learn about
 * the password or the SAE random values. H2E (the default when the AP offers it) has no password-dependent
 * loop count. Correct results are checked against the IEEE 802.11-2020 Annex J.10 test vectors in test_sae.c.
 *
 * Provenance of the algorithms: IEEE 802.11-2020 12.4.4 (HnP 12.4.4.2.2, H2E 12.4.4.2.3, SSWU), 12.4.5 (commit,
 * confirm, KDF). The hostap sae.c implementation was read to resolve ambiguities (encoding of the KDF context,
 * HKDF labels, element order); no code was copied. */
#include "sae.h"
#include "wpa3.h"
#include <stdlib.h>
#include <string.h>

typedef sae_u256 u256;

/* ------------------------------------------------------------ 256-bit helpers */

static void bn_from_be(u256 *r, const uint8_t b[32]) {
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = b + 28 - 4 * i;
        r->w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
}
static void bn_to_be(const u256 *a, uint8_t b[32]) {
    for (int i = 0; i < 8; i++) {
        uint8_t *p = b + 28 - 4 * i;
        p[0] = (uint8_t)(a->w[i] >> 24); p[1] = (uint8_t)(a->w[i] >> 16); p[2] = (uint8_t)(a->w[i] >> 8); p[3] = (uint8_t)a->w[i];
    }
}
static int bn_cmp(const u256 *a, const u256 *b) {
    for (int i = 7; i >= 0; i--) { if (a->w[i] != b->w[i]) return a->w[i] > b->w[i] ? 1 : -1; }
    return 0;
}
static int bn_is_zero(const u256 *a) { uint32_t v = 0; for (int i = 0; i < 8; i++) v |= a->w[i]; return v == 0; }
static uint32_t bn_add(u256 *r, const u256 *a, const u256 *b) {
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (uint64_t)a->w[i] + b->w[i]; r->w[i] = (uint32_t)c; c >>= 32; }
    return (uint32_t)c;
}
static uint32_t bn_sub(u256 *r, const u256 *a, const u256 *b) {
    int64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (int64_t)a->w[i] - b->w[i]; r->w[i] = (uint32_t)c; c >>= 32; }
    return (uint32_t)(c & 1);
}
static void bn_set(u256 *r, uint32_t v) { memset(r, 0, sizeof *r); r->w[0] = v; }
static void bn_shr1(u256 *r, const u256 *a) {
    for (int i = 0; i < 8; i++) r->w[i] = a->w[i] >> 1 | (i < 7 ? a->w[i + 1] << 31 : 0);
}
static void bn_shr2(u256 *r, const u256 *a) { u256 t; bn_shr1(&t, a); bn_shr1(r, &t); }

static void mod_add(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    u256 t; uint32_t c = bn_add(&t, a, b);
    if (c || bn_cmp(&t, m) >= 0) bn_sub(&t, &t, m);
    *r = t;
}
static void mod_sub(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    u256 t; uint32_t br = bn_sub(&t, a, b);
    if (br) bn_add(&t, &t, m);
    *r = t;
}
/* r = (big-endian byte string) mod m, for any m < 2^256 with a,b < m invariants */
static void reduce_bytes(u256 *r, const uint8_t *b, size_t len, const u256 *m) {
    u256 acc; bn_set(&acc, 0);
    for (size_t i = 0; i < len; i++) {
        for (int k = 0; k < 8; k++) mod_add(&acc, &acc, &acc, m);
        u256 v; bn_set(&v, b[i]);
        mod_add(&acc, &acc, &v, m);
    }
    *r = acc;
}

/* ------------------------------------------------------------ P-256 constants and field */

static const uint8_t P_BE[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff };
static const uint8_t N_BE[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51 };
static const uint8_t B_BE[32] = {
    0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
    0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b };
static const uint8_t GX_BE[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96 };
static const uint8_t GY_BE[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5 };

static struct {
    int ready;
    u256 p, n, n_minus_1, rr, one_m, b_m, a_m, three_m, z_m, p_minus_2, p_plus1_div4, gx, gy;
    uint32_t n0;
} C;

static void mmul(u256 *r, const u256 *a, const u256 *b) {
    uint32_t t[10] = { 0 };
    for (int i = 0; i < 8; i++) {
        uint64_t c = 0, s;
        for (int j = 0; j < 8; j++) { s = (uint64_t)t[j] + (uint64_t)a->w[j] * b->w[i] + c; t[j] = (uint32_t)s; c = s >> 32; }
        s = (uint64_t)t[8] + c; t[8] = (uint32_t)s; t[9] = (uint32_t)(s >> 32);
        uint32_t m = t[0] * C.n0;
        s = (uint64_t)t[0] + (uint64_t)m * C.p.w[0]; c = s >> 32;
        for (int j = 1; j < 8; j++) { s = (uint64_t)t[j] + (uint64_t)m * C.p.w[j] + c; t[j - 1] = (uint32_t)s; c = s >> 32; }
        s = (uint64_t)t[8] + c; t[7] = (uint32_t)s; c = s >> 32;
        t[8] = t[9] + (uint32_t)c;
    }
    u256 res; memcpy(res.w, t, 32);
    if (t[8] || bn_cmp(&res, &C.p) >= 0) bn_sub(&res, &res, &C.p);
    *r = res;
}
static void msq(u256 *r, const u256 *a) { mmul(r, a, a); }
static void fadd(u256 *r, const u256 *a, const u256 *b) { mod_add(r, a, b, &C.p); }
static void fsub(u256 *r, const u256 *a, const u256 *b) { mod_sub(r, a, b, &C.p); }
static void to_m(u256 *r, const u256 *a) { mmul(r, a, &C.rr); }
static void from_m(u256 *r, const u256 *a) { u256 one; bn_set(&one, 1); mmul(r, a, &one); }
static void fexp(u256 *r, const u256 *a, const u256 *e) {
    u256 acc = C.one_m;
    for (int i = 255; i >= 0; i--) {
        msq(&acc, &acc);
        if (e->w[i / 32] >> (i % 32) & 1) mmul(&acc, &acc, a);
    }
    *r = acc;
}
static void finv(u256 *r, const u256 *a) { fexp(r, a, &C.p_minus_2); }
/* sqrt for p = 3 mod 4: a^((p+1)/4); returns 1 if a is a square (result is a root) */
static int fsqrt(u256 *r, const u256 *a) {
    u256 y, y2;
    fexp(&y, a, &C.p_plus1_div4);
    msq(&y2, &y);
    *r = y;
    return bn_cmp(&y2, a) == 0;
}

static void ec_init(void) {
    if (C.ready) return;
    bn_from_be(&C.p, P_BE); bn_from_be(&C.n, N_BE);
    u256 one, two, t; bn_set(&one, 1); bn_set(&two, 2);
    bn_sub(&C.n_minus_1, &C.n, &one);
    /* n0 = -p^-1 mod 2^32 by Newton iteration */
    uint32_t inv = C.p.w[0];
    for (int i = 0; i < 5; i++) inv *= 2 - C.p.w[0] * inv;
    C.n0 = (uint32_t)(0 - inv);
    bn_set(&t, 0); bn_sub(&C.rr, &t, &C.p);                  /* 2^256 mod p */
    for (int i = 0; i < 256; i++) mod_add(&C.rr, &C.rr, &C.rr, &C.p);   /* * 2^256 -> R^2 mod p */
    to_m(&C.one_m, &one);
    u256 bb; bn_from_be(&bb, B_BE); to_m(&C.b_m, &bb);
    u256 v; bn_set(&v, 3); to_m(&C.three_m, &v);
    bn_sub(&v, &C.p, &v); to_m(&C.a_m, &v);                    /* a = -3 */
    bn_set(&v, 10); bn_sub(&v, &C.p, &v); to_m(&C.z_m, &v);     /* Z = -10 */
    bn_sub(&C.p_minus_2, &C.p, &two);
    bn_add(&t, &C.p, &one); bn_shr2(&C.p_plus1_div4, &t);
    bn_from_be(&C.gx, GX_BE); bn_from_be(&C.gy, GY_BE);
    C.ready = 1;
}

/* ------------------------------------------------------------ curve points (Jacobian, Montgomery domain) */

typedef struct { u256 x, y, z; } jp;

static int jp_is_inf(const jp *p) { return bn_is_zero(&p->z); }
static void jp_set_inf(jp *p) { p->x = C.one_m; p->y = C.one_m; bn_set(&p->z, 0); }
static void jp_from_affine(jp *p, const u256 *x, const u256 *y) { to_m(&p->x, x); to_m(&p->y, y); p->z = C.one_m; }

static void jp_dbl(jp *r, const jp *p) {
    if (jp_is_inf(p) || bn_is_zero(&p->y)) { jp_set_inf(r); return; }
    u256 delta, gamma, beta, alpha, t1, t2, x3, y3, z3;
    msq(&delta, &p->z); msq(&gamma, &p->y); mmul(&beta, &p->x, &gamma);
    fsub(&t1, &p->x, &delta); fadd(&t2, &p->x, &delta); mmul(&alpha, &t1, &t2);
    fadd(&t1, &alpha, &alpha); fadd(&alpha, &t1, &alpha);          /* 3*(X-d)(X+d) */
    msq(&x3, &alpha);
    fadd(&t1, &beta, &beta); fadd(&t1, &t1, &t1);                   /* 4 beta */
    fadd(&t2, &t1, &t1);                                            /* 8 beta */
    fsub(&x3, &x3, &t2);
    fadd(&t2, &p->y, &p->z); msq(&z3, &t2); fsub(&z3, &z3, &gamma); fsub(&z3, &z3, &delta);
    fsub(&t1, &t1, &x3); mmul(&y3, &alpha, &t1);
    msq(&t2, &gamma); fadd(&t2, &t2, &t2); fadd(&t2, &t2, &t2); fadd(&t2, &t2, &t2);   /* 8 gamma^2 */
    fsub(&y3, &y3, &t2);
    r->x = x3; r->y = y3; r->z = z3;
}

static void jp_add(jp *r, const jp *p, const jp *q) {
    if (jp_is_inf(p)) { *r = *q; return; }
    if (jp_is_inf(q)) { *r = *p; return; }
    u256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t, x3, y3, z3;
    msq(&z1z1, &p->z); msq(&z2z2, &q->z);
    mmul(&u1, &p->x, &z2z2); mmul(&u2, &q->x, &z1z1);
    mmul(&t, &q->z, &z2z2); mmul(&s1, &p->y, &t);
    mmul(&t, &p->z, &z1z1); mmul(&s2, &q->y, &t);
    fsub(&h, &u2, &u1);
    fsub(&rr, &s2, &s1);
    if (bn_is_zero(&h)) {
        if (bn_is_zero(&rr)) { jp_dbl(r, p); return; }
        jp_set_inf(r); return;
    }
    fadd(&rr, &rr, &rr);
    fadd(&t, &h, &h); msq(&i, &t);
    mmul(&j, &h, &i);
    mmul(&v, &u1, &i);
    msq(&x3, &rr); fsub(&x3, &x3, &j); fsub(&x3, &x3, &v); fsub(&x3, &x3, &v);
    fsub(&t, &v, &x3); mmul(&y3, &rr, &t);
    mmul(&t, &s1, &j); fadd(&t, &t, &t); fsub(&y3, &y3, &t);
    fadd(&t, &p->z, &q->z); msq(&z3, &t); fsub(&z3, &z3, &z1z1); fsub(&z3, &z3, &z2z2); mmul(&z3, &z3, &h);
    r->x = x3; r->y = y3; r->z = z3;
}

static void jp_mul(jp *r, const jp *p, const u256 *k) {
    jp acc; jp_set_inf(&acc);
    for (int i = 255; i >= 0; i--) {
        jp_dbl(&acc, &acc);
        if (k->w[i / 32] >> (i % 32) & 1) jp_add(&acc, &acc, p);
    }
    *r = acc;
}

static int jp_to_affine(const jp *p, u256 *x, u256 *y) {
    if (jp_is_inf(p)) return -1;
    u256 zi, zi2, zi3, t;
    finv(&zi, &p->z); msq(&zi2, &zi); mmul(&zi3, &zi2, &zi);
    mmul(&t, &p->x, &zi2); from_m(x, &t);
    mmul(&t, &p->y, &zi3); from_m(y, &t);
    return 0;
}

/* y^2 = x^3 - 3x + b in the Montgomery domain: returns rhs for x (mont) */
static void rhs(u256 *r, const u256 *xm) {
    u256 t, x3;
    msq(&t, xm); mmul(&x3, &t, xm);
    mmul(&t, &C.three_m, xm);
    fsub(&x3, &x3, &t); fadd(r, &x3, &C.b_m);
}
static int on_curve(const u256 *x, const u256 *y) {
    if (bn_cmp(x, &C.p) >= 0 || bn_cmp(y, &C.p) >= 0) return 0;
    u256 xm, ym, l, rr;
    to_m(&xm, x); to_m(&ym, y);
    msq(&l, &ym); rhs(&rr, &xm);
    return bn_cmp(&l, &rr) == 0;
}

/* ------------------------------------------------------------ SSWU (Z = -10, A = -3) */

static int sswu(const u256 *u, u256 *ox, u256 *oy) {
    u256 um, u2, t1, t2, m, t, x1a, x1b, x1, gx1, x2, gx2, v, x, y, ym, tmp;
    to_m(&um, u);
    msq(&u2, &um); mmul(&t1, &C.z_m, &u2); msq(&t2, &t1); fadd(&m, &t1, &t2);
    int m_zero = bn_is_zero(&m);
    fexp(&t, &m, &C.p_minus_2);                                     /* m^(p-2): 0 when m == 0 */
    mmul(&tmp, &C.z_m, &C.a_m); finv(&tmp, &tmp); mmul(&x1a, &C.b_m, &tmp);          /* b / (z a) */
    u256 zero; bn_set(&zero, 0);
    fsub(&tmp, &zero, &C.b_m); finv(&t2, &C.a_m); mmul(&tmp, &tmp, &t2);             /* -b / a */
    fadd(&t2, &C.one_m, &t); mmul(&x1b, &tmp, &t2);
    x1 = m_zero ? x1a : x1b;
    rhs(&gx1, &x1);
    mmul(&t1, &C.z_m, &u2); mmul(&x2, &t1, &x1);
    rhs(&gx2, &x2);
    int is_qr = fsqrt(&tmp, &gx1);
    v = is_qr ? gx1 : gx2; x = is_qr ? x1 : x2;
    fsqrt(&ym, &v);
    from_m(&y, &ym);
    u256 xp; from_m(&xp, &x);
    if ((y.w[0] & 1) != (u->w[0] & 1)) bn_sub(&y, &C.p, &y);
    *ox = xp; *oy = y;
    return on_curve(&xp, &y) ? 0 : -1;
}

/* ------------------------------------------------------------ password element */

static const uint8_t *max_mac(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) > 0 ? a : b; }
static const uint8_t *min_mac(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) > 0 ? b : a; }

static int pwe_hnp(const uint8_t *pw, size_t pw_len, const uint8_t m1[6], const uint8_t m2[6], u256 *px, u256 *py) {
    uint8_t key[12], buf[300], seed[32], val[32], pbe[32];
    int found = 0, odd = 0;
    u256 fx;
    if (pw_len > 255) return -1;
    memcpy(key, max_mac(m1, m2), 6); memcpy(key + 6, min_mac(m1, m2), 6);
    memcpy(buf, pw, pw_len);
    bn_to_be(&C.p, pbe);
    memset(&fx, 0, sizeof fx);
    for (unsigned counter = 1; counter <= 40 || !found; counter++) {
        if (counter > 200) return -1;
        buf[pw_len] = (uint8_t)counter;
        wpa3_hmac_sha256(key, 12, buf, pw_len + 1, seed);
        wpa3_kdf_sha256(seed, 32, "SAE Hunting and Pecking", pbe, 32, val, 256);
        u256 x, xm, y2, y;
        bn_from_be(&x, val);
        if (bn_cmp(&x, &C.p) >= 0) continue;
        to_m(&xm, &x); rhs(&y2, &xm);
        if (!fsqrt(&y, &y2)) continue;
        if (!found) { found = 1; fx = x; odd = seed[31] & 1; }
    }
    u256 xm, y2, ym, y;
    to_m(&xm, &fx); rhs(&y2, &xm); fsqrt(&ym, &y2); from_m(&y, &ym);
    if ((int)(y.w[0] & 1) != odd) bn_sub(&y, &C.p, &y);
    *px = fx; *py = y;
    return 0;
}

static int pt_h2e(const uint8_t *ssid, size_t ssid_len, const uint8_t *pw, size_t pw_len,
                  const uint8_t *pwid, size_t pwid_len, u256 *tx, u256 *ty) {
    uint8_t seed[32], msg[256 + 80], pv[48];
    if (pw_len > 255 || pwid_len > 80) return -1;
    memcpy(msg, pw, pw_len); if (pwid_len) memcpy(msg + pw_len, pwid, pwid_len);
    wpa3_hmac_sha256(ssid, ssid_len, msg, pw_len + pwid_len, seed);      /* HKDF-Extract(ssid, password [|| id]) */
    static const char *lab[2] = { "SAE Hash to Element u1 P1", "SAE Hash to Element u2 P2" };
    u256 px[2], py[2];
    for (int k = 0; k < 2; k++) {
        /* HKDF-Expand(seed, label, 48): T1 = HMAC(seed, label|01), T2 = HMAC(seed, T1|label|02) */
        uint8_t t1[32], t2[32], tmp[64];
        size_t ll = strlen(lab[k]);
        memcpy(tmp, lab[k], ll); tmp[ll] = 1;
        wpa3_hmac_sha256(seed, 32, tmp, ll + 1, t1);
        memcpy(tmp, t1, 32); memcpy(tmp + 32, lab[k], ll); tmp[32 + ll] = 2;
        wpa3_hmac_sha256(seed, 32, tmp, 32 + ll + 1, t2);
        memcpy(pv, t1, 32); memcpy(pv + 32, t2, 16);
        u256 u;
        reduce_bytes(&u, pv, 48, &C.p);
        if (sswu(&u, &px[k], &py[k])) return -1;
    }
    jp a, b, r;
    jp_from_affine(&a, &px[0], &py[0]); jp_from_affine(&b, &px[1], &py[1]);
    jp_add(&r, &a, &b);
    return jp_to_affine(&r, tx, ty);
}

static int pwe_from_pt(const u256 *tx, const u256 *ty, const uint8_t m1[6], const uint8_t m2[6], u256 *px, u256 *py) {
    uint8_t addrs[12], zero[32] = { 0 }, h[32];
    memcpy(addrs, max_mac(m1, m2), 6); memcpy(addrs + 6, min_mac(m1, m2), 6);
    wpa3_hmac_sha256(zero, 32, addrs, 12, h);                               /* HKDF-Extract(0^32, max||min) */
    u256 val, one;
    reduce_bytes(&val, h, 32, &C.n_minus_1);
    bn_set(&one, 1); mod_add(&val, &val, &one, &C.n);                        /* (h mod (n-1)) + 1 */
    jp a, r;
    jp_from_affine(&a, tx, ty);
    jp_mul(&r, &a, &val);
    return jp_to_affine(&r, px, py);
}

/* ------------------------------------------------------------ public building blocks */

int sae_pwe_hnp(const uint8_t *pw, size_t pw_len, const uint8_t m1[6], const uint8_t m2[6], uint8_t x[32], uint8_t y[32]) {
    ec_init();
    u256 px, py;
    if (pwe_hnp(pw, pw_len, m1, m2, &px, &py)) return -1;
    bn_to_be(&px, x); bn_to_be(&py, y);
    return 0;
}

int sae_pwe_h2e(const uint8_t *ssid, size_t ssid_len, const uint8_t *pw, size_t pw_len, const uint8_t *pwid, size_t pwid_len,
                const uint8_t m1[6], const uint8_t m2[6], uint8_t x[32], uint8_t y[32], uint8_t pt_x[32], uint8_t pt_y[32]) {
    ec_init();
    u256 tx, ty, px, py;
    if (pt_h2e(ssid, ssid_len, pw, pw_len, pwid, pwid_len, &tx, &ty)) return -1;
    if (pt_x) bn_to_be(&tx, pt_x);
    if (pt_y) bn_to_be(&ty, pt_y);
    if (pwe_from_pt(&tx, &ty, m1, m2, &px, &py)) return -1;
    bn_to_be(&px, x); bn_to_be(&py, y);
    return 0;
}

int sae_p256_mul(const uint8_t k[32], const uint8_t *px, const uint8_t *py, uint8_t ox[32], uint8_t oy[32]) {
    ec_init();
    u256 kk, x, y; jp p, r;
    bn_from_be(&kk, k);
    if (px) { bn_from_be(&x, px); bn_from_be(&y, py); if (!on_curve(&x, &y)) return -1; }
    else { x = C.gx; y = C.gy; }
    jp_from_affine(&p, &x, &y);
    jp_mul(&r, &p, &kk);
    if (jp_to_affine(&r, &x, &y)) return -1;
    bn_to_be(&x, ox); bn_to_be(&y, oy);
    return 0;
}

int sae_sswu(const uint8_t u[32], uint8_t x[32], uint8_t y[32]) {
    ec_init();
    u256 uu, px, py;
    reduce_bytes(&uu, u, 32, &C.p);
    if (sswu(&uu, &px, &py)) return -1;
    bn_to_be(&px, x); bn_to_be(&py, y);
    return 0;
}

/* ------------------------------------------------------------ protocol */

static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static unsigned rd16(const uint8_t *p) { return (unsigned)p[0] | (unsigned)p[1] << 8; }

int sae_init(sae_t *s, const uint8_t *pw, size_t pw_len, const uint8_t own[6], const uint8_t peer[6],
             const uint8_t *ssid, size_t ssid_len, const char *pwid, int h2e) {
    if (!pw_len || pw_len > sizeof s->pw || ssid_len > 32 || (h2e && !ssid)) return -1;
    memset(s, 0, sizeof *s);
    memcpy(s->pw, pw, pw_len); s->pw_len = pw_len;
    memcpy(s->own, own, 6); memcpy(s->peer, peer, 6);
    if (ssid) { memcpy(s->ssid, ssid, ssid_len); s->ssid_len = ssid_len; }
    if (pwid) {
        size_t l = strlen(pwid);
        if (!h2e || l > sizeof s->pwid) return -1;
        memcpy(s->pwid, pwid, l); s->pwid_len = l; s->have_pwid = 1;
    }
    s->h2e = h2e ? 1 : 0;
    return 0;
}

void sae_set_test_rand(sae_t *s, const uint8_t rand_[32], const uint8_t mask[32]) {
    memcpy(s->fixed_rand, rand_, 32); memcpy(s->fixed_mask, mask, 32); s->fixed = 1;
}

static void random_scalar(u256 *r) {
    uint8_t b[32];
    for (;;) {
        arc4random_buf(b, 32);
        bn_from_be(r, b);
        if (!bn_is_zero(r) && bn_cmp(r, &C.n) < 0) break;
    }
}

static int make_commit(sae_t *s) {
    ec_init();
    if (s->h2e) {
        u256 tx, ty;
        if (pt_h2e(s->ssid, s->ssid_len, s->pw, s->pw_len, s->pwid, s->pwid_len, &tx, &ty)) return SAE_ERR_PWE;
        if (pwe_from_pt(&tx, &ty, s->own, s->peer, &s->pwe_x, &s->pwe_y)) return SAE_ERR_PWE;
    } else if (pwe_hnp(s->pw, s->pw_len, s->own, s->peer, &s->pwe_x, &s->pwe_y)) return SAE_ERR_PWE;
    u256 mask, one;
    bn_set(&one, 1);
    for (;;) {
        if (s->fixed) { bn_from_be(&s->rand_, s->fixed_rand); bn_from_be(&mask, s->fixed_mask); }
        else { random_scalar(&s->rand_); random_scalar(&mask); }
        mod_add(&s->scalar, &s->rand_, &mask, &C.n);
        if (s->fixed || bn_cmp(&s->scalar, &one) > 0) break;     /* scalar must be > 1 */
    }
    jp pwe, m;
    jp_from_affine(&pwe, &s->pwe_x, &s->pwe_y);
    jp_mul(&m, &pwe, &mask);
    if (jp_to_affine(&m, &s->elem_x, &s->elem_y)) return SAE_ERR_PWE;
    bn_sub(&s->elem_y, &C.p, &s->elem_y);                           /* inverse of the point */
    s->have_commit = 1;
    return 0;
}

static int put_status_hdr(uint8_t *out, size_t cap, unsigned seq, unsigned status) {
    if (cap < 6) return SAE_ERR_MALFORMED;
    le16(out, 3); le16(out + 2, seq); le16(out + 4, status);
    return 6;
}

int sae_build_status(uint16_t seq, uint16_t status, uint8_t *out, size_t cap) {
    int n = put_status_hdr(out, cap, seq, status);
    if (n < 0 || cap < 8) return SAE_ERR_MALFORMED;
    le16(out + 6, SAE_GROUP);
    return 8;
}

int sae_build_commit(sae_t *s, uint8_t *out, size_t cap) {
    int r;
    if (!s->have_commit && (r = make_commit(s))) return r;
    size_t need = 6 + 2 + 32 + 64 + (s->token_len ? s->token_len + 3 : 0) + (s->have_pwid ? s->pwid_len + 3 : 0);
    if (cap < need) return SAE_ERR_MALFORMED;
    size_t n = put_status_hdr(out, cap, 1, s->h2e ? SAE_STATUS_H2E : SAE_STATUS_SUCCESS);
    le16(out + n, SAE_GROUP); n += 2;
    if (!s->h2e && s->token_len) { memcpy(out + n, s->token, s->token_len); n += s->token_len; }
    bn_to_be(&s->scalar, out + n); n += 32;
    bn_to_be(&s->elem_x, out + n); n += 32;
    bn_to_be(&s->elem_y, out + n); n += 32;
    if (s->h2e) {
        if (s->have_pwid) { out[n++] = 255; out[n++] = (uint8_t)(1 + s->pwid_len); out[n++] = 33; memcpy(out + n, s->pwid, s->pwid_len); n += s->pwid_len; }
        if (s->token_len) { out[n++] = 255; out[n++] = (uint8_t)(1 + s->token_len); out[n++] = 93; memcpy(out + n, s->token, s->token_len); n += s->token_len; }
    }
    if (s->state < 1) s->state = 1;
    return (int)n;
}

int sae_last_status(const sae_t *s) { return s->status; }

static void be_ctx_sum(const sae_t *s, uint8_t val[32]) {
    u256 sum; mod_add(&sum, &s->scalar, &s->peer_scalar, &C.n);
    bn_to_be(&sum, val);
}

static int derive_keys(sae_t *s) {
    jp pwe, pe, k;
    u256 kx, ky;
    jp_from_affine(&pwe, &s->pwe_x, &s->pwe_y);
    jp_mul(&k, &pwe, &s->peer_scalar);
    jp_from_affine(&pe, &s->peer_x, &s->peer_y);
    jp_add(&k, &k, &pe);
    jp_mul(&k, &k, &s->rand_);
    if (jp_to_affine(&k, &kx, &ky)) return SAE_ERR_INVALID;
    uint8_t kb[32], salt[64], keyseed[32], val[32], keys[64];
    bn_to_be(&kx, kb);
    size_t sl;
    if (s->h2e && s->peer_rejected_len) { memcpy(salt, s->peer_rejected, s->peer_rejected_len); sl = s->peer_rejected_len; }
    else { memset(salt, 0, 32); sl = 32; }
    wpa3_hmac_sha256(salt, sl, kb, 32, keyseed);
    be_ctx_sum(s, val);
    wpa3_kdf_sha256(keyseed, 32, "SAE KCK and PMK", val, 32, keys, 512);
    memcpy(s->kck, keys, 32); memcpy(s->pmk, keys + 32, 32);
    memcpy(s->pmkid, val, 16);
    s->have_keys = 1;
    return 0;
}

int sae_process_commit(sae_t *s, const uint8_t *b, size_t len) {
    ec_init();
    if (len < 6 || rd16(b) != 3 || rd16(b + 2) != 1) return SAE_ERR_MALFORMED;
    unsigned status = rd16(b + 4);
    s->status = (int)status;
    const uint8_t *p = b + 6, *end = b + len;
    if (status == SAE_STATUS_ANTI_CLOGGING) {
        if (end - p < 2) return SAE_ERR_MALFORMED;
        if (rd16(p) != SAE_GROUP) return SAE_ERR_GROUP;
        p += 2;
        const uint8_t *tok = p; size_t tl = (size_t)(end - p);
        if (s->h2e) {                                              /* token sits in an Anti-Clogging Token Container element */
            if (tl < 3 || tok[0] != 255 || (size_t)tok[1] + 2 > tl || tok[1] < 2 || tok[2] != 93) return SAE_ERR_MALFORMED;
            tl = (size_t)tok[1] - 1; tok += 3;
        }
        if (!tl || tl > sizeof s->token) return SAE_ERR_MALFORMED;
        memcpy(s->token, tok, tl); s->token_len = tl;
        return SAE_ERR_TOKEN;
    }
    if (status == SAE_STATUS_UNSUPPORTED_GROUP) return SAE_ERR_GROUP;
    if (status != (s->h2e ? SAE_STATUS_H2E : SAE_STATUS_SUCCESS)) return SAE_ERR_STATUS;
    if (!s->have_commit) return SAE_ERR_STATE;
    if (end - p < 2) return SAE_ERR_MALFORMED;
    if (rd16(p) != SAE_GROUP) return SAE_ERR_GROUP;
    p += 2;
    if (end - p < 96) return SAE_ERR_MALFORMED;
    u256 sc, ex, ey;
    bn_from_be(&sc, p); bn_from_be(&ex, p + 32); bn_from_be(&ey, p + 64);
    /* 1 < scalar < n */
    u256 one; bn_set(&one, 1);
    if (bn_cmp(&sc, &one) <= 0 || bn_cmp(&sc, &C.n) >= 0) return SAE_ERR_INVALID;
    if (!on_curve(&ex, &ey)) return SAE_ERR_INVALID;
    if (bn_cmp(&sc, &s->scalar) == 0 && bn_cmp(&ex, &s->elem_x) == 0 && bn_cmp(&ey, &s->elem_y) == 0)
        return SAE_ERR_DROP;                                       /* reflection attack */
    if (s->state >= 2 && bn_cmp(&sc, &s->peer_scalar) == 0) return SAE_ERR_DROP;
    p += 96;
    s->peer_rejected_len = 0;
    if (s->h2e) {                                                  /* optional extension elements after the element */
        int got_id = 0;
        while (end - p >= 3) {
            size_t el = p[1];
            if (p[0] != 255 || (size_t)(end - p) < el + 2 || el < 1) return SAE_ERR_MALFORMED;
            if (p[2] == 33) {
                if (!s->have_pwid || el - 1 != s->pwid_len || memcmp(p + 3, s->pwid, s->pwid_len)) return SAE_ERR_INVALID;
                got_id = 1;
            } else if (p[2] == 92) {
                if (el - 1 > sizeof s->peer_rejected) return SAE_ERR_MALFORMED;
                memcpy(s->peer_rejected, p + 3, el - 1); s->peer_rejected_len = el - 1;
            }
            p += el + 2;
        }
        if (s->have_pwid && !got_id) return SAE_ERR_INVALID;
    }
    s->peer_scalar = sc; s->peer_x = ex; s->peer_y = ey;
    int r = derive_keys(s);
    if (r) return r;
    s->state = 2;
    return 0;
}

static void confirm_mac(const sae_t *s, const uint8_t sc[2], const u256 *sc1, const u256 *x1, const u256 *y1,
                        const u256 *sc2, const u256 *x2, const u256 *y2, uint8_t out[32]) {
    uint8_t buf[2 + 5 * 32 + 32];
    size_t n = 0;
    memcpy(buf, sc, 2); n = 2;
    bn_to_be(sc1, buf + n); n += 32; bn_to_be(x1, buf + n); n += 32; bn_to_be(y1, buf + n); n += 32;
    bn_to_be(sc2, buf + n); n += 32; bn_to_be(x2, buf + n); n += 32; bn_to_be(y2, buf + n); n += 32;
    wpa3_hmac_sha256(s->kck, 32, buf, n, out);
}

int sae_build_confirm(sae_t *s, uint8_t *out, size_t cap) {
    if (!s->have_keys) return SAE_ERR_STATE;
    if (cap < 6 + 2 + 32) return SAE_ERR_MALFORMED;
    if (s->send_confirm < 0xffff) s->send_confirm++;
    put_status_hdr(out, cap, 2, SAE_STATUS_SUCCESS);
    le16(out + 6, s->send_confirm);
    confirm_mac(s, out + 6, &s->scalar, &s->elem_x, &s->elem_y, &s->peer_scalar, &s->peer_x, &s->peer_y, out + 8);
    return 40;
}

int sae_process_confirm(sae_t *s, const uint8_t *b, size_t len) {
    if (len < 6 || rd16(b) != 3 || rd16(b + 2) != 2) return SAE_ERR_MALFORMED;
    s->status = (int)rd16(b + 4);
    if (s->status != SAE_STATUS_SUCCESS) return SAE_ERR_STATUS;
    if (!s->have_keys) return SAE_ERR_STATE;
    if (len < 40) return SAE_ERR_MALFORMED;
    uint8_t v[32];
    confirm_mac(s, b + 6, &s->peer_scalar, &s->peer_x, &s->peer_y, &s->scalar, &s->elem_x, &s->elem_y, v);
    uint8_t d = 0;
    for (int i = 0; i < 32; i++) d |= v[i] ^ b[8 + i];
    if (d) return SAE_ERR_CONFIRM;
    s->state = 3;
    return 0;
}

const uint8_t *sae_get_pmk(const sae_t *s) { return s->state == 3 ? s->pmk : NULL; }
const uint8_t *sae_get_pmkid(const sae_t *s) { return s->have_keys ? s->pmkid : NULL; }
