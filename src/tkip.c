// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* tkip.c - TKIP. See tkip.h. */
#include "tkip.h"
#include "wep.h"
#include <string.h>

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static uint32_t rotl(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }
static uint32_t rotr(uint32_t v, int b) { return (v >> b) | (v << (32 - b)); }

/* ---- Michael ---- */
static void mblock(uint32_t *l, uint32_t *r)
{
    *r ^= rotl(*l, 17); *l += *r;
    *r ^= ((*l & 0x00ff00ffu) << 8) | ((*l & 0xff00ff00u) >> 8); *l += *r;
    *r ^= rotl(*l, 3); *l += *r;
    *r ^= rotr(*l, 2); *l += *r;
}

void michael_raw(const uint8_t key[8], const uint8_t *msg, size_t len, uint8_t mic[8])
{
    uint32_t l = rd32(key), r = rd32(key + 4);
    size_t i, blocks = len / 4;
    for (i = 0; i < blocks; i++) { l ^= rd32(msg + 4 * i); mblock(&l, &r); }
    uint32_t last = 0;                                     /* padding: 0x5a then zeros, then one more zero block */
    size_t rem = len % 4;
    for (size_t k = 0; k < rem; k++) last |= (uint32_t)msg[4 * blocks + k] << (8 * k);
    last |= 0x5au << (8 * rem);
    l ^= last; mblock(&l, &r);
    mblock(&l, &r);                                        /* l ^= 0 */
    wr32(mic, l); wr32(mic + 4, r);
}

void michael_mic(const uint8_t key[8], const uint8_t da[6], const uint8_t sa[6], int prio,
                 const uint8_t *data, size_t len, uint8_t mic[8])
{
    uint8_t buf[16 + 2400];
    if (len > 2400) { memset(mic, 0, 8); return; }
    memcpy(buf, da, 6); memcpy(buf + 6, sa, 6);
    buf[12] = (uint8_t)prio; buf[13] = buf[14] = buf[15] = 0;
    memcpy(buf + 16, data, len);
    michael_raw(key, buf, 16 + len, mic);
}

/* ---- key mixing ---- */
static uint16_t sbox[256];
static void sbox_init(void)
{
    if (sbox[0]) return;
    /* TKIP S-box entry = (2*S, 3*S) of the AES S-box value S (0x63 -> 0xC6A5 for index 0). Build the AES S-box first. */
    uint8_t aes[256], p = 1, q = 1;
    do {
        p = p ^ (uint8_t)(p << 1) ^ (p & 0x80 ? 0x1B : 0);               /* p *= 3 */
        q ^= q << 1; q ^= q << 2; q ^= q << 4; if (q & 0x80) q ^= 0x09;  /* q /= 3 */
        uint8_t x = q ^ (uint8_t)(q << 1 | q >> 7) ^ (uint8_t)(q << 2 | q >> 6) ^ (uint8_t)(q << 3 | q >> 5) ^ (uint8_t)(q << 4 | q >> 4);
        aes[p] = x ^ 0x63;
    } while (p != 1);
    aes[0] = 0x63;
    for (int i = 0; i < 256; i++) {
        uint8_t s = aes[i], s2 = (uint8_t)(s << 1) ^ (s & 0x80 ? 0x1B : 0);
        sbox[i] = (uint16_t)(s2 << 8 | (s2 ^ s));
    }
}

static uint16_t S_(uint16_t v)
{
    uint16_t t = sbox[v >> 8];
    return sbox[v & 255] ^ (uint16_t)((t << 8) | (t >> 8));
}
static uint16_t k16(const uint8_t *tk, int byte) { return (uint16_t)(tk[byte] | tk[byte + 1] << 8); }
static uint16_t ror1(uint16_t v) { return (uint16_t)((v >> 1) | (v << 15)); }

void tkip_phase1(const uint8_t tk[16], const uint8_t ta[6], uint32_t iv32, uint16_t p[5])
{
    sbox_init();
    p[0] = (uint16_t)iv32; p[1] = (uint16_t)(iv32 >> 16);
    p[2] = k16(ta, 0); p[3] = k16(ta, 2); p[4] = k16(ta, 4);
    for (int i = 0; i < 8; i++) {
        int j = 2 * (i & 1);
        p[0] = (uint16_t)(p[0] + S_(p[4] ^ k16(tk, 0 + j)));
        p[1] = (uint16_t)(p[1] + S_(p[0] ^ k16(tk, 4 + j)));
        p[2] = (uint16_t)(p[2] + S_(p[1] ^ k16(tk, 8 + j)));
        p[3] = (uint16_t)(p[3] + S_(p[2] ^ k16(tk, 12 + j)));
        p[4] = (uint16_t)(p[4] + S_(p[3] ^ k16(tk, 0 + j)) + i);
    }
}

void tkip_phase2(const uint8_t tk[16], const uint16_t t[5], uint16_t iv16, uint8_t rc4key[16])
{
    uint16_t p[6];
    sbox_init();
    for (int i = 0; i < 5; i++) p[i] = t[i];
    p[5] = (uint16_t)(t[4] + iv16);
    p[0] = (uint16_t)(p[0] + S_(p[5] ^ k16(tk, 0)));
    p[1] = (uint16_t)(p[1] + S_(p[0] ^ k16(tk, 2)));
    p[2] = (uint16_t)(p[2] + S_(p[1] ^ k16(tk, 4)));
    p[3] = (uint16_t)(p[3] + S_(p[2] ^ k16(tk, 6)));
    p[4] = (uint16_t)(p[4] + S_(p[3] ^ k16(tk, 8)));
    p[5] = (uint16_t)(p[5] + S_(p[4] ^ k16(tk, 10)));
    p[0] = (uint16_t)(p[0] + ror1(p[5] ^ k16(tk, 12)));
    p[1] = (uint16_t)(p[1] + ror1(p[0] ^ k16(tk, 14)));
    p[2] = (uint16_t)(p[2] + ror1(p[1]));
    p[3] = (uint16_t)(p[3] + ror1(p[2]));
    p[4] = (uint16_t)(p[4] + ror1(p[3]));
    p[5] = (uint16_t)(p[5] + ror1(p[4]));
    rc4key[0] = (uint8_t)(iv16 >> 8);
    rc4key[1] = (uint8_t)(((iv16 >> 8) | 0x20) & 0x7F);
    rc4key[2] = (uint8_t)iv16;
    rc4key[3] = (uint8_t)((p[5] ^ k16(tk, 0)) >> 1);
    for (int i = 0; i < 6; i++) { rc4key[4 + 2 * i] = (uint8_t)p[i]; rc4key[5 + 2 * i] = (uint8_t)(p[i] >> 8); }
}

/* ---- MPDU ---- */
int tkip_encrypt(const uint8_t tk[16], const uint8_t mic_key[8], const uint8_t ta[6], const uint8_t da[6], const uint8_t sa[6],
                 int prio, uint64_t tsc, int keyid, const uint8_t *plain, size_t len, uint8_t *out)
{
    uint16_t ttak[5]; uint8_t rk[16];
    if (len > 2300 || (tsc >> 48)) return -1;
    uint32_t iv32 = (uint32_t)(tsc >> 16); uint16_t iv16 = (uint16_t)tsc;
    tkip_phase1(tk, ta, iv32, ttak);
    tkip_phase2(tk, ttak, iv16, rk);
    out[0] = rk[0]; out[1] = rk[1]; out[2] = rk[2];
    out[3] = (uint8_t)(0x20 | ((keyid & 3) << 6));
    wr32(out + 4, iv32);
    uint8_t *body = out + 8;
    memmove(body, plain, len);
    michael_mic(mic_key, da, sa, prio, body, len, body + len);
    wr32(body + len + 8, wep_crc32(body, len + 8));
    rc4_crypt(rk, 16, 0, body, len + 12);
    return (int)(len + TKIP_OVERHEAD);
}

int tkip_decrypt(const uint8_t tk[16], const uint8_t mic_key[8], const uint8_t ta[6], const uint8_t da[6], const uint8_t sa[6],
                 int prio, const uint8_t *in, size_t in_len, uint8_t *plain, uint64_t *tsc, int *keyid)
{
    uint16_t ttak[5]; uint8_t rk[16], tmp[2400], mic[8];
    if (in_len < TKIP_OVERHEAD || in_len - 8 > sizeof tmp) return -1;
    if (!(in[3] & 0x20) || in[1] != ((in[0] | 0x20) & 0x7F)) return -1;     /* ExtIV must be set, TSC1 byte consistent */
    uint32_t iv32 = rd32(in + 4);
    uint16_t iv16 = (uint16_t)(in[0] << 8 | in[2]);
    tkip_phase1(tk, ta, iv32, ttak);
    tkip_phase2(tk, ttak, iv16, rk);
    size_t n = in_len - 8, pl = n - 12;
    memcpy(tmp, in + 8, n);
    rc4_crypt(rk, 16, 0, tmp, n);
    if (rd32(tmp + pl + 8) != wep_crc32(tmp, pl + 8)) return -2;
    michael_mic(mic_key, da, sa, prio, tmp, pl, mic);
    uint8_t d = 0; for (int i = 0; i < 8; i++) d |= mic[i] ^ tmp[pl + i];
    if (d) return -3;
    memcpy(plain, tmp, pl);
    if (tsc) *tsc = (uint64_t)iv32 << 16 | iv16;
    if (keyid) *keyid = in[3] >> 6;
    return (int)pl;
}
