// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wep.c - RC4, CRC-32 and WEP. See wep.h. */
#include "wep.h"
#include <string.h>

void rc4_crypt(const uint8_t *key, size_t klen, size_t skip, uint8_t *data, size_t len)
{
    uint8_t s[256], t;
    unsigned i, j = 0;
    for (i = 0; i < 256; i++) s[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) { j = (j + s[i] + key[i % klen]) & 255; t = s[i]; s[i] = s[j]; s[j] = t; }
    i = j = 0;
    for (size_t n = 0; n < skip + len; n++) {
        i = (i + 1) & 255; j = (j + s[i]) & 255; t = s[i]; s[i] = s[j]; s[j] = t;
        if (n >= skip) data[n - skip] ^= s[(s[i] + s[j]) & 255];
    }
}

uint32_t wep_crc32(const uint8_t *p, size_t n)
{
    static uint32_t tab[256]; static int init;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) { uint32_t c = i; for (int k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1; tab[i] = c; }
        init = 1;
    }
    uint32_t c = 0xFFFFFFFFu;
    while (n--) c = tab[(c ^ *p++) & 255] ^ (c >> 8);
    return ~c;
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int wep_parse_key(const char *s, uint8_t key[13], int *len)
{
    if (!s) return -1;
    size_t n = strlen(s);
    if (n == 5 || n == 13) { memcpy(key, s, n); *len = (int)n; return 0; }     // ASCII (checked first: "0x123" is 5 ASCII chars)
    if (n > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { s += 2; n -= 2; }
    if (n != 10 && n != 26) return -1;
    for (size_t i = 0; i < n; i++) if (hexv(s[i]) < 0) return -1;
    for (size_t i = 0; i < n / 2; i++) key[i] = (uint8_t)(hexv(s[2 * i]) << 4 | hexv(s[2 * i + 1]));
    *len = (int)(n / 2);
    return 0;
}

int wep_encrypt(const uint8_t *key, int klen, int keyid, const uint8_t iv[3], const uint8_t *plain, size_t len, uint8_t *out)
{
    uint8_t k[16];
    if (klen != 5 && klen != 13) return -1;
    memcpy(k, iv, 3); memcpy(k + 3, key, klen);
    out[0] = iv[0]; out[1] = iv[1]; out[2] = iv[2]; out[3] = (uint8_t)((keyid & 3) << 6);
    memmove(out + 4, plain, len);
    uint32_t icv = wep_crc32(plain, len);                  /* plain may alias out + 4: crc taken before it is overwritten */
    out[4 + len] = (uint8_t)icv; out[5 + len] = (uint8_t)(icv >> 8); out[6 + len] = (uint8_t)(icv >> 16); out[7 + len] = (uint8_t)(icv >> 24);
    rc4_crypt(k, 3 + klen, 0, out + 4, len + 4);
    return (int)(len + WEP_OVERHEAD);
}

int wep_decrypt(const uint8_t *key, int klen, const uint8_t *in, size_t in_len, uint8_t *plain, int *keyid)
{
    uint8_t k[16];
    if ((klen != 5 && klen != 13) || in_len < WEP_OVERHEAD) return -1;
    memcpy(k, in, 3); memcpy(k + 3, key, klen);
    size_t pl = in_len - WEP_OVERHEAD;
    if (keyid) *keyid = in[3] >> 6;
    uint8_t tmp[2400];
    if (pl + 4 > sizeof tmp) return -1;
    memcpy(tmp, in + 4, pl + 4);
    rc4_crypt(k, 3 + klen, 0, tmp, pl + 4);
    uint32_t icv = (uint32_t)tmp[pl] | (uint32_t)tmp[pl + 1] << 8 | (uint32_t)tmp[pl + 2] << 16 | (uint32_t)tmp[pl + 3] << 24;
    if (icv != wep_crc32(tmp, pl)) return -2;
    memcpy(plain, tmp, pl);
    return (int)pl;
}

void wep_next_iv(uint32_t *ctr, uint8_t iv[3])
{
    for (;;) {
        uint32_t c = (*ctr)++ & 0xFFFFFF;
        iv[0] = (uint8_t)c; iv[1] = (uint8_t)(c >> 8); iv[2] = (uint8_t)(c >> 16);
        if (!(iv[1] == 0xFF && iv[0] >= 3 && iv[0] <= 15)) return;    /* FMS weak IV (A+3, N-1, X) */
    }
}
