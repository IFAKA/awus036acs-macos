// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_wep.c - tests for src/wep.c. Prints "WEP TEST OK" and exits 0 on success.
 *
 * PUBLISHED VECTORS: RC4 "Key"/"Plaintext", "Wiki"/"pedia", "Secret"/"Attack at dawn" (Wikipedia RC4 article, the
 *   classic known-answer tests); CRC-32("123456789") == 0xCBF43926 (CRC catalogue check value).
 * INDEPENDENT CROSS-CHECK (not a published WEP vector): the two full WEP MPDU bodies were produced by a separate pure
 *   Python RC4 + zlib.crc32 script that follows 802.11 12.3.2 (IV | keyid | RC4(IV||key, data | ICV)).
 * ROUND TRIPS: all key ids, both key sizes, tamper detection, the shared-key challenge body, IV counter. */
#include "wep.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void unhex(const char *s, uint8_t *o) { for (; s[0] && s[1]; s += 2, o++) { unsigned v; sscanf(s, "%2x", &v); *o = (uint8_t)v; } }
static int eqhex(const uint8_t *b, const char *hex) { uint8_t t[128]; unhex(hex, t); return memcmp(b, t, strlen(hex) / 2) == 0; }

static void test_rc4(void)
{
    uint8_t d[32];
    memcpy(d, "Plaintext", 9); rc4_crypt((const uint8_t *)"Key", 3, 0, d, 9);
    CHECK(eqhex(d, "bbf316e8d940af0ad3"));
    memcpy(d, "pedia", 5); rc4_crypt((const uint8_t *)"Wiki", 4, 0, d, 5);
    CHECK(eqhex(d, "1021bf0420"));
    memcpy(d, "Attack at dawn", 14); rc4_crypt((const uint8_t *)"Secret", 6, 0, d, 14);
    CHECK(eqhex(d, "45a01f645fc35b383552544b9bf5"));
    /* skip: discarding n bytes == encrypting n zero bytes first and ignoring them */
    uint8_t a[16] = {0}, b[16 + 256] = {0};
    rc4_crypt((const uint8_t *)"Key", 3, 256, a, 16);
    rc4_crypt((const uint8_t *)"Key", 3, 0, b, 16 + 256);
    CHECK(!memcmp(a, b + 256, 16));
}

static void test_crc(void)
{
    CHECK(wep_crc32((const uint8_t *)"123456789", 9) == 0xCBF43926u);
    CHECK(wep_crc32((const uint8_t *)"", 0) == 0);
}

static void test_frames(void)
{
    uint8_t out[128], plain[128], key13[13];
    static const uint8_t iv1[3] = {1, 2, 3}, iv2[3] = {0xff, 0xfe, 0xfd};
    int n = wep_encrypt((const uint8_t *)"Hello", 5, 0, iv1, (const uint8_t *)"The quick brown fox", 19, out);
    CHECK(n == 27);
    CHECK(eqhex(out, "01020300a128d9c5e4d371c71df6f4772fc8f07d2a4156e10166a4"));
    for (int i = 0; i < 13; i++) key13[i] = (uint8_t)(0x10 + i);
    uint8_t pt[40]; for (int i = 0; i < 40; i++) pt[i] = (uint8_t)i;
    n = wep_encrypt(key13, 13, 3, iv2, pt, 40, out);
    CHECK(n == 48);
    CHECK(eqhex(out, "fffefdc0f60a1272e38c6c7d2af4e813c784e9959830a6bc25c854506ee884e92020578b23bf1264bfb2dbcbcda3d5c9"));
    int kid = -1;
    CHECK(wep_decrypt(key13, 13, out, 48, plain, &kid) == 40 && kid == 3 && !memcmp(plain, pt, 40));
    /* wrong key, flipped bit, truncated */
    CHECK(wep_decrypt((const uint8_t *)"Hello", 5, out, 48, plain, NULL) == -2);
    out[10] ^= 1; CHECK(wep_decrypt(key13, 13, out, 48, plain, NULL) == -2); out[10] ^= 1;
    CHECK(wep_decrypt(key13, 13, out, 7, plain, NULL) == -1);
    CHECK(wep_decrypt(key13, 12, out, 48, plain, NULL) == -1);
    /* in-place encrypt */
    memcpy(out + 4, pt, 40);
    CHECK(wep_encrypt(key13, 13, 3, iv2, out + 4, 40, out) == 48);
    CHECK(eqhex(out, "fffefdc0f60a1272e38c6c7d2af4e813c784e9959830a6bc25c854506ee884e92020578b23bf1264bfb2dbcbcda3d5c9"));
    /* every key id round-trips */
    for (int k = 0; k < 4; k++) {
        n = wep_encrypt((const uint8_t *)"Hello", 5, k, iv1, pt, 40, out);
        CHECK(wep_decrypt((const uint8_t *)"Hello", 5, out, n, plain, &kid) == 40 && kid == k);
    }
    /* shared-key auth, transaction 3: algo=1 seq=3 status=0, challenge element (id 16, 128 bytes) is the encrypted body */
    uint8_t body[6 + 2 + 128], enc[6 + 2 + 128 + 8], dec[200];
    body[0] = 1; body[1] = 0; body[2] = 3; body[3] = 0; body[4] = 0; body[5] = 0; body[6] = 16; body[7] = 128;
    for (int i = 0; i < 128; i++) body[8 + i] = (uint8_t)(i * 7);
    n = wep_encrypt(key13, 13, 0, iv1, body, sizeof body, enc);
    CHECK(n == (int)sizeof enc);
    CHECK(wep_decrypt(key13, 13, enc, n, dec, NULL) == (int)sizeof body && !memcmp(dec, body, sizeof body));
}

static void test_key_parse(void)
{
    uint8_t k[13]; int l;
    CHECK(wep_parse_key("abcde", k, &l) == 0 && l == 5 && !memcmp(k, "abcde", 5));
    CHECK(wep_parse_key("abcdefghijklm", k, &l) == 0 && l == 13);
    CHECK(wep_parse_key("0102030405", k, &l) == 0 && l == 5 && k[0] == 1 && k[4] == 5);
    CHECK(wep_parse_key("0x0A0b0C0d0E", k, &l) == 0 && l == 5 && k[0] == 0x0a && k[1] == 0x0b);
    CHECK(wep_parse_key("000102030405060708090a0b0c", k, &l) == 0 && l == 13 && k[12] == 0x0c);
    CHECK(wep_parse_key("0x123", k, &l) == 0 && l == 5);            /* 5 ASCII characters win over hex */
    CHECK(wep_parse_key("abcdef", k, &l) < 0);                      /* 6 chars */
    CHECK(wep_parse_key("zz02030405", k, &l) < 0);                  /* 10 chars, not hex */
    CHECK(wep_parse_key("", k, &l) < 0);
    CHECK(wep_parse_key(NULL, k, &l) < 0);
}

static void test_iv(void)
{
    uint32_t c = 0; uint8_t iv[3]; int weak = 0;
    for (int i = 0; i < 300000; i++) { wep_next_iv(&c, iv); if (iv[1] == 0xFF && iv[0] >= 3 && iv[0] <= 15) weak++; }
    CHECK(weak == 0);
    c = 0; wep_next_iv(&c, iv); CHECK(iv[0] == 0 && iv[1] == 0 && iv[2] == 0);
    wep_next_iv(&c, iv); CHECK(iv[0] == 1);
}

int main(void)
{
    test_rc4(); test_crc(); test_frames(); test_key_parse(); test_iv();
    if (fails) { printf("WEP TEST FAILED (%d)\n", fails); return 1; }
    printf("WEP TEST OK\n");
    return 0;
}
