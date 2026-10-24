// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_tkip.c - TKIP unit tests.
 * Provenance of the vectors, stated honestly:
 *  - Michael: the chain of published test vectors from IEEE 802.11i-2004 Annex (key = previous MIC, messages "",
 *    "M", "Mi", "Mic", "Mich", "Michael"). These are independent published values.
 *  - Key mixing (phase 1 / 2) and the MPDU: the published IEEE mixing vectors could not be fetched, so the fixed vector
 *    below was produced by the hostap (wlantest tkip.c, Jouni Malinen) reference code compiled in an off-line harness.
 *    The same harness compared this implementation against hostap on 20000 random (TK, TA, TSC, MAC addresses, data)
 *    inputs with zero mismatches. The MPDU body was also recomputed independently in Python (RC4 + zlib CRC-32).
 * Not tested on air: no TKIP network is available here. */
#include <stdio.h>
#include <string.h>
#include "tkip.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s\n", m); fails++; } } while (0)

static void unhex(const char *h, uint8_t *o) { for (; h[0]; h += 2) { unsigned v; sscanf(h, "%2x", &v); *o++ = (uint8_t)v; } }

int main(void)
{
    /* Michael chain */
    static const struct { const char *key, *msg, *mic; } mv[] = {
        {"0000000000000000", "", "82925c1ca1d130b8"},
        {"82925c1ca1d130b8", "M", "434721ca40639b3f"},
        {"434721ca40639b3f", "Mi", "e8f9becae97e5d29"},
        {"e8f9becae97e5d29", "Mic", "90038fc6cf13c1db"},
        {"90038fc6cf13c1db", "Mich", "d55e100510128986"},
        {"d55e100510128986", "Michael", "0a942b124ecaa546"},
    };
    for (unsigned i = 0; i < sizeof mv / sizeof mv[0]; i++) {
        uint8_t k[8], want[8], got[8];
        unhex(mv[i].key, k); unhex(mv[i].mic, want);
        michael_raw(k, (const uint8_t *)mv[i].msg, strlen(mv[i].msg), got);
        CHECK(!memcmp(got, want, 8), "michael vector");
    }

    uint8_t tk[16], ta[6] = {0x10, 0x22, 0x33, 0x44, 0x55, 0x66}, da[6] = {1, 2, 3, 4, 5, 6}, sa[6] = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    uint8_t mk[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    for (int i = 0; i < 16; i++) tk[i] = (uint8_t)(i * 17 + 3);

    /* mixing vector (hostap oracle) */
    uint16_t ttak[5]; uint8_t rk[16], want[40];
    tkip_phase1(tk, ta, 0x01020304, ttak);
    uint8_t ttb[10]; for (int i = 0; i < 5; i++) { ttb[2 * i] = (uint8_t)ttak[i]; ttb[2 * i + 1] = (uint8_t)(ttak[i] >> 8); }
    unhex("0d879f197683a3bb3a19", want);
    CHECK(!memcmp(ttb, want, 10), "phase1 vector");
    tkip_phase2(tk, ttak, 0x0506, rk);
    unhex("052506ff79150db14a0d42034d00fc81", want);
    CHECK(!memcmp(rk, want, 16), "phase2 vector");

    /* MPDU vector */
    const char *msg = "Hello TKIP!";
    uint8_t out[128], pl[128];
    int n = tkip_encrypt(tk, mk, ta, da, sa, 0, 0x010203040506ULL, 0, (const uint8_t *)msg, strlen(msg), out);
    unhex("05250620040302010e6f4d52c2ed5a87e73706e8afd269684cc9be123628f0", want);
    CHECK(n == 31 && !memcmp(out, want, 31), "mpdu vector");

    uint64_t tsc = 0; int kid = -1;
    n = tkip_decrypt(tk, mk, ta, da, sa, 0, out, 31, pl, &tsc, &kid);
    CHECK(n == (int)strlen(msg) && !memcmp(pl, msg, n), "decrypt round trip");
    CHECK(tsc == 0x010203040506ULL && kid == 0, "tsc / keyid reported");

    /* tamper: body bit -> ICV, wrong MIC key -> Michael, wrong addr -> Michael, key id */
    uint8_t bad[128];
    memcpy(bad, out, 31); bad[10] ^= 1;
    CHECK(tkip_decrypt(tk, mk, ta, da, sa, 0, bad, 31, pl, NULL, NULL) == -2, "tamper detected by ICV");
    uint8_t mk2[8]; memcpy(mk2, mk, 8); mk2[0] ^= 1;
    CHECK(tkip_decrypt(tk, mk2, ta, da, sa, 0, out, 31, pl, NULL, NULL) == -3, "wrong MIC key detected");
    CHECK(tkip_decrypt(tk, mk, ta, sa, da, 0, out, 31, pl, NULL, NULL) == -3, "swapped addresses detected");
    CHECK(tkip_decrypt(tk, mk, ta, da, sa, 1, out, 31, pl, NULL, NULL) == -3, "wrong priority detected");
    memcpy(bad, out, 31); bad[3] &= (uint8_t)~0x20;
    CHECK(tkip_decrypt(tk, mk, ta, da, sa, 0, bad, 31, pl, NULL, NULL) == -1, "missing ExtIV rejected");
    CHECK(tkip_decrypt(tk, mk, ta, da, sa, 0, out, 10, pl, NULL, NULL) == -1, "short frame rejected");

    /* lengths 0..60 and TSC low-word rollover */
    uint8_t data[64];
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)(i * 7);
    for (int len = 0; len <= 60; len++) {
        uint64_t t = 0xFFFEULL + (uint64_t)len;
        n = tkip_encrypt(tk, mk, ta, da, sa, 3, t, 2, data, len, out);
        int r = tkip_decrypt(tk, mk, ta, da, sa, 3, out, n, pl, &tsc, &kid);
        CHECK(n == len + TKIP_OVERHEAD && r == len && !memcmp(pl, data, len) && tsc == t && kid == 2, "round trip lengths");
    }
    if (fails) { printf("TKIP TEST FAILED (%d)\n", fails); return 1; }
    printf("TKIP TEST OK\n");
    return 0;
}
