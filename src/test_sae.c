// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_sae.c - tests for src/sae.c and src/wpa3.c. Prints "SAE TEST OK" and exits 0 on success.
 *
 * PUBLISHED / THIRD-PARTY VECTORS
 *   - IEEE Std 802.11-2020 Annex J.10 (SAE test vectors, as transcribed in hostap src/common/common_module_tests.c,
 *     sae_tests(), fetched from git.w1.fi on 2026-10-25): hunting-and-pecking commit message with fixed rand/mask,
 *     peer commit -> KCK, PMK, PMKID; and the H2E case (ssid "byteme", password "mekmitasdigoat", identifier
 *     "psk4internet", MACs 00:09:5b:66:ec:1e / 00:0b:6b:d9:02:46) -> PWE. The H2E vector exercises SSWU, point addition
 *     and scalar multiplication.
 *   - AES-CMAC: RFC 4493 section 4 (all four examples).
 *   - AES key wrap / CCM stay covered by test_wpa.c (RFC 3394, RFC 3610).
 * INDEPENDENT CROSS-CHECKS (python3 hashlib/hmac + `cryptography` 50.0, generated 2026-10-25, not published vectors):
 *   - P-256 scalar multiplication on G and on an arbitrary point, including n-1 and n-2.
 *   - the SAE confirm value for the Annex J.10 commits (HMAC-SHA256 over send-confirm | scalar | element ...).
 *   - SHA-256 KDF (802.11-2020 12.7.1.6.2) and the WPA3 PTK / EAPOL CMAC MIC, PMF CCMP and BIP frames.
 * SELF-CONSISTENCY: full SAE exchanges between two instances of this code (HnP and H2E, with a password identifier),
 *   wrong password, reflection, anti-clogging token flow, unsupported group, invalid scalar/element, AKM 8 4-way
 *   handshake against an authenticator written in this file.
 * NOT tested: any real AP (no WPA3 AP of ours). */
#include "sae.h"
#include "wpa3.h"
#include <CommonCrypto/CommonCrypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
static unsigned rd_le16(const uint8_t *p) { return (unsigned)p[0] | (unsigned)p[1] << 8; }
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void unhex(const char *s, uint8_t *o) {
    for (; s[0] && s[1]; s += 2, o++) { unsigned v; sscanf(s, "%2x", &v); *o = (uint8_t)v; }
}
static int eqhex(const uint8_t *b, const char *hex) {
    uint8_t t[512]; unhex(hex, t); return memcmp(b, t, strlen(hex) / 2) == 0;
}

/* ---- IEEE 802.11-2020 Annex J.10 data (from hostap sae_tests) ---- */
static const uint8_t local_rand[32] = {
    0x99, 0x24, 0x65, 0xfd, 0x3d, 0xaa, 0x3c, 0x60, 0xaa, 0x65, 0x65, 0xb7,
    0xf6, 0x2a, 0x2a, 0x7f, 0x2e, 0x12, 0xdd, 0x12, 0xf1, 0x98, 0xfa, 0xf4,
    0xfb, 0xed, 0x89, 0xd7, 0xff, 0x1a, 0xce, 0x94,
};
static const uint8_t local_mask[32] = {
    0x95, 0x07, 0xa9, 0x0f, 0x77, 0x7a, 0x04, 0x4d, 0x6a, 0x08, 0x30, 0xb9,
    0x1e, 0xa3, 0xd5, 0xdd, 0x70, 0xbe, 0xce, 0x44, 0xe1, 0xac, 0xff, 0xb8,
    0x69, 0x83, 0xb5, 0xe1, 0xbf, 0x9f, 0xb3, 0x22,
};
static const uint8_t local_commit[98] = {
    0x13, 0x00, 0x2e, 0x2c, 0x0f, 0x0d, 0xb5, 0x24, 0x40, 0xad, 0x14, 0x6d,
    0x96, 0x71, 0x14, 0xce, 0x00, 0x5c, 0xe1, 0xea, 0xb0, 0xaa, 0x2c, 0x2e,
    0x5c, 0x28, 0x71, 0xb7, 0x74, 0xf6, 0xc2, 0x57, 0x5c, 0x65, 0xd5, 0xad,
    0x9e, 0x00, 0x82, 0x97, 0x07, 0xaa, 0x36, 0xba, 0x8b, 0x85, 0x97, 0x38,
    0xfc, 0x96, 0x1d, 0x08, 0x24, 0x35, 0x05, 0xf4, 0x7c, 0x03, 0x53, 0x76,
    0xd7, 0xac, 0x4b, 0xc8, 0xd7, 0xb9, 0x50, 0x83, 0xbf, 0x43, 0x82, 0x7d,
    0x0f, 0xc3, 0x1e, 0xd7, 0x78, 0xdd, 0x36, 0x71, 0xfd, 0x21, 0xa4, 0x6d,
    0x10, 0x91, 0xd6, 0x4b, 0x6f, 0x9a, 0x1e, 0x12, 0x72, 0x62, 0x13, 0x25,
    0xdb, 0xe1,
};
static const uint8_t peer_commit[98] = {
    0x13, 0x00, 0x59, 0x1b, 0x96, 0xf3, 0x39, 0x7f, 0xb9, 0x45, 0x10, 0x08,
    0x48, 0xe7, 0xb5, 0x50, 0x54, 0x3b, 0x67, 0x20, 0xd8, 0x83, 0x37, 0xee,
    0x93, 0xfc, 0x49, 0xfd, 0x6d, 0xf7, 0xe0, 0x8b, 0x52, 0x23, 0xe7, 0x1b,
    0x9b, 0xb0, 0x48, 0xd3, 0x87, 0x3f, 0x20, 0x55, 0x69, 0x53, 0xa9, 0x6c,
    0x91, 0x53, 0x6f, 0xd8, 0xee, 0x6c, 0xa9, 0xb4, 0xa6, 0x8a, 0x14, 0x8b,
    0x05, 0x6a, 0x90, 0x9b, 0xe0, 0x3e, 0x83, 0xae, 0x20, 0x8f, 0x60, 0xf8,
    0xef, 0x55, 0x37, 0x85, 0x80, 0x74, 0xdb, 0x06, 0x68, 0x70, 0x32, 0x39,
    0x98, 0x62, 0x99, 0x9b, 0x51, 0x1e, 0x0a, 0x15, 0x52, 0xa5, 0xfe, 0xa3,
    0x17, 0xc2,
};
static const uint8_t kck[32] = {
    0x1e, 0x73, 0x3f, 0x6d, 0x9b, 0xd5, 0x32, 0x56, 0x28, 0x73, 0x04, 0x33,
    0x88, 0x31, 0xb0, 0x9a, 0x39, 0x40, 0x6d, 0x12, 0x10, 0x17, 0x07, 0x3a,
    0x5c, 0x30, 0xdb, 0x36, 0xf3, 0x6c, 0xb8, 0x1a,
};
static const uint8_t pmk[32] = {
    0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1, 0xa9, 0x17, 0x90, 0xf9,
    0x53, 0xfa, 0xaa, 0x45, 0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63,
    0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7, 0xfe, 0x59,
};
static const uint8_t pmkid[16] = {
    0x87, 0x47, 0xa6, 0x00, 0xee, 0xa3, 0xf9, 0xf2, 0x24, 0x75, 0xdf, 0x58,
    0xca, 0x1e, 0x54, 0x98,
};
static const uint8_t pwe_19_x[32] = {
    0xc9, 0x30, 0x49, 0xb9, 0xe6, 0x40, 0x00, 0xf8, 0x48, 0x20, 0x16, 0x49,
    0xe9, 0x99, 0xf2, 0xb5, 0xc2, 0x2d, 0xea, 0x69, 0xb5, 0x63, 0x2c, 0x9d,
    0xf4, 0xd6, 0x33, 0xb8, 0xaa, 0x1f, 0x6c, 0x1e,
};
static const uint8_t pwe_19_y[32] = {
    0x73, 0x63, 0x4e, 0x94, 0xb5, 0x3d, 0x82, 0xe7, 0x38, 0x3a, 0x8d, 0x25,
    0x81, 0x99, 0xd9, 0xdc, 0x1a, 0x5e, 0xe8, 0x26, 0x9d, 0x06, 0x03, 0x82,
    0xcc, 0xbf, 0x33, 0xe6, 0x14, 0xff, 0x59, 0xa0,
};


/* ======================================================================== helpers */
static const uint8_t MA[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0a};
static const uint8_t MB[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};

/* ---- P-256 (python cryptography cross-check) ---- */
static void test_p256(void) {
    static const struct { const char *k, *x, *y; } g[] = {
        {"0000000000000000000000000000000000000000000000000000000000000001",
         "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"},
        {"0000000000000000000000000000000000000000000000000000000000000002",
         "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"},
        {"00000000000000000000000000000000000000000000000000000000deadbeef",
         "b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c18394", "2a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e"},
        {"7fffffff80000000ffffffffffffffff00000000123456789abcdef012345678",
         "086490adf0f2a14eb755340fdd4ae2887f6bb37d2487e9002a4ab295ab808499", "05271e8e49bff9fdd58bd9f370de3cce96af2b2d4e9ca8270e566d1a7f9b4019"},
        {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
         "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"},
        {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
         "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", "f888aaee24712fc0d6c26539608bcf244582521ac3167dd661fb4862dd878c2e"},
    };
    uint8_t k[32], x[32], y[32];
    for (size_t i = 0; i < sizeof g / sizeof g[0]; i++) {
        unhex(g[i].k, k);
        CHECK(sae_p256_mul(k, NULL, NULL, x, y) == 0);
        CHECK(eqhex(x, g[i].x) && eqhex(y, g[i].y));
    }
    uint8_t px[32], py[32];
    unhex("471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c", px);
    unhex("dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858", py);
    static const struct { const char *k, *x, *y; } p[] = {
        {"0000000000000000000000000000000000000000000000000000000000000003",
         "e64c2d46a9d3fa97a28a58bd090d7534b16e73fdf51dbdab4ce6f3fd2e52e011", "f09a9bc65e4636cf11cbe4b954f6eb7b181e0305d1884c240b7316bfce42c274"},
        {"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
         "61f24e8c6d4f9c3c3545dec12ecda05cb73507a3bbcdd2de3ac1f0b411569638", "f14d6b14e91ce7fead3e591a16ff41ffaac671865dd97bb8a019b5dd0c86f030"},
    };
    for (size_t i = 0; i < 2; i++) {
        unhex(p[i].k, k);
        CHECK(sae_p256_mul(k, px, py, x, y) == 0);
        CHECK(eqhex(x, p[i].x) && eqhex(y, p[i].y));
    }
    /* k = n gives the point at infinity */
    unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", k);
    CHECK(sae_p256_mul(k, NULL, NULL, x, y) < 0);
}

/* ---- Annex J.10 hunting-and-pecking and H2E known answers ---- */
static void test_annex_j10(void) {
    const uint8_t addr1[6] = {0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87};
    const uint8_t addr2[6] = {0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c};
    const char *pw = "mekmitasdigoat";
    sae_t s;
    uint8_t buf[256];
    CHECK(sae_init(&s, (const uint8_t *)pw, strlen(pw), addr1, addr2, NULL, 0, NULL, 0) == 0);
    sae_set_test_rand(&s, local_rand, local_mask);
    int n = sae_build_commit(&s, buf, sizeof buf);
    CHECK(n == 6 + (int)sizeof local_commit);
    CHECK(n > 6 && memcmp(buf + 6, local_commit, sizeof local_commit) == 0);
    CHECK(buf[0] == 3 && buf[1] == 0 && buf[2] == 1 && buf[3] == 0 && buf[4] == 0 && buf[5] == 0);
    uint8_t pc[6 + 98] = {3, 0, 1, 0, 0, 0};
    memcpy(pc + 6, peer_commit, sizeof peer_commit);
    CHECK(sae_process_commit(&s, pc, sizeof pc) == 0);
    CHECK(memcmp(s.kck, kck, 32) == 0);
    CHECK(memcmp(s.pmk, pmk, 32) == 0);
    CHECK(memcmp(sae_get_pmkid(&s), pmkid, 16) == 0);
    CHECK(sae_get_pmk(&s) == NULL);                          /* not before the confirm is accepted */
    /* confirm values, independent HMAC from python */
    n = sae_build_confirm(&s, buf, sizeof buf);
    CHECK(n == 40 && buf[2] == 2 && buf[6] == 1 && buf[7] == 0);
    CHECK(eqhex(buf + 8, "b6dec375e4522d27520827d0933cdde7ad3caf3771e4b00702ba4332797fba59"));
    uint8_t pconf[40] = {3, 0, 2, 0, 0, 0, 1, 0};
    unhex("e632b0ce42c22f54b2660b02d034ccb20f93246528f40f4f7fce40fd832166a7", pconf + 8);
    CHECK(sae_process_confirm(&s, pconf, sizeof pconf) == 0);
    CHECK(sae_get_pmk(&s) && memcmp(sae_get_pmk(&s), pmk, 32) == 0);
    pconf[20] ^= 1;
    sae_t s2 = s; s2.state = 2;
    CHECK(sae_process_confirm(&s2, pconf, sizeof pconf) == SAE_ERR_CONFIRM);

    /* H2E: password element from the PT */
    const uint8_t a1b[6] = {0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e};
    const uint8_t a2b[6] = {0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46};
    uint8_t x[32], y[32], ptx[32], pty[32];
    CHECK(sae_pwe_h2e((const uint8_t *)"byteme", 6, (const uint8_t *)pw, strlen(pw), (const uint8_t *)"psk4internet", 12,
                      a1b, a2b, x, y, ptx, pty) == 0);
    CHECK(memcmp(x, pwe_19_x, 32) == 0 && memcmp(y, pwe_19_y, 32) == 0);
    CHECK(sae_pwe_h2e((const uint8_t *)"byteme", 6, (const uint8_t *)pw, strlen(pw), (const uint8_t *)"psk4internet", 12,
                      a2b, a1b, x, y, NULL, NULL) == 0);       /* MAC order must not matter */
    CHECK(memcmp(x, pwe_19_x, 32) == 0 && memcmp(y, pwe_19_y, 32) == 0);
    CHECK(sae_pwe_h2e((const uint8_t *)"byteme", 6, (const uint8_t *)pw, strlen(pw), (const uint8_t *)"psk4internEt", 12,
                      a1b, a2b, x, y, NULL, NULL) == 0);
    CHECK(memcmp(x, pwe_19_x, 32) != 0);
}

/* ---- full exchanges ---- */
static int exchange(const char *pwa, const char *pwb, int h2e, const char *pwid_a, const char *pwid_b, int expect_ok) {
    const uint8_t ssid[] = "TestNet";
    sae_t a, b;
    uint8_t ca[300], cb[300], fa[64], fb[64];
    int ok = 1;
    if (sae_init(&a, (const uint8_t *)pwa, strlen(pwa), MA, MB, ssid, 7, pwid_a, h2e)) return 0;
    if (sae_init(&b, (const uint8_t *)pwb, strlen(pwb), MB, MA, ssid, 7, pwid_b, h2e)) return 0;
    int na = sae_build_commit(&a, ca, sizeof ca), nb = sae_build_commit(&b, cb, sizeof cb);
    CHECK(na > 0 && nb > 0);
    if (na <= 0 || nb <= 0) return 0;
    CHECK(rd_le16(ca + 4) == (h2e ? 126 : 0));
    int ra = sae_process_commit(&a, cb, (size_t)nb), rb = sae_process_commit(&b, ca, (size_t)na);
    if (ra || rb) return !expect_ok;
    int fna = sae_build_confirm(&a, fa, sizeof fa), fnb = sae_build_confirm(&b, fb, sizeof fb);
    CHECK(fna == 40 && fnb == 40);
    ra = sae_process_confirm(&a, fb, (size_t)fnb); rb = sae_process_confirm(&b, fa, (size_t)fna);
    ok = (ra == 0 && rb == 0);
    if (ok) {
        CHECK(memcmp(sae_get_pmk(&a), sae_get_pmk(&b), 32) == 0);
        CHECK(memcmp(sae_get_pmkid(&a), sae_get_pmkid(&b), 16) == 0);
        CHECK(memcmp(sae_get_pmk(&a), sae_get_pmkid(&a), 16) != 0);
    } else {
        CHECK(ra == SAE_ERR_CONFIRM && rb == SAE_ERR_CONFIRM);
        CHECK(sae_get_pmk(&a) == NULL && sae_get_pmk(&b) == NULL);
    }
    return ok == expect_ok;
}

static void test_exchanges(void) {
    for (int i = 0; i < 6; i++) {                        /* random scalars, several rounds incl. HnP loop variance */
        CHECK(exchange("correct horse", "correct horse", 0, NULL, NULL, 1));
        CHECK(exchange("correct horse", "correct horse", 1, NULL, NULL, 1));
    }
    CHECK(exchange("pw with id", "pw with id", 1, "alice", "alice", 1));
    CHECK(exchange("correct horse", "correct horsf", 0, NULL, NULL, 0));
    CHECK(exchange("correct horse", "correct horsf", 1, NULL, NULL, 0));
    CHECK(exchange("pw", "pw", 1, "alice", "bob", 0));      /* identifier mismatch: peer commit rejected */
    CHECK(exchange("a", "a", 0, NULL, NULL, 1));
}

static void test_failures(void) {
    const uint8_t ssid[] = "TestNet";
    sae_t a, b;
    uint8_t ca[300], cb[300], tmp[300];
    for (int h2e = 0; h2e < 2; h2e++) {
        sae_init(&a, (const uint8_t *)"pw", 2, MA, MB, ssid, 7, NULL, h2e);
        sae_init(&b, (const uint8_t *)"pw", 2, MB, MA, ssid, 7, NULL, h2e);
        int na = sae_build_commit(&a, ca, sizeof ca), nb = sae_build_commit(&b, cb, sizeof cb);
        CHECK(na == 6 + 2 + 96 && nb == na);
        /* reflection: our own commit played back at us */
        CHECK(sae_process_commit(&a, ca, (size_t)na) == SAE_ERR_DROP);
        /* confirm before keys */
        CHECK(sae_build_confirm(&a, tmp, sizeof tmp) == SAE_ERR_STATE);
        /* invalid scalar 0, 1, n and bad element */
        memcpy(tmp, cb, (size_t)nb); memset(tmp + 8, 0, 32);
        CHECK(sae_process_commit(&a, tmp, (size_t)nb) == SAE_ERR_INVALID);
        tmp[39] = 1;
        CHECK(sae_process_commit(&a, tmp, (size_t)nb) == SAE_ERR_INVALID);
        unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", tmp + 8);
        CHECK(sae_process_commit(&a, tmp, (size_t)nb) == SAE_ERR_INVALID);
        memcpy(tmp, cb, (size_t)nb); tmp[8 + 32 + 63] ^= 1;
        CHECK(sae_process_commit(&a, tmp, (size_t)nb) == SAE_ERR_INVALID);
        /* truncated */
        CHECK(sae_process_commit(&a, cb, (size_t)nb - 1) == SAE_ERR_MALFORMED);
        /* unsupported group, in the message and as status 77 */
        memcpy(tmp, cb, (size_t)nb); tmp[6] = 20;
        CHECK(sae_process_commit(&a, tmp, (size_t)nb) == SAE_ERR_GROUP);
        uint8_t st[8];
        CHECK(sae_build_status(1, SAE_STATUS_UNSUPPORTED_GROUP, st, sizeof st) == 8);
        CHECK(sae_process_commit(&a, st, 8) == SAE_ERR_GROUP && sae_last_status(&a) == 77);
        /* another status code */
        memcpy(tmp, cb, (size_t)nb); tmp[4] = 1; if (h2e) tmp[4] = 1;
        CHECK(sae_process_commit(&a, tmp, (size_t)nb) == SAE_ERR_STATUS && sae_last_status(&a) == 1);
        /* anti-clogging token: status 76 gives SAE_ERR_TOKEN and the token rides in the next commit */
        uint8_t tk[40]; size_t tl = 0;
        tk[tl++] = 3; tk[tl++] = 0; tk[tl++] = 1; tk[tl++] = 0; tk[tl++] = 76; tk[tl++] = 0; tk[tl++] = 19; tk[tl++] = 0;
        if (h2e) { tk[tl++] = 255; tk[tl++] = 1 + 20; tk[tl++] = 93; }
        for (int i = 0; i < 20; i++) tk[tl++] = (uint8_t)(0xA0 + i);
        CHECK(sae_process_commit(&a, tk, tl) == SAE_ERR_TOKEN && sae_last_status(&a) == 76);
        int n2 = sae_build_commit(&a, tmp, sizeof tmp);
        CHECK(n2 == na + 20 + (h2e ? 3 : 0));
        if (h2e) { CHECK(memcmp(tmp + n2 - 20, tk + tl - 20, 20) == 0 && tmp[n2 - 23] == 255 && tmp[n2 - 21] == 93); }
        else CHECK(memcmp(tmp + 8, tk + 8, 20) == 0);
        /* same scalar / element as before */
        CHECK(memcmp(tmp + (h2e ? 8 : 28), ca + 8, 96) == 0);
        /* B can still parse the tokenised commit */
        if (h2e) CHECK(sae_process_commit(&b, tmp, (size_t)n2) == 0);   /* HnP: the token is for the AP to read */
        /* confirm with wrong status / size */
        CHECK(sae_process_confirm(&b, tmp, 5) == SAE_ERR_MALFORMED);
    }
    /* arguments */
    CHECK(sae_init(&a, (const uint8_t *)"pw", 0, MA, MB, ssid, 7, NULL, 0) < 0);
    CHECK(sae_init(&a, (const uint8_t *)"pw", 2, MA, MB, NULL, 0, NULL, 1) < 0);
    CHECK(sae_init(&a, (const uint8_t *)"pw", 2, MA, MB, ssid, 7, "id", 0) < 0);
}

/* ---- AES-CMAC, RFC 4493 section 4 ---- */
static void test_cmac(void) {
    uint8_t key[16], msg[64], mac[16];
    unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
    unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", msg);
    static const struct { size_t l; const char *m; } v[] = {
        {0, "bb1d6929e95937287fa37d129b756746"}, {16, "070a16b46b4d4144f79bdd9dd04a287c"},
        {40, "dfa66747de9ae63030ca32611497c827"}, {64, "51f0bebf7e3b9d92fc49741779363cfe"},
    };
    for (int i = 0; i < 4; i++) { aes_cmac(key, msg, v[i].l, mac); CHECK(eqhex(mac, v[i].m)); }
}

/* ---- KDF / PTK / EAPOL MIC (python hmac and cryptography CMAC) ---- */
static void test_kdf(void) {
    uint8_t key[32], ctx[76], out[48];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 76; i++) ctx[i] = (uint8_t)i;
    CHECK(wpa3_kdf_sha256(key, 32, "Pairwise key expansion", ctx, 76, out, 384) == 0);
    CHECK(eqhex(out, "ca5d2b63205753bc5b26c31a135d1fb964f1ce5d87062246c4da6433d5422ca19065f6c58c3da70e0756992606528f4d"));
    CHECK(wpa3_kdf_sha256(key, 32, "SAE Hunting and Pecking", ctx, 32, out, 256) == 0);
    CHECK(eqhex(out, "dec2b3ee85bea0913c28f01956daf77bba6367923b9a75912628465acd791522"));
    CHECK(wpa3_kdf_sha256(key, 32, "x", ctx, 4, out, 7) < 0);
    uint8_t aa[6] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, spa[6] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5};
    uint8_t an[32], sn[32], ptk[48];
    for (int i = 0; i < 32; i++) { an[i] = (uint8_t)(0x10 + i); sn[i] = (uint8_t)(0x50 + i); }
    wpa3_ptk(key, aa, spa, an, sn, ptk);
    CHECK(eqhex(ptk, "cbb734180855fe143921e8094acdb154382eae6338d498d47859b52b643c724eed2183019bbaa5d64145ef995bb596f6"));
    uint8_t ptk2[48]; wpa3_ptk(key, spa, aa, sn, an, ptk2);          /* argument order is normalised */
    CHECK(memcmp(ptk, ptk2, 48) == 0);
    /* EAPOL MIC over a 99-byte frame whose MIC field (offset 81..96) is garbage in the input */
    uint8_t fr[99]; for (int i = 0; i < 99; i++) fr[i] = (uint8_t)i;
    uint8_t mic[16];
    wpa3_eapol_mic(ptk, fr, 99, mic);
    CHECK(eqhex(mic, "a570d632d8de691c6ca53b70b7d5fbc1"));
    memcpy(fr + 81, mic, 16);
    CHECK(wpa3_eapol_verify_mic(ptk, fr, 99) == 0);
    fr[3] ^= 1;
    CHECK(wpa3_eapol_verify_mic(ptk, fr, 99) != 0);
}

/* ---- IEs ---- */
static void test_ies(void) {
    uint8_t ie[64];
    int n = wpa3_build_rsn_ie(ie, sizeof ie, WPA3_CIPHER_CCMP, 1, NULL);
    CHECK(n > 0 && ie[0] == 0x30 && ie[1] == n - 2);
    CHECK(wpa3_rsn_caps(ie, (size_t)n) == (1 | 2 | 4));
    n = wpa3_build_rsn_ie(ie, sizeof ie, WPA3_CIPHER_CCMP, 0, pmkid);
    CHECK(n > 0 && wpa3_rsn_caps(ie, (size_t)n) == (1 | 2));
    CHECK(memcmp(ie + n - 16, pmkid, 16) == 0 || memcmp(ie + n - 16 - 4, pmkid, 16) == 0);
    /* hand-built AP RSN IE: AKM PSK + SAE, MFPC only (transition mode) */
    static const uint8_t trans[] = {0x30, 0x18, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
                                    0x02, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x0f, 0xac, 0x08, 0x80, 0x00};
    CHECK(wpa3_rsn_caps(trans, sizeof trans) == (1 | 2 | 8));
    static const uint8_t wpa2only[] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
                                       0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00};
    CHECK(wpa3_rsn_caps(wpa2only, sizeof wpa2only) == 8);   /* PSK only: no SAE, no PMF */
    CHECK(wpa3_rsn_caps(trans, 10) < 0);
    uint8_t x[3];
    CHECK(wpa3_build_rsnxe(x, sizeof x) == 3 && x[0] == 0xF4 && x[1] == 1 && x[2] == 0x20);
    static const uint8_t b1[] = {0x01, 0x04, 0x82, 0x84, 0x8b, 0x96, 0xF4, 0x01, 0x20};
    static const uint8_t b2[] = {0x01, 0x04, 0x82, 0x84, 0x8b, 0xFB};
    static const uint8_t b3[] = {0x01, 0x04, 0x82, 0x84, 0x8b, 0x96};
    static const uint8_t b4[] = {0x01, 0x02, 0x82, 0xFB, 0xF4, 0x01, 0x20};
    CHECK(wpa3_ap_h2e(b1, sizeof b1) == 1);
    CHECK(wpa3_ap_h2e(b2, sizeof b2) == 2);
    CHECK(wpa3_ap_h2e(b3, sizeof b3) == 0);
    CHECK(wpa3_ap_h2e(b4, sizeof b4) == 3);
    CHECK(wpa3_is_robust(12, 0) && wpa3_is_robust(10, 0) && wpa3_is_robust(13, 8) && !wpa3_is_robust(13, 4) &&
          !wpa3_is_robust(13, 7) && !wpa3_is_robust(8, 0));
}

/* ---- AKM 8 4-way handshake against an authenticator written here ---- */
static int auth_frame(uint8_t *out, uint16_t info, uint64_t replay, const uint8_t nonce[32], const uint8_t *kd, size_t kdl,
                      const uint8_t kck[16]) {
    int n = eapol_key_build(out, 512, info, 16, replay, nonce, kd, kdl, NULL);
    if (n > 0 && kck) wpa3_eapol_mic(kck, out, (size_t)n, out + 4 + 77);   /* version 0: AES-CMAC */
    return n;
}
static void test_4way(void) {
    uint8_t pmk_[32], aa[6] = {2, 0, 0, 0, 0, 0xa}, spa[6] = {2, 0, 0, 0, 0, 0xb};
    for (int i = 0; i < 32; i++) pmk_[i] = (uint8_t)(i * 3);
    uint8_t rsn[64];
    int rl = wpa3_build_rsn_ie(rsn, sizeof rsn, WPA3_CIPHER_CCMP, 1, pmkid);
    wpa3_t w;
    CHECK(wpa3_init(&w, pmk_, aa, spa, rsn, (size_t)rl) == 0);
    uint8_t an[32], f[512], o[512]; size_t ol; int ev;
    for (int i = 0; i < 32; i++) an[i] = (uint8_t)(0x90 + i);
    int n = auth_frame(f, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | 0, 1, an, NULL, 0, NULL);
    CHECK(wpa3_rx_eapol(&w, f, (size_t)n, o, &ol, &ev) == 0 && ol > 0 && ev == 0);
    eapol_key_t k;
    CHECK(eapol_key_parse(o, ol, &k) == 0);
    CHECK((k.info & 7) == 0 && (k.info & EAPOL_KEY_MIC) && !(k.info & EAPOL_KEY_ACK));
    CHECK(k.key_data_len == (size_t)rl && memcmp(k.key_data, rsn, (size_t)rl) == 0);
    uint8_t ptk[48];
    wpa3_ptk(pmk_, aa, spa, an, k.nonce, ptk);
    CHECK(wpa3_eapol_verify_mic(ptk, o, k.frame_len) == 0);          /* M2 MIC is AES-CMAC under the KCK */
    /* M3: RSN IE + GTK KDE + IGTK KDE, wrapped */
    uint8_t kd[200], wr[216]; size_t kl = 0;
    memcpy(kd, rsn, (size_t)rl); kl = (size_t)rl;
    static const uint8_t gtk[16] = {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f};
    kd[kl++] = 0xdd; kd[kl++] = 6 + 16; kd[kl++] = 0; kd[kl++] = 0x0f; kd[kl++] = 0xac; kd[kl++] = 1; kd[kl++] = 2 | 4; kd[kl++] = 0;
    memcpy(kd + kl, gtk, 16); kl += 16;
    static const uint8_t igtk[16] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};
    kd[kl++] = 0xdd; kd[kl++] = 4 + 2 + 6 + 16; kd[kl++] = 0; kd[kl++] = 0x0f; kd[kl++] = 0xac; kd[kl++] = 9; kd[kl++] = 4; kd[kl++] = 0;
    for (int i = 0; i < 6; i++) kd[kl++] = (uint8_t)(i + 1);
    memcpy(kd + kl, igtk, 16); kl += 16;
    kd[kl++] = 0xdd; while (kl % 8) kd[kl++] = 0;
    CHECK(aes_wrap(ptk + 16, kd, kl, wr) == 0);
    uint16_t m3 = EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | EAPOL_KEY_MIC | EAPOL_KEY_INSTALL | EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPTED;
    n = auth_frame(f, m3, 2, an, wr, kl + 8, ptk);
    uint8_t bad[512]; memcpy(bad, f, (size_t)n); bad[4 + 77] ^= 1;
    CHECK(wpa3_rx_eapol(&w, bad, (size_t)n, o, &ol, &ev) == WPA_ERR_MIC);
    CHECK(wpa3_rx_eapol(&w, f, (size_t)n, o, &ol, &ev) == 0 && ol > 0);
    CHECK((ev & WPA3_EV_PTK) && (ev & WPA3_EV_GTK) && (ev & WPA3_EV_IGTK));
    CHECK(eapol_key_parse(o, ol, &k) == 0 && wpa3_eapol_verify_mic(ptk, o, k.frame_len) == 0 && k.replay == 2);
    CHECK(wpa3_get_tk(&w) && memcmp(wpa3_get_tk(&w), ptk + 32, 16) == 0);
    CHECK(w.have_gtk && w.gtk_id == 2 && w.gtk_tx == 1 && memcmp(w.gtk, gtk, 16) == 0);
    CHECK(w.have_igtk && w.igtk_id == 4 && memcmp(w.igtk, igtk, 16) == 0 && w.igtk_ipn[0] == 1 && w.igtk_ipn[5] == 6);
    CHECK(w.ap_rsn_len == (size_t)rl);
    CHECK(wpa3_rx_eapol(&w, f, (size_t)n, o, &ol, &ev) == WPA_ERR_REPLAY);
    /* group message 1 with a new GTK and IGTK */
    uint8_t g2[16], kd2[100]; size_t k2 = 0;
    for (int i = 0; i < 16; i++) g2[i] = (uint8_t)(0xc0 + i);
    kd2[k2++] = 0xdd; kd2[k2++] = 22; kd2[k2++] = 0; kd2[k2++] = 0x0f; kd2[k2++] = 0xac; kd2[k2++] = 1; kd2[k2++] = 3; kd2[k2++] = 0;
    memcpy(kd2 + k2, g2, 16); k2 += 16;
    kd2[k2++] = 0xdd; while (k2 % 8) kd2[k2++] = 0;
    CHECK(aes_wrap(ptk + 16, kd2, k2, wr) == 0);
    n = auth_frame(f, EAPOL_KEY_ACK | EAPOL_KEY_MIC | EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPTED | (3 << 4), 3, an, wr, k2 + 8, ptk);
    CHECK(wpa3_rx_eapol(&w, f, (size_t)n, o, &ol, &ev) == 0 && ol > 0 && (ev & WPA3_EV_GTK) && !(ev & WPA3_EV_PTK));
    CHECK(w.gtk_id == 3 && memcmp(w.gtk, g2, 16) == 0);
    /* frames with legacy key descriptor version 2 (HMAC-SHA1) are refused for AKM 8 */
    n = auth_frame(f, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | 2, 9, an, NULL, 0, NULL);
    CHECK(wpa3_rx_eapol(&w, f, (size_t)n, o, &ol, &ev) < 0);
}

/* ---- protected management frames ---- */
static void test_pmf(void) {
    uint8_t sta[6] = {2, 0, 0, 0, 0, 1}, ap[6] = {2, 0, 0, 0, 0, 2};
    uint8_t hdr[24] = {0xC0, 0x00, 0, 0};
    memcpy(hdr + 4, sta, 6); memcpy(hdr + 10, ap, 6); memcpy(hdr + 16, ap, 6); hdr[22] = 0x10;
    uint8_t tk[16]; for (int i = 0; i < 16; i++) tk[i] = (uint8_t)(0x40 + i);
    uint8_t body[2] = {7, 0}, fr[128], back[64];
    int n = wpa3_mgmt_protect(tk, hdr, body, 2, 5, 0, fr, sizeof fr);
    CHECK(n == 24 + 8 + 2 + 8);
    /* nonce for management frames carries the priority byte 0 and A2 = ap here (frame from the AP) */
    CHECK(eqhex(fr, "c040000002000000000102000000000202000000000210000500002000000000980e92d4087079fc661b"));
    uint64_t pn = 0;
    CHECK(wpa3_mgmt_unprotect(tk, fr, (size_t)n, back, &pn) == 2 && pn == 5 && back[0] == 7 && back[1] == 0);
    fr[n - 1] ^= 1;
    CHECK(wpa3_mgmt_unprotect(tk, fr, (size_t)n, back, &pn) < 0);
    fr[n - 1] ^= 1; fr[5] ^= 1;                                 /* header (AAD) tamper */
    CHECK(wpa3_mgmt_unprotect(tk, fr, (size_t)n, back, &pn) < 0);
    fr[5] ^= 1; fr[1] &= ~0x40;                                 /* not marked protected */
    CHECK(wpa3_mgmt_unprotect(tk, fr, (size_t)n, back, &pn) < 0);
    uint8_t req[4] = {8, 0, 0x12, 0x34}, rep[4];
    CHECK(wpa3_sa_query_reply_body(req, 4, rep) == 4 && rep[0] == 8 && rep[1] == 1 && rep[2] == 0x12 && rep[3] == 0x34);
    CHECK(wpa3_sa_query_reply_body(rep, 4, rep) < 0);

    /* BIP-CMAC-128 */
    uint8_t igtk[16], ipn[6] = {1, 2, 3, 4, 5, 6}, bh[24] = {0xC0, 0x00, 0, 0};
    for (int i = 0; i < 16; i++) igtk[i] = (uint8_t)(0x60 + i);
    memset(bh + 4, 0xff, 6); memcpy(bh + 10, ap, 6); memcpy(bh + 16, ap, 6); bh[22] = 0x20;
    n = wpa3_bip_protect(igtk, 4, ipn, bh, body, 2, fr, sizeof fr);
    CHECK(n == 2 + 18);
    CHECK(eqhex(fr, "07004c100400010203040506f80c0f6a0bb51723"));
    uint8_t ipn_o[6];
    CHECK(wpa3_bip_verify(igtk, bh, fr, (size_t)n, ipn_o) == 0 && memcmp(ipn_o, ipn, 6) == 0);
    fr[3] ^= 1;
    CHECK(wpa3_bip_verify(igtk, bh, fr, (size_t)n, ipn_o) != 0);
    fr[3] ^= 1; fr[n - 1] ^= 1;
    CHECK(wpa3_bip_verify(igtk, bh, fr, (size_t)n, ipn_o) != 0);
}

int main(void) {
    test_p256();
    test_annex_j10();
    test_exchanges();
    test_failures();
    test_cmac();
    test_kdf();
    test_ies();
    test_4way();
    test_pmf();
    if (fails) { printf("SAE TEST FAILED (%d)\n", fails); return 1; }
    printf("SAE TEST OK\n");
    return 0;
}
