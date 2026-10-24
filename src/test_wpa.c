// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_wpa.c - tests for src/wpa.c. Prints "WPA TEST OK" and exits 0 on success.
 *
 * EXTERNAL PUBLISHED VECTORS (verified against the spec value):
 *   - PMK "password"/"IEEE"                  : IEEE 802.11i-2004 Annex H.4.1 (also RFC 6070-style PBKDF2 use)
 *   - PMK "ThisIsAPassword"/"ThisIsASSID"    : IEEE 802.11i-2004 Annex H.4.1
 *   - AES key wrap                           : RFC 3394 section 4.1 (128-bit KEK, 128-bit data)
 *   - AES-CCM core (M=8, L=2, 13B nonce)     : RFC 3610 section 8, Packet Vector #1
 *
 * INDEPENDENT CROSS-CHECK (not a published vector): PTK (PRF-384) and EAPOL MIC expected values
 *   were generated with an independent Python hashlib/hmac implementation of the 802.11 PRF
 *   and HMAC-SHA1-128.
 *
 * SELF-CONSISTENCY ONLY (no published vector used): key descriptor version 1 (WPA1 desc 254 and RSN-TKIP desc 2;
 *   HMAC-MD5 MIC recomputed with CommonCrypto, RC4 key data, 64-byte PTK, G1 with a raw GTK), full 4-way handshake vs. a minimal
 *   authenticator in this file, group rekey, tamper/replay rejection, the 802.11 CCMP header/AAD/nonce
 *   construction (round trips + tamper of each header field). The 802.11i H.6 / 802.11-2016 J.x CCMP
 *   MPDU vector was NOT used because I could not recall it exactly. */
#include "wpa.h"
#include "wep.h"
#include <CommonCrypto/CommonCrypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void unhex(const char *s, uint8_t *o) {
    for (; s[0] && s[1]; s += 2, o++) { unsigned v; sscanf(s, "%2x", &v); *o = (uint8_t)v; }
}
static int eqhex(const uint8_t *b, const char *hex) {
    uint8_t t[128]; unhex(hex, t); return memcmp(b, t, strlen(hex) / 2) == 0;
}

static void test_pmk(void) {
    uint8_t pmk[32];
    wpa_pmk("password", (const uint8_t *)"IEEE", 4, pmk);
    CHECK(eqhex(pmk, "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"));
    wpa_pmk("ThisIsAPassword", (const uint8_t *)"ThisIsASSID", 11, pmk);
    CHECK(eqhex(pmk, "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"));
}

static void test_ptk_mic(void) {
    uint8_t pmk[32], aa[6], spa[6], an[32], sn[32], ptk[48], fr[99], mic[16];
    wpa_pmk("ThisIsAPassword", (const uint8_t *)"ThisIsASSID", 11, pmk);
    unhex("a0a1a2a3a4a5", aa); unhex("b0b1b2b3b4b5", spa);
    for (int i = 0; i < 32; i++) { an[i] = 0x10 + i; sn[i] = 0x50 + i; }
    wpa_ptk(pmk, aa, spa, an, sn, ptk);
    CHECK(eqhex(ptk, "5ac8544c2f233c8a03a02a397f2b9fae84ec6a450e26ce33bab594d1b26547d0"
                     "b5b6f6278cf20a2bc52b24837293d234"));
    /* order independence of the min/max rule */
    uint8_t p2[48]; wpa_ptk(pmk, spa, aa, sn, an, p2); CHECK(!memcmp(p2, ptk, 48));
    for (int i = 0; i < 99; i++) fr[i] = (uint8_t)i;
    eapol_key_mic(ptk, fr, 99, mic);
    /* MIC field (bytes 81..96) is zeroed before hashing; expected from independent Python hmac */
    CHECK(eqhex(mic, "e80e723c339fa1357da27d918edeea1a"));
}

static void test_wrap(void) {
    uint8_t kek[16], pt[16], ct[24], back[16];
    unhex("000102030405060708090A0B0C0D0E0F", kek);
    unhex("00112233445566778899AABBCCDDEEFF", pt);
    CHECK(aes_wrap(kek, pt, 16, ct) == 0);
    CHECK(eqhex(ct, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"));   /* RFC 3394 4.1 */
    CHECK(aes_unwrap(kek, ct, 24, back) == 0 && !memcmp(back, pt, 16));
    ct[5] ^= 1; CHECK(aes_unwrap(kek, ct, 24, back) != 0);
}

static void test_ccm(void) {
    /* RFC 3610 Packet Vector #1 */
    uint8_t key[16], nonce[13], pkt[31], out[23], mic[8], back[23];
    unhex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF", key);
    unhex("00000003020100A0A1A2A3A4A5", nonce);
    for (int i = 0; i < 23; i++) pkt[8 + i] = 8 + i;
    for (int i = 0; i < 8; i++) pkt[i] = (uint8_t)i;
    CHECK(ccm_seal(key, nonce, pkt, 8, pkt + 8, 23, out, mic) == 0);
    CHECK(eqhex(out, "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384"));
    CHECK(eqhex(mic, "17E8D12CFDF926E0"));
    CHECK(ccm_open(key, nonce, pkt, 8, out, 23, mic, back) == 0 && !memcmp(back, pkt + 8, 23));
    mic[0] ^= 1; CHECK(ccm_open(key, nonce, pkt, 8, out, 23, mic, back) != 0);
}

/* ---- minimal authenticator ---- */
typedef struct { uint8_t pmk[32], ptk[64], an[32], sn[32], aa[6], spa[6]; uint64_t replay; } auth_t;

static void auth_m1(auth_t *a, uint8_t *f, size_t *n) {
    arc4random_buf(a->an, 32); a->replay++;
    int l = eapol_key_build(f, 256, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | 2, 16, a->replay, a->an, NULL, 0, NULL);
    *n = (size_t)l;
}
static int wrap_kd(auth_t *a, const uint8_t *kd, size_t n, uint8_t *out) {
    uint8_t p[256]; memcpy(p, kd, n);
    p[n++] = 0xDD; while (n % 8) p[n++] = 0;
    if (n < 16) { while (n < 16) p[n++] = 0; }
    aes_wrap(a->ptk + 16, p, n, out);
    return (int)n + 8;
}
static size_t gtk_kde(uint8_t *kd, int id, const uint8_t *gtk) {
    static const uint8_t h[] = { 0xDD, 22, 0x00, 0x0F, 0xAC, 1 };
    memcpy(kd, h, 6); kd[6] = (uint8_t)(id | 4); kd[7] = 0; memcpy(kd + 8, gtk, 16); return 24;
}
static void auth_m3(auth_t *a, const uint8_t *rsn, size_t rl, const uint8_t *gtk, uint8_t *f, size_t *n) {
    uint8_t kd[128], w[160]; size_t l = 0;
    memcpy(kd, rsn, rl); l = rl; l += gtk_kde(kd + l, 1, gtk);
    int wl = wrap_kd(a, kd, l, w);
    a->replay++;
    int fl = eapol_key_build(f, 512, EAPOL_KEY_PAIRWISE | EAPOL_KEY_INSTALL | EAPOL_KEY_ACK | EAPOL_KEY_MIC |
                             EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPTED | 2, 16, a->replay, a->an, w, (size_t)wl, a->ptk);
    *n = (size_t)fl;
}
static void auth_g1(auth_t *a, int id, const uint8_t *gtk, uint8_t *f, size_t *n) {
    uint8_t kd[32], w[64]; size_t l = gtk_kde(kd, id, gtk);
    int wl = wrap_kd(a, kd, l, w);
    a->replay++;
    int fl = eapol_key_build(f, 512, EAPOL_KEY_ACK | EAPOL_KEY_MIC | EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPTED | 2,
                             16, a->replay, NULL, w, (size_t)wl, a->ptk);
    *n = (size_t)fl;
}

static void test_handshake(void) {
    const char *pass = "correct horse battery"; const uint8_t ssid[] = "HomeNet";
    uint8_t aa[6] = { 2, 0, 0, 0, 0, 1 }, spa[6] = { 2, 0, 0, 0, 0, 2 };
    uint8_t rsn[22] = { 0x30, 20, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 2, 0, 0 };
    uint8_t gtk[16], gtk2[16], f[600], o[600], tmp[600]; size_t fl, ol; int ev, r;
    arc4random_buf(gtk, 16); arc4random_buf(gtk2, 16);
    wpa_t w; auth_t a; memset(&a, 0, sizeof a);
    CHECK(wpa_init(&w, pass, ssid, 7, aa, spa, rsn, sizeof rsn) == 0);
    wpa_pmk(pass, ssid, 7, a.pmk); memcpy(a.aa, aa, 6); memcpy(a.spa, spa, 6);

    /* M1 */
    auth_m1(&a, f, &fl);
    CHECK(wpa_rx_eapol(&w, f, fl, o, &ol, &ev) == 0 && ol > 0 && ev == 0);
    CHECK(wpa_get_tk(&w) == NULL);
    eapol_key_t k; CHECK(eapol_key_parse(o, ol, &k) == 0);
    CHECK(k.info == (EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC | 2) && k.replay == a.replay);
    CHECK(k.key_data_len == sizeof rsn && !memcmp(k.key_data, rsn, sizeof rsn));
    memcpy(a.sn, k.nonce, 32);
    wpa_ptk(a.pmk, aa, spa, a.an, a.sn, a.ptk);
    CHECK(eapol_key_verify_mic(a.ptk, o, ol) == 0);               /* M2 MIC ok */
    memcpy(tmp, o, ol); tmp[4 + 77] ^= 1; CHECK(eapol_key_verify_mic(a.ptk, tmp, ol) != 0);

    /* M3 tampering: each must be rejected without advancing state */
    uint8_t m3[600]; size_t m3l; auth_m3(&a, rsn, sizeof rsn, gtk, m3, &m3l);
    memcpy(tmp, m3, m3l); tmp[4 + 77 + 3] ^= 0x10;
    CHECK(wpa_rx_eapol(&w, tmp, m3l, o, &ol, &ev) == WPA_ERR_MIC);
    memcpy(tmp, m3, m3l); tmp[m3l - 1] ^= 1;                      /* key data bit flip (MIC now wrong) */
    CHECK(wpa_rx_eapol(&w, tmp, m3l, o, &ol, &ev) == WPA_ERR_MIC);
    {   /* key data corrupted but MIC recomputed by an attacker who has KCK: unwrap integrity must fail */
        memcpy(tmp, m3, m3l); tmp[m3l - 3] ^= 1;
        eapol_key_mic(a.ptk, tmp, m3l, tmp + 4 + 77);
        CHECK(wpa_rx_eapol(&w, tmp, m3l, o, &ol, &ev) == WPA_ERR_KEYDATA);
    }
    {   /* wrong ANonce with valid MIC */
        uint8_t an2[32]; memcpy(an2, a.an, 32); an2[0] ^= 1;
        memcpy(tmp, m3, m3l); memcpy(tmp + 4 + 13, an2, 32); eapol_key_mic(a.ptk, tmp, m3l, tmp + 4 + 77);
        CHECK(wpa_rx_eapol(&w, tmp, m3l, o, &ol, &ev) == WPA_ERR_UNEXPECTED);
    }
    CHECK(wpa_get_tk(&w) == NULL);

    /* genuine M3 */
    r = wpa_rx_eapol(&w, m3, m3l, o, &ol, &ev);
    CHECK(r == 0 && ev == (WPA_EV_PTK | WPA_EV_GTK) && ol > 0);
    CHECK(wpa_get_tk(&w) && !memcmp(wpa_get_tk(&w), a.ptk + 32, 16));
    size_t gl; int gid; const uint8_t *g = wpa_get_gtk(&w, &gl, &gid);
    CHECK(g && gl == 16 && gid == 1 && !memcmp(g, gtk, 16));
    CHECK(w.ap_rsn_len == sizeof rsn && !memcmp(w.ap_rsn, rsn, sizeof rsn));
    CHECK(eapol_key_parse(o, ol, &k) == 0 && k.info == (EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC | EAPOL_KEY_SECURE | 2));
    CHECK(k.replay == a.replay && eapol_key_verify_mic(a.ptk, o, ol) == 0);   /* M4 ok */

    /* exact replay of M3 rejected; retransmit with a new replay counter answered but not re-announced */
    CHECK(wpa_rx_eapol(&w, m3, m3l, o, &ol, &ev) == WPA_ERR_REPLAY);
    auth_m3(&a, rsn, sizeof rsn, gtk, m3, &m3l);
    CHECK(wpa_rx_eapol(&w, m3, m3l, o, &ol, &ev) == 0 && ev == 0 && ol > 0);
    /* a fresh M1 after install is refused (no PTK rekey) */
    auth_m1(&a, f, &fl); CHECK(wpa_rx_eapol(&w, f, fl, o, &ol, &ev) == WPA_ERR_UNEXPECTED);

    /* group rekey */
    uint8_t g1[600]; size_t g1l; auth_g1(&a, 2, gtk2, g1, &g1l);
    memcpy(tmp, g1, g1l); tmp[g1l - 2] ^= 1;
    CHECK(wpa_rx_eapol(&w, tmp, g1l, o, &ol, &ev) == WPA_ERR_MIC);
    r = wpa_rx_eapol(&w, g1, g1l, o, &ol, &ev);
    CHECK(r == 0 && ev == WPA_EV_GTK && ol > 0);
    g = wpa_get_gtk(&w, &gl, &gid); CHECK(g && gid == 2 && !memcmp(g, gtk2, 16));
    CHECK(eapol_key_parse(o, ol, &k) == 0 && k.info == (EAPOL_KEY_MIC | EAPOL_KEY_SECURE | 2) && k.replay == a.replay);
    CHECK(eapol_key_verify_mic(a.ptk, o, ol) == 0);
    CHECK(wpa_rx_eapol(&w, g1, g1l, o, &ol, &ev) == WPA_ERR_REPLAY);
    CHECK(wpa_rx_eapol(&w, g1, 20, o, &ol, &ev) == WPA_ERR_MALFORMED);
}


/* ---- key descriptor version 1 (HMAC-MD5 MIC, RC4 key data): WPA1 (descriptor 254) and RSN with TKIP (descriptor 2).
 * Self-consistency only: the authenticator here is written from the spec text (802.11i-2004 8.5.2, WPA1 key
 * descriptor), the MIC is additionally recomputed with CommonCrypto HMAC-MD5 directly. */
static void v1_seal(auth_t *a, uint8_t *f, size_t fl, int desc, int rc4_kd) {
    f[4] = (uint8_t)desc;
    if (rc4_kd) {                                   /* IV field = random, key data RC4(IV||KEK), skip 256 */
        arc4random_buf(f + 4 + 45, 16);
        uint8_t key[32]; memcpy(key, f + 4 + 45, 16); memcpy(key + 16, a->ptk + 16, 16);
        size_t kdl = (size_t)(f[4 + 93] << 8 | f[4 + 94]);
        rc4_crypt(key, 32, 256, f + 4 + 95, kdl);
    }
    eapol_key_mic(a->ptk, f, fl, f + 4 + 77);
    uint8_t z[1024], h[16]; memcpy(z, f, fl); memset(z + 4 + 77, 0, 16);
    CCHmac(kCCHmacAlgMD5, a->ptk, 16, z, fl, h);
    CHECK(!memcmp(h, f + 4 + 77, 16));              /* MIC really is HMAC-MD5 */
}

static void test_v1(int wpa1) {
    const char *pass = "correct horse battery"; const uint8_t ssid[] = "HomeNet";
    uint8_t aa[6] = { 2, 0, 0, 0, 0, 1 }, spa[6] = { 2, 0, 0, 0, 0, 2 };
    uint8_t ie_wpa[24] = { 0xDD, 22, 0x00, 0x50, 0xF2, 1, 1, 0, 0x00, 0x50, 0xF2, 2, 1, 0, 0x00, 0x50, 0xF2, 2, 1, 0, 0x00, 0x50, 0xF2, 2 };
    uint8_t ie_rsn[22] = { 0x30, 20, 1, 0, 0x00, 0x0F, 0xAC, 2, 1, 0, 0x00, 0x0F, 0xAC, 2, 1, 0, 0x00, 0x0F, 0xAC, 2, 0, 0 };
    const uint8_t *ie = wpa1 ? ie_wpa : ie_rsn; size_t iel = wpa1 ? sizeof ie_wpa : sizeof ie_rsn;
    uint8_t gtk[32], f[600], o[600]; size_t fl, ol; int ev;
    arc4random_buf(gtk, 32);
    wpa_t w; auth_t a; memset(&a, 0, sizeof a);
    CHECK(wpa_init_ex(&w, pass, ssid, 7, aa, spa, ie, iel, 1, wpa1) == 0);
    wpa_pmk(pass, ssid, 7, a.pmk); memcpy(a.aa, aa, 6); memcpy(a.spa, spa, 6);

    /* PRF-512 starts with PRF-384 */
    uint8_t p48[48], p64[64]; arc4random_buf(a.an, 32); arc4random_buf(a.sn, 32);
    wpa_ptk(a.pmk, aa, spa, a.an, a.sn, p48); wpa_ptk_n(a.pmk, aa, spa, a.an, a.sn, p64, 64);
    CHECK(!memcmp(p48, p64, 48));

    /* M1 (key_len 32, version 1) */
    arc4random_buf(a.an, 32); a.replay++;
    int l = eapol_key_build(f, 256, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | 1, 32, a.replay, a.an, NULL, 0, NULL);
    f[4] = wpa1 ? 254 : 2; fl = (size_t)l;
    CHECK(wpa_rx_eapol(&w, f, fl, o, &ol, &ev) == 0 && ol > 0 && ev == 0);
    eapol_key_t k; CHECK(eapol_key_parse(o, ol, &k) == 0);
    CHECK(k.desc == (wpa1 ? 254 : 2) && k.info == (EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC | 1));
    CHECK(k.key_len == (wpa1 ? 32 : 0));
    CHECK(k.key_data_len == iel && !memcmp(k.key_data, ie, iel));
    memcpy(a.sn, k.nonce, 32);
    wpa_ptk_n(a.pmk, aa, spa, a.an, a.sn, a.ptk, 64);
    CHECK(eapol_key_verify_mic(a.ptk, o, ol) == 0);
    {   uint8_t z[600], h[16]; memcpy(z, o, ol); memset(z + 4 + 77, 0, 16);
        CCHmac(kCCHmacAlgMD5, a.ptk, 16, z, ol, h); CHECK(!memcmp(h, o + 4 + 77, 16)); }
    /* a version 2 frame in a version 1 handshake is refused */
    l = eapol_key_build(f, 256, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | 2, 32, a.replay + 1, a.an, NULL, 0, NULL);
    f[4] = wpa1 ? 254 : 2;
    CHECK(wpa_rx_eapol(&w, f, (size_t)l, o, &ol, &ev) != 0 || w.ver == 2);   /* a new M1 may restart; never installs */
    CHECK(wpa_get_tk(&w) == NULL);
    /* restart cleanly with a fresh version-1 M1 */
    arc4random_buf(a.an, 32); a.replay += 2;
    l = eapol_key_build(f, 256, EAPOL_KEY_PAIRWISE | EAPOL_KEY_ACK | 1, 32, a.replay, a.an, NULL, 0, NULL);
    f[4] = wpa1 ? 254 : 2;
    CHECK(wpa_rx_eapol(&w, f, (size_t)l, o, &ol, &ev) == 0);
    CHECK(eapol_key_parse(o, ol, &k) == 0); memcpy(a.sn, k.nonce, 32);
    wpa_ptk_n(a.pmk, aa, spa, a.an, a.sn, a.ptk, 64);

    /* M3 */
    uint8_t kd[128]; size_t kl = 0;
    memcpy(kd, ie, iel); kl = iel;
    uint16_t info = EAPOL_KEY_PAIRWISE | EAPOL_KEY_INSTALL | EAPOL_KEY_ACK | EAPOL_KEY_MIC | 1;
    if (!wpa1) {
        static const uint8_t h6[] = { 0xDD, 38, 0x00, 0x0F, 0xAC, 1 };
        memcpy(kd + kl, h6, 6); kd[kl + 6] = 1 | 4; kd[kl + 7] = 0; memcpy(kd + kl + 8, gtk, 32); kl += 40;
        while (kl % 8) kd[kl++] = 0;
        info |= EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPTED;
    }
    a.replay++;
    l = eapol_key_build(f, 512, info, 32, a.replay, a.an, kd, kl, a.ptk);
    uint8_t m3[600]; memcpy(m3, f, (size_t)l); size_t m3l = (size_t)l;
    v1_seal(&a, m3, m3l, wpa1 ? 254 : 2, !wpa1);
    uint8_t tmp[600];
    memcpy(tmp, m3, m3l); tmp[4 + 77 + 1] ^= 1;
    CHECK(wpa_rx_eapol(&w, tmp, m3l, o, &ol, &ev) == WPA_ERR_MIC);
    CHECK(wpa_rx_eapol(&w, m3, m3l, o, &ol, &ev) == 0);
    CHECK(ev == (wpa1 ? WPA_EV_PTK : (WPA_EV_PTK | WPA_EV_GTK)));
    CHECK(wpa_get_ptk(&w) && !memcmp(wpa_get_ptk(&w), a.ptk, 64));
    CHECK(w.ap_rsn_len == iel && !memcmp(w.ap_rsn, ie, iel));
    CHECK(eapol_key_parse(o, ol, &k) == 0 && k.desc == (wpa1 ? 254 : 2));
    CHECK(k.info == (EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC | (wpa1 ? 0 : EAPOL_KEY_SECURE) | 1));
    CHECK(eapol_key_verify_mic(a.ptk, o, ol) == 0);
    if (!wpa1) {
        size_t gl; int gid; const uint8_t *g = wpa_get_gtk(&w, &gl, &gid);
        CHECK(g && gl == 32 && gid == 1 && !memcmp(g, gtk, 32));
    }

    /* G1 with a 32-byte TKIP group key */
    uint8_t g2[32]; arc4random_buf(g2, 32);
    uint8_t gkd[64]; size_t gkl;
    if (wpa1) { memcpy(gkd, g2, 32); gkl = 32; }
    else { static const uint8_t h6[] = { 0xDD, 38, 0x00, 0x0F, 0xAC, 1 }; memcpy(gkd, h6, 6); gkd[6] = 2 | 4; gkd[7] = 0; memcpy(gkd + 8, g2, 32); gkl = 40; }
    info = EAPOL_KEY_ACK | EAPOL_KEY_MIC | EAPOL_KEY_SECURE | 1;
    if (wpa1) info |= (2 << 4) | EAPOL_KEY_INSTALL; else info |= EAPOL_KEY_ENCRYPTED;
    a.replay++;
    l = eapol_key_build(f, 512, info, 32, a.replay, NULL, gkd, gkl, a.ptk);
    v1_seal(&a, f, (size_t)l, wpa1 ? 254 : 2, 1);
    CHECK(wpa_rx_eapol(&w, f, (size_t)l, o, &ol, &ev) == 0 && ev == WPA_EV_GTK);
    size_t gl; int gid; const uint8_t *g = wpa_get_gtk(&w, &gl, &gid);
    CHECK(g && gl == 32 && gid == 2 && !memcmp(g, g2, 32) && (wpa1 ? w.gtk_tx == 1 : 1));
    CHECK(eapol_key_parse(o, ol, &k) == 0 && (k.info & ~0x30) == (EAPOL_KEY_MIC | EAPOL_KEY_SECURE | 1));
    CHECK(eapol_key_verify_mic(a.ptk, o, ol) == 0);
}

static void test_ccmp(void) {
    uint8_t tk[16]; unhex("c97c1f67ce371185514a8a19f2bdd52f", tk);
    uint8_t hdr[32] = { 0x88, 0x41, 0x2c, 0x00,                 /* QoS data, to-DS=1, protected */
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,                      /* A1 */
        0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,                      /* A2 */
        0x02, 0x66, 0x77, 0x88, 0x99, 0x00,                      /* A3 */
        0x30, 0x12,                                              /* seq ctl */
        0x05, 0x00 };                                            /* QoS: TID 5 */
    size_t hl = 26;
    uint8_t pt[100], ct[116], back[100]; uint64_t pn; int kid;
    for (int i = 0; i < 100; i++) pt[i] = (uint8_t)(i * 7 + 1);
    CHECK(ccmp_encrypt(tk, hdr, hl, 0x0000B5039776E70CULL & 0xFFFFFFFFFFFFULL, 2, pt, 100, ct) == 116);
    CHECK(ct[0] == 0x0C && ct[1] == 0xE7 && ct[2] == 0 && ct[3] == (0x20 | 2 << 6) && ct[4] == 0x76 && ct[7] == 0xB5);
    CHECK(ccmp_decrypt(tk, hdr, hl, ct, 116, back, &pn, &kid) == 100 && !memcmp(back, pt, 100));
    CHECK(pn == 0xB5039776E70CULL && kid == 2);
    /* retry/pwrmgt/moredata and seq number are NOT protected; must still decrypt */
    uint8_t h2[32]; memcpy(h2, hdr, 32); h2[1] |= 0x08 | 0x10 | 0x20; h2[22] = 0xF0 | (hdr[22] & 0x0F); h2[23] = 0x77;
    CHECK(ccmp_decrypt(tk, h2, hl, ct, 116, back, NULL, NULL) == 100);
    /* protected fields must break the MIC: A1, A2, A3, fragment number, TID, FC bits, PN, ciphertext, MIC */
    int offs[] = { 5, 11, 17, 22, 24 };
    for (int i = 0; i < 5; i++) {
        memcpy(h2, hdr, 32); h2[offs[i]] ^= 1;
        CHECK(ccmp_decrypt(tk, h2, hl, ct, 116, back, NULL, NULL) < 0);
    }
    memcpy(h2, hdr, 32); h2[1] ^= 0x01; CHECK(ccmp_decrypt(tk, h2, hl, ct, 116, back, NULL, NULL) < 0);
    uint8_t c2[116];
    int flips[] = { 0, 4, 9, 60, 107, 108, 115 };
    for (int i = 0; i < 7; i++) {
        memcpy(c2, ct, 116); c2[flips[i]] ^= 0x80;
        CHECK(ccmp_decrypt(tk, hdr, hl, c2, 116, back, NULL, NULL) < 0);
    }
    uint8_t tk2[16]; memcpy(tk2, tk, 16); tk2[3] ^= 1;
    CHECK(ccmp_decrypt(tk2, hdr, hl, ct, 116, back, NULL, NULL) < 0);
    /* non-QoS, 4-address, empty and odd-size payloads round-trip */
    uint8_t h3[32] = { 0x08, 0x43, 0, 0, 1,1,1,1,1,1, 2,2,2,2,2,2, 3,3,3,3,3,3, 0x10, 0, 4,4,4,4,4,4 };
    size_t lens[] = { 0, 1, 15, 16, 17, 31, 1500 };
    for (int i = 0; i < 7; i++) {
        uint8_t *p = malloc(1500), *c = malloc(1516), *b = malloc(1500);
        arc4random_buf(p, 1500);
        CHECK(ccmp_encrypt(tk, h3, 30, 1, 0, p, lens[i], c) == (int)lens[i] + 16);
        CHECK(ccmp_decrypt(tk, h3, 30, c, lens[i] + 16, b, NULL, NULL) == (int)lens[i] && !memcmp(b, p, lens[i]));
        free(p); free(c); free(b);
    }
    CHECK(ccmp_decrypt(tk, h3, 30, ct, 15, back, NULL, NULL) < 0);
    CHECK(ccmp_encrypt(tk, h3, 20, 1, 0, pt, 4, ct) < 0);        /* header too short */
}

int main(void) {
    test_pmk(); test_ptk_mic(); test_wrap(); test_ccm(); test_handshake(); test_v1(1); test_v1(0); test_ccmp();
    if (fails) { printf("WPA TEST FAILED (%d)\n", fails); return 1; }
    printf("WPA TEST OK\n");
    return 0;
}
