// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wpa.c - WPA2-Personal supplicant (RSN/CCMP/PSK) on Apple CommonCrypto. See wpa.h. */
#include "wpa.h"
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include "wep.h"
#include <stdlib.h>
#include <string.h>

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint64_t be64(const uint8_t *p) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) v = v << 8 | p[i]; return v;
}
static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = (uint8_t)v; }
static void put64(uint8_t *p, uint64_t v) { for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; } }

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0; for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0;
}

/* ------------------------------------------------------------ keys */

void wpa_pmk(const char *pass, const uint8_t *ssid, size_t ssid_len, uint8_t pmk[32]) {
    CCKeyDerivationPBKDF(kCCPBKDF2, pass, strlen(pass), ssid, ssid_len,
                         kCCPRFHmacAlgSHA1, 4096, pmk, 32);
}

static int cmp_mem(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a, b, n); }

void wpa_ptk_n(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
               const uint8_t anonce[32], const uint8_t snonce[32], uint8_t *ptk, size_t len) {
    static const char label[] = "Pairwise key expansion";   /* 22 bytes + 0x00 separator */
    uint8_t msg[sizeof(label) + 76 + 1];
    size_t n = sizeof(label);                                /* includes the NUL */
    memcpy(msg, label, n);
    const uint8_t *lo = cmp_mem(aa, spa, 6) < 0 ? aa : spa, *hi = lo == aa ? spa : aa;
    memcpy(msg + n, lo, 6); memcpy(msg + n + 6, hi, 6);
    const uint8_t *nl = cmp_mem(anonce, snonce, 32) < 0 ? anonce : snonce, *nh = nl == anonce ? snonce : anonce;
    memcpy(msg + n + 12, nl, 32); memcpy(msg + n + 44, nh, 32);
    n += 76;
    uint8_t out[80];
    for (int i = 0; i < 4; i++) {
        msg[n] = (uint8_t)i;
        CCHmac(kCCHmacAlgSHA1, pmk, 32, msg, n + 1, out + 20 * i);
    }
    memcpy(ptk, out, len);        /* PRF-512's first 48 bytes equal PRF-384 */
}

void wpa_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
             const uint8_t anonce[32], const uint8_t snonce[32], uint8_t ptk[48]) {
    wpa_ptk_n(pmk, aa, spa, anonce, snonce, ptk, 48);
}

/* ------------------------------------------------------------ AES */

/* one-shot ECB cryptor, kept simple for the control path */
static CCCryptorRef ecb_new(const uint8_t key[16], int enc) {
    CCCryptorRef c = NULL;
    if (CCCryptorCreate(enc ? kCCEncrypt : kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode,
                        key, 16, NULL, &c) != kCCSuccess) return NULL;
    return c;
}
static void ecb_blk(CCCryptorRef c, const uint8_t in[16], uint8_t out[16]) {
    size_t moved = 0;
    CCCryptorUpdate(c, in, 16, out, 16, &moved);
}

/* RFC 3394 */
int aes_wrap(const uint8_t kek[16], const uint8_t *plain, size_t len, uint8_t *out) {
    if (len < 16 || len % 8) return -1;
    CCCryptorRef c = ecb_new(kek, 1); if (!c) return -1;
    size_t n = len / 8;
    uint8_t a[8], b[16];
    memset(a, 0xA6, 8);
    memcpy(out + 8, plain, len);
    for (int j = 0; j < 6; j++)
        for (size_t i = 1; i <= n; i++) {
            memcpy(b, a, 8); memcpy(b + 8, out + 8 * i, 8);
            ecb_blk(c, b, b);
            uint64_t t = n * j + i;
            memcpy(a, b, 8);
            for (int k = 0; k < 8; k++) a[7 - k] ^= (uint8_t)(t >> (8 * k));
            memcpy(out + 8 * i, b + 8, 8);
        }
    memcpy(out, a, 8);
    CCCryptorRelease(c);
    return 0;
}

int aes_unwrap(const uint8_t kek[16], const uint8_t *in, size_t len, uint8_t *out) {
    if (len < 24 || len % 8) return -1;
    CCCryptorRef c = ecb_new(kek, 0); if (!c) return -1;
    size_t n = len / 8 - 1;
    uint8_t a[8], b[16];
    memcpy(a, in, 8);
    memcpy(out, in + 8, len - 8);
    for (int j = 5; j >= 0; j--)
        for (size_t i = n; i >= 1; i--) {
            uint64_t t = n * j + i;
            memcpy(b, a, 8);
            for (int k = 0; k < 8; k++) b[7 - k] ^= (uint8_t)(t >> (8 * k));
            memcpy(b + 8, out + 8 * (i - 1), 8);
            ecb_blk(c, b, b);
            memcpy(a, b, 8);
            memcpy(out + 8 * (i - 1), b + 8, 8);
        }
    CCCryptorRelease(c);
    uint8_t iv[8]; memset(iv, 0xA6, 8);
    return ct_eq(a, iv, 8) ? 0 : -1;
}

/* ------------------------------------------------------------ CCM (RFC 3610, M=8, L=2) */

static void xor16(uint8_t *d, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) d[i] ^= s[i]; }

/* CBC-MAC T over B0 | encoded AAD | plaintext */
static void ccm_mac(CCCryptorRef c, const uint8_t nonce[13], const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t len, uint8_t t[16]) {
    uint8_t x[16], blk[16];
    blk[0] = (uint8_t)((aad_len ? 0x40 : 0) | (((8 - 2) / 2) << 3) | (2 - 1));
    memcpy(blk + 1, nonce, 13);
    put16(blk + 14, (uint16_t)len);
    ecb_blk(c, blk, x);
    if (aad_len) {
        uint8_t pre[2]; put16(pre, (uint16_t)aad_len);
        size_t off = 0;                      /* offset in (pre || aad) stream */
        size_t total = 2 + aad_len;
        while (off < total) {
            memset(blk, 0, 16);
            for (size_t i = 0; i < 16 && off + i < total; i++) {
                size_t p = off + i;
                blk[i] = p < 2 ? pre[p] : aad[p - 2];
            }
            xor16(x, blk, 16); ecb_blk(c, x, x);
            off += 16;
        }
    }
    for (size_t off = 0; off < len; off += 16) {
        size_t n = len - off < 16 ? len - off : 16;
        memset(blk, 0, 16); memcpy(blk, pt + off, n);
        xor16(x, blk, 16); ecb_blk(c, x, x);
    }
    memcpy(t, x, 16);
}

/* CTR from counter 1 over in -> out; s0 receives keystream block 0 */
static void ccm_ctr(CCCryptorRef c, const uint8_t nonce[13], const uint8_t *in, size_t len,
                    uint8_t *out, uint8_t s0[16]) {
    uint8_t a[16], s[16];
    a[0] = 2 - 1; memcpy(a + 1, nonce, 13);
    put16(a + 14, 0); ecb_blk(c, a, s0);
    for (size_t off = 0, ctr = 1; off < len; off += 16, ctr++) {
        size_t n = len - off < 16 ? len - off : 16;
        put16(a + 14, (uint16_t)ctr); ecb_blk(c, a, s);
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ s[i];
    }
}

int ccm_seal(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t aad_len,
             const uint8_t *in, size_t len, uint8_t *out, uint8_t mic[8]) {
    if (len > 0xFFFF || aad_len > 0xFEFF) return -1;
    CCCryptorRef c = ecb_new(key, 1); if (!c) return -1;
    uint8_t t[16], s0[16];
    ccm_mac(c, nonce, aad, aad_len, in, len, t);   /* before out is written (in may == out) */
    ccm_ctr(c, nonce, in, len, out, s0);
    for (int i = 0; i < 8; i++) mic[i] = t[i] ^ s0[i];
    CCCryptorRelease(c);
    return 0;
}

int ccm_open(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t aad_len,
             const uint8_t *in, size_t len, const uint8_t mic[8], uint8_t *out) {
    if (len > 0xFFFF || aad_len > 0xFEFF) return -1;
    CCCryptorRef c = ecb_new(key, 1); if (!c) return -1;
    uint8_t t[16], s0[16], m[8];
    ccm_ctr(c, nonce, in, len, out, s0);
    ccm_mac(c, nonce, aad, aad_len, out, len, t);
    for (int i = 0; i < 8; i++) m[i] = t[i] ^ s0[i];
    CCCryptorRelease(c);
    if (!ct_eq(m, mic, 8)) { memset(out, 0, len); return -1; }
    return 0;
}

/* ------------------------------------------------------------ CCMP */

/* build AAD (returns length) and nonce from the 802.11 header */
static int ccmp_aad_nonce(const uint8_t *hdr, size_t hdr_len, uint64_t pn, uint8_t *aad, uint8_t nonce[13]) {
    if (hdr_len < 24) return -1;
    int type = (hdr[0] >> 2) & 3;
    int to_ds = hdr[1] & 1, from_ds = hdr[1] & 2;
    int a4 = to_ds && from_ds;
    int qos = type == 2 && (hdr[0] & 0x80);
    size_t need = 24 + (a4 ? 6 : 0) + (qos ? 2 : 0);
    if (hdr_len < need) return -1;
    size_t n = 0;
    uint8_t fc0 = hdr[0], fc1 = hdr[1];
    if (type == 2) fc0 &= ~0x70;                 /* data: subtype bits 4-6 zeroed (QoS bit kept) */
    fc1 &= ~(0x08 | 0x10 | 0x20);                /* retry, pwr mgmt, more data */
    fc1 |= 0x40;                                 /* protected */
    aad[n++] = fc0; aad[n++] = fc1;
    memcpy(aad + n, hdr + 4, 18); n += 18;       /* A1 A2 A3 */
    aad[n++] = hdr[22] & 0x0F; aad[n++] = 0;     /* sequence number masked, fragment kept */
    if (a4) { memcpy(aad + n, hdr + 24, 6); n += 6; }
    int prio = 0;
    if (qos) {
        uint8_t q = hdr[24 + (a4 ? 6 : 0)];
        prio = q & 0x0F;
        aad[n++] = (uint8_t)prio; aad[n++] = 0;
    }
    nonce[0] = (uint8_t)(prio | (type == 0 ? 0x10 : 0));
    memcpy(nonce + 1, hdr + 10, 6);              /* A2 */
    for (int i = 0; i < 6; i++) nonce[7 + i] = (uint8_t)(pn >> (8 * (5 - i)));
    return (int)n;
}

int ccmp_encrypt(const uint8_t *tk, const uint8_t *hdr, size_t hdr_len, uint64_t pn, int key_id,
                 const uint8_t *plain, size_t plain_len, uint8_t *out) {
    uint8_t aad[32], nonce[13];
    if (pn >> 48) return -1;
    int al = ccmp_aad_nonce(hdr, hdr_len, pn, aad, nonce);
    if (al < 0) return -1;
    out[0] = (uint8_t)pn; out[1] = (uint8_t)(pn >> 8); out[2] = 0;
    out[3] = (uint8_t)(0x20 | ((key_id & 3) << 6));
    out[4] = (uint8_t)(pn >> 16); out[5] = (uint8_t)(pn >> 24);
    out[6] = (uint8_t)(pn >> 32); out[7] = (uint8_t)(pn >> 40);
    if (ccm_seal(tk, nonce, aad, (size_t)al, plain, plain_len, out + 8, out + 8 + plain_len)) return -1;
    return (int)(plain_len + 16);
}

int ccmp_decrypt(const uint8_t *tk, const uint8_t *hdr, size_t hdr_len, const uint8_t *in,
                 size_t in_len, uint8_t *plain, uint64_t *pn_out, int *key_id) {
    uint8_t aad[32], nonce[13];
    if (in_len < 16 || !(in[3] & 0x20)) return -1;
    uint64_t pn = (uint64_t)in[0] | (uint64_t)in[1] << 8 | (uint64_t)in[4] << 16 |
                  (uint64_t)in[5] << 24 | (uint64_t)in[6] << 32 | (uint64_t)in[7] << 40;
    int al = ccmp_aad_nonce(hdr, hdr_len, pn, aad, nonce);
    if (al < 0) return -1;
    size_t pl = in_len - 16;
    if (ccm_open(tk, nonce, aad, (size_t)al, in + 8, pl, in + 8 + pl, plain)) return -1;
    if (pn_out) *pn_out = pn;
    if (key_id) *key_id = in[3] >> 6;
    return (int)pl;
}

/* ------------------------------------------------------------ EAPOL-Key */

#define KF_FIXED 95                       /* key descriptor body without key data */
#define OFF_BODY 4

int eapol_key_parse(const uint8_t *e, size_t len, eapol_key_t *k) {
    if (len < OFF_BODY + KF_FIXED) return -1;
    if (e[1] != 3) return -1;             /* packet type: EAPOL-Key */
    size_t body = be16(e + 2);
    if (body < KF_FIXED || OFF_BODY + body > len) return -1;
    const uint8_t *b = e + OFF_BODY;
    if (b[0] != 2 && b[0] != 254) return -1;   /* descriptor type: IEEE 802.11 (RSN) or WPA1 */
    k->desc = b[0];
    k->info = be16(b + 1);
    k->key_len = be16(b + 3);
    k->replay = be64(b + 5);
    k->nonce = b + 13; k->iv = b + 45; k->rsc = b + 61;
    k->mic = b + 77;
    size_t kdl = be16(b + 93);
    if (KF_FIXED + kdl > body) return -1;
    k->key_data = b + KF_FIXED; k->key_data_len = kdl;
    k->frame_len = OFF_BODY + body;
    return 0;
}

void eapol_key_mic(const uint8_t kck[16], const uint8_t *e, size_t frame_len, uint8_t mic[16]) {
    uint8_t tmp[1024], *buf = frame_len <= sizeof(tmp) ? tmp : malloc(frame_len);
    uint8_t h[20];
    if (!buf) { memset(mic, 0, 16); return; }
    memcpy(buf, e, frame_len);
    memset(buf + OFF_BODY + 77, 0, 16);
    if ((be16(e + OFF_BODY + 1) & EAPOL_KEY_VER_MASK) == 1) CCHmac(kCCHmacAlgMD5, kck, 16, buf, frame_len, h);
    else CCHmac(kCCHmacAlgSHA1, kck, 16, buf, frame_len, h);
    memcpy(mic, h, 16);
    if (buf != tmp) free(buf);
}

int eapol_key_verify_mic(const uint8_t kck[16], const uint8_t *e, size_t frame_len) {
    uint8_t m[16];
    if (frame_len < OFF_BODY + KF_FIXED) return -1;
    eapol_key_mic(kck, e, frame_len, m);
    return ct_eq(m, e + OFF_BODY + 77, 16) ? 0 : -1;
}

static int key_build(int desc, uint8_t *out, size_t cap, uint16_t info, uint16_t key_len, uint64_t replay,
                     const uint8_t nonce[32], const uint8_t *kd, size_t kd_len, const uint8_t kck[16]) {
    size_t total = OFF_BODY + KF_FIXED + kd_len;
    if (total > cap || kd_len > 0xFFFF) return -1;
    memset(out, 0, OFF_BODY + KF_FIXED);
    out[0] = 2; out[1] = 3; put16(out + 2, (uint16_t)(KF_FIXED + kd_len));
    uint8_t *b = out + OFF_BODY;
    b[0] = (uint8_t)desc; put16(b + 1, info); put16(b + 3, key_len); put64(b + 5, replay);
    if (nonce) memcpy(b + 13, nonce, 32);
    put16(b + 93, (uint16_t)kd_len);
    if (kd_len) memcpy(b + KF_FIXED, kd, kd_len);
    if (kck && (info & EAPOL_KEY_MIC)) eapol_key_mic(kck, out, total, b + 77);
    return (int)total;
}

int eapol_key_build(uint8_t *out, size_t cap, uint16_t info, uint16_t key_len, uint64_t replay,
                    const uint8_t nonce[32], const uint8_t *kd, size_t kd_len, const uint8_t kck[16]) {
    return key_build(2, out, cap, info, key_len, replay, nonce, kd, kd_len, kck);
}

int wpa_parse_key_data(const uint8_t *kd, size_t len, uint8_t *gtk, size_t *gtk_len, int *gtk_id,
                       int *gtk_tx, uint8_t *rsn, size_t *rsn_len) {
    int found = 0;
    size_t off = 0;
    while (off + 2 <= len) {
        uint8_t id = kd[off], l = kd[off + 1];
        if (id == 0xDD && l == 0) break;                  /* padding */
        if (off + 2 + l > len) return -1;
        const uint8_t *d = kd + off + 2;
        if (id == 0xDD && l >= 6 + 16 && d[0] == 0x00 && d[1] == 0x0F && d[2] == 0xAC && d[3] == 1) {
            size_t gl = l - 6;
            if (gl <= 32 && !(found & 1)) {
                if (gtk) memcpy(gtk, d + 6, gl);
                if (gtk_len) *gtk_len = gl;
                if (gtk_id) *gtk_id = d[4] & 3;
                if (gtk_tx) *gtk_tx = (d[4] >> 2) & 1;
                found |= 1;
            }
        } else if ((id == 0x30 || (id == 0xDD && l >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 1)) &&
                   !(found & 2)) {
            if (rsn && rsn_len && (size_t)l + 2 <= 128) { memcpy(rsn, kd + off, (size_t)l + 2); *rsn_len = (size_t)l + 2; }
            found |= 2;
        }
        off += 2 + l;
    }
    return found;
}

/* ------------------------------------------------------------ state machine */

int wpa_init_ex(wpa_t *w, const char *pass, const uint8_t *ssid, size_t ssid_len,
                const uint8_t aa[6], const uint8_t spa[6], const uint8_t *ie, size_t ie_len,
                int pairwise_tkip, int wpa1) {
    if (ie_len > sizeof(w->rsn_ie)) return -1;
    memset(w, 0, sizeof(*w));
    wpa_pmk(pass, ssid, ssid_len, w->pmk);
    memcpy(w->aa, aa, 6); memcpy(w->spa, spa, 6);
    memcpy(w->rsn_ie, ie, ie_len); w->rsn_len = ie_len;
    w->ptk_len = pairwise_tkip ? 64 : 48;
    w->wpa1 = wpa1;
    return 0;
}

int wpa_init(wpa_t *w, const char *pass, const uint8_t *ssid, size_t ssid_len,
             const uint8_t aa[6], const uint8_t spa[6], const uint8_t *rsn_ie, size_t rsn_len) {
    return wpa_init_ex(w, pass, ssid, ssid_len, aa, spa, rsn_ie, rsn_len, 0, 0);
}

const uint8_t *wpa_get_tk(const wpa_t *w) { return w->state == 2 ? w->ptk + 32 : NULL; }
const uint8_t *wpa_get_ptk(const wpa_t *w) { return w->state == 2 ? w->ptk : NULL; }
const uint8_t *wpa_get_gtk(const wpa_t *w, size_t *len, int *key_id) {
    if (!w->have_gtk) return NULL;
    if (len) *len = w->gtk_len;
    if (key_id) *key_id = w->gtk_id;
    return w->gtk;
}

#define MAX_KD 512

/* decrypt key data of a verified frame into plain (size MAX_KD); returns length or <0.
 * Version 2: AES key wrap (RFC 3394), data is 8 bytes longer than the plaintext.
 * Version 1: RC4 keyed with Key-IV || KEK, first 256 keystream bytes discarded, same length. */
static int decrypt_kd(const wpa_t *w, const eapol_key_t *k, uint8_t *plain) {
    size_t n = k->key_data_len;
    if (w->ver == 1) {
        uint8_t key[32];
        if (n == 0 || n > MAX_KD) return WPA_ERR_KEYDATA;
        memcpy(key, k->iv, 16); memcpy(key + 16, w->ptk + 16, 16);
        memcpy(plain, k->key_data, n);
        rc4_crypt(key, 32, 256, plain, n);
        return (int)n;
    }
    if (!(k->info & EAPOL_KEY_ENCRYPTED)) return WPA_ERR_KEYDATA;
    if (n < 24 || n % 8 || n - 8 > MAX_KD) return WPA_ERR_KEYDATA;
    if (aes_unwrap(w->ptk + 16, k->key_data, n, plain)) return WPA_ERR_KEYDATA;
    return (int)(n - 8);
}

int wpa_rx_eapol(wpa_t *w, const uint8_t *e, size_t len, uint8_t *out, size_t *out_len, int *event) {
    eapol_key_t k;
    int r, n;
    *out_len = 0; *event = 0;
    if (eapol_key_parse(e, len, &k)) return WPA_ERR_MALFORMED;
    int ver = k.info & EAPOL_KEY_VER_MASK;
    if (ver != 1 && ver != 2) return WPA_ERR_MALFORMED;
    if (k.desc != (w->wpa1 ? 254 : 2)) return WPA_ERR_MALFORMED;
    if (w->wpa1 && ver != 1) return WPA_ERR_MALFORMED;
    if ((k.info & (EAPOL_KEY_REQUEST | EAPOL_KEY_ERROR)) || !(k.info & EAPOL_KEY_ACK))
        return WPA_ERR_UNEXPECTED;                            /* only authenticator messages */

    int pairwise = !!(k.info & EAPOL_KEY_PAIRWISE);

    if (pairwise && !(k.info & EAPOL_KEY_MIC)) {              /* ---- message 1 */
        if (w->state == 2) return WPA_ERR_UNEXPECTED;         /* no PTK rekey: re-associate instead */
        if (k.info & (EAPOL_KEY_INSTALL | EAPOL_KEY_SECURE)) return WPA_ERR_MALFORMED;
        w->ver = ver;
        memcpy(w->anonce, k.nonce, 32);
        arc4random_buf(w->snonce, 32);
        wpa_ptk_n(w->pmk, w->aa, w->spa, w->anonce, w->snonce, w->ptk, (size_t)w->ptk_len);
        w->replay = k.replay; w->have_replay = 1;
        /* WPA1 supplicants echo the AP's key_length (32 for TKIP); RSN supplicants send 0. */
        n = key_build(w->wpa1 ? 254 : 2, out, 256 + w->rsn_len, EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC | (uint16_t)ver,
                      w->wpa1 ? k.key_len : 0, k.replay, w->snonce, w->rsn_ie, w->rsn_len, w->ptk);
        if (n < 0) return WPA_ERR_MALFORMED;
        *out_len = (size_t)n; w->state = 1;
        return 0;
    }

    if (!(k.info & EAPOL_KEY_MIC)) return WPA_ERR_MALFORMED;
    /* SECURE is set on RSN message 3 and on every group message; WPA1 message 3 does not carry it. */
    if (!(k.info & EAPOL_KEY_SECURE) && !(w->wpa1 && pairwise)) return WPA_ERR_MALFORMED;
    if (w->state == 0) return WPA_ERR_UNEXPECTED;
    if (ver != w->ver) return WPA_ERR_MALFORMED;
    if (eapol_key_verify_mic(w->ptk, e, k.frame_len)) return WPA_ERR_MIC;
    if (w->have_replay && k.replay <= w->replay) return WPA_ERR_REPLAY;

    uint8_t kd[MAX_KD];
    if (pairwise) {                                           /* ---- message 3 */
        if (!(k.info & EAPOL_KEY_INSTALL)) return WPA_ERR_MALFORMED;
        if (!ct_eq(k.nonce, w->anonce, 32)) return WPA_ERR_UNEXPECTED;
        if (w->wpa1 && !(k.info & EAPOL_KEY_ENCRYPTED)) {     /* WPA1 sends the IE in clear */
            if (k.key_data_len > MAX_KD) return WPA_ERR_KEYDATA;
            memcpy(kd, k.key_data, k.key_data_len); n = (int)k.key_data_len;
        } else if ((n = decrypt_kd(w, &k, kd)) < 0) return n;
        uint8_t gtk[32], rsn[128]; size_t gl = 0, rl = 0; int gid = 0, gtx = 0;
        r = wpa_parse_key_data(kd, (size_t)n, gtk, &gl, &gid, &gtx, rsn, &rl);
        if (r < 0 || !(r & 2)) return WPA_ERR_KEYDATA;        /* AP RSN / WPA IE is mandatory in M3 */
        int first = w->state == 1;
        w->replay = k.replay; w->have_replay = 1;
        memcpy(w->ap_rsn, rsn, rl); w->ap_rsn_len = rl;
        if (r & 1) {
            memcpy(w->gtk, gtk, gl); w->gtk_len = gl; w->gtk_id = gid; w->gtk_tx = gtx;
            if (first || !w->have_gtk) *event |= WPA_EV_GTK;
            w->have_gtk = 1;
        }
        n = key_build(w->wpa1 ? 254 : 2, out, 256, EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC | (w->wpa1 ? 0 : EAPOL_KEY_SECURE) | (uint16_t)ver,
                      w->wpa1 ? k.key_len : 0, k.replay, NULL, NULL, 0, w->ptk);
        if (n < 0) return WPA_ERR_MALFORMED;
        *out_len = (size_t)n;
        w->state = 2;
        if (first) *event |= WPA_EV_PTK;                      /* never re-announce on M3 retransmit */
        else *event &= ~WPA_EV_GTK;
        return 0;
    }

    /* ---- group message 1 */
    if (w->state != 2) return WPA_ERR_UNEXPECTED;
    uint8_t gtk[32]; size_t gl = 0; int gid = 0, gtx = 0;
    if ((n = decrypt_kd(w, &k, kd)) < 0) return n;
    if (w->wpa1) {                                            /* key data IS the GTK; index and Tx are in the key info */
        if (n < 16 || n > 32) return WPA_ERR_KEYDATA;
        memcpy(gtk, kd, (size_t)n); gl = (size_t)n;
        gid = (k.info >> 4) & 3; gtx = !!(k.info & EAPOL_KEY_INSTALL);
    } else {
        r = wpa_parse_key_data(kd, (size_t)n, gtk, &gl, &gid, &gtx, NULL, NULL);
        if (r < 0 || !(r & 1)) return WPA_ERR_KEYDATA;
    }
    w->replay = k.replay;
    memcpy(w->gtk, gtk, gl); w->gtk_len = gl; w->gtk_id = gid; w->gtk_tx = gtx; w->have_gtk = 1;
    n = key_build(w->wpa1 ? 254 : 2, out, 256, EAPOL_KEY_MIC | EAPOL_KEY_SECURE | (uint16_t)ver | (uint16_t)(k.info & 0x30),
                  0, k.replay, NULL, NULL, 0, w->ptk);
    if (n < 0) return WPA_ERR_MALFORMED;
    *out_len = (size_t)n; *event |= WPA_EV_GTK;
    return 0;
}
