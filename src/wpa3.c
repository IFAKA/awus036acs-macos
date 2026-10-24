// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wpa3.c - WPA3-Personal / PMF helpers. See wpa3.h. Apple CommonCrypto only. */
#include "wpa3.h"
#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>
#include <string.h>

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0; for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0;
}

/* ------------------------------------------------------------ primitives */

void wpa3_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t len, uint8_t out[32]) {
    CCHmac(kCCHmacAlgSHA256, key, key_len, msg, len, out);
}

void wpa3_hmac_sha256_v(const uint8_t *key, size_t key_len, int n, const uint8_t *const *m, const size_t *ml, uint8_t out[32]) {
    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256, key, key_len);
    for (int i = 0; i < n; i++) if (ml[i]) CCHmacUpdate(&ctx, m[i], ml[i]);
    CCHmacFinal(&ctx, out);
}

int wpa3_kdf_sha256(const uint8_t *key, size_t key_len, const char *label,
                    const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t bits) {
    if (bits % 8 || bits == 0 || bits > 2040) return -1;
    size_t len = bits / 8, pos = 0;
    uint8_t ctr[2], lb[2] = { (uint8_t)bits, (uint8_t)(bits >> 8) };
    const uint8_t *m[4]; size_t ml[4];
    m[0] = ctr; ml[0] = 2;
    m[1] = (const uint8_t *)label; ml[1] = strlen(label);
    m[2] = ctx; ml[2] = ctx_len;
    m[3] = lb; ml[3] = 2;
    for (unsigned i = 1; pos < len; i++) {
        uint8_t h[32];
        ctr[0] = (uint8_t)i; ctr[1] = (uint8_t)(i >> 8);
        wpa3_hmac_sha256_v(key, key_len, 4, m, ml, h);
        size_t n = len - pos < 32 ? len - pos : 32;
        memcpy(out + pos, h, n); pos += n;
    }
    return 0;
}

static void aes_ecb_enc(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    size_t moved = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, key, 16, NULL, in, 16, out, 16, &moved);
}

static void cmac_dbl(const uint8_t in[16], uint8_t out[16]) {
    uint8_t carry = in[0] >> 7;
    for (int i = 0; i < 15; i++) out[i] = (uint8_t)(in[i] << 1 | in[i + 1] >> 7);
    out[15] = (uint8_t)(in[15] << 1) ^ (carry ? 0x87 : 0);
}

void aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16]) {
    uint8_t l[16] = { 0 }, k1[16], k2[16], x[16] = { 0 }, y[16], last[16];
    aes_ecb_enc(key, l, l);
    cmac_dbl(l, k1); cmac_dbl(k1, k2);
    size_t n = (len + 15) / 16;
    int complete = len > 0 && len % 16 == 0;
    if (n == 0) n = 1;
    for (size_t i = 0; i + 1 < n; i++) {
        for (int j = 0; j < 16; j++) y[j] = x[j] ^ msg[16 * i + j];
        aes_ecb_enc(key, y, x);
    }
    size_t off = 16 * (n - 1), rem = len - off;
    if (complete) { for (int j = 0; j < 16; j++) last[j] = msg[off + j] ^ k1[j]; }
    else {
        memset(last, 0, 16); memcpy(last, msg + off, rem); last[rem] = 0x80;
        for (int j = 0; j < 16; j++) last[j] ^= k2[j];
    }
    for (int j = 0; j < 16; j++) y[j] = x[j] ^ last[j];
    aes_ecb_enc(key, y, mac);
}

/* ------------------------------------------------------------ keys and EAPOL */

void wpa3_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
              const uint8_t anonce[32], const uint8_t snonce[32], uint8_t ptk[48]) {
    uint8_t ctx[76];
    const uint8_t *lo = memcmp(aa, spa, 6) < 0 ? aa : spa, *hi = lo == aa ? spa : aa;
    memcpy(ctx, lo, 6); memcpy(ctx + 6, hi, 6);
    const uint8_t *nl = memcmp(anonce, snonce, 32) < 0 ? anonce : snonce, *nh = nl == anonce ? snonce : anonce;
    memcpy(ctx + 12, nl, 32); memcpy(ctx + 44, nh, 32);
    wpa3_kdf_sha256(pmk, 32, "Pairwise key expansion", ctx, sizeof ctx, ptk, 384);
}

void wpa3_eapol_mic(const uint8_t kck[16], const uint8_t *e, size_t frame_len, uint8_t mic[16]) {
    uint8_t tmp[1024], *buf = frame_len <= sizeof tmp ? tmp : malloc(frame_len);
    if (!buf || frame_len < 4 + 95) { memset(mic, 0, 16); if (buf != tmp) free(buf); return; }
    memcpy(buf, e, frame_len);
    memset(buf + 4 + 77, 0, 16);
    aes_cmac(kck, buf, frame_len, mic);
    if (buf != tmp) free(buf);
}

int wpa3_eapol_verify_mic(const uint8_t kck[16], const uint8_t *e, size_t frame_len) {
    uint8_t m[16];
    if (frame_len < 4 + 95) return -1;
    wpa3_eapol_mic(kck, e, frame_len, m);
    return ct_eq(m, e + 4 + 77, 16) ? 0 : -1;
}

/* ------------------------------------------------------------ IEs */

int wpa3_build_rsn_ie(uint8_t *out, size_t cap, int group_cipher, int pmf_required, const uint8_t *pmkid) {
    size_t n = 0;
    uint8_t b[64];
    b[n++] = 0x30; b[n++] = 0;
    b[n++] = 1; b[n++] = 0;                                         /* version */
    memcpy(b + n, "\x00\x0f\xac", 3); b[n + 3] = (uint8_t)group_cipher; n += 4;
    b[n++] = 1; b[n++] = 0;                                         /* pairwise count */
    memcpy(b + n, "\x00\x0f\xac\x04", 4); n += 4;                   /* CCMP */
    b[n++] = 1; b[n++] = 0;                                         /* AKM count */
    memcpy(b + n, "\x00\x0f\xac\x08", 4); n += 4;                   /* SAE */
    uint16_t caps = 0x0080 | (pmf_required ? 0x0040 : 0);           /* MFPC always (WPA3 mandates PMF), MFPR optional */
    b[n++] = (uint8_t)caps; b[n++] = (uint8_t)(caps >> 8);
    if (pmkid) {
        b[n++] = 1; b[n++] = 0; memcpy(b + n, pmkid, 16); n += 16;
    } else {
        b[n++] = 0; b[n++] = 0;                                     /* PMKID count 0, needed to reach the next field */
    }
    memcpy(b + n, "\x00\x0f\xac\x06", 4); n += 4;                   /* group management cipher: BIP-CMAC-128 */
    b[1] = (uint8_t)(n - 2);
    if (n > cap) return -1;
    memcpy(out, b, n);
    return (int)n;
}

int wpa3_build_rsnxe(uint8_t *out, size_t cap) {
    if (cap < 3) return -1;
    out[0] = 0xF4; out[1] = 1; out[2] = 0x20;
    return 3;
}

int wpa3_ap_h2e(const uint8_t *ies, size_t len) {
    int r = 0;
    for (size_t o = 0; o + 2 <= len; ) {
        uint8_t id = ies[o], l = ies[o + 1];
        if (o + 2 + l > len) break;
        const uint8_t *d = ies + o + 2;
        if (id == 244 && l >= 1 && (d[0] & 0x20)) r |= 1;
        if (id == 1 || id == 50) for (int i = 0; i < l; i++) if (d[i] == (0x80 | 123)) r |= 2;
        o += 2 + l;
    }
    return r;
}

int wpa3_rsn_caps(const uint8_t *ie, size_t len) {
    if (len < 2 || ie[0] != 0x30 || (size_t)ie[1] + 2 > len) return -1;
    const uint8_t *p = ie + 2, *e = ie + 2 + ie[1];
    int r = 0;
    if (e - p < 2) return -1;
    p += 2;                                                          /* version */
    if (e - p < 4) return -1; p += 4;                                /* group cipher */
    if (e - p < 2) return -1;
    size_t pc = (size_t)p[0] | (size_t)p[1] << 8; p += 2;
    if ((size_t)(e - p) < pc * 4) return -1; p += pc * 4;
    if (e - p < 2) return -1;
    size_t ac = (size_t)p[0] | (size_t)p[1] << 8; p += 2;
    if ((size_t)(e - p) < ac * 4) return -1;
    for (size_t i = 0; i < ac; i++, p += 4) {
        if (p[0] == 0 && p[1] == 0x0f && p[2] == 0xac) {
            if (p[3] == 8) r |= 1;
            if (p[3] == 2) r |= 8;
        }
    }
    if (e - p >= 2) {
        uint16_t caps = (uint16_t)(p[0] | p[1] << 8);
        if (caps & 0x0080) r |= 2;
        if (caps & 0x0040) r |= 4;
    }
    return r;
}

/* ------------------------------------------------------------ KDEs */

int wpa3_parse_kdes(const uint8_t *kd, size_t len, wpa3_kdes_t *o) {
    memset(o, 0, sizeof *o);
    size_t off = 0;
    while (off + 2 <= len) {
        uint8_t id = kd[off], l = kd[off + 1];
        if (id == 0xDD && l == 0) break;                            /* padding */
        if (off + 2 + l > len) return -1;
        const uint8_t *d = kd + off + 2;
        if (id == 0xDD && l >= 4 && d[0] == 0x00 && d[1] == 0x0F && d[2] == 0xAC) {
            if (d[3] == 1 && l >= 6 + 16 && l - 6 <= 32 && !o->have_gtk) {
                o->gtk_len = (size_t)l - 6; memcpy(o->gtk, d + 6, o->gtk_len);
                o->gtk_id = d[4] & 3; o->gtk_tx = (d[4] >> 2) & 1; o->have_gtk = 1;
            } else if (d[3] == 9 && l == 4 + 2 + 6 + 16 && !o->have_igtk) {
                o->igtk_id = d[4] | d[5] << 8;
                memcpy(o->igtk_ipn, d + 6, 6); memcpy(o->igtk, d + 12, 16); o->have_igtk = 1;
            }
        } else if (id == 0x30 && !o->have_rsn && (size_t)l + 2 <= sizeof o->rsn) {
            memcpy(o->rsn, kd + off, (size_t)l + 2); o->rsn_len = (size_t)l + 2; o->have_rsn = 1;
        }
        off += 2 + l;
    }
    return 0;
}

/* ------------------------------------------------------------ handshake */

int wpa3_init(wpa3_t *w, const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
              const uint8_t *rsn_ie, size_t rsn_len) {
    if (rsn_len > sizeof w->rsn_ie) return -1;
    memset(w, 0, sizeof *w);
    memcpy(w->pmk, pmk, 32); memcpy(w->aa, aa, 6); memcpy(w->spa, spa, 6);
    memcpy(w->rsn_ie, rsn_ie, rsn_len); w->rsn_len = rsn_len;
    return 0;
}

const uint8_t *wpa3_get_tk(const wpa3_t *w) { return w->state == 2 ? w->ptk + 32 : NULL; }
const uint8_t *wpa3_get_ptk(const wpa3_t *w) { return w->state == 2 ? w->ptk : NULL; }

#define MAX_KD 512
#define KEYINFO_VER0 0

/* build an EAPOL-Key frame (descriptor 2, version 0) and fill the CMAC MIC */
static int build_key(uint8_t *out, size_t cap, uint16_t info, uint64_t replay, const uint8_t nonce[32],
                     const uint8_t *kd, size_t kd_len, const uint8_t kck[16]) {
    int n = eapol_key_build(out, cap, (uint16_t)(info & ~EAPOL_KEY_VER_MASK), 0, replay, nonce, kd, kd_len, NULL);
    if (n < 0) return n;
    if (info & EAPOL_KEY_MIC) wpa3_eapol_mic(kck, out, (size_t)n, out + 4 + 77);
    return n;
}

static int decrypt_kd(const wpa3_t *w, const eapol_key_t *k, uint8_t *plain) {
    size_t n = k->key_data_len;
    if (!(k->info & EAPOL_KEY_ENCRYPTED)) return WPA_ERR_KEYDATA;
    if (n < 24 || n % 8 || n - 8 > MAX_KD) return WPA_ERR_KEYDATA;
    if (aes_unwrap(w->ptk + 16, k->key_data, n, plain)) return WPA_ERR_KEYDATA;
    return (int)(n - 8);
}

static void take_keys(wpa3_t *w, const wpa3_kdes_t *kd, int *event, int first) {
    if (kd->have_gtk) {
        memcpy(w->gtk, kd->gtk, kd->gtk_len); w->gtk_len = kd->gtk_len; w->gtk_id = kd->gtk_id; w->gtk_tx = kd->gtk_tx;
        if (first || !w->have_gtk) *event |= WPA3_EV_GTK;
        w->have_gtk = 1;
    }
    if (kd->have_igtk) {
        memcpy(w->igtk, kd->igtk, 16); memcpy(w->igtk_ipn, kd->igtk_ipn, 6); w->igtk_id = kd->igtk_id;
        if (first || !w->have_igtk) *event |= WPA3_EV_IGTK;
        w->have_igtk = 1;
    }
}

int wpa3_rx_eapol(wpa3_t *w, const uint8_t *e, size_t len, uint8_t *out, size_t *out_len, int *event) {
    eapol_key_t k;
    int n;
    *out_len = 0; *event = 0;
    if (eapol_key_parse(e, len, &k)) return WPA_ERR_MALFORMED;
    if (k.desc != 2 || (k.info & EAPOL_KEY_VER_MASK) != KEYINFO_VER0) return WPA_ERR_MALFORMED;
    if ((k.info & (EAPOL_KEY_REQUEST | EAPOL_KEY_ERROR)) || !(k.info & EAPOL_KEY_ACK)) return WPA_ERR_UNEXPECTED;
    int pairwise = !!(k.info & EAPOL_KEY_PAIRWISE);

    if (pairwise && !(k.info & EAPOL_KEY_MIC)) {                    /* ---- message 1 */
        if (w->state == 2) return WPA_ERR_UNEXPECTED;
        if (k.info & (EAPOL_KEY_INSTALL | EAPOL_KEY_SECURE)) return WPA_ERR_MALFORMED;
        memcpy(w->anonce, k.nonce, 32);
        arc4random_buf(w->snonce, 32);
        wpa3_ptk(w->pmk, w->aa, w->spa, w->anonce, w->snonce, w->ptk);
        w->replay = k.replay; w->have_replay = 1;
        n = build_key(out, 256 + w->rsn_len, EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC, k.replay, w->snonce,
                      w->rsn_ie, w->rsn_len, w->ptk);
        if (n < 0) return WPA_ERR_MALFORMED;
        *out_len = (size_t)n; w->state = 1;
        return 0;
    }

    if (!(k.info & EAPOL_KEY_MIC) || !(k.info & EAPOL_KEY_SECURE)) return WPA_ERR_MALFORMED;
    if (w->state == 0) return WPA_ERR_UNEXPECTED;
    if (wpa3_eapol_verify_mic(w->ptk, e, k.frame_len)) return WPA_ERR_MIC;
    if (w->have_replay && k.replay <= w->replay) return WPA_ERR_REPLAY;

    uint8_t kd[MAX_KD];
    wpa3_kdes_t kdes;
    if (pairwise) {                                                 /* ---- message 3 */
        if (!(k.info & EAPOL_KEY_INSTALL)) return WPA_ERR_MALFORMED;
        if (!ct_eq(k.nonce, w->anonce, 32)) return WPA_ERR_UNEXPECTED;
        if ((n = decrypt_kd(w, &k, kd)) < 0) return n;
        if (wpa3_parse_kdes(kd, (size_t)n, &kdes) < 0 || !kdes.have_rsn) return WPA_ERR_KEYDATA;
        int first = w->state == 1;
        w->replay = k.replay; w->have_replay = 1;
        memcpy(w->ap_rsn, kdes.rsn, kdes.rsn_len); w->ap_rsn_len = kdes.rsn_len;
        take_keys(w, &kdes, event, first);
        n = build_key(out, 256, EAPOL_KEY_PAIRWISE | EAPOL_KEY_MIC | EAPOL_KEY_SECURE, k.replay, NULL, NULL, 0, w->ptk);
        if (n < 0) return WPA_ERR_MALFORMED;
        *out_len = (size_t)n;
        w->state = 2;
        if (first) *event |= WPA3_EV_PTK;
        else *event &= ~(WPA3_EV_GTK | WPA3_EV_IGTK);
        return 0;
    }

    /* ---- group message 1 */
    if (w->state != 2) return WPA_ERR_UNEXPECTED;
    if ((n = decrypt_kd(w, &k, kd)) < 0) return n;
    if (wpa3_parse_kdes(kd, (size_t)n, &kdes) < 0 || (!kdes.have_gtk && !kdes.have_igtk)) return WPA_ERR_KEYDATA;
    w->replay = k.replay;
    take_keys(w, &kdes, event, 1);
    n = build_key(out, 256, EAPOL_KEY_MIC | EAPOL_KEY_SECURE | (uint16_t)(k.info & 0x30), k.replay, NULL, NULL, 0, w->ptk);
    if (n < 0) return WPA_ERR_MALFORMED;
    *out_len = (size_t)n;
    return 0;
}

/* ------------------------------------------------------------ protected management frames */

int wpa3_mgmt_protect(const uint8_t tk[16], const uint8_t *hdr, const uint8_t *body, size_t body_len,
                      uint64_t pn, int key_id, uint8_t *out, size_t cap) {
    if (((hdr[0] >> 2) & 3) != 0 || cap < 24 + body_len + 16) return -1;
    memcpy(out, hdr, 24);
    out[1] |= 0x40;                                                 /* Protected Frame */
    int n = ccmp_encrypt(tk, out, 24, pn, key_id, body, body_len, out + 24);
    return n < 0 ? n : 24 + n;
}

int wpa3_mgmt_unprotect(const uint8_t tk[16], const uint8_t *frame, size_t len, uint8_t *body_out, uint64_t *pn) {
    if (len < 24 + 16 || ((frame[0] >> 2) & 3) != 0 || !(frame[1] & 0x40) || (frame[1] & 0x80)) return -1;
    return ccmp_decrypt(tk, frame, 24, frame + 24, len - 24, body_out, pn, NULL);
}

int wpa3_is_robust(int subtype, int category) {
    if (subtype == 10 || subtype == 12) return 1;                   /* Disassoc, Deauth */
    if (subtype != 13) return 0;
    switch (category) {
    case 4: case 7: case 11: case 15: case 17: case 127: return 0;   /* Public, HT, unprotected WNM, self-protected, unprotected DMG, vendor */
    default: return 1;
    }
}

int wpa3_sa_query_reply_body(const uint8_t *req, size_t len, uint8_t out[4]) {
    if (len < 4 || req[0] != 8 || req[1] != 0) return -1;
    out[0] = 8; out[1] = 1; out[2] = req[2]; out[3] = req[3];
    return 4;
}

static void bip_mic(const uint8_t igtk[16], const uint8_t *hdr, const uint8_t *body, size_t body_len, uint8_t mic[8]) {
    uint8_t tmp[20 + 2048], *buf = body_len <= 2048 ? tmp : malloc(20 + body_len);
    uint8_t m[16];
    if (!buf) { memset(mic, 0, 8); return; }
    buf[0] = hdr[0]; buf[1] = hdr[1] & ~(0x08 | 0x10 | 0x20);        /* retry, pwr mgmt, more data masked */
    memcpy(buf + 2, hdr + 4, 18);                                    /* A1 A2 A3 */
    memcpy(buf + 20, body, body_len);
    aes_cmac(igtk, buf, 20 + body_len, m);
    memcpy(mic, m, 8);
    if (buf != tmp) free(buf);
}

int wpa3_bip_protect(const uint8_t igtk[16], int key_id, const uint8_t ipn[6], const uint8_t *hdr,
                     const uint8_t *body, size_t body_len, uint8_t *out, size_t cap) {
    if (cap < body_len + 18) return -1;
    memcpy(out, body, body_len);
    uint8_t *m = out + body_len;
    m[0] = 76; m[1] = 16; m[2] = (uint8_t)key_id; m[3] = (uint8_t)(key_id >> 8);
    memcpy(m + 4, ipn, 6); memset(m + 10, 0, 8);
    bip_mic(igtk, hdr, out, body_len + 18, m + 10);
    return (int)(body_len + 18);
}

int wpa3_bip_verify(const uint8_t igtk[16], const uint8_t *hdr, const uint8_t *body, size_t body_len, uint8_t ipn_out[6]) {
    uint8_t tmp[2048 + 18], m[8];
    if (body_len < 18 || body_len > sizeof tmp) return -1;
    const uint8_t *mm = body + body_len - 18;
    if (mm[0] != 76 || mm[1] != 16) return -1;
    memcpy(tmp, body, body_len);
    memset(tmp + body_len - 8, 0, 8);
    bip_mic(igtk, hdr, tmp, body_len, m);
    if (!ct_eq(m, mm + 10, 8)) return -1;
    if (ipn_out) memcpy(ipn_out, mm + 4, 6);
    return 0;
}
