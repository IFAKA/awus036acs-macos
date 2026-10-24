// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wpa.h - self-contained WPA2-Personal (RSN, CCMP, PSK) supplicant library.
 * Apple CommonCrypto only. No device or network needed.
 * Key descriptor versions: 2 (HMAC-SHA1-128 MIC, AES key wrap; WPA2-CCMP) and 1 (HMAC-MD5 MIC, RC4 key data; WPA1 and
 * TKIP). Descriptor type 2 (RSN) and 254 (WPA1 vendor style). The version in use is taken from the AP's message 1. */
#ifndef WPA_H
#define WPA_H
#include <stddef.h>
#include <stdint.h>

/* ---- key derivation ---- */
void wpa_pmk(const char *pass, const uint8_t *ssid, size_t ssid_len, uint8_t pmk[32]);
/* PTK layout: KCK=ptk[0..16], KEK=ptk[16..32], TK=ptk[32..48]; TKIP (len 64) adds the Michael keys
 * ptk[48..56] (Authenticator->Supplicant, i.e. our RX) and ptk[56..64] (Supplicant->Authenticator, our TX). */
void wpa_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
             const uint8_t anonce[32], const uint8_t snonce[32], uint8_t ptk[48]);
void wpa_ptk_n(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
               const uint8_t anonce[32], const uint8_t snonce[32], uint8_t *ptk, size_t len); /* len 48 or 64 */

/* ---- AES primitives (exposed for tests) ---- */
int aes_wrap(const uint8_t kek[16], const uint8_t *plain, size_t len, uint8_t *out); /* len%8==0, len>=16; out len+8 */
int aes_unwrap(const uint8_t kek[16], const uint8_t *in, size_t len, uint8_t *out);  /* len%8==0, len>=24; out len-8; 0 ok, -1 bad */
/* raw CCM, M=8, L=2, 13-byte nonce. out gets len bytes, mic 8 bytes. */
int ccm_seal(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t aad_len,
             const uint8_t *in, size_t len, uint8_t *out, uint8_t mic[8]);
int ccm_open(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t aad_len,
             const uint8_t *in, size_t len, const uint8_t mic[8], uint8_t *out); /* 0 ok, -1 MIC fail */

/* ---- EAPOL-Key frames ---- */
#define EAPOL_KEY_VER_MASK  0x0007
#define EAPOL_KEY_PAIRWISE  0x0008
#define EAPOL_KEY_INSTALL   0x0040
#define EAPOL_KEY_ACK       0x0080
#define EAPOL_KEY_MIC       0x0100
#define EAPOL_KEY_SECURE    0x0200
#define EAPOL_KEY_ERROR     0x0400
#define EAPOL_KEY_REQUEST   0x0800
#define EAPOL_KEY_ENCRYPTED 0x1000

typedef struct {
    int desc;                      /* descriptor type: 2 (RSN) or 254 (WPA1) */
    uint16_t info;                 /* key information (host order) */
    uint16_t key_len;
    uint64_t replay;
    const uint8_t *nonce;          /* 32 */
    const uint8_t *iv;             /* 16 */
    const uint8_t *rsc;            /* 8  */
    const uint8_t *mic;            /* 16 */
    const uint8_t *key_data;
    size_t key_data_len;
    size_t frame_len;              /* EAPOL header + body actually used */
} eapol_key_t;

/* parse an EAPOL frame (4-byte header + descriptor type 2 or 254 key frame; k->desc tells which). 0 ok, <0 malformed.
 * Pointers in *k reference `eapol`. */
int eapol_key_parse(const uint8_t *eapol, size_t len, eapol_key_t *k);
/* compute the MIC (HMAC-SHA1-128, or HMAC-MD5 when the frame's key descriptor version is 1) with the MIC field zeroed */
void eapol_key_mic(const uint8_t kck[16], const uint8_t *eapol, size_t frame_len, uint8_t mic[16]);
/* 0 if MIC valid */
int eapol_key_verify_mic(const uint8_t kck[16], const uint8_t *eapol, size_t frame_len);
/* generic builder; if kck != NULL and info has MIC bit, MIC is filled. returns frame length or <0 */
int eapol_key_build(uint8_t *out, size_t cap, uint16_t info, uint16_t key_len, uint64_t replay,
                    const uint8_t nonce[32], const uint8_t *key_data, size_t kd_len,
                    const uint8_t kck[16]);
/* walk key data (plain KDE/IE list); GTK KDE -> gtk/gtk_id/tx, RSN IE (0x30) or WPA vendor IE (dd 00:50:f2:01) -> rsn.
 * Any output pointer may be NULL. Returns bitmask: 1 = GTK found, 2 = RSN IE found, <0 malformed. */
int wpa_parse_key_data(const uint8_t *kd, size_t len, uint8_t *gtk, size_t *gtk_len, int *gtk_id,
                       int *gtk_tx, uint8_t *rsn, size_t *rsn_len);

/* ---- supplicant state machine ---- */
#define WPA_EV_PTK 1               /* PTK complete: TK may be installed (after sending M4) */
#define WPA_EV_GTK 2               /* new GTK available */

#define WPA_ERR_MALFORMED  (-1)
#define WPA_ERR_MIC        (-2)
#define WPA_ERR_REPLAY     (-3)
#define WPA_ERR_UNEXPECTED (-4)
#define WPA_ERR_KEYDATA    (-5)

typedef struct {
    uint8_t pmk[32], ptk[64];
    int ptk_len;                             /* 48 (CCMP) or 64 (TKIP) */
    int wpa1;                                /* WPA1: key descriptor 254, no RSN, GTK only in group message 1 */
    int ver;                                 /* key descriptor version of this handshake (1 or 2), set by message 1 */
    uint8_t aa[6], spa[6];
    uint8_t anonce[32], snonce[32];
    uint8_t rsn_ie[64]; size_t rsn_len;      /* our RSN IE (sent in M2) */
    uint8_t ap_rsn[128]; size_t ap_rsn_len;  /* AP's RSN IE from M3 (caller may compare with beacon) */
    uint8_t gtk[32]; size_t gtk_len; int gtk_id, gtk_tx; int have_gtk;
    uint64_t replay; int have_replay;
    int state;                               /* 0 idle, 1 M2 sent, 2 installed */
} wpa_t;

/* rsn_ie: the full IE (0x30, len, ...) that goes in M2 key data. returns 0 or -1 */
int wpa_init(wpa_t *w, const char *pass, const uint8_t *ssid, size_t ssid_len,
             const uint8_t aa[6], const uint8_t spa[6], const uint8_t *rsn_ie, size_t rsn_len);
/* Same, choosing the PTK length (64 when the pairwise cipher is TKIP) and WPA1 (descriptor 254, ie = WPA vendor IE). */
int wpa_init_ex(wpa_t *w, const char *pass, const uint8_t *ssid, size_t ssid_len,
                const uint8_t aa[6], const uint8_t spa[6], const uint8_t *ie, size_t ie_len,
                int pairwise_tkip, int wpa1);
const uint8_t *wpa_get_ptk(const wpa_t *w);                 /* whole PTK (ptk_len bytes) once installed, else NULL */
/* Process a received EAPOL frame. *out_len = bytes of reply written to out (0 if none; out >= 256+key data).
 * Returns 0 on success, WPA_ERR_* on rejection (frame must be dropped). *event is a WPA_EV_* mask. */
int wpa_rx_eapol(wpa_t *w, const uint8_t *eapol, size_t len, uint8_t *out, size_t *out_len, int *event);
const uint8_t *wpa_get_tk(const wpa_t *w);                  /* 16 bytes or NULL if not installed */
const uint8_t *wpa_get_gtk(const wpa_t *w, size_t *len, int *key_id); /* NULL if none */

/* ---- CCMP (802.11-2016 12.5.3) ----
 * hdr: 802.11 MAC header (24/30 bytes, +2 QoS). out: ccmp hdr 8 + data + mic 8.
 * ccmp_encrypt returns plain_len+16 or <0. */
int ccmp_encrypt(const uint8_t *tk, const uint8_t *hdr, size_t hdr_len, uint64_t pn, int key_id,
                 const uint8_t *plain, size_t plain_len, uint8_t *out);
/* in = ccmp hdr + ciphertext + mic. returns plaintext length or <0 (MIC fail / malformed).
 * pn / key_id (may be NULL) report the PN and key id from the CCMP header for replay checks. */
int ccmp_decrypt(const uint8_t *tk, const uint8_t *hdr, size_t hdr_len, const uint8_t *in,
                 size_t in_len, uint8_t *plain, uint64_t *pn, int *key_id);

#endif
