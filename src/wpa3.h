// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wpa3.h - WPA3-Personal / PMF helpers (AKM 00-0F-AC:8 SAE, key descriptor version 0). Pure functions, Apple
 * CommonCrypto only, no device or network needed. Reuses wpa.[ch] for EAPOL-Key parsing, AES key wrap and CCMP.
 *
 * What is here:
 *   - SHA-256 KDF of 802.11-2020 12.7.1.6.2 ("KDF-Hash-Length"), HMAC-SHA-256, AES-128-CMAC (RFC 4493)
 *   - PTK derivation with the SHA-256 KDF, EAPOL-Key MIC = AES-128-CMAC (key descriptor version 0)
 *   - RSN IE (AKM 8, MFPC/MFPR) and RSNXE (SAE H2E) builders, AP signalling check for H2E
 *   - a 4-way / group handshake supplicant for AKM 8 (wpa3_t), including the IGTK KDE
 *   - protected management frames: unicast CCMP protect / verify, SA Query reply, BIP-CMAC-128 (IGTK) MMIE
 * Integration into link.c is NOT done here; see PLAN.md for the call sequence. */
#ifndef WPA3_H
#define WPA3_H
#include <stddef.h>
#include <stdint.h>
#include "wpa.h"

/* ---- primitives ---- */
void wpa3_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t len, uint8_t out[32]);
/* HMAC-SHA-256 over a list of fragments (n <= 8) */
void wpa3_hmac_sha256_v(const uint8_t *key, size_t key_len, int n, const uint8_t *const *m, const size_t *ml, uint8_t out[32]);
/* KDF-Hash-Length with SHA-256: out = first `bits` bits (bits % 8 == 0, bits <= 2040) of
 * concat_i HMAC(key, LE16(i) | label | context | LE16(bits)). Returns 0, or -1 on bad args. */
int wpa3_kdf_sha256(const uint8_t *key, size_t key_len, const char *label,
                    const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t bits);
void aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16]);

/* ---- keys and EAPOL ---- */
/* PTK = KDF-SHA256(PMK, "Pairwise key expansion", min(AA,SPA)|max|min(ANonce,SNonce)|max, 384): KCK=ptk[0..16],
 * KEK=ptk[16..32], TK=ptk[32..48] (CCMP). Same layout as wpa_ptk. */
void wpa3_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
              const uint8_t anonce[32], const uint8_t snonce[32], uint8_t ptk[48]);
/* MIC = AES-128-CMAC(KCK, EAPOL frame with the MIC field zeroed) */
void wpa3_eapol_mic(const uint8_t kck[16], const uint8_t *eapol, size_t frame_len, uint8_t mic[16]);
int wpa3_eapol_verify_mic(const uint8_t kck[16], const uint8_t *eapol, size_t frame_len); /* 0 = valid */

/* ---- information elements ---- */
#define WPA3_CIPHER_CCMP 4          /* 00-0F-AC:4 */
#define WPA3_CIPHER_TKIP 2
/* Our RSN IE for AKM 8 (SAE). group = WPA3_CIPHER_*; pairwise is CCMP. pmf_required sets MFPR (always sets MFPC,
 * and adds Group Management Cipher BIP-CMAC-128). pmkid may be NULL or 16 bytes (SAE PMKID, put in the
 * (re)association request and in message 2). Returns IE length (0x30, len, ...) or -1. */
int wpa3_build_rsn_ie(uint8_t *out, size_t cap, int group_cipher, int pmf_required, const uint8_t *pmkid);
/* RSNXE announcing SAE hash-to-element: F4 01 20. Returns 3. */
int wpa3_build_rsnxe(uint8_t *out, size_t cap);
/* Look at the AP's Beacon/Probe Response IEs. Returns bit 0 = RSNXE says SAE H2E supported, bit 1 = BSS membership
 * selector 123 (SAE H2E only) present in the (extended) supported rates, i.e. the AP requires H2E. */
int wpa3_ap_h2e(const uint8_t *ies, size_t len);
/* RSN IE of the AP: AKM list contains 8 (SAE) -> bit 0; MFPC -> bit 1; MFPR -> bit 2; PSK (2) also offered -> bit 3
 * (transition mode). Returns <0 if malformed. ie = the full IE (0x30 len ...). */
int wpa3_rsn_caps(const uint8_t *ie, size_t len);

/* ---- KDE walker ---- */
typedef struct {
    int have_gtk; uint8_t gtk[32]; size_t gtk_len; int gtk_id, gtk_tx;
    int have_igtk; uint8_t igtk[16]; int igtk_id; uint8_t igtk_ipn[6];
    int have_rsn; uint8_t rsn[128]; size_t rsn_len;
} wpa3_kdes_t;
int wpa3_parse_kdes(const uint8_t *kd, size_t len, wpa3_kdes_t *o); /* 0 or -1 malformed */

/* ---- supplicant (4-way + group key) for AKM 8 ---- */
#define WPA3_EV_PTK  WPA_EV_PTK
#define WPA3_EV_GTK  WPA_EV_GTK
#define WPA3_EV_IGTK 4
typedef struct {
    uint8_t pmk[32], ptk[48];
    uint8_t aa[6], spa[6], anonce[32], snonce[32];
    uint8_t rsn_ie[96]; size_t rsn_len;      /* our RSN IE (sent in M2); must equal the one in the association request */
    uint8_t ap_rsn[128]; size_t ap_rsn_len;  /* AP's RSN IE from M3 (caller compares with the beacon) */
    uint8_t gtk[32]; size_t gtk_len; int gtk_id, gtk_tx; int have_gtk;
    uint8_t igtk[16]; int igtk_id; uint8_t igtk_ipn[6]; int have_igtk;
    uint64_t replay; int have_replay;
    int state;                               /* 0 idle, 1 M2 sent, 2 installed */
    int akm;                                 /* 8 SAE (key descriptor version 0), 5 802.1X-SHA256 (3), 1 802.1X (2, SHA-1 PTK + HMAC-SHA1 MIC) */
} wpa3_t;
int wpa3_init(wpa3_t *w, const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
              const uint8_t *rsn_ie, size_t rsn_len);
/* Same, for the WPA2-Enterprise AKMs: akm 1 (802.1X, SHA-1 KDF, HMAC-SHA1-128 MIC), 5 (802.1X-SHA256), or 8. The PMK is
 * MSK[0..32) from eap_get_pmk(). Returns -1 for another akm. */
int wpa3_init_akm(wpa3_t *w, const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
                  const uint8_t *rsn_ie, size_t rsn_len, int akm);
/* Same contract as wpa_rx_eapol (WPA_ERR_* on rejection, *event = WPA3_EV_* mask). out >= 256 + rsn_len bytes. */
int wpa3_rx_eapol(wpa3_t *w, const uint8_t *eapol, size_t len, uint8_t *out, size_t *out_len, int *event);
const uint8_t *wpa3_get_tk(const wpa3_t *w);   /* 16 bytes or NULL */
const uint8_t *wpa3_get_ptk(const wpa3_t *w);

/* ---- protected management frames ---- */
/* Unicast robust management frame protection with the pairwise TK (CCMP, mgmt nonce flag set).
 * hdr: 24-byte management header (FC type must be 0); body: frame body in clear (e.g. reason code for Deauth).
 * out: header (Protected bit set) + 8 CCMP header + encrypted body + 8 MIC. cap >= 24 + body_len + 16.
 * Returns frame length or <0. */
int wpa3_mgmt_protect(const uint8_t tk[16], const uint8_t *hdr, const uint8_t *body, size_t body_len,
                      uint64_t pn, int key_id, uint8_t *out, size_t cap);
/* frame: a received protected management frame (header + CCMP + data + MIC). body_out >= len - 40.
 * Returns clear body length, <0 on MIC/format failure; *pn gets the packet number for the caller's replay check
 * (it must be strictly greater than the last accepted one). */
int wpa3_mgmt_unprotect(const uint8_t tk[16], const uint8_t *frame, size_t len, uint8_t *body_out, uint64_t *pn);
/* True for management frames that PMF protects when keys are installed: Disassoc(10), Deauth(12), and Action
 * frames (13) whose category is robust (not Public(4), HT(7), Unprotected WNM(11) etc.; here: SA Query 8,
 * spectrum mgmt 0, QoS 1, DLS 2, BlockAck 3, Radio meas 5, FT 6, WNM 10, Protected Dual 9, ...). */
int wpa3_is_robust(int subtype, int category);
/* SA Query Response body (category 8, action 1, same transaction id) from a request body; returns 4 or <0. */
int wpa3_sa_query_reply_body(const uint8_t *req_body, size_t len, uint8_t out[4]);
/* BIP-CMAC-128 (broadcast/multicast robust management frames): append MMIE (id 76, len 16: key id, IPN, MIC8) to
 * body and compute the MIC with the IGTK. hdr 24 bytes. out receives body + 18 bytes. Returns length or <0. */
int wpa3_bip_protect(const uint8_t igtk[16], int key_id, const uint8_t ipn[6], const uint8_t *hdr,
                     const uint8_t *body, size_t body_len, uint8_t *out, size_t cap);
/* body = frame body including the trailing MMIE. 0 ok (ipn_out gets the 6-byte IPN, little endian as in the
 * element; caller compares for replay), <0 bad. */
int wpa3_bip_verify(const uint8_t igtk[16], const uint8_t *hdr, const uint8_t *body, size_t body_len, uint8_t ipn_out[6]);

#endif
