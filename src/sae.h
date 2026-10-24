// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* sae.h - WPA3-Personal SAE (IEEE 802.11-2020 12.4), ECC group 19 (NIST P-256) only.
 * Both password-element derivations: hunting-and-pecking (HnP) and hash-to-element (H2E, SSWU).
 * Self-contained 256-bit arithmetic (no OpenSSL, no heap). NOT hardened against side channels (see sae.c).
 * No device or network needed; the frames are the bodies of Authentication frames.
 *
 * Typical STA use (all buffers are the Authentication frame body, starting at the "Authentication Algorithm" field):
 *   sae_init(&s, pw, pwlen, own_mac, bssid, ssid, ssidlen, NULL, h2e);   h2e = wpa3_ap_h2e(beacon_ies) != 0
 *   n = sae_build_commit(&s, buf, sizeof buf);          send as Auth seq 1 (status 0, or 126 for H2E, already in buf)
 *   rx Auth algo 3 seq 1:  r = sae_process_commit(&s, body, len);
 *        r == SAE_ERR_TOKEN : AP wants an anti-clogging token: n = sae_build_commit(...) again (it now carries the token)
 *        r == 0             : n = sae_build_confirm(&s, buf, sizeof buf); send as Auth seq 2
 *   rx Auth algo 3 seq 2:  r = sae_process_confirm(&s, body, len);  0 = AP proved the password
 *   sae_get_pmk() / sae_get_pmkid(): feed PMK to wpa3_init(), PMKID into the RSN IE of the (re)association request. */
#ifndef SAE_H
#define SAE_H
#include <stddef.h>
#include <stdint.h>

#define SAE_GROUP              19
#define SAE_STATUS_SUCCESS      0
#define SAE_STATUS_ANTI_CLOGGING 76
#define SAE_STATUS_UNSUPPORTED_GROUP 77
#define SAE_STATUS_H2E        126

#define SAE_OK            0
#define SAE_ERR_MALFORMED (-1)
#define SAE_ERR_TOKEN     (-2)   /* status 76: token stored, call sae_build_commit() again */
#define SAE_ERR_GROUP     (-3)   /* status 77, or the peer used a group other than 19 */
#define SAE_ERR_STATUS    (-4)   /* the AP answered with another status code (sae_last_status()) */
#define SAE_ERR_DROP      (-5)   /* reflection / replay: ignore the frame, do not abort */
#define SAE_ERR_CONFIRM   (-6)   /* confirm MIC mismatch: wrong password or attack */
#define SAE_ERR_STATE     (-7)
#define SAE_ERR_PWE       (-8)   /* could not derive the password element */
#define SAE_ERR_INVALID   (-9)   /* invalid scalar / element in the peer commit */

typedef struct { uint32_t w[8]; } sae_u256;   /* little-endian limbs */

typedef struct {
    uint8_t own[6], peer[6];
    uint8_t ssid[32]; size_t ssid_len;
    uint8_t pw[256]; size_t pw_len;
    uint8_t pwid[80]; size_t pwid_len; int have_pwid;
    int h2e;
    int state;                          /* 0 new, 1 committed (own commit built), 2 peer commit processed, 3 accepted */
    int have_commit;
    int status;                         /* last status code seen from the peer */
    sae_u256 pwe_x, pwe_y;              /* password element, plain (non-Montgomery) */
    sae_u256 rand_, scalar, peer_scalar;
    sae_u256 elem_x, elem_y, peer_x, peer_y;
    int fixed; uint8_t fixed_rand[32], fixed_mask[32];   /* test hook */
    uint8_t token[128]; size_t token_len;
    uint8_t peer_rejected[64]; size_t peer_rejected_len;
    uint8_t kck[32], pmk[32], pmkid[16];
    uint16_t send_confirm;
    int have_keys;
} sae_t;

/* pw: password bytes (1..255). own/peer: our and the AP's MAC (BSSID). ssid: needed for H2E (may be NULL for HnP).
 * pwid: SAE password identifier or NULL (H2E only). h2e: 1 = hash-to-element, 0 = hunting-and-pecking.
 * Returns 0, or -1 on bad arguments. The password element is derived lazily inside sae_build_commit(). */
int sae_init(sae_t *s, const uint8_t *pw, size_t pw_len, const uint8_t own[6], const uint8_t peer[6],
             const uint8_t *ssid, size_t ssid_len, const char *pwid, int h2e);
/* Build the SAE Commit Authentication body (algo 3, seq 1, status 0 or 126, group, [token], scalar, element, ...).
 * Returns length or <0 (SAE_ERR_PWE...). Safe to call again after SAE_ERR_TOKEN: same scalar/element, token added. */
int sae_build_commit(sae_t *s, uint8_t *out, size_t cap);
/* Process a received Authentication body with algo 3, seq 1. See the header comment for the return values. */
int sae_process_commit(sae_t *s, const uint8_t *body, size_t len);
/* Build the Confirm (algo 3, seq 2, status 0, send-confirm, confirm). Needs a processed peer commit. */
int sae_build_confirm(sae_t *s, uint8_t *out, size_t cap);
/* Process a received Authentication body with algo 3, seq 2. 0 = valid, state becomes accepted. */
int sae_process_confirm(sae_t *s, const uint8_t *body, size_t len);
/* A status-only SAE frame (e.g. SAE_STATUS_UNSUPPORTED_GROUP as reply); returns length. */
int sae_build_status(uint16_t seq, uint16_t status, uint8_t *out, size_t cap);
const uint8_t *sae_get_pmk(const sae_t *s);     /* 32 bytes after sae_process_confirm() succeeded, else NULL */
const uint8_t *sae_get_pmkid(const sae_t *s);   /* 16 bytes, available after sae_process_commit() succeeded */
int sae_last_status(const sae_t *s);

/* ---- test hooks and building blocks (used by test_sae.c) ---- */
void sae_set_test_rand(sae_t *s, const uint8_t rand_[32], const uint8_t mask[32]);
/* PWE by hunting-and-pecking: x/y big endian. */
int sae_pwe_hnp(const uint8_t *pw, size_t pw_len, const uint8_t mac1[6], const uint8_t mac2[6], uint8_t x[32], uint8_t y[32]);
/* PT then PWE by hash-to-element. pt_x/pt_y (may be NULL) receive PT. */
int sae_pwe_h2e(const uint8_t *ssid, size_t ssid_len, const uint8_t *pw, size_t pw_len, const uint8_t *pwid, size_t pwid_len,
                const uint8_t mac1[6], const uint8_t mac2[6], uint8_t x[32], uint8_t y[32], uint8_t pt_x[32], uint8_t pt_y[32]);
/* P-256 scalar multiplication: k*(px,py), or k*G when px == NULL. Returns -1 for the point at infinity. */
int sae_p256_mul(const uint8_t k[32], const uint8_t *px, const uint8_t *py, uint8_t ox[32], uint8_t oy[32]);
/* SSWU map of u (reduced mod p) to a curve point */
int sae_sswu(const uint8_t u[32], uint8_t x[32], uint8_t y[32]);

#endif
