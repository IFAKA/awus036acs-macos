// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* tkip.h - TKIP (IEEE 802.11-2016 12.5.2): Michael MIC and the two-phase per-packet key mixing, plus whole-MPDU
 * encrypt/decrypt. Pure functions, no I/O. TKIP is deprecated (Michael is weak); it exists for WPA1 / mixed-mode APs.
 *
 * Keys: tk = 16-byte temporal key; mic_key = 8-byte Michael key for the direction in use. In a PTK (64 bytes) the
 * TK is ptk[32..48], the Authenticator->Supplicant MIC key ptk[48..56], the Supplicant->Authenticator one ptk[56..64].
 * In a 32-byte GTK: TK = gtk[0..16]; the AP's (transmit) MIC key = gtk[16..24]. */
#ifndef TKIP_H
#define TKIP_H
#include <stddef.h>
#include <stdint.h>

/* Michael over an arbitrary message (padding 0x5a + zeros is applied). Published vectors: 802.11i-2004 Annex M / H. */
void michael_raw(const uint8_t key[8], const uint8_t *msg, size_t len, uint8_t mic[8]);
/* Michael over the MSDU: message = DA | SA | priority | 0 0 0 | data. */
void michael_mic(const uint8_t key[8], const uint8_t da[6], const uint8_t sa[6], int prio,
                 const uint8_t *data, size_t len, uint8_t mic[8]);

/* Phase 1: TTAK from TK, transmitter address, upper 32 bits of the TSC. Phase 2: 16-byte RC4 key (first 3 bytes are the
 * on-air IV bytes) from TTAK, TK, lower 16 bits of the TSC. */
void tkip_phase1(const uint8_t tk[16], const uint8_t ta[6], uint32_t iv32, uint16_t ttak[5]);
void tkip_phase2(const uint8_t tk[16], const uint16_t ttak[5], uint16_t iv16, uint8_t rc4key[16]);

#define TKIP_OVERHEAD 20   /* IV/ExtIV header 8 + MIC 8 + ICV 4 */
/* out = TKIP header (8) | RC4(plain | MIC | ICV). tsc is the 48-bit packet number. Returns len + 20, or -1. */
int tkip_encrypt(const uint8_t tk[16], const uint8_t mic_key[8], const uint8_t ta[6], const uint8_t da[6], const uint8_t sa[6],
                 int prio, uint64_t tsc, int keyid, const uint8_t *plain, size_t len, uint8_t *out);
/* in = TKIP header | ciphertext | MIC | ICV. Returns plaintext length; -1 malformed, -2 ICV mismatch, -3 Michael mismatch.
 * *tsc / *keyid (may be NULL) report the packet number and key id for replay checks (only trust them on success). */
int tkip_decrypt(const uint8_t tk[16], const uint8_t mic_key[8], const uint8_t ta[6], const uint8_t da[6], const uint8_t sa[6],
                 int prio, const uint8_t *in, size_t in_len, uint8_t *plain, uint64_t *tsc, int *keyid);
#endif
