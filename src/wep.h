// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* wep.h - RC4, CRC-32 and WEP (IEEE 802.11-2016 12.3.2, the legacy WEP-40 / WEP-104 cipher). Pure functions, no I/O.
 * WEP is broken (FMS/KoreK/PTW key recovery); it is implemented only so the adapter can join legacy networks. */
#ifndef WEP_H
#define WEP_H
#include <stddef.h>
#include <stdint.h>

/* RC4 in place. The first `skip` keystream bytes are discarded (0 for WEP, 256 for the WPA1/TKIP key-data unwrap). */
void rc4_crypt(const uint8_t *key, size_t klen, size_t skip, uint8_t *data, size_t len);
/* CRC-32 (IEEE 802.3, reflected, init/xorout 0xFFFFFFFF): the WEP/TKIP ICV. crc32("123456789") == 0xCBF43926. */
uint32_t wep_crc32(const uint8_t *p, size_t n);

/* Key text: 5 or 13 ASCII characters, or 10 or 26 hex digits (optionally prefixed "0x"). Returns 0 and fills key / *len
 * (5 or 13), or -1 for any other shape. */
int wep_parse_key(const char *text, uint8_t key[13], int *len);

#define WEP_OVERHEAD 8     /* IV(3) + key id byte(1) + ICV(4) */
/* Encrypt one MPDU body. out = IV(3) | keyid<<6 (1) | RC4(plain | ICV) ; returns len + 8. klen is 5 or 13. */
int wep_encrypt(const uint8_t *key, int klen, int keyid, const uint8_t iv[3], const uint8_t *plain, size_t len, uint8_t *out);
/* in = IV | keyid byte | ciphertext | ICV. Returns plaintext length, -1 malformed, -2 ICV mismatch. *keyid (may be NULL) = key id in the frame. */
int wep_decrypt(const uint8_t *key, int klen, const uint8_t *in, size_t in_len, uint8_t *plain, int *keyid);
/* Next IV from a 24-bit counter, skipping the FMS-weak ones (byte1 == 0xFF and byte0 in 3..15). */
void wep_next_iv(uint32_t *ctr, uint8_t iv[3]);

#endif
