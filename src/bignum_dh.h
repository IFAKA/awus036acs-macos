// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* bignum_dh.h - small big-endian modular exponentiation and Diffie-Hellman group 5 (RFC 3526, 1536-bit MODP, g = 2) for
 * WPS. Pure functions, no I/O, no allocation. Montgomery multiplication on 32-bit limbs; NOT constant time (the exponent
 * is a fresh random per-session key used on a local link; see docs/WPS.md). */
#ifndef BIGNUM_DH_H
#define BIGNUM_DH_H
#include <stddef.h>
#include <stdint.h>

#define DH_LEN 192            /* bytes in a group-5 number */

/* out = base^exp mod mod. All big-endian. mod: odd, nbytes long (4..192, multiple of 4), top limb nonzero.
 * base is zero-padded/treated as nbytes long and must be < mod. exp is elen bytes (any length). out is nbytes.
 * Returns 0, or -1 for a bad modulus/size. */
int bn_modexp(const uint8_t *base, const uint8_t *exp, size_t elen, const uint8_t *mod, size_t nbytes, uint8_t *out);

/* pub = 2^priv mod p. priv is any 192 random bytes (not all zero). 0 ok, -1 bad priv. */
int dh_public(const uint8_t priv[DH_LEN], uint8_t pub[DH_LEN]);
/* out = peer^priv mod p. Rejects peer <= 1 or >= p-1 (small-subgroup/trivial values): returns -1. 0 ok. */
int dh_shared(const uint8_t priv[DH_LEN], const uint8_t peer[DH_LEN], uint8_t out[DH_LEN]);
/* the prime, big-endian */
extern const uint8_t DH_GROUP5_P[DH_LEN];
#endif
