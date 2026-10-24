// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_mschap.h - MS-CHAPv2 (RFC 2759), MPPE keys (RFC 3079), NT password hash, MD4 (RFC 1320) and the LEAP
 * challenge/response helpers. Pure functions. MD4 is written here because OpenSSL 3 moved it into its legacy
 * provider; DES/SHA-1/MD5 come from Apple CommonCrypto. MD4, DES and MS-CHAPv2 are broken/weak by today's standards:
 * they exist only because enterprise networks (PEAP-MSCHAPv2, TTLS-MSCHAPv2, LEAP) still use them. */
#ifndef EAP_MSCHAP_H
#define EAP_MSCHAP_H
#include <stddef.h>
#include <stdint.h>

void eap_md4(const uint8_t *in, size_t len, uint8_t out[16]);
/* NtPasswordHash: MD4 of the UTF-16LE form of the (UTF-8) password. */
void eap_nt_password_hash(const char *pw, size_t pw_len, uint8_t out[16]);
void eap_hash_nt_hash(const uint8_t pw_hash[16], uint8_t out[16]);           /* HashNtPasswordHash */
/* ChallengeResponse(): three DES encryptions of the 8-byte challenge with the 21-byte zero-padded hash */
void eap_challenge_response(const uint8_t challenge[8], const uint8_t pw_hash[16], uint8_t out[24]);
/* ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName); a "DOMAIN\" prefix of user is ignored (RFC 2759 says
 * the name must be given without the domain). */
void eap_mschapv2_challenge_hash(const uint8_t peer_ch[16], const uint8_t auth_ch[16], const char *user, size_t ulen,
                                 uint8_t out[8]);
void eap_mschapv2_nt_response(const uint8_t auth_ch[16], const uint8_t peer_ch[16], const char *user, size_t ulen,
                              const uint8_t pw_hash[16], uint8_t out[24]);
/* GenerateAuthenticatorResponse -> "S=" + 40 upper-case hex digits (42 chars, no NUL written beyond out[42]) */
void eap_mschapv2_auth_response(const uint8_t pw_hash[16], const uint8_t nt_resp[24], const uint8_t peer_ch[16],
                                const uint8_t auth_ch[16], const char *user, size_t ulen, char out[43]);
/* RFC 3079 3.4 / 3.5: master key and the two directional 16-byte keys. is_server selects the labelling. */
void eap_mppe_master_key(const uint8_t pw_hash_hash[16], const uint8_t nt_resp[24], uint8_t master[16]);
void eap_mppe_asym_key(const uint8_t master[16], int is_send, int is_server, uint8_t key[16]);

/* LEAP (Cisco, 8-byte challenges). key = MD5(hash(hash(pw)), ap_challenge, ap_response, peer_challenge, peer_response),
 * the naming being hostap's: the "ap_*" pair belongs to the challenge that WE sent (peer-issued challenge). */
void eap_leap_key(const uint8_t pw_hash_hash[16], const uint8_t ap_chal[8], const uint8_t ap_resp[24],
                  const uint8_t peer_chal[8], const uint8_t peer_resp[24], uint8_t key[16]);
void eap_md5(const uint8_t *in, size_t len, uint8_t out[16]);
void eap_sha1(const uint8_t *in, size_t len, uint8_t out[20]);

#endif
