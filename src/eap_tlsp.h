// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_tlsp.h - the TLS provider behind EAP-TLS / PEAP / TTLS: a TLS engine that works on byte buffers (no sockets).
 *
 * WHY OPENSSL AND NOT SECURETRANSPORT.  EAP needs the TLS master secret (PRF export, RFC 5705) to make the MSK:
 *   MSK = TLS-PRF(master_secret, "client EAP encryption" | "ttls keying material", client_random | server_random).
 * Apple's SecureTransport / Network.framework / SecItem APIs have no public master-secret or keying-material export,
 * and SecureTransport is deprecated. So the provider is OpenSSL 3 (SSL_export_keying_material) run on memory BIOs.
 * It is the ONLY file that includes OpenSSL; eap.c talks to it through this header, so mbedTLS (SSL export:
 * mbedtls_ssl_set_export_keys_cb, TLS 1.2 PRF) or BoringSSL can replace eap_tlsp.c without touching the rest.
 *
 * LINKING / LICENCE.  Homebrew openssl@3 is Apache-2.0. Apache-2.0 is compatible with GPLv3 but NOT with
 * GPL-2.0-only, which is this repository's licence. So: (1) do not ship a binary that links OpenSSL until that is
 * settled, either by relicensing the combined work to GPL-2.0-or-later/GPLv3 or by swapping this provider for mbedTLS
 * (Apache-2.0 OR GPL-2.0-or-later, compatible) or by using the "system library" route; (2) link it STATICALLY
 * (libssl.a/libcrypto.a, see Makefile test-eap) so the daemon has no runtime dependency on /opt/homebrew.
 * Only TLS 1.0..1.2 is offered: RFC 5705 keys of TLS 1.3 EAP use a different exporter and end-of-handshake rules that
 * are not implemented (hostap also defaults PEAP/TTLS to TLS 1.2 for compatibility). Session tickets are disabled. */
#ifndef EAP_TLSP_H
#define EAP_TLSP_H
#include <stddef.h>
#include <stdint.h>

typedef struct tlsp tlsp_t;

typedef struct {
    int server;                          /* 1 = authenticator side (used by the loopback tests only) */
    const uint8_t *ca_pem; size_t ca_pem_len;            /* trust anchors (PEM, may hold several certificates) */
    const uint8_t *cert_pem; size_t cert_pem_len;        /* own certificate (+ chain), PEM */
    const uint8_t *key_pem; size_t key_pem_len;          /* private key, PEM */
    const char *key_pass;                                /* passphrase for key_pem or the PKCS#12 file */
    const uint8_t *p12; size_t p12_len;                  /* alternative to cert_pem/key_pem: a PKCS#12 bundle (DER) */
    int insecure_skip_verify;                            /* client: accept any server certificate (INSECURE) */
    const char *server_name;                             /* client: required name in the server certificate, or NULL */
    int require_client_cert;                             /* server: demand and verify a client certificate */
} tlsp_cfg_t;

/* NULL on error (message in tlsp_error(NULL)). */
tlsp_t *tlsp_new(const tlsp_cfg_t *cfg);
void tlsp_free(tlsp_t *t);
const char *tlsp_error(const tlsp_t *t);        /* last error text, never NULL */
/* Feed TLS records received from the peer. */
int tlsp_in(tlsp_t *t, const uint8_t *data, size_t len);
/* Advance the handshake. Returns 1 when complete, 0 when more peer data is needed, -1 on failure (certificate
 * rejected, alert, ...). Safe to call after completion (returns 1). */
int tlsp_handshake(tlsp_t *t);
/* Bytes the engine wants to send. Returns the number written (0 = nothing pending). Call until it returns 0. */
size_t tlsp_out(tlsp_t *t, uint8_t *buf, size_t cap);
size_t tlsp_out_pending(const tlsp_t *t);
/* Application data through the established tunnel. Write returns len or -1; read returns bytes (0 = none yet, -1 error). */
int tlsp_write(tlsp_t *t, const uint8_t *data, size_t len);
int tlsp_read(tlsp_t *t, uint8_t *buf, size_t cap);
/* RFC 5705 exporter (TLS PRF) with no context. Returns 0 or -1. */
int tlsp_export(tlsp_t *t, const char *label, uint8_t *out, size_t out_len);
int tlsp_is_established(const tlsp_t *t);

#endif
