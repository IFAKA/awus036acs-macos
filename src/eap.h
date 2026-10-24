// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap.h - 802.1X / EAP supplicant (peer) engine for WPA2-Enterprise. Pure functions on byte buffers: no sockets, no
 * USB, no threads, no timers. The link layer feeds it EAP packets and sends back what it returns.
 *
 * Methods: EAP-TLS (client certificate from PKCS#12 or PEM), PEAP v0/v1 with MS-CHAPv2, EAP-TTLS with MS-CHAPv2 or PAP,
 * and LEAP (INSECURE: broken by ASLEAP; off unless cfg.allow_leap). Identity, Notification, Nak and expanded-type
 * framing, TLS fragmentation (L/M/S flags) and retransmitted requests are handled here.
 * Server certificates are validated against cfg.ca_pem by default; insecure_skip_verify turns that off (INSECURE).
 * TLS comes from eap_tlsp.h (OpenSSL, see the licence note there). PEAP crypto-binding TLVs are not verified.
 *
 * Call sequence (what link.c must do):
 *   eap_cfg_t c = {0}; c.identity = "user@example.org"; c.password = "..."; c.ca_pem = ...; (zero it, set what you need)
 *   eap_t *e = eap_new(&c);                          copies every string/buffer; c may be freed afterwards
 *   send eap_eapol_start() (optional; most APs start with an Identity request anyway)
 *   for every EAPOL frame of type EAP-Packet (0) received from the AP:
 *        eap_eapol_unwrap(frame, len, &pkt, &plen);
 *        st = eap_rx(e, pkt, plen, out, sizeof out, &olen);
 *        if (olen) send eap_eapol_wrap(frame_out, out, olen);
 *        st == EAP_ST_SUCCESS -> eap_get_pmk(e, pmk): hand the PMK to wpa_init-style 4-way (wpa.c, AKM 1 = 802.1X)
 *        st == EAP_ST_FAILURE -> give up (eap_error(e) says why)
 *   eap_free(e). */
#ifndef EAP_H
#define EAP_H
#include <stddef.h>
#include <stdint.h>

#define EAP_CODE_REQUEST  1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS  3
#define EAP_CODE_FAILURE  4

#define EAP_TYPE_IDENTITY     1
#define EAP_TYPE_NOTIFICATION 2
#define EAP_TYPE_NAK          3
#define EAP_TYPE_TLS          13
#define EAP_TYPE_LEAP         17
#define EAP_TYPE_TTLS         21
#define EAP_TYPE_PEAP         25
#define EAP_TYPE_MSCHAPV2     26
#define EAP_TYPE_TLV          33
#define EAP_TYPE_EXPANDED     254

#define EAP_INNER_MSCHAPV2 0     /* TTLS phase-2 method (default). PEAP always uses MS-CHAPv2. */
#define EAP_INNER_PAP      1

#define EAP_ST_CONTINUE 0        /* keep going; send out[0..olen) if olen > 0 */
#define EAP_ST_SUCCESS  1        /* EAP-Success accepted; the MSK is available */
#define EAP_ST_FAILURE  2        /* authentication failed (EAP-Failure, bad server proof, certificate rejected, ...) */
#define EAP_ST_IGNORED  3        /* dropped (malformed, wrong state, not a request we answer); olen == 0 */

#define EAP_OUT_MIN 1600         /* minimum `cap` for eap_rx() output with the default fragment size */

typedef struct {
    const int *methods; int n_methods;     /* acceptable outer methods (EAP_TYPE_*) in order of preference;
                                              NULL = PEAP, TTLS, and TLS if a client cert is set */
    const char *identity;                  /* identity in the EAP-Response/Identity (outer / anonymous identity) */
    const char *inner_identity;            /* user name for MS-CHAPv2 / PAP; NULL = identity */
    const char *password;                  /* UTF-8 */
    int inner;                             /* EAP_INNER_* for TTLS */
    const uint8_t *ca_pem; size_t ca_pem_len;          /* trust anchors for the server certificate (PEM) */
    const uint8_t *cert_pem; size_t cert_pem_len;      /* EAP-TLS client certificate chain (PEM) ... */
    const uint8_t *key_pem; size_t key_pem_len;        /* ... and private key (PEM; defaults to cert_pem when NULL) */
    const uint8_t *p12; size_t p12_len;                /* ... or a PKCS#12 bundle (DER) */
    const char *key_pass;                              /* passphrase of the key / PKCS#12 */
    const char *server_name;                           /* optional: name the server certificate must match */
    int insecure_skip_verify;                          /* INSECURE: do not validate the server certificate */
    int allow_leap;                                    /* INSECURE: permit LEAP */
    int peap_v0_only;                                  /* 1 = never speak PEAPv1 (default: follow the server's version) */
    size_t frag_size;                                  /* TLS bytes per EAP packet (default 1000, max 1400) */
} eap_cfg_t;

typedef struct eap eap_t;

eap_t *eap_new(const eap_cfg_t *cfg);                  /* NULL on bad configuration (eap_new_error()) */
const char *eap_new_error(void);
void eap_free(eap_t *e);
void eap_reset(eap_t *e);                              /* new authentication (e.g. after EAPOL-Start / reconnect) */

/* Process one EAP packet (code, id, length, ...; no EAPOL header). out receives the EAP packet to send, if any. */
int eap_rx(eap_t *e, const uint8_t *pkt, size_t len, uint8_t *out, size_t cap, size_t *out_len);

/* After EAP_ST_SUCCESS: the Master Session Key. LEAP has a 16-byte key, the others 64 bytes. */
const uint8_t *eap_get_msk(const eap_t *e, size_t *len);
/* PMK = MSK[0..32) (RFC 5247 / 802.11-2020 12.7.1.3); LEAP: the 16-byte key zero padded. Returns 0, or -1 before success. */
int eap_get_pmk(const eap_t *e, uint8_t pmk[32]);
const char *eap_error(const eap_t *e);                 /* last failure / diagnostic text, never NULL */
int eap_method(const eap_t *e);                        /* EAP_TYPE_* in use, 0 before one was selected */

/* ---- 802.1X (EAPOL) framing ---- */
size_t eap_eapol_wrap(uint8_t *out, const uint8_t *eap, size_t len);   /* version 1, type 0 (EAP-Packet); returns len+4 */
size_t eap_eapol_start(uint8_t out[4]);                                /* EAPOL-Start; returns 4 */
/* 0: EAP packet found (*eap,*eap_len); 1: another EAPOL type (3 = Key: hand to wpa_rx_eapol); <0: malformed */
int eap_eapol_unwrap(const uint8_t *eapol, size_t len, const uint8_t **eap, size_t *eap_len);

#endif
