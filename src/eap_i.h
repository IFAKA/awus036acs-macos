// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_i.h - internal types shared by eap.c and the eap_*.c method files. Not part of the public API. */
#ifndef EAP_I_H
#define EAP_I_H
#include <stdlib.h>
#include "eap.h"
#include "eap_mschap.h"
#include "eap_tlsp.h"

#define EAP_MAX_TLS_MSG (96 * 1024)

typedef struct eap_tlsm eap_tlsm_t;

struct eap {
    eap_cfg_t cfg;                                  /* deep copy */
    char *s_identity, *s_inner, *s_password, *s_key_pass, *s_server_name;
    uint8_t *b_ca, *b_cert, *b_key, *b_p12; int methods[4]; int n_methods;
    int started;                                    /* got the first request */
    int state;                                      /* 0 running, 1 success, 2 failure */
    int method;                                     /* outer EAP type in use */
    int expanded;                                   /* current request used expanded framing */
    int have_last; uint8_t last_id; uint8_t last_resp[EAP_OUT_MIN + 64]; size_t last_resp_len;
    char err[160];
    /* keys */
    uint8_t msk[64]; size_t msk_len; int key_ok;
    int phase2_ok;                                  /* tunnelled method proved itself / nothing more to prove */
    /* TLS engine shared by TLS, PEAP, TTLS */
    const eap_tlsm_t *tm;
    tlsp_t *tls; int est_done;
    uint8_t flags_ver;                              /* version bits put into every TLS flags byte (PEAP) */
    uint8_t *rx; size_t rx_len, rx_cap, rx_expect;
    uint8_t *tx; size_t tx_len, tx_cap, tx_off; int tx_first;
    /* PEAP / MS-CHAPv2 / TTLS */
    int peap_ver;
    uint8_t cur_id;                                 /* id of the request being answered (inner v0 packets reuse it) */
    int ms_state;                                   /* 0 none, 1 response sent, 2 success verified, 3 failed */
    uint8_t ms_auth_ch[16], ms_peer_ch[16], ms_nt[24], ms_pwhash[16]; uint8_t ms_ident;
    int ttls_sent;
    /* LEAP */
    int leap_state; uint8_t leap_ap_ch[8], leap_ap_resp[24], leap_peer_ch[8], leap_peer_resp[24];
};

struct eap_tlsm {
    int type; const char *key_label;
    int (*start)(eap_t *e, uint8_t srv_flags);       /* before the TLS session is created (reads version bits) */
    int (*established)(eap_t *e);                    /* handshake finished: derive keys, maybe send phase 2 */
    int (*app_data)(eap_t *e, const uint8_t *d, size_t n);   /* one decrypted record */
};

extern const eap_tlsm_t eap_tls_m, eap_peap_m, eap_ttls_m;

void eap_set_err(eap_t *e, const char *fmt, ...);
/* queue application data into the tunnel (encrypts and appends the records to the TX buffer) */
int eap_tun_send(eap_t *e, const uint8_t *d, size_t n);
int eap_derive_msk(eap_t *e, const char *label);
tlsp_t *eap_tls_session(eap_t *e);                  /* builds the client TLS context from cfg */

/* LEAP (eap_leap.c): handles the whole EAP packet (Request, Success, Response). Returns EAP_ST_*. */
int eap_leap_rx(eap_t *e, const uint8_t *pkt, size_t len, uint8_t *out, size_t cap, size_t *out_len);

#endif
