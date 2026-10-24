// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_tls.c - EAP-TLS (RFC 5216): mutual TLS 1.0-1.2 with a client certificate. The MSK is
 * TLS-PRF(master_secret, "client EAP encryption", client_random | server_random)[0..64). */
#include "eap_i.h"

static int tls_established(eap_t *e) {
    if (eap_derive_msk(e, "client EAP encryption")) return -1;
    e->phase2_ok = 1;                                  /* nothing is tunnelled */
    return 0;
}

const eap_tlsm_t eap_tls_m = { EAP_TYPE_TLS, "client EAP encryption", NULL, tls_established, NULL };
