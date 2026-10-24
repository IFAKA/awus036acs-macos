// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap.c - EAP peer core: packet framing, Identity / Notification / Nak, expanded types, retransmission, EAP-TLS style
 * fragmentation (RFC 5216 section 3.1: L = length included, M = more fragments, S = start) and the shared TLS engine
 * used by EAP-TLS, PEAP and EAP-TTLS. The methods themselves are in eap_tls.c, eap_peap.c, eap_ttls.c and eap_leap.c. */
#include "eap_i.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_new_err[160];
const char *eap_new_error(void) { return g_new_err; }
const char *eap_error(const eap_t *e) { return e ? e->err : g_new_err; }
int eap_method(const eap_t *e) { return e->method; }

void eap_set_err(eap_t *e, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->err, sizeof e->err, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------ config copy */
static char *dups(const char *s) { return s ? strdup(s) : NULL; }
static uint8_t *dupb(const uint8_t *b, size_t n) {
    if (!b || !n) return NULL;
    uint8_t *p = malloc(n);
    if (p) memcpy(p, b, n);
    return p;
}
static void wipe_free(void *p, size_t n) { if (p) { volatile uint8_t *v = p; while (n--) *v++ = 0; } free(p); }

eap_t *eap_new(const eap_cfg_t *c) {
    g_new_err[0] = 0;
    if (!c || !c->identity) { snprintf(g_new_err, sizeof g_new_err, "identity required"); return NULL; }
    int def[3] = {EAP_TYPE_PEAP, EAP_TYPE_TTLS, EAP_TYPE_TLS};
    int m[4], nm = 0;
    const int *src = c->methods ? c->methods : def;
    int ns = c->methods ? c->n_methods : ((c->p12 || c->cert_pem) ? 3 : 2);   /* default: TLS only with a client cert */
    for (int i = 0; i < ns && nm < 4; i++) {
        int t = src[i];
        if (t == EAP_TYPE_LEAP && !c->allow_leap) { snprintf(g_new_err, sizeof g_new_err, "LEAP is insecure: set allow_leap"); return NULL; }
        if (t != EAP_TYPE_TLS && t != EAP_TYPE_PEAP && t != EAP_TYPE_TTLS && t != EAP_TYPE_LEAP) {
            snprintf(g_new_err, sizeof g_new_err, "unsupported method %d", t); return NULL;
        }
        m[nm++] = t;
    }
    if (!nm) { snprintf(g_new_err, sizeof g_new_err, "no methods"); return NULL; }
    for (int i = 0; i < nm; i++) {
        int t = m[i];
        if (t != EAP_TYPE_TLS && !c->password) { snprintf(g_new_err, sizeof g_new_err, "password required for method %d", t); return NULL; }
        if (t == EAP_TYPE_TLS && !c->p12 && !c->cert_pem) { snprintf(g_new_err, sizeof g_new_err, "EAP-TLS needs a client certificate"); return NULL; }
        if (t != EAP_TYPE_LEAP && !c->ca_pem && !c->insecure_skip_verify) {
            snprintf(g_new_err, sizeof g_new_err, "a CA certificate is required (or set insecure_skip_verify)"); return NULL;
        }
    }
    eap_t *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    e->cfg = *c;
    e->s_identity = dups(c->identity); e->s_inner = dups(c->inner_identity ? c->inner_identity : c->identity);
    e->s_password = dups(c->password); e->s_key_pass = dups(c->key_pass); e->s_server_name = dups(c->server_name);
    e->b_ca = dupb(c->ca_pem, c->ca_pem_len); e->b_cert = dupb(c->cert_pem, c->cert_pem_len);
    e->b_key = dupb(c->key_pem, c->key_pem_len); e->b_p12 = dupb(c->p12, c->p12_len);
    e->cfg.identity = e->s_identity; e->cfg.inner_identity = e->s_inner; e->cfg.password = e->s_password;
    e->cfg.key_pass = e->s_key_pass; e->cfg.server_name = e->s_server_name;
    e->cfg.ca_pem = e->b_ca; e->cfg.cert_pem = e->b_cert; e->cfg.key_pem = e->b_key; e->cfg.p12 = e->b_p12;
    memcpy(e->methods, m, sizeof m); e->n_methods = nm;
    e->cfg.methods = e->methods; e->cfg.n_methods = nm;
    if (!e->cfg.frag_size) e->cfg.frag_size = 1000;
    if (e->cfg.frag_size > 1400) e->cfg.frag_size = 1400;
    if (e->cfg.frag_size < 64) e->cfg.frag_size = 64;
    if ((!e->s_identity) || (c->ca_pem && !e->b_ca)) { eap_free(e); return NULL; }
    return e;
}

static void tls_reset(eap_t *e) {
    tlsp_free(e->tls); e->tls = NULL;
    free(e->rx); free(e->tx);
    e->rx = e->tx = NULL; e->rx_len = e->rx_cap = e->rx_expect = e->tx_len = e->tx_cap = e->tx_off = 0;
    e->est_done = 0; e->flags_ver = 0; e->ttls_sent = 0; e->ms_state = 0; e->peap_ver = 0;
}

void eap_reset(eap_t *e) {
    tls_reset(e);
    e->tm = NULL; e->method = 0; e->started = 0; e->state = 0; e->have_last = 0; e->key_ok = 0; e->phase2_ok = 0;
    e->msk_len = 0; memset(e->msk, 0, sizeof e->msk); e->leap_state = 0; e->err[0] = 0;
}

void eap_free(eap_t *e) {
    if (!e) return;
    tls_reset(e);
    wipe_free(e->s_password, e->s_password ? strlen(e->s_password) : 0);
    wipe_free(e->s_key_pass, e->s_key_pass ? strlen(e->s_key_pass) : 0);
    free(e->s_identity); free(e->s_inner); free(e->s_server_name);
    free(e->b_ca); free(e->b_cert); wipe_free(e->b_key, e->cfg.key_pem_len); free(e->b_p12);
    memset(e, 0, sizeof *e);
    free(e);
}

const uint8_t *eap_get_msk(const eap_t *e, size_t *len) {
    if (e->state != 1 || !e->msk_len) return NULL;
    if (len) *len = e->msk_len;
    return e->msk;
}
int eap_get_pmk(const eap_t *e, uint8_t pmk[32]) {
    if (e->state != 1 || !e->msk_len) return -1;
    memset(pmk, 0, 32);
    memcpy(pmk, e->msk, e->msk_len < 32 ? e->msk_len : 32);
    return 0;
}

/* ------------------------------------------------------------ EAPOL framing */
size_t eap_eapol_wrap(uint8_t *out, const uint8_t *eap, size_t len) {
    out[0] = 1; out[1] = 0; out[2] = (uint8_t)(len >> 8); out[3] = (uint8_t)len;
    memmove(out + 4, eap, len);
    return len + 4;
}
size_t eap_eapol_start(uint8_t out[4]) { out[0] = 1; out[1] = 1; out[2] = 0; out[3] = 0; return 4; }
int eap_eapol_unwrap(const uint8_t *f, size_t len, const uint8_t **eap, size_t *eap_len) {
    if (len < 4) return -1;
    size_t bl = (size_t)f[2] << 8 | f[3];
    if (4 + bl > len) return -1;
    if (f[1] != 0) return 1;
    if (bl < 4) return -1;
    *eap = f + 4; *eap_len = bl;
    return 0;
}

/* ------------------------------------------------------------ TLS engine */
tlsp_t *eap_tls_session(eap_t *e) {
    tlsp_cfg_t t;
    memset(&t, 0, sizeof t);
    t.ca_pem = e->cfg.ca_pem; t.ca_pem_len = e->cfg.ca_pem_len;
    t.cert_pem = e->cfg.cert_pem; t.cert_pem_len = e->cfg.cert_pem_len;
    t.key_pem = e->cfg.key_pem; t.key_pem_len = e->cfg.key_pem_len;
    t.p12 = e->cfg.p12; t.p12_len = e->cfg.p12_len; t.key_pass = e->cfg.key_pass;
    t.insecure_skip_verify = e->cfg.insecure_skip_verify; t.server_name = e->cfg.server_name;
    tlsp_t *s = tlsp_new(&t);
    if (!s) eap_set_err(e, "TLS setup failed: %s", tlsp_error(NULL));
    return s;
}

int eap_derive_msk(eap_t *e, const char *label) {
    uint8_t km[128];
    if (tlsp_export(e->tls, label, km, sizeof km)) { eap_set_err(e, "TLS key export failed: %s", tlsp_error(e->tls)); return -1; }
    memcpy(e->msk, km, 64); e->msk_len = 64; e->key_ok = 1;
    memset(km, 0, sizeof km);
    return 0;
}

static int buf_add(uint8_t **b, size_t *len, size_t *cap, const uint8_t *d, size_t n) {
    if (*len + n > EAP_MAX_TLS_MSG) return -1;
    if (*len + n > *cap) {
        size_t nc = (*len + n) * 2 + 256;
        uint8_t *nb = realloc(*b, nc);
        if (!nb) return -1;
        *b = nb; *cap = nc;
    }
    memcpy(*b + *len, d, n);
    *len += n;
    return 0;
}

static int drain(eap_t *e) {
    uint8_t buf[2048];
    size_t n;
    if (!e->tls) return 0;
    while ((n = tlsp_out(e->tls, buf, sizeof buf)) > 0)
        if (buf_add(&e->tx, &e->tx_len, &e->tx_cap, buf, n)) return -1;
    return 0;
}

int eap_tun_send(eap_t *e, const uint8_t *d, size_t n) {
    if (tlsp_write(e->tls, d, n) < 0) { eap_set_err(e, "tunnel write failed: %s", tlsp_error(e->tls)); return -1; }
    return 0;
}

/* Next fragment (or an empty acknowledgement) into pl. */
static int emit(eap_t *e, uint8_t *pl, size_t cap, size_t *pl_len) {
    size_t frag = e->cfg.frag_size, n = 1;
    uint8_t fl = e->flags_ver & 7;
    if (cap < frag + 8) return -1;
    if (e->tx_off < e->tx_len) {
        size_t chunk = e->tx_len - e->tx_off;
        if (chunk > frag) chunk = frag;
        if (e->tx_off == 0 && e->tx_len > frag) {
            fl |= 0x80;
            pl[1] = (uint8_t)(e->tx_len >> 24); pl[2] = (uint8_t)(e->tx_len >> 16);
            pl[3] = (uint8_t)(e->tx_len >> 8); pl[4] = (uint8_t)e->tx_len;
            n = 5;
        }
        if (e->tx_off + chunk < e->tx_len) fl |= 0x40;
        memcpy(pl + n, e->tx + e->tx_off, chunk);
        n += chunk; e->tx_off += chunk;
        if (e->tx_off == e->tx_len) e->tx_len = e->tx_off = 0;
    }
    pl[0] = fl;
    *pl_len = n;
    return 0;
}

/* Returns 0 (payload built), -1 (authentication failed; payload may hold a TLS alert), -2 (ignore). */
static int tls_engine(eap_t *e, const eap_tlsm_t *m, const uint8_t *d, size_t n, uint8_t *pl, size_t cap, size_t *pl_len) {
    if (e->tm != m) { tls_reset(e); e->tm = m; }
    *pl_len = 0;
    uint8_t fl = n ? d[0] : 0;
    const uint8_t *p = n ? d + 1 : d;
    size_t pn = n ? n - 1 : 0;

    if (fl & 0x20) {                                                /* Start */
        tls_reset(e); e->tm = m;
        if (m->start && m->start(e, fl)) return -1;
        e->tls = eap_tls_session(e);
        if (!e->tls) return -1;
        tlsp_handshake(e->tls);                                     /* produces the ClientHello */
        if (drain(e)) return -1;
        return emit(e, pl, cap, pl_len) ? -1 : 0;
    }
    if (!e->tls) return -2;
    uint32_t total = 0;
    if (fl & 0x80) {
        if (pn < 4) return -2;
        total = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
        p += 4; pn -= 4;
        if (total > EAP_MAX_TLS_MSG) { eap_set_err(e, "TLS message too large"); return -1; }
    }
    if (pn == 0 && !(fl & 0x40)) return emit(e, pl, cap, pl_len) ? -1 : 0;   /* fragment ack or empty ack */

    if (!e->rx_len) e->rx_expect = total;
    if (buf_add(&e->rx, &e->rx_len, &e->rx_cap, p, pn)) { eap_set_err(e, "TLS reassembly overflow"); return -1; }
    if (fl & 0x40) {                                                /* more fragments follow: acknowledge */
        e->tx_len = e->tx_off = 0;
        return emit(e, pl, cap, pl_len) ? -1 : 0;
    }
    if (e->rx_expect && e->rx_len != e->rx_expect) { eap_set_err(e, "TLS length mismatch"); e->rx_len = 0; return -2; }

    int fail = 0;
    e->tx_len = e->tx_off = 0;
    if (tlsp_in(e->tls, e->rx, e->rx_len)) fail = 1;
    e->rx_len = 0; e->rx_expect = 0;
    if (!fail) {
        int r = tlsp_handshake(e->tls);
        if (r < 0) { eap_set_err(e, "%s", tlsp_error(e->tls)); fail = 1; }
        else if (r == 1 && !e->est_done) {
            e->est_done = 1;
            if (m->established && m->established(e)) fail = 1;
        }
        if (!fail && e->est_done) {
            uint8_t buf[2048];
            int k;
            while (!fail && (k = tlsp_read(e->tls, buf, sizeof buf)) > 0)
                if (m->app_data && m->app_data(e, buf, (size_t)k)) fail = 1;
            if (k < 0 && !fail) { eap_set_err(e, "tunnel read failed: %s", tlsp_error(e->tls)); fail = 1; }
        }
    } else eap_set_err(e, "TLS input failed");
    if (drain(e)) fail = 1;
    if (emit(e, pl, cap, pl_len)) return -1;
    return fail ? -1 : 0;
}

/* ------------------------------------------------------------ packet level */
static const eap_tlsm_t *tlsm_for(int type) {
    switch (type) {
    case EAP_TYPE_TLS: return &eap_tls_m;
    case EAP_TYPE_PEAP: return &eap_peap_m;
    case EAP_TYPE_TTLS: return &eap_ttls_m;
    }
    return NULL;
}
static int allowed(const eap_t *e, int type) {
    for (int i = 0; i < e->n_methods; i++) if (e->methods[i] == type) return 1;
    return 0;
}

/* header of a response: returns its length; type may be written expanded */
static size_t put_hdr(uint8_t *o, uint8_t id, int type, int expanded) {
    o[0] = EAP_CODE_RESPONSE; o[1] = id;
    o[4] = expanded ? EAP_TYPE_EXPANDED : (uint8_t)type;
    if (!expanded) return 5;
    o[5] = o[6] = o[7] = 0; o[8] = 0; o[9] = 0; o[10] = 0; o[11] = (uint8_t)type;
    return 12;
}
static void put_len(uint8_t *o, size_t total) { o[2] = (uint8_t)(total >> 8); o[3] = (uint8_t)total; }

int eap_rx(eap_t *e, const uint8_t *pkt, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    *out_len = 0;
    if (!e || len < 4) return EAP_ST_IGNORED;
    size_t plen = (size_t)pkt[2] << 8 | pkt[3];
    if (plen < 4 || plen > len) return EAP_ST_IGNORED;
    len = plen;
    int code = pkt[0];
    uint8_t id = pkt[1];
    if (e->state) return EAP_ST_IGNORED;
    if (cap < e->cfg.frag_size + 64) { eap_set_err(e, "output buffer too small"); return EAP_ST_IGNORED; }

    if (code == EAP_CODE_FAILURE) {
        if (!e->started) return EAP_ST_IGNORED;
        e->state = 2; if (!e->err[0]) eap_set_err(e, "EAP-Failure received");
        return EAP_ST_FAILURE;
    }
    if (code == EAP_CODE_SUCCESS) {
        if (e->method == EAP_TYPE_LEAP) return eap_leap_rx(e, pkt, len, out, cap, out_len);
        if (!e->started || !e->key_ok || !e->phase2_ok || e->ms_state == 3) {
            eap_set_err(e, "EAP-Success before the method completed: ignored");   /* it is unauthenticated: never trust it */
            return EAP_ST_IGNORED;
        }
        e->state = 1;
        tlsp_free(e->tls); e->tls = NULL;
        return EAP_ST_SUCCESS;
    }
    if (code == EAP_CODE_RESPONSE) {
        if (e->method == EAP_TYPE_LEAP) return eap_leap_rx(e, pkt, len, out, cap, out_len);
        return EAP_ST_IGNORED;
    }
    if (code != EAP_CODE_REQUEST || len < 5) return EAP_ST_IGNORED;

    if (e->have_last && id == e->last_id && e->started) {           /* retransmitted request: repeat the answer */
        memcpy(out, e->last_resp, e->last_resp_len); *out_len = e->last_resp_len;
        return EAP_ST_CONTINUE;
    }
    int type = pkt[4], expanded = 0;
    const uint8_t *d = pkt + 5;
    size_t dn = len - 5;
    if (type == EAP_TYPE_EXPANDED) {
        if (dn >= 7 && d[0] == 0 && d[1] == 0 && d[2] == 0 && d[3] == 0 && d[4] == 0 && d[5] == 0) {
            type = d[6]; d += 7; dn -= 7; expanded = 1;
        } else type = -1;                                           /* vendor specific: we know none */
    }
    e->cur_id = id;
    e->expanded = expanded;
    uint8_t *pl = out + 12;
    size_t pn = 0, hl;
    int rc = 0, st = EAP_ST_CONTINUE;
    int rtype = type;

    if (type == EAP_TYPE_IDENTITY) {
        if (e->started) eap_reset(e);
        e->started = 1;
        size_t il = strlen(e->cfg.identity);
        if (il > cap - 16) il = cap - 16;
        memcpy(pl, e->cfg.identity, il); pn = il;
    } else if (type == EAP_TYPE_NOTIFICATION) {
        pn = 0;
    } else if (type > 0 && allowed(e, type) && (tlsm_for(type) || type == EAP_TYPE_LEAP)) {
        e->started = 1;
        if (e->method != type) { tls_reset(e); e->tm = NULL; e->key_ok = e->phase2_ok = 0; e->leap_state = 0; }
        e->method = type;
        if (type == EAP_TYPE_LEAP) {
            int r = eap_leap_rx(e, pkt, len, out, cap, out_len);
            if (*out_len) { memcpy(e->last_resp, out, *out_len < sizeof e->last_resp ? *out_len : sizeof e->last_resp); e->last_resp_len = *out_len; e->last_id = id; e->have_last = 1; }
            return r;
        }
        rc = tls_engine(e, tlsm_for(type), d, dn, pl, cap - 12, &pn);
        if (rc == -2) return EAP_ST_IGNORED;
        if (rc == -1) { st = EAP_ST_FAILURE; e->state = 2; if (!e->err[0]) eap_set_err(e, "authentication failed"); }
    } else {                                                        /* Nak with our list */
        rtype = EAP_TYPE_NAK; expanded = 0;
        for (int i = 0; i < e->n_methods; i++) pl[pn++] = (uint8_t)e->methods[i];
        if (!pn) pl[pn++] = 0;
    }
    if (e->state == 2 && !pn && st == EAP_ST_FAILURE) return st;
    hl = put_hdr(out, id, rtype, expanded);
    if (hl == 12 && pn) memmove(out + 12, pl, pn);
    else if (hl == 5) memmove(out + 5, pl, pn);
    put_len(out, hl + pn);
    *out_len = hl + pn;
    if (*out_len <= sizeof e->last_resp) { memcpy(e->last_resp, out, *out_len); e->last_resp_len = *out_len; e->last_id = id; e->have_last = 1; }
    return st;
}
