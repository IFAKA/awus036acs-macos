// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_tlsp.c - Mbed TLS 4.x implementation of eap_tlsp.h (TLS 1.2 over in-memory buffers). Mbed TLS is used under its
 * GPL-2.0-or-later option (it is "Apache-2.0 OR GPL-2.0-or-later"). Not hardened beyond what Mbed TLS gives. */
#include "eap_tlsp.h"
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct tlsp {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca, own;
    mbedtls_pk_context key;
    uint8_t *in; size_t in_len, in_off, in_cap;      /* bytes from the peer, not yet consumed by Mbed TLS */
    uint8_t *out; size_t out_len, out_off, out_cap;  /* bytes for the peer */
    int done, server;
    char err[160];
};
static char g_err[160];

static void set_err(tlsp_t *t, const char *what, int rc) {
    char *dst = t ? t->err : g_err;
    char tmp[100] = "";
    if (rc) mbedtls_strerror(rc, tmp, sizeof tmp);
    snprintf(dst, 160, "%s%s%s", what, tmp[0] ? ": " : "", tmp);
}
const char *tlsp_error(const tlsp_t *t) { return t ? t->err : g_err; }

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    tlsp_t *t = ctx;
    if (t->out_len + len > t->out_cap) {
        size_t nc = (t->out_cap ? t->out_cap : 1024);
        while (nc < t->out_len + len) nc *= 2;
        uint8_t *p = realloc(t->out, nc);
        if (!p) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        t->out = p; t->out_cap = nc;
    }
    memcpy(t->out + t->out_len, buf, len);
    t->out_len += len;
    return (int)len;
}
static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    tlsp_t *t = ctx;
    size_t avail = t->in_len - t->in_off;
    if (!avail) return MBEDTLS_ERR_SSL_WANT_READ;
    if (len > avail) len = avail;
    memcpy(buf, t->in + t->in_off, len);
    t->in_off += len;
    if (t->in_off == t->in_len) t->in_off = t->in_len = 0;
    return (int)len;
}

/* PEM parsing in Mbed TLS needs the terminating NUL inside the length. */
static uint8_t *pem_dup(const uint8_t *p, size_t n) {
    uint8_t *d = malloc(n + 1);
    if (d) { memcpy(d, p, n); d[n] = 0; }
    return d;
}

/* 0 = identity loaded, 1 = none configured, -1 = error (message set). */
static int load_identity(tlsp_t *t, const tlsp_cfg_t *c) {
    if (c->p12) {
        snprintf(g_err, sizeof g_err, "PKCS#12 client identities are not supported; convert to PEM "
                 "(openssl pkcs12 -in x.p12 -nodes -out x.pem) and pass cert_pem/key_pem");
        return -1;
    }
    if (!c->cert_pem) return 1;
    uint8_t *cp = pem_dup(c->cert_pem, c->cert_pem_len);
    if (!cp) { snprintf(g_err, sizeof g_err, "out of memory"); return -1; }
    int rc = mbedtls_x509_crt_parse(&t->own, cp, c->cert_pem_len + 1);
    free(cp);
    if (rc != 0) { set_err(NULL, "loading client certificate", rc); return -1; }
    const uint8_t *kp = c->key_pem ? c->key_pem : c->cert_pem;
    size_t kl = c->key_pem ? c->key_pem_len : c->cert_pem_len;
    uint8_t *kd = pem_dup(kp, kl);
    if (!kd) { snprintf(g_err, sizeof g_err, "out of memory"); return -1; }
    size_t pl = c->key_pass ? strlen(c->key_pass) : 0;
    rc = mbedtls_pk_parse_key(&t->key, kd, kl + 1, (const unsigned char *)(c->key_pass ? c->key_pass : ""), pl);
    memset(kd, 0, kl + 1); free(kd);
    if (rc != 0) { set_err(NULL, "loading private key", rc); return -1; }
    return 0;
}

tlsp_t *tlsp_new(const tlsp_cfg_t *c) {
    static int psa_ok;
    if (!psa_ok) {
        psa_status_t s = psa_crypto_init();
        if (s != PSA_SUCCESS) { snprintf(g_err, sizeof g_err, "psa_crypto_init failed (%d)", (int)s); return NULL; }
        psa_ok = 1;
    }
    tlsp_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->server = c->server;
    mbedtls_ssl_init(&t->ssl); mbedtls_ssl_config_init(&t->conf);
    mbedtls_x509_crt_init(&t->ca); mbedtls_x509_crt_init(&t->own); mbedtls_pk_init(&t->key);
    int rc = mbedtls_ssl_config_defaults(&t->conf, c->server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc) { set_err(NULL, "ssl config", rc); goto bad; }
    /* Mbed TLS 4.x speaks TLS 1.2 and 1.3 only (1.0/1.1 were removed). TLS 1.3 EAP keying is not implemented: pin 1.2. */
    mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_session_tickets(&t->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    mbedtls_ssl_conf_renegotiation(&t->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);

    int ir = load_identity(t, c);
    if (ir < 0) goto bad;
    if (ir == 0 && (rc = mbedtls_ssl_conf_own_cert(&t->conf, &t->own, &t->key)) != 0) { set_err(NULL, "own certificate", rc); goto bad; }

    int ncas = 0;
    if (c->ca_pem) {
        uint8_t *cp = pem_dup(c->ca_pem, c->ca_pem_len);
        if (!cp) { snprintf(g_err, sizeof g_err, "out of memory"); goto bad; }
        rc = mbedtls_x509_crt_parse(&t->ca, cp, c->ca_pem_len + 1);   /* >0 = number of certificates that failed to parse */
        free(cp);
        ncas = (rc >= 0 && t->ca.version != 0) ? 1 : 0;
    }
    if (c->server) {
        if (ir != 0) { snprintf(g_err, sizeof g_err, "server needs a certificate"); goto bad; }
        if (ncas) mbedtls_ssl_conf_ca_chain(&t->conf, &t->ca, NULL);
        mbedtls_ssl_conf_authmode(&t->conf, c->require_client_cert ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
    } else {
        if (c->ca_pem && !ncas && !c->insecure_skip_verify) { snprintf(g_err, sizeof g_err, "no usable CA certificate"); goto bad; }
        if (!c->insecure_skip_verify) {
            if (!c->ca_pem) { snprintf(g_err, sizeof g_err, "server certificate validation needs a CA (or insecure_skip_verify)"); goto bad; }
            mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        } else mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);
        if (ncas) mbedtls_ssl_conf_ca_chain(&t->conf, &t->ca, NULL);
    }
    if ((rc = mbedtls_ssl_setup(&t->ssl, &t->conf)) != 0) { set_err(NULL, "ssl setup", rc); goto bad; }
    if (!c->server) {
        /* NULL host = no name check (Mbed TLS insists the caller decides); a name also becomes the SNI. */
        const char *h = (!c->insecure_skip_verify && c->server_name && c->server_name[0]) ? c->server_name : NULL;
        if ((rc = mbedtls_ssl_set_hostname(&t->ssl, h)) != 0) { set_err(NULL, "server name", rc); goto bad; }
    }
    mbedtls_ssl_set_bio(&t->ssl, t, bio_send, bio_recv, NULL);
    return t;
bad:
    tlsp_free(t);
    return NULL;
}

void tlsp_free(tlsp_t *t) {
    if (!t) return;
    mbedtls_ssl_free(&t->ssl); mbedtls_ssl_config_free(&t->conf);
    mbedtls_x509_crt_free(&t->ca); mbedtls_x509_crt_free(&t->own); mbedtls_pk_free(&t->key);
    free(t->in); free(t->out); free(t);
}

int tlsp_in(tlsp_t *t, const uint8_t *d, size_t n) {
    if (!n) return 0;
    if (t->in_len + n > t->in_cap) {
        size_t nc = t->in_cap ? t->in_cap : 1024;
        while (nc < t->in_len + n) nc *= 2;
        uint8_t *p = realloc(t->in, nc);
        if (!p) return -1;
        t->in = p; t->in_cap = nc;
    }
    memcpy(t->in + t->in_len, d, n);
    t->in_len += n;
    return 0;
}

int tlsp_handshake(tlsp_t *t) {
    if (t->done) return 1;
    int rc = mbedtls_ssl_handshake(&t->ssl);
    if (rc == 0) {
        if (mbedtls_ssl_get_version_number(&t->ssl) != MBEDTLS_SSL_VERSION_TLS1_2) { set_err(t, "TLS version is not 1.2", 0); return -1; }
        t->done = 1; return 1;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    uint32_t vr = mbedtls_ssl_get_verify_result(&t->ssl);
    if (vr != 0 && vr != 0xFFFFFFFFu) {
        char v[100] = "";
        mbedtls_x509_crt_verify_info(v, sizeof v, "", vr);
        for (char *p = v; *p; p++) if (*p == '\n') *p = ' ';
        snprintf(t->err, sizeof t->err, "TLS handshake failed: certificate verify: %s", v);
    } else set_err(t, "TLS handshake failed", rc);
    return -1;
}

size_t tlsp_out_pending(const tlsp_t *t) { return t->out_len - t->out_off; }
size_t tlsp_out(tlsp_t *t, uint8_t *buf, size_t cap) {
    size_t n = t->out_len - t->out_off;
    if (n > cap) n = cap;
    if (n) memcpy(buf, t->out + t->out_off, n);
    t->out_off += n;
    if (t->out_off == t->out_len) t->out_off = t->out_len = 0;
    return n;
}

int tlsp_write(tlsp_t *t, const uint8_t *d, size_t n) {
    if (!t->done) return -1;
    size_t off = 0;
    while (off < n) {
        int r = mbedtls_ssl_write(&t->ssl, d + off, n - off);
        if (r > 0) { off += (size_t)r; continue; }
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        set_err(t, "SSL_write", r);
        return -1;
    }
    return (int)n;
}
int tlsp_read(tlsp_t *t, uint8_t *buf, size_t cap) {
    if (!t->done) return -1;
    int r = mbedtls_ssl_read(&t->ssl, buf, cap);
    if (r > 0) return r;
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    set_err(t, "SSL_read", r);
    return -1;
}

int tlsp_export(tlsp_t *t, const char *label, uint8_t *out, size_t n) {
    if (!t->done) return -1;
    int rc = mbedtls_ssl_export_keying_material(&t->ssl, out, n, label, strlen(label), NULL, 0, 0);
    if (rc != 0) { set_err(t, "key export", rc); return -1; }
    return 0;
}
int tlsp_is_established(const tlsp_t *t) { return t->done; }
