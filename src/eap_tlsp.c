// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* eap_tlsp.c - OpenSSL 3 memory-BIO implementation of eap_tlsp.h. Not hardened beyond what OpenSSL gives. */
#include "eap_tlsp.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct tlsp {
    SSL_CTX *ctx; SSL *ssl; BIO *rbio, *wbio;
    int done, server;
    char err[160];
};
static char g_err[160];

static void set_err(tlsp_t *t, const char *what) {
    char *dst = t ? t->err : g_err;
    unsigned long e = ERR_get_error();
    char tmp[120] = "";
    if (e) ERR_error_string_n(e, tmp, sizeof tmp);
    snprintf(dst, 160, "%s%s%s", what, tmp[0] ? ": " : "", tmp);
    ERR_clear_error();
}
const char *tlsp_error(const tlsp_t *t) { return t ? t->err : g_err; }

static int pw_cb(char *buf, int size, int rw, void *u) {
    (void)rw;
    const char *p = u ? u : "";
    int n = (int)strlen(p);
    if (n > size) n = size;
    memcpy(buf, p, (size_t)n);
    return n;
}

static int load_ca(SSL_CTX *ctx, const uint8_t *pem, size_t len) {
    BIO *b = BIO_new_mem_buf(pem, (int)len);
    X509_STORE *st = SSL_CTX_get_cert_store(ctx);
    int n = 0;
    X509 *x;
    if (!b) return -1;
    while ((x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) { if (X509_STORE_add_cert(st, x)) n++; X509_free(x); }
    ERR_clear_error();                               /* the final "no start line" is the normal end of the list */
    BIO_free(b);
    return n;
}

static int load_identity(SSL_CTX *ctx, const tlsp_cfg_t *c) {
    if (c->p12) {
        const unsigned char *p = c->p12;
        PKCS12 *p12 = d2i_PKCS12(NULL, &p, (long)c->p12_len);
        EVP_PKEY *pk = NULL; X509 *cert = NULL; STACK_OF(X509) *ca = NULL;
        if (!p12) return -1;
        /* Old exports (RC2-40 / 3DES-SHA1) need the legacy provider; a static libcrypto may not find it: ignore failure. */
        OSSL_PROVIDER_load(NULL, "legacy"); OSSL_PROVIDER_load(NULL, "default");
        if (!PKCS12_parse(p12, c->key_pass ? c->key_pass : "", &pk, &cert, &ca)) { PKCS12_free(p12); return -1; }
        PKCS12_free(p12);
        int ok = pk && cert && SSL_CTX_use_certificate(ctx, cert) == 1 && SSL_CTX_use_PrivateKey(ctx, pk) == 1;
        for (int i = 0; ok && ca && i < sk_X509_num(ca); i++) {
            X509 *x = sk_X509_value(ca, i);
            X509_up_ref(x);
            if (SSL_CTX_add_extra_chain_cert(ctx, x) != 1) { X509_free(x); ok = 0; }
        }
        EVP_PKEY_free(pk); X509_free(cert); sk_X509_pop_free(ca, X509_free);
        return ok ? 0 : -1;
    }
    if (!c->cert_pem) return 1;                      /* no identity configured */
    BIO *b = BIO_new_mem_buf(c->cert_pem, (int)c->cert_pem_len);
    X509 *x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
    if (!x || SSL_CTX_use_certificate(ctx, x) != 1) { X509_free(x); BIO_free(b); return -1; }
    X509_free(x);
    while ((x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL)       /* intermediates */
        if (SSL_CTX_add_extra_chain_cert(ctx, x) != 1) { X509_free(x); BIO_free(b); return -1; }
    ERR_clear_error();
    BIO_free(b);
    const uint8_t *kp = c->key_pem ? c->key_pem : c->cert_pem;
    size_t kl = c->key_pem ? c->key_pem_len : c->cert_pem_len;
    b = BIO_new_mem_buf(kp, (int)kl);
    EVP_PKEY *pk = b ? PEM_read_bio_PrivateKey(b, NULL, pw_cb, (void *)c->key_pass) : NULL;
    BIO_free(b);
    if (!pk) return -1;
    int ok = SSL_CTX_use_PrivateKey(ctx, pk) == 1;
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

tlsp_t *tlsp_new(const tlsp_cfg_t *c) {
    tlsp_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->server = c->server;
    t->ctx = SSL_CTX_new(TLS_method());
    if (!t->ctx) { set_err(NULL, "SSL_CTX_new"); free(t); return NULL; }
    SSL_CTX_set_min_proto_version(t->ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(t->ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(t->ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_session_cache_mode(t->ctx, SSL_SESS_CACHE_OFF);
    int r = load_identity(t->ctx, c);
    if (r < 0) { set_err(NULL, "loading client certificate / private key"); goto bad; }
    if (r == 0 && SSL_CTX_check_private_key(t->ctx) != 1) { set_err(NULL, "private key does not match certificate"); goto bad; }
    if (c->server) {
        if (r != 0) { snprintf(g_err, sizeof g_err, "server needs a certificate"); goto bad; }
        if (c->ca_pem) load_ca(t->ctx, c->ca_pem, c->ca_pem_len);
        if (c->require_client_cert) SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        if (c->ca_pem && load_ca(t->ctx, c->ca_pem, c->ca_pem_len) <= 0 && !c->insecure_skip_verify) {
            snprintf(g_err, sizeof g_err, "no usable CA certificate"); goto bad;
        }
        if (!c->insecure_skip_verify) {
            if (!c->ca_pem) { snprintf(g_err, sizeof g_err, "server certificate validation needs a CA (or insecure_skip_verify)"); goto bad; }
            SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);
        } else SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);
    }
    t->ssl = SSL_new(t->ctx);
    t->rbio = BIO_new(BIO_s_mem()); t->wbio = BIO_new(BIO_s_mem());
    if (!t->ssl || !t->rbio || !t->wbio) { set_err(NULL, "SSL_new"); goto bad; }
    BIO_set_mem_eof_return(t->rbio, -1);              /* empty read BIO means "want read", not EOF */
    SSL_set_bio(t->ssl, t->rbio, t->wbio);
    t->rbio = t->wbio = NULL;                         /* owned by ssl now */
    t->rbio = SSL_get_rbio(t->ssl); t->wbio = SSL_get_wbio(t->ssl);
    if (!c->server && !c->insecure_skip_verify && c->server_name && c->server_name[0])
        if (X509_VERIFY_PARAM_set1_host(SSL_get0_param(t->ssl), c->server_name, 0) != 1) { set_err(NULL, "server name"); goto bad; }
    if (c->server) SSL_set_accept_state(t->ssl); else SSL_set_connect_state(t->ssl);
    return t;
bad:
    if (t->ssl) SSL_free(t->ssl); else { BIO_free(t->rbio); BIO_free(t->wbio); }
    SSL_CTX_free(t->ctx); free(t);
    return NULL;
}

void tlsp_free(tlsp_t *t) {
    if (!t) return;
    SSL_free(t->ssl); SSL_CTX_free(t->ctx); free(t);
}

int tlsp_in(tlsp_t *t, const uint8_t *d, size_t n) {
    if (!n) return 0;
    return BIO_write(t->rbio, d, (int)n) == (int)n ? 0 : -1;
}

int tlsp_handshake(tlsp_t *t) {
    if (t->done) return 1;
    int r = SSL_do_handshake(t->ssl);
    if (r == 1) { t->done = 1; return 1; }
    int e = SSL_get_error(t->ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) { ERR_clear_error(); return 0; }
    long vr = SSL_get_verify_result(t->ssl);
    if (vr != X509_V_OK) snprintf(t->err, sizeof t->err, "TLS handshake failed: certificate verify: %s", X509_verify_cert_error_string(vr));
    else set_err(t, "TLS handshake failed");
    ERR_clear_error();
    return -1;
}

size_t tlsp_out_pending(const tlsp_t *t) { return (size_t)BIO_ctrl_pending(t->wbio); }
size_t tlsp_out(tlsp_t *t, uint8_t *buf, size_t cap) {
    int n = BIO_read(t->wbio, buf, (int)cap);
    return n > 0 ? (size_t)n : 0;
}

int tlsp_write(tlsp_t *t, const uint8_t *d, size_t n) {
    if (!t->done) return -1;
    int r = SSL_write(t->ssl, d, (int)n);
    if (r != (int)n) { set_err(t, "SSL_write"); return -1; }
    return r;
}
int tlsp_read(tlsp_t *t, uint8_t *buf, size_t cap) {
    if (!t->done) return -1;
    int r = SSL_read(t->ssl, buf, (int)cap);
    if (r > 0) return r;
    int e = SSL_get_error(t->ssl, r);
    if (e == SSL_ERROR_WANT_READ) { ERR_clear_error(); return 0; }
    set_err(t, "SSL_read");
    return -1;
}

int tlsp_export(tlsp_t *t, const char *label, uint8_t *out, size_t n) {
    if (!t->done) return -1;
    if (SSL_export_keying_material(t->ssl, out, n, label, strlen(label), NULL, 0, 0) != 1) { set_err(t, "key export"); return -1; }
    return 0;
}
int tlsp_is_established(const tlsp_t *t) { return t->done; }
