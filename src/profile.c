// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "profile.h"

static const char *const secs[] = { "auto", "open", "wep", "wep-shared", "wpa", "wpa2", "sae", "eap" };

int profile_check(const profile_t *p, const char **why)
{
    const char *w = NULL;
    size_t sl = strlen(p->ssid), kl = strlen(p->key);
    int known = 0;
    for (size_t i = 0; i < sizeof secs / sizeof secs[0]; i++) if (!strcmp(p->security, secs[i])) known = 1;
    if (sl < 1 || sl > 32) w = "ssid must be 1-32 bytes";
    else if (!known) w = "security must be auto, open, wep, wep-shared, wpa, wpa2, sae or eap";
    else if (!strcmp(p->security, "eap") && !p->eap.identity[0]) w = "802.1X needs an identity";
    else if (!strcmp(p->security, "eap") && p->eap.method[0] && strcmp(p->eap.method, "peap") && strcmp(p->eap.method, "ttls") && strcmp(p->eap.method, "tls") && strcmp(p->eap.method, "leap")) w = "eap method must be peap, ttls, tls or leap";
    else if (!strcmp(p->security, "eap") && p->eap.inner[0] && strcmp(p->eap.inner, "mschapv2") && strcmp(p->eap.inner, "pap")) w = "eap inner must be mschapv2 or pap";
    else if (!strcmp(p->security, "open") && kl) w = "an open network has no key";
    else if ((!strcmp(p->security, "wpa") || !strcmp(p->security, "wpa2")) && (kl < 8 || kl > 63)) w = "WPA passphrase must be 8-63 characters";
    else if (!strcmp(p->security, "sae") && (kl < 1 || kl > 63)) w = "SAE password must be 1-63 characters";
    else if ((!strcmp(p->security, "wep") || !strcmp(p->security, "wep-shared")) && kl != 5 && kl != 13 && kl != 10 && kl != 26) w = "WEP key must be 5/13 characters or 10/26 hex digits";
    else if (!strcmp(p->security, "auto") && kl && kl < 5) w = "key too short";
    else if (p->priority < -1000 || p->priority > 1000) w = "priority must be -1000..1000";
    if (why) *why = w;
    return w ? -1 : 0;
}

int profiles_put(profiles_t *ps, const profile_t *p, const char **why)
{
    if (profile_check(p, why)) return -1;
    for (int i = 0; i < ps->n; i++) if (!strcmp(ps->p[i].ssid, p->ssid)) { ps->p[i] = *p; return 0; }
    if (ps->n >= PROFILE_MAX) { if (why) *why = "profile table is full"; return -2; }
    ps->p[ps->n++] = *p;
    return 0;
}

int profiles_remove(profiles_t *ps, const char *ssid)
{
    for (int i = 0; i < ps->n; i++) if (!strcmp(ps->p[i].ssid, ssid)) {
        memmove(&ps->p[i], &ps->p[i + 1], (size_t)(ps->n - i - 1) * sizeof ps->p[0]);
        ps->n--;
        return 0;
    }
    return -1;
}

const profile_t *profiles_find(const profiles_t *ps, const char *ssid)
{
    for (int i = 0; i < ps->n; i++) if (!strcmp(ps->p[i].ssid, ssid)) return &ps->p[i];
    return NULL;
}

int profiles_pick(const profiles_t *ps, int (*visible)(void *ctx, const profile_t *p), void *ctx, const char *skip_ssid)
{
    int best = -1;
    for (int i = 0; i < ps->n; i++) {
        const profile_t *p = &ps->p[i];
        if (!p->autojoin || (skip_ssid && !strcmp(p->ssid, skip_ssid)) || !visible(ctx, p)) continue;
        if (best < 0 || p->priority > ps->p[best].priority) best = i;
    }
    return best;
}

// ---- writer ----
typedef struct { char *o; size_t cap, n; int bad; } wr_t;
static void wput(wr_t *w, const char *s, size_t k)
{
    if (w->n + k + 1 > w->cap) { w->bad = 1; return; }
    memcpy(w->o + w->n, s, k); w->n += k; w->o[w->n] = 0;
}
static void wstr(wr_t *w, const char *s) { wput(w, s, strlen(s)); }
static void wjson(wr_t *w, const char *s)
{
    wput(w, "\"", 1);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        char t[8];
        if (c == '"' || c == '\\') { t[0] = '\\'; t[1] = (char)c; wput(w, t, 2); }
        else if (c < 0x20 || c == 0x7f) { int k = snprintf(t, sizeof t, "\\u%04x", c); wput(w, t, (size_t)k); }
        else wput(w, (const char *)&c, 1);
    }
    wput(w, "\"", 1);
}

int profiles_to_json(const profiles_t *ps, char *out, size_t cap)
{
    wr_t w = { out, cap, 0, 0 };
    if (cap) out[0] = 0;
    wstr(&w, "{\"version\":1,\"profiles\":[");
    for (int i = 0; i < ps->n; i++) {
        const profile_t *p = &ps->p[i];
        char t[48];
        wstr(&w, i ? ",\n  {" : "\n  {");
        wstr(&w, "\"ssid\":"); wjson(&w, p->ssid);
        wstr(&w, ",\"security\":"); wjson(&w, p->security);
        wstr(&w, ",\"key\":"); wjson(&w, p->key);
        snprintf(t, sizeof t, ",\"hidden\":%s", p->hidden ? "true" : "false"); wstr(&w, t);
        snprintf(t, sizeof t, ",\"priority\":%d", p->priority); wstr(&w, t);
        snprintf(t, sizeof t, ",\"autojoin\":%s", p->autojoin ? "true" : "false"); wstr(&w, t);
        snprintf(t, sizeof t, ",\"prefer_sae\":%s", p->prefer_sae ? "true" : "false"); wstr(&w, t);
        snprintf(t, sizeof t, ",\"default_route\":%s", p->default_route ? "true" : "false"); wstr(&w, t);
        if (!strcmp(p->security, "eap") || p->eap.identity[0]) {
            const eapconf_t *e = &p->eap;
            wstr(&w, ",\"eap_method\":"); wjson(&w, e->method);
            wstr(&w, ",\"eap_inner\":"); wjson(&w, e->inner);
            wstr(&w, ",\"eap_identity\":"); wjson(&w, e->identity);
            wstr(&w, ",\"eap_anon\":"); wjson(&w, e->anon);
            wstr(&w, ",\"eap_ca\":"); wjson(&w, e->ca);
            wstr(&w, ",\"eap_cert\":"); wjson(&w, e->cert);
            wstr(&w, ",\"eap_key\":"); wjson(&w, e->keyfile);
            wstr(&w, ",\"eap_key_pass\":"); wjson(&w, e->keypass);
            wstr(&w, ",\"eap_server_name\":"); wjson(&w, e->server);
            snprintf(t, sizeof t, ",\"eap_insecure\":%s", e->insecure ? "true" : "false"); wstr(&w, t);
            snprintf(t, sizeof t, ",\"eap_allow_leap\":%s", e->allow_leap ? "true" : "false"); wstr(&w, t);
        }
        wstr(&w, "}");
    }
    wstr(&w, ps->n ? "\n]}\n" : "]}\n");
    return w.bad ? -1 : (int)w.n;
}

// ---- reader: a small recursive-descent JSON parser, just enough for our own file ----
typedef struct { const char *s; int err; } rd_t;
static void ws(rd_t *r) { while (*r->s == ' ' || *r->s == '\t' || *r->s == '\n' || *r->s == '\r') r->s++; }
static int hexd(int c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

// Parse a string into out (cap bytes). Strings longer than cap are an error. \u escapes above 0xFF are rejected (we only write \u00xx).
static int rstr(rd_t *r, char *out, size_t cap)
{
    size_t n = 0;
    ws(r);
    if (*r->s != '"') return r->err = 1;
    r->s++;
    while (*r->s && *r->s != '"') {
        int c = (unsigned char)*r->s++;
        if (c == '\\') {
            int e = *r->s++;
            if (e == 'n') c = '\n'; else if (e == 't') c = '\t'; else if (e == 'r') c = '\r';
            else if (e == '"' || e == '\\' || e == '/') c = e;
            else if (e == 'u') {
                int v = 0;
                for (int i = 0; i < 4; i++) { int h = hexd(*r->s); if (h < 0) return r->err = 1; v = v << 4 | h; r->s++; }
                if (v > 0xFF || v == 0) return r->err = 1;
                c = v;
            } else return r->err = 1;
        }
        if (out) { if (n + 1 >= cap) return r->err = 1; out[n] = (char)c; }
        n++;
    }
    if (*r->s != '"') return r->err = 1;
    r->s++;
    if (out) out[n] = 0;
    return 0;
}

static void skip_value(rd_t *r);
static void skip_container(rd_t *r, char close)
{
    r->s++;
    ws(r);
    if (*r->s == close) { r->s++; return; }
    for (;;) {
        if (close == '}') { if (rstr(r, NULL, 0)) return; ws(r); if (*r->s != ':') { r->err = 1; return; } r->s++; }
        skip_value(r);
        if (r->err) return;
        ws(r);
        if (*r->s == ',') { r->s++; continue; }
        if (*r->s == close) { r->s++; return; }
        r->err = 1; return;
    }
}
static void skip_value(rd_t *r)
{
    ws(r);
    if (*r->s == '"') rstr(r, NULL, 0);
    else if (*r->s == '{') skip_container(r, '}');
    else if (*r->s == '[') skip_container(r, ']');
    else {
        const char *b = r->s;
        while (*r->s && *r->s != ',' && *r->s != '}' && *r->s != ']' && *r->s != ' ' && *r->s != '\n' && *r->s != '\r' && *r->s != '\t') r->s++;
        if (r->s == b) r->err = 1;
    }
}

static int rbool(rd_t *r, int *v)
{
    ws(r);
    if (!strncmp(r->s, "true", 4)) { *v = 1; r->s += 4; return 0; }
    if (!strncmp(r->s, "false", 5)) { *v = 0; r->s += 5; return 0; }
    return r->err = 1;
}

static int rprofile(rd_t *r, profile_t *p)
{
    memset(p, 0, sizeof *p);
    snprintf(p->security, sizeof p->security, "auto");
    p->prefer_sae = 1;
    ws(r);
    if (*r->s != '{') return r->err = 1;
    r->s++; ws(r);
    if (*r->s == '}') { r->s++; return 0; }
    for (;;) {
        char k[24];
        if (rstr(r, k, sizeof k)) return 1;
        ws(r);
        if (*r->s != ':') return r->err = 1;
        r->s++;
        if (!strcmp(k, "ssid")) { if (rstr(r, p->ssid, sizeof p->ssid)) return 1; }
        else if (!strcmp(k, "security")) { if (rstr(r, p->security, sizeof p->security)) return 1; }
        else if (!strcmp(k, "key")) { if (rstr(r, p->key, sizeof p->key)) return 1; }
        else if (!strcmp(k, "eap_method")) { if (rstr(r, p->eap.method, sizeof p->eap.method)) return 1; }
        else if (!strcmp(k, "eap_inner")) { if (rstr(r, p->eap.inner, sizeof p->eap.inner)) return 1; }
        else if (!strcmp(k, "eap_identity")) { if (rstr(r, p->eap.identity, sizeof p->eap.identity)) return 1; }
        else if (!strcmp(k, "eap_anon")) { if (rstr(r, p->eap.anon, sizeof p->eap.anon)) return 1; }
        else if (!strcmp(k, "eap_ca")) { if (rstr(r, p->eap.ca, sizeof p->eap.ca)) return 1; }
        else if (!strcmp(k, "eap_cert")) { if (rstr(r, p->eap.cert, sizeof p->eap.cert)) return 1; }
        else if (!strcmp(k, "eap_key")) { if (rstr(r, p->eap.keyfile, sizeof p->eap.keyfile)) return 1; }
        else if (!strcmp(k, "eap_key_pass")) { if (rstr(r, p->eap.keypass, sizeof p->eap.keypass)) return 1; }
        else if (!strcmp(k, "eap_server_name")) { if (rstr(r, p->eap.server, sizeof p->eap.server)) return 1; }
        else if (!strcmp(k, "eap_insecure")) { if (rbool(r, &p->eap.insecure)) return 1; }
        else if (!strcmp(k, "eap_allow_leap")) { if (rbool(r, &p->eap.allow_leap)) return 1; }
        else if (!strcmp(k, "hidden")) { if (rbool(r, &p->hidden)) return 1; }
        else if (!strcmp(k, "autojoin")) { if (rbool(r, &p->autojoin)) return 1; }
        else if (!strcmp(k, "prefer_sae")) { if (rbool(r, &p->prefer_sae)) return 1; }
        else if (!strcmp(k, "default_route")) { if (rbool(r, &p->default_route)) return 1; }
        else if (!strcmp(k, "priority")) {
            ws(r);
            char *e; long v = strtol(r->s, &e, 10);
            if (e == r->s) return r->err = 1;
            p->priority = v < -100000 ? -100000 : v > 100000 ? 100000 : (int)v;
            r->s = e;
        } else { skip_value(r); if (r->err) return 1; }
        ws(r);
        if (*r->s == ',') { r->s++; ws(r); continue; }
        if (*r->s == '}') { r->s++; return 0; }
        return r->err = 1;
    }
}

int profiles_from_json(const char *text, profiles_t *ps, int *skipped)
{
    rd_t r = { text, 0 };
    int sk = 0;
    memset(ps, 0, sizeof *ps);
    ws(&r);
    if (*r.s != '{') return -1;
    r.s++; ws(&r);
    while (*r.s && *r.s != '}') {
        char k[24];
        if (rstr(&r, k, sizeof k)) return -1;
        ws(&r);
        if (*r.s != ':') return -1;
        r.s++; ws(&r);
        if (!strcmp(k, "profiles")) {
            if (*r.s != '[') return -1;
            r.s++; ws(&r);
            while (*r.s && *r.s != ']') {
                profile_t p;
                if (rprofile(&r, &p)) return -1;
                if (ps->n < PROFILE_MAX && profile_check(&p, NULL) == 0 && !profiles_find(ps, p.ssid)) ps->p[ps->n++] = p;
                else sk++;
                ws(&r);
                if (*r.s == ',') { r.s++; ws(&r); }
            }
            if (*r.s != ']') return -1;
            r.s++;
        } else {
            skip_value(&r);
            if (r.err) return -1;
        }
        ws(&r);
        if (*r.s == ',') { r.s++; ws(&r); }
    }
    if (*r.s != '}') return -1;
    if (skipped) *skipped = sk;
    return 0;
}

int profiles_load(const char *path, profiles_t *ps)
{
    memset(ps, 0, sizeof *ps);
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 0 : -1;
    static char buf[64 * 1024];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    int big = !feof(f);
    fclose(f);
    if (big) return -1;
    buf[n] = 0;
    return profiles_from_json(buf, ps, NULL);
}

static void mkdirs(const char *path)
{
    char t[512];
    snprintf(t, sizeof t, "%s", path);
    char *slash = strrchr(t, '/');
    if (!slash || slash == t) return;
    *slash = 0;
    for (char *p = t + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(t, 0755); *p = '/'; }
    mkdir(t, 0700);
}

int profiles_save(const char *path, const profiles_t *ps)
{
    static char buf[64 * 1024];
    char tmp[600];
    int n = profiles_to_json(ps, buf, sizeof buf);
    if (n < 0 || snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) return -1;
    mkdirs(path);
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    fchmod(fd, 0600);
    ssize_t w = write(fd, buf, (size_t)n);
    int ok = w == n && fsync(fd) == 0;
    if (close(fd)) ok = 0;
    if (!ok || rename(tmp, path)) { unlink(tmp); return -1; }
    return 0;
}
