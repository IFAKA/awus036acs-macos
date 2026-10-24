// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <ctype.h>
#include <string.h>
#include "proto.h"

static int safe(unsigned char c) { return isalnum(c) || c == '.' || c == '_' || c == ':' || c == '/' || c == ',' || c == '+' || c == '-'; }

int proto_enc(char *out, size_t cap, const char *s)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t n = 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (safe(c)) { if (n + 2 > cap) return -1; out[n++] = (char)c; }
        else { if (n + 4 > cap) return -1; out[n++] = '%'; out[n++] = hx[c >> 4]; out[n++] = hx[c & 15]; }
    }
    if (n + 1 > cap) return -1;
    out[n] = 0;
    return (int)n;
}

static int hexv(int c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

int proto_dec(char *out, size_t cap, const char *s, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)s[i];
        if (c == '%') {
            if (i + 2 >= n) return -1;
            int h = hexv(s[i + 1]), l = hexv(s[i + 2]);
            if (h < 0 || l < 0) return -1;
            c = h << 4 | l;
            i += 2;
            if (c == 0) return -1;
        }
        if (o + 1 >= cap) return -1;
        out[o++] = (char)c;
    }
    out[o] = 0;
    return (int)o;
}

static int is_key(const char *s, size_t n)
{
    if (!n || n >= 24) return 0;
    for (size_t i = 0; i < n; i++) if (!(islower((unsigned char)s[i]) || isdigit((unsigned char)s[i]) || s[i] == '_')) return 0;
    return 1;
}

int proto_parse(const char *line, proto_req_t *rq)
{
    memset(rq, 0, sizeof *rq);
    size_t len = strlen(line);
    if (len == 0 || len >= PROTO_LINE) return -1;
    int first = 1;
    const char *p = line;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ' ') e++;
        size_t n = (size_t)(e - p);
        const char *eq = memchr(p, '=', n);
        if (first) {
            if (eq || n >= sizeof rq->cmd) return -1;
            for (size_t i = 0; i < n; i++) if (!islower((unsigned char)p[i]) && p[i] != '-') return -1;
            memcpy(rq->cmd, p, n); rq->cmd[n] = 0;
            first = 0;
        } else if (eq && is_key(p, (size_t)(eq - p))) {
            if (rq->nopt >= PROTO_MAXOPT) return -1;
            memcpy(rq->opt[rq->nopt].k, p, (size_t)(eq - p)); rq->opt[rq->nopt].k[eq - p] = 0;
            if (proto_dec(rq->opt[rq->nopt].v, PROTO_VAL, eq + 1, (size_t)(e - eq - 1)) < 0) return -1;
            rq->nopt++;
        } else {
            if (rq->npos >= PROTO_MAXPOS) return -1;
            if (proto_dec(rq->pos[rq->npos], PROTO_VAL, p, n) < 0) return -1;
            rq->npos++;
        }
        p = e;
    }
    return first ? -1 : 0;
}

const char *proto_opt(const proto_req_t *rq, const char *key)
{
    for (int i = 0; i < rq->nopt; i++) if (!strcmp(rq->opt[i].k, key)) return rq->opt[i].v;
    return NULL;
}

const char *proto_pos(const proto_req_t *rq, int i) { return i >= 0 && i < rq->npos ? rq->pos[i] : NULL; }

long backoff_ms(int attempt)
{
    if (attempt < 0) attempt = 0;
    if (attempt >= 5) return 30000;
    return 1000L << attempt;
}
