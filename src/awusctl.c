// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// awusctl: command-line control of the adapter. Talks to the awusd daemon over its unix socket (proto.h); `scan` and
// `join` also work WITHOUT the daemon (they then drive the USB device directly, one shot, as before). Run `awusctl help`.
// Keys (passphrase / WEP key) are read from the environment variable named by --key-env and sent over the 0600 socket;
// they never appear on a command line. Only join networks you own or are allowed to test. Direct-mode log: /tmp/awusctl.log
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "rtl.h"
#include "phy.h"
#include "mac.h"
#include "rx.h"
#include "tx.h"
#include "bringup.h"
#include "scanparse.h"
#include "scanlib.h"
#include "country.h"
#include "proto.h"
#include "link.h"
#include "bench.h"

static FILE *E;                  // user-facing messages; in direct mode stderr itself is redirected to the register log

// ---------------------------------------------------------------- daemon client
static char sockpath[256];
static const char *last_err;

// Send one request line, return the whole response in a malloc'd buffer (NUL terminated), or NULL when the daemon is not reachable.
static char *rpc(const char *line)
{
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", sockpath);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    if (connect(fd, (struct sockaddr *)&a, sizeof a)) { close(fd); return NULL; }
    size_t n = strlen(line);
    if (write(fd, line, n) != (ssize_t)n || write(fd, "\n", 1) != 1) { close(fd); return NULL; }
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    for (;;) {
        if (len + 4096 > cap) { cap *= 2; buf = realloc(buf, cap); }
        ssize_t r = read(fd, buf + len, cap - len - 1);
        if (r <= 0) break;
        len += r;
    }
    close(fd);
    buf[len] = 0;
    return buf;
}

typedef struct { char line[PROTO_LINE + 256]; size_t n; } req_t;
static void rq_word(req_t *q, const char *w)
{
    char e[1100];
    if (proto_enc(e, sizeof e, w) < 0) { fprintf(E, "awusctl: argument too long\n"); exit(2); }
    if (q->n + strlen(e) + 2 >= sizeof q->line) { fprintf(E, "awusctl: request too long\n"); exit(2); }
    q->n += snprintf(q->line + q->n, sizeof q->line - q->n, "%s%s", q->n ? " " : "", e);
}
static void rq_kv(req_t *q, const char *k, const char *v)
{
    char e[1100];
    proto_enc(e, sizeof e, v);
    if (q->n + strlen(k) + strlen(e) + 3 >= sizeof q->line) { fprintf(E, "awusctl: request too long\n"); exit(2); }
    q->n += snprintf(q->line + q->n, sizeof q->line - q->n, " %s=%s", k, e);
}

// Print one response body line: "key=value" lines decoded, "word k=v k=v" lines decoded token by token.
static void print_body_line(const char *l)
{
    char tmp[PROTO_LINE * 2];
    snprintf(tmp, sizeof tmp, "%s", l);
    int first = 1;
    char *sv;
    for (char *t = strtok_r(tmp, " ", &sv); t; t = strtok_r(NULL, " ", &sv)) {
        char *eq = strchr(t, '=');
        char d[PROTO_VAL * 2];
        if (eq) {
            *eq = 0;
            int n = proto_dec(d, sizeof d, eq + 1, strlen(eq + 1));
            printf("%s%s=%s", first ? "" : "  ", t, n < 0 ? eq + 1 : d);
        } else printf("%s%s:", first ? "" : "  ", t);
        first = 0;
    }
    putchar('\n');
}

// Returns 0 on OK, 1 on ERR, 3 when the daemon is unreachable. On OK `*body` points into resp after the first line.
static int call(const req_t *q, char **resp, const char **body)
{
    *resp = rpc(q->line);
    if (!*resp) return 3;
    char *nl = strchr(*resp, '\n');
    if (nl) *nl = 0;
    *body = nl ? nl + 1 : "";
    if (!strncmp(*resp, "OK", 2)) return 0;
    last_err = *resp;
    return 1;
}

static int simple_cmd(const req_t *q)
{
    char *resp; const char *body;
    int rc = call(q, &resp, &body);
    if (rc == 3) { fprintf(E, "awusctl: awusd is not running (no socket at %s)\n", sockpath); return 3; }
    if (rc) { fprintf(E, "awusctl: %s\n", last_err[0] == 'E' ? last_err + 4 : last_err); free(resp); return 1; }
    char *b = strdup(body);
    char *sv2;
    for (char *l = strtok_r(b, "\n", &sv2); l; l = strtok_r(NULL, "\n", &sv2)) print_body_line(l);
    free(b); free(resp);
    return 0;
}

static int scan_via_daemon(const char *band, int dwell, int passes, int json, int *reachable)
{
    req_t q = {0};
    rq_word(&q, "scan");
    if (band) rq_kv(&q, "band", band);
    char t[16];
    if (dwell) { snprintf(t, sizeof t, "%d", dwell); rq_kv(&q, "dwell", t); }
    if (passes) { snprintf(t, sizeof t, "%d", passes); rq_kv(&q, "passes", t); }
    char *resp; const char *body;
    int rc = call(&q, &resp, &body);
    *reachable = rc != 3;
    if (rc == 3) return 3;
    if (rc) { fprintf(E, "awusctl scan: %s\n", last_err + 4); free(resp); return 1; }
    scan_row_t *rows = calloc(SCAN_MAX_APS, sizeof *rows);
    int n = 0, cached = 0;
    char *b = strdup(body);
    char *sv2;
    for (char *l = strtok_r(b, "\n", &sv2); l; l = strtok_r(NULL, "\n", &sv2)) {
        proto_req_t p;
        if (!strncmp(l, "cached=", 7)) cached = l[7] == '1';
        if (strncmp(l, "ap ", 3) || proto_parse(l, &p) || n >= SCAN_MAX_APS) continue;
        scan_row_t *w = &rows[n++];
        snprintf(w->ssid, sizeof w->ssid, "%s", proto_opt(&p, "ssid"));
        int j = 0;
        for (const char *c = w->ssid; *c && j + 3 < (int)sizeof w->ssid_json; c++) { if (*c == '"' || *c == '\\') w->ssid_json[j++] = '\\'; w->ssid_json[j++] = *c; }
        w->hidden = atoi(proto_opt(&p, "hidden"));
        snprintf(w->bssid, sizeof w->bssid, "%s", proto_opt(&p, "bssid"));
        w->channel = atoi(proto_opt(&p, "ch")); w->rssi = atoi(proto_opt(&p, "rssi"));
        snprintf(w->security, sizeof w->security, "%s", proto_opt(&p, "sec"));
        snprintf(w->cipher, sizeof w->cipher, "%s", proto_opt(&p, "cipher"));
        snprintf(w->phy, sizeof w->phy, "%s", proto_opt(&p, "phy"));
        w->wps = atoi(proto_opt(&p, "wps")); w->allowed = atoi(proto_opt(&p, "ok")); w->dfs = atoi(proto_opt(&p, "dfs"));
        w->ht = atoi(proto_opt(&p, "ht")); w->vht = atoi(proto_opt(&p, "vht")); w->he = atoi(proto_opt(&p, "he"));
        w->streams = atoi(proto_opt(&p, "streams")); w->max_rate = atof(proto_opt(&p, "rate"));
    }
    if (cached) fprintf(E, "awusctl: connected, showing the last scan (the radio is tied to the AP's channel)\n");
    if (json) scan_print_json(stdout, rows, n); else scan_print_table(stdout, rows, n);
    free(b); free(rows); free(resp);
    return 0;
}

// ---------------------------------------------------------------- direct mode (no daemon)
static int cmd_scan_direct(const char *band_s, int dwell, int passes, int json, const char *country)
{
    int band = !band_s || !strcmp(band_s, "all") ? 0 : atoi(band_s);
    rtl_t r = {0};
    char b[160];
    const char *step;
    r.verbose = 1;                                          // register log goes to /tmp/awusctl.log
    if (rtl_bringup(&r, 1, &step, b, sizeof b)) { fprintf(E, "awusctl: bring-up failed at %s: %s\n", step, b); return 1; }
    if (rtl_set_monitor(&r)) { fprintf(E, "awusctl: set_monitor failed\n"); rtl_close(&r); return 1; }
    r.verbose = 0;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    static scan_t S;
    scan_reset(&S, country);
    int rc = scan_run(&r, &S, band, dwell, passes, NULL);
    rtl_close(&r);
    if (rc) { fprintf(E, "awusctl: scan failed (USB error)\n"); return 1; }
    if (S.dropped) fprintf(E, "awusctl: %d network(s) not listed (table full)\n", S.dropped);
    scan_sort(&S);
    scan_row_t *rows = calloc(S.n ? S.n : 1, sizeof *rows);
    for (int i = 0; i < S.n; i++) scan_row(&S.aps[i], &rows[i]);
    if (json) scan_print_json(stdout, rows, S.n); else scan_print_table(stdout, rows, S.n);
    free(rows);
    return 0;
}

static volatile sig_atomic_t stop_req;
static void on_sig(int s) { (void)s; stop_req = 1; }

static int g_bench, g_bench_secs = 5, g_legacy, g_maxbw, g_rate, g_vht, g_ping6, g_prefer_psk;
static const char *g_bench_down = "10,20,40,80";

static void bench_report(link_t *L, uint32_t peer)
{
    bench_res_t r;
    fprintf(E, "bench peer=%u.%u.%u.%u secs=%d rates: data tx code %d, last rx code %d\n", peer >> 24, (peer >> 16) & 255, (peer >> 8) & 255, peer & 255, g_bench_secs, L->data_rate, L->s.rx_rate);
    if (!bench_run(L, peer, 1, g_bench_secs, 1400, 0, &r))
        fprintf(E, "BENCH up   %7.2f Mbit/s  sent %lu recv %lu loss %ld%%  tx_report ok %lu retry_over %lu of %lu  rx_rate %d\n", r.mbps, r.sent, r.recv, r.sent ? (long)(100 - 100 * r.recv / r.sent) : 100, r.tx_ok, r.tx_retry_over, r.tx_submitted, r.rx_rate);
    char *d = strdup(g_bench_down), *sv, *tok;
    for (tok = strtok_r(d, ",", &sv); tok; tok = strtok_r(NULL, ",", &sv))
        if (!bench_run(L, peer, 2, g_bench_secs, 1400, atoi(tok), &r))
            fprintf(E, "BENCH down offered %4s -> %7.2f Mbit/s  sent %lu recv %lu loss %ld%%  rx_rate %d bw %d\n", tok, r.mbps, r.sent, r.recv, r.sent ? (long)(100 - 100 * (long)r.recv / (long)r.sent) : 100, r.rx_rate, 0);
    fprintf(E, "BENCH counters: dec_ok %lu dec_fail %lu replay %lu data_rx %lu rx_crc_err %lu frames %lu\n", L->st_dec_ok, L->st_dec_fail, L->st_replay, L->s.data_rx, rtl_rx_stats.crc_err, rtl_rx_stats.frames);
    fprintf(E, "BENCH tx reports by hw rate:");
    for (int i = 0; i < 128; i++) if (rtl_tx_stats.ccx_rate_hist[i]) fprintf(E, " %d:%lu", i, rtl_tx_stats.ccx_rate_hist[i]);
    fprintf(E, " (retries %lu)\n", rtl_tx_stats.ccx_retries);
    fprintf(E, "BENCH rx data frames by hw rate:");
    for (int i = 0; i < 128; i++) if (L->s.rx_rate_hist[i]) fprintf(E, " %d:%lu", i, L->s.rx_rate_hist[i]);
    fprintf(E, "\n");
    free(d);
}

static int cmd_join_direct(const char *ssid, const char *bssid_s, int ch, int hidden, const char *sec_s, const char *key_env, int keyid)
{
    uint8_t bssid[6]; int have_b = 0;
    link_sec_t sec = LINK_SEC_AUTO;
    if (bssid_s) have_b = sscanf(bssid_s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) == 6;
    if (sec_s) {
        if (!strcmp(sec_s, "auto")) sec = LINK_SEC_AUTO; else if (!strcmp(sec_s, "open")) sec = LINK_SEC_OPEN;
        else if (!strcmp(sec_s, "wep")) sec = LINK_SEC_WEP; else if (!strcmp(sec_s, "wep-shared")) sec = LINK_SEC_WEP_SHARED;
        else if (!strcmp(sec_s, "wpa")) sec = LINK_SEC_WPA; else if (!strcmp(sec_s, "wpa2")) sec = LINK_SEC_WPA2; else if (!strcmp(sec_s, "sae")) sec = LINK_SEC_SAE;
        else { fprintf(E, "awusctl join: --sec must be auto, open, wep, wep-shared, wpa, wpa2 or sae\n"); return 2; }
    }
    const char *key = key_env ? getenv(key_env) : NULL;
    if ((sec == LINK_SEC_WPA || sec == LINK_SEC_WPA2 || sec == LINK_SEC_SAE || sec == LINK_SEC_WEP || sec == LINK_SEC_WEP_SHARED) && !key) {
        fprintf(E, "awusctl join: --sec %s needs --key-env VAR\n", link_sec_str(sec)); return 2;
    }
    if (sec == LINK_SEC_OPEN) key = NULL;
    if (!freopen("/tmp/awusctl.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(E, "awusctl: awusd is not running; joining directly (one shot)\n");
    struct sigaction sg; memset(&sg, 0, sizeof sg); sg.sa_handler = on_sig; sigemptyset(&sg.sa_mask);
    sigaction(SIGINT, &sg, NULL); sigaction(SIGTERM, &sg, NULL);

    rtl_t r = {0};
    char b[160]; const char *step;
    r.verbose = 1;
    if (rtl_bringup(&r, ch ? ch : 1, &step, b, sizeof b)) { fprintf(E, "join FAIL bringup %s: %s\n", step, b); return 1; }
    if (rtl_set_monitor(&r)) { fprintf(E, "join FAIL set_monitor\n"); rtl_close(&r); return 1; }
    r.verbose = 0;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    static link_t L;
    link_init(&L, &r);
    L.out = E; L.stop = &stop_req;
    link_cfg_t cfg = { .ssid = ssid, .bssid = have_b ? bssid : NULL, .channel = ch, .hidden = hidden, .sec = sec, .key = key, .wep_keyid = keyid, .legacy = g_legacy, .max_bw = g_maxbw, .data_rate = g_rate, .vht = g_vht, .prefer_psk = g_prefer_psk };
    int rc = 1;
    if (link_join(&r, &cfg, &L)) { fprintf(E, "join FAIL %s %s\n", L.fail_step, L.fail_reason); goto out; }
    char ips[20], gws[20];
    link_ipstr(ips, sizeof ips, L.n.lease.ip); link_ipstr(gws, sizeof gws, L.n.lease.gw);
    link_ping_t pr;
    int prc = link_ping(&L, L.n.lease.gw, g_bench ? 20 : 6, &pr);
    if (prc) { fprintf(E, "join FAIL ping %s (ip=%s gw=%s)\n", prc > 0 ? "no_reply_to_first_echo" : "deauthenticated_or_stopped", ips, gws); goto out; }
    fprintf(E, "join OK sec=%s pairwise=%s group=%s ch=%d ip=%s gw=%s ping %d/%d loss %d%% avg_rtt %ldms\n",
            link_sec_str(L.sec), link_cipher_str(L.pw_cipher), link_cipher_str(L.grp_cipher), L.s.channel, ips, gws,
            pr.recv, pr.sent, pr.sent ? 100 - 100 * pr.recv / pr.sent : 100, pr.avg_rtt_ms);
    rc = pr.recv == pr.sent ? 0 : 3;
    if (g_ping6) {                      // IPv6: Router Solicitation, SLAAC, then ping the router's link-local address
        link_ping_t p6;
        int c6 = link_ping6(&L, NULL, 6, &p6);
        char ll[48], gua[48], rt[48];
        inet_ntop(AF_INET6, L.n6.ll, ll, sizeof ll);
        inet_ntop(AF_INET6, L.n6.has_gua ? L.n6.gua : L.n6.ll, gua, sizeof gua);
        inet_ntop(AF_INET6, L.n6.router, rt, sizeof rt);
        fprintf(E, "ping6 ll=%s addr=%s router=%s ra=%u prefix_len=%d dns6=%d: %s %d/%d avg_rtt %ldms\n", ll, gua, L.n6.has_router ? rt : "-",
                L.n6.ra_count, L.n6.prefix_len, L.n6.ndns, c6 ? (c6 > 0 ? "no_reply" : "aborted") : "ok", p6.recv, p6.sent, p6.avg_rtt_ms);
        if (c6 || p6.recv != p6.sent) rc = 4;
    }
    if (g_bench) {
        uint32_t peer = bench_find_peer(L.n.lease.ip, L.n.lease.mask);
        if (!peer) fprintf(E, "bench: no local interface on the lease subnet\n"); else bench_report(&L, peer);
    }
out:
    if (L.s.associated) link_leave(&L);
    rtl_close(&r);
    return rc;
}


static int usage(FILE *o)
{
    fprintf(o,
"usage: awusctl COMMAND [options]       (talks to the awusd daemon; scan and join also work without it)\n"
"  status                         state, link, lease, LED, counters\n"
"  scan [--band 2|5|all] [--dwell MS] [--passes N] [--json] [--country CC (direct mode)]\n"
"  join --ssid S [--bssid B] [--ch N] [--hidden] [--sec open|wep|wep-shared|wpa|wpa2|sae|auto] [--prefer-psk] [--key-env VAR]\n"
"       [--wep-keyid N] [--default-route]     with the daemon: connect and stay; without: join, ping 6x, leave\n"
"  bench --ssid S [--ch N] [--key-env VAR] [--secs N] [--down 20,50,100] [--legacy-rates] [--bw 20|40|80]   goodput test (no daemon)\n"
"  wps pbc | wps pin (--pin N | --pin-env VAR) [--ssid S | --bssid B]   WPS enrol (daemon): saves a profile on success; wps reset clears the limiter\n"
"  adhoc create|join --ssid S --ch N [--key-env VAR]   beacon as (create) or join an ad-hoc IBSS network (daemon); adhoc stop; leave also stops it\n"
"  leave                          disconnect and stop auto-join until join / autojoin on / profile add\n"
"  ping [--host IP] [--count N]   ping the gateway (or IP) from the daemon's link\n"
"  rf on|off                      radio on/off (off: deauth, RF block disabled, LED off)\n"
"  txpower get | txpower set 0-63\n"
"  country get | country set CC   (%s)\n"
"  profile add --ssid S [--key-env VAR] [--security auto|open|wep|wpa|wpa2|sae] [--prefer-psk] [--hidden] [--priority N]\n"
"                [--no-autojoin] [--default-route] | profile list | profile remove --ssid S\n"
"  autojoin on|off|get\n"
"  debug drop | unplug [MS] | wake | failnext N | renew | rebind | led on|off|auto     (test hooks)\n"
"  quit                           stop the daemon\n"
"  --sock PATH (any command)      socket path (default /var/run/awusd.sock as root, else $TMPDIR/awusd.sock)\n"
"The passphrase / WEP key comes only from the environment variable named by --key-env. Example:\n"
"    MYPSK=... awusctl profile add --ssid HomeNet --key-env MYPSK\n", country_list());
    return 2;
}

int main(int argc, char **argv)
{
    E = fdopen(dup(2), "w");
    if (!E) return 2;
    if (argc < 2) return usage(stderr);
    if (!strcmp(argv[1], "help") || !strcmp(argv[1], "--help")) { usage(stdout); return 0; }
    proto_sock_path(sockpath, sizeof sockpath);
    const char *cmd = argv[1];
    // generic option scan
    const char *pin_arg = NULL, *pin_env = NULL;
    const char *ssid = NULL, *key_env = NULL, *sec = NULL, *bssid = NULL, *host = NULL, *band = NULL, *country = NULL, *security = NULL;
    int ch = 0, hidden = 0, json = 0, dwell = 0, passes = 0, count = 0, prio = 0, have_prio = 0, noauto = 0, defroute = 0, keyid = 0;
    const char *pos[4]; int npos = 0;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
#define OPT(n) (!strcmp(a, n) && i + 1 < argc)
        if (OPT("--ssid")) ssid = argv[++i];
        else if (OPT("--key-env")) key_env = argv[++i];
        else if (OPT("--pin")) pin_arg = argv[++i];
        else if (OPT("--pin-env")) pin_env = argv[++i];
        else if (OPT("--sec")) sec = argv[++i];
        else if (OPT("--security")) security = argv[++i];
        else if (OPT("--bssid")) bssid = argv[++i];
        else if (OPT("--host")) host = argv[++i];
        else if (OPT("--band")) band = argv[++i];
        else if (OPT("--country")) country = argv[++i];
        else if (OPT("--ch")) ch = atoi(argv[++i]);
        else if (OPT("--dwell")) dwell = atoi(argv[++i]);
        else if (OPT("--passes")) passes = atoi(argv[++i]);
        else if (OPT("--count")) count = atoi(argv[++i]);
        else if (OPT("--priority")) { prio = atoi(argv[++i]); have_prio = 1; }
        else if (OPT("--wep-keyid")) keyid = atoi(argv[++i]);
        else if (OPT("--sock")) snprintf(sockpath, sizeof sockpath, "%s", argv[++i]);
        else if (OPT("--secs")) g_bench_secs = atoi(argv[++i]);
        else if (OPT("--down")) g_bench_down = argv[++i];
        else if (OPT("--bw")) g_maxbw = atoi(argv[++i]);
        else if (!strcmp(a, "--vht")) g_vht = 1;
        else if (!strcmp(a, "--ping6")) g_ping6 = 1;
        else if (OPT("--rate")) g_rate = atoi(argv[++i]);
        else if (!strcmp(a, "--legacy-rates")) g_legacy = 1;
        else if (!strcmp(a, "--prefer-psk")) g_prefer_psk = 1;
        else if (!strcmp(a, "--hidden")) hidden = 1;
        else if (!strcmp(a, "--json")) json = 1;
        else if (!strcmp(a, "--no-autojoin")) noauto = 1;
        else if (!strcmp(a, "--default-route")) defroute = 1;
        else if (a[0] != '-' && npos < 4) pos[npos++] = a;
        else { fprintf(E, "awusctl %s: unknown or incomplete option %s\n", cmd, a); return 2; }
    }
    if (band && strcmp(band, "2") && strcmp(band, "5") && strcmp(band, "all")) { fprintf(E, "awusctl scan: --band must be 2, 5 or all\n"); return 2; }
    const char *key = NULL;
    if (key_env) {
        key = getenv(key_env);
        if (!key || !*key) { fprintf(E, "awusctl %s: environment variable %s is empty or unset\n", cmd, key_env); return 2; }
    }

    if (!strcmp(cmd, "scan")) {
        int reach;
        int rc = scan_via_daemon(band, dwell, passes, json, &reach);
        if (reach) return rc;
        // no daemon: direct
        if (!freopen("/tmp/awusctl.log", "w", stderr)) return 2;
        setvbuf(stderr, NULL, _IOLBF, 0);
        int d = dwell ? dwell : 250, p = passes ? passes : 2;
        if (d < 20 || d > 5000 || p < 1 || p > 50) { fprintf(E, "awusctl scan: bad --dwell (20-5000) or --passes (1-50)\n"); return 2; }
        if (country && country_norm(country, (char[3]){0})) { fprintf(E, "awusctl scan: unknown country\n"); return 2; }
        return cmd_scan_direct(band, d, p, json, country);
    }
    if (!strcmp(cmd, "join")) {
        if (!ssid || !*ssid || strlen(ssid) > 32) { fprintf(E, "awusctl join: --ssid S (1-32 bytes) is required\n"); return 2; }
        if (ch < 0 || ch > 165) { fprintf(E, "awusctl join: bad --ch\n"); return 2; }
        req_t q = {0};
        rq_word(&q, "join"); rq_kv(&q, "ssid", ssid);
        char t[16];
        if (sec) rq_kv(&q, "sec", sec);
        if (key) rq_kv(&q, "key", key);
        if (bssid) rq_kv(&q, "bssid", bssid);
        if (ch) { snprintf(t, sizeof t, "%d", ch); rq_kv(&q, "ch", t); }
        if (hidden) rq_kv(&q, "hidden", "1");
        if (defroute) rq_kv(&q, "default_route", "1");
        if (g_prefer_psk) rq_kv(&q, "prefer_sae", "0");
        char *resp; const char *body;
        int rc = call(&q, &resp, &body);
        if (rc != 3) {
            if (rc) { fprintf(E, "awusctl join: %s\n", last_err + 4); free(resp); return 1; }
            char *b = strdup(body);
            char *sv2;
    for (char *l = strtok_r(b, "\n", &sv2); l; l = strtok_r(NULL, "\n", &sv2)) print_body_line(l);
            free(b); free(resp);
            return 0;
        }
        return cmd_join_direct(ssid, bssid, ch, hidden, sec, key_env, keyid);
    }
    if (!strcmp(cmd, "bench")) {       // direct-mode join + goodput measurement, then leave
        if (!ssid || !*ssid || strlen(ssid) > 32) { fprintf(E, "awusctl bench: --ssid S is required\n"); return 2; }
        char *x = rpc("status");
        if (x) { free(x); fprintf(E, "awusctl bench: awusd is running; stop it first (bench drives the USB device itself)\n"); return 2; }
        g_bench = 1;
        return cmd_join_direct(ssid, bssid, ch, hidden, sec, key_env, keyid);
    }
    if (!strcmp(cmd, "profile")) {
        if (npos < 1) return usage(stderr);
        req_t q = {0};
        rq_word(&q, "profile"); rq_word(&q, pos[0]);
        if (ssid) rq_kv(&q, "ssid", ssid);
        if (key) rq_kv(&q, "key", key);
        if (security) rq_kv(&q, "security", security);
        if (hidden) rq_kv(&q, "hidden", "1");
        if (have_prio) { char t[16]; snprintf(t, sizeof t, "%d", prio); rq_kv(&q, "priority", t); }
        if (noauto) rq_kv(&q, "autojoin", "0");
        if (defroute) rq_kv(&q, "default_route", "1");
        if (g_prefer_psk) rq_kv(&q, "prefer_sae", "0");
        return simple_cmd(&q);
    }
    if (!strcmp(cmd, "wps")) {
        if (npos < 1) return usage(stderr);
        if (pin_env) { pin_arg = getenv(pin_env); if (!pin_arg || !*pin_arg) { fprintf(E, "awusctl wps: environment variable %s is empty or unset\n", pin_env); return 2; } }
        req_t q = {0};
        rq_word(&q, "wps"); rq_word(&q, pos[0]);
        if (pin_arg) rq_kv(&q, "pin", pin_arg);
        if (ssid) rq_kv(&q, "ssid", ssid);
        if (bssid) rq_kv(&q, "bssid", bssid);
        return simple_cmd(&q);
    }
    if (!strcmp(cmd, "adhoc")) {
        if (npos < 1) return usage(stderr);
        req_t q = {0};
        rq_word(&q, "adhoc"); rq_word(&q, pos[0]);
        if (ssid) rq_kv(&q, "ssid", ssid);
        if (ch) { char t[16]; snprintf(t, sizeof t, "%d", ch); rq_kv(&q, "ch", t); }
        if (key) rq_kv(&q, "key", key);
        return simple_cmd(&q);
    }
    if (!strcmp(cmd, "ping")) {
        req_t q = {0};
        rq_word(&q, "ping");
        if (host) rq_kv(&q, "host", host);
        if (count) { char t[16]; snprintf(t, sizeof t, "%d", count); rq_kv(&q, "count", t); }
        return simple_cmd(&q);
    }
    static const char *const known[] = { "status", "leave", "rf", "txpower", "country", "autojoin", "debug", "quit", NULL };
    for (int i = 0; known[i]; i++) if (!strcmp(cmd, known[i])) {
        req_t q = {0};
        rq_word(&q, cmd);
        for (int k = 0; k < npos; k++) rq_word(&q, pos[k]);
        return simple_cmd(&q);
    }
    fprintf(E, "awusctl: unknown command %s\n", cmd);
    return usage(stderr);
}
