// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// awusctl: command-line control of the adapter (vendor-parity checklist). Subcommands:
//   awusctl scan [--band 2|5|all] [--dwell MS] [--passes N] [--json]
//   awusctl join --ssid S [--bssid B] [--ch N] [--hidden] [--sec open|wep|wpa|wpa2|auto] [--key-env VAR] [--wep-keyid N]
// `join` associates, runs the security handshake, gets a DHCP lease, pings the gateway, then leaves (Deauthentication,
// reason 3). It needs no root (no utun). The passphrase / WEP key is read from the environment variable named by --key-env,
// never from argv. Only join networks you own or are allowed to test.
// Hops channels (2.4 GHz 1-13; 5 GHz 36-64, 100-144, 149-165), collects Beacons and Probe Responses and prints one
// row per BSSID: SSID, BSSID, channel (from the frame's own DS/HT element, not the RX channel), RSSI, security, WPS, rates.
// Passive on DFS channels (52-144). On every other channel it sends ONE broadcast wildcard Probe Request per dwell
// (the normal thing any station does). No deauth/disassoc frames exist in this file; nothing is ever sent to a named network.
// Log: /tmp/awusctl.log
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include "rtl.h"
#include "phy.h"
#include "mac.h"
#include "rx.h"
#include "tx.h"
#include "bringup.h"
#include "scanparse.h"
#include "link.h"

static const int chan24[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static const int chan5[]  = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};
#define N24 (int)(sizeof(chan24)/sizeof(chan24[0]))
#define N5  (int)(sizeof(chan5)/sizeof(chan5[0]))

#define MAX_APS 256
typedef struct {
    uint8_t bssid[6];
    scan_ap_t ap;
    int channel;                 // true primary channel (IE) or, failing that, the channel we heard it on
    long rssi_sum; int rssi_n;
    int seen_probe_resp;
} entry_t;
static entry_t aps[MAX_APS];
static int naps;
static uint8_t sa[6];
static int dropped;
static FILE *E;                  // user-facing messages; stderr itself is redirected to the register log

static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }

static int is_hidden(const scan_ap_t *a)
{
    if (!a->has_ssid || a->ssid_len == 0) return 1;
    for (int i = 0; i < a->ssid_len; i++) if (a->ssid[i]) return 0;
    return 1;                    // all-zero SSID of any length is how APs hide it
}

static void on_frame(void *ud, const rtl_frame_t *f)
{
    (void)ud;
    if (f->crc_err || !f->has_fcs || f->len < 24 + 12 + 4) return;
    int sub = f->data[0] & 0xFC;
    if (sub != 0x80 && sub != 0x50) return;            // beacon / probe response
    const uint8_t *bssid = f->data + 16;
    scan_ap_t a;
    if (scan_parse_beacon(f->data + 24, f->len - 24 - 4, &a)) return;
    entry_t *e = NULL;
    for (int i = 0; i < naps; i++) if (!memcmp(aps[i].bssid, bssid, 6)) { e = &aps[i]; break; }
    if (!e) {
        if (naps >= MAX_APS) { dropped++; return; }
        e = &aps[naps++];
        memset(e, 0, sizeof *e);
        memcpy(e->bssid, bssid, 6);
        e->ap = a;
    } else if (is_hidden(&e->ap) && !is_hidden(&a)) {
        e->ap = a;               // a Probe Response revealed the SSID of a hidden network
    } else if (!e->ap.rsn && !e->ap.wpa1 && (a.rsn || a.wpa1)) {
        e->ap = a;               // keep the richest copy
    }
    e->channel = a.channel ? a.channel : (e->ap.channel ? e->ap.channel : f->channel);
    if (f->rssi_valid) { e->rssi_sum += f->rssi_dbm; e->rssi_n++; }
    if (sub == 0x50) e->seen_probe_resp = 1;
}

// Broadcast wildcard Probe Request (SSID element of length 0): header 24 bytes + SSID + Supported Rates.
static int send_wildcard_probe(rtl_t *r)
{
    static const uint8_t bc[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    static const uint8_t rates[] = {0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C};   // OFDM 6..54 Mbps, no CCK
    uint8_t f[48];
    int n = 0;
    f[n++] = 0x40; f[n++] = 0x00;          // FC: mgmt, probe request
    f[n++] = 0x00; f[n++] = 0x00;          // duration
    memcpy(f + n, bc, 6); n += 6;          // DA
    memcpy(f + n, sa, 6); n += 6;          // SA: our random locally-administered address
    memcpy(f + n, bc, 6); n += 6;          // BSSID: wildcard
    f[n++] = 0x00; f[n++] = 0x00;          // seq (hardware fills)
    f[n++] = 0x00; f[n++] = 0x00;          // SSID element, length 0 = wildcard
    f[n++] = 0x01; f[n++] = sizeof rates;
    memcpy(f + n, rates, sizeof rates); n += sizeof rates;
    return rtl_tx_frame(r, f, n, 60, 0);   // 6 Mbps OFDM, broadcast: no hardware retries
}

static int is_dfs(int ch) { return ch >= 52 && ch <= 144; }

// SSID for display: valid UTF-8 passes through, control bytes become '?', invalid UTF-8 becomes '?' per byte.
static int utf8_len(const uint8_t *s, int n)
{
    if (s[0] < 0x80) return 1;
    int l = (s[0] & 0xE0) == 0xC0 ? 2 : (s[0] & 0xF0) == 0xE0 ? 3 : (s[0] & 0xF8) == 0xF0 ? 4 : 0;
    if (!l || l > n) return 0;
    for (int i = 1; i < l; i++) if ((s[i] & 0xC0) != 0x80) return 0;
    return l;
}

static void ssid_text(const scan_ap_t *a, int json, char *out, size_t on)
{
    size_t k = 0;
    for (int i = 0; i < a->ssid_len; ) {
        int l = utf8_len(a->ssid + i, a->ssid_len - i);
        char tmp[8];
        int tl;
        if (l == 1) {
            uint8_t c = a->ssid[i];
            if (json && c == '"') { memcpy(tmp, "\\\"", 2); tl = 2; }
            else if (json && c == '\\') { memcpy(tmp, "\\\\", 2); tl = 2; }
            else if (c < 32 || c == 127) { if (json) tl = snprintf(tmp, sizeof tmp, "\\u%04x", c); else { tmp[0] = '?'; tl = 1; } }
            else { tmp[0] = (char)c; tl = 1; }
            i++;
        } else if (l > 1) { memcpy(tmp, a->ssid + i, l); tl = l; i += l; }
        else { tmp[0] = '?'; tl = 1; i++; }
        if (k + tl + 1 > on) break;
        memcpy(out + k, tmp, tl); k += tl;
    }
    out[k] = 0;
}

static int cmp_rssi(const void *x, const void *y)
{
    const entry_t *a = x, *b = y;
    int ra = a->rssi_n ? (int)(a->rssi_sum / a->rssi_n) : -999, rb = b->rssi_n ? (int)(b->rssi_sum / b->rssi_n) : -999;
    return rb - ra;
}

static void phy_str(const entry_t *e, char *b, size_t n)
{
    const scan_ap_t *a = &e->ap;
    char h[24] = "";
    if (a->ht) { snprintf(h + strlen(h), sizeof h - strlen(h), "n"); if (a->nss) snprintf(h + strlen(h), sizeof h - strlen(h), "%d", a->nss); }
    if (a->vht) snprintf(h + strlen(h), sizeof h - strlen(h), "%sac", h[0] ? "/" : "");
    if (a->he)  snprintf(h + strlen(h), sizeof h - strlen(h), "%sax", h[0] ? "/" : "");
    if (!h[0]) snprintf(h, sizeof h, "legacy");
    snprintf(b, n, "%g %s", a->max_rate / 2.0, h);
}

static void print_table(void)
{
    printf("%-24s %-17s %3s %5s  %-20s %-9s %-3s %s\n", "SSID", "BSSID", "CH", "RSSI", "SECURITY", "CIPHER", "WPS", "LEGACY(Mb/s) PHY");
    for (int i = 0; i < naps; i++) {
        entry_t *e = &aps[i];
        char ss[200], sec[64], ci[32], ph[48];
        if (is_hidden(&e->ap)) strcpy(ss, "<hidden>"); else ssid_text(&e->ap, 0, ss, sizeof ss);
        scan_security_str(&e->ap, sec, sizeof sec);
        scan_cipher_str(&e->ap, ci, sizeof ci);
        phy_str(e, ph, sizeof ph);
        printf("%-24s %02x:%02x:%02x:%02x:%02x:%02x %3d %5d  %-20s %-9s %-3s %s\n", ss,
               e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5],
               e->channel, e->rssi_n ? (int)(e->rssi_sum / e->rssi_n) : 0, sec, ci, e->ap.wps ? "yes" : "no", ph);
    }
    printf("%d network(s)\n", naps);
}

static void print_json(void)
{
    printf("[\n");
    for (int i = 0; i < naps; i++) {
        entry_t *e = &aps[i];
        char ss[200], sec[64], ci[32];
        ssid_text(&e->ap, 1, ss, sizeof ss);
        scan_security_str(&e->ap, sec, sizeof sec);
        scan_cipher_str(&e->ap, ci, sizeof ci);
        printf("  {\"ssid\": \"%s\", \"hidden\": %s, \"bssid\": \"%02x:%02x:%02x:%02x:%02x:%02x\", \"channel\": %d, "
               "\"band\": \"%s\", \"rssi\": %d, \"security\": \"%s\", \"cipher\": \"%s\", \"wps\": %s, "
               "\"max_rate_mbps\": %g, \"ht\": %s, \"vht\": %s, \"he\": %s, \"streams\": %d}%s\n",
               is_hidden(&e->ap) ? "" : ss, is_hidden(&e->ap) ? "true" : "false",
               e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5],
               e->channel, e->channel > 14 ? "5GHz" : "2.4GHz", e->rssi_n ? (int)(e->rssi_sum / e->rssi_n) : 0, sec, ci,
               e->ap.wps ? "true" : "false", e->ap.max_rate / 2.0, e->ap.ht ? "true" : "false",
               e->ap.vht ? "true" : "false", e->ap.he ? "true" : "false", e->ap.nss, i + 1 < naps ? "," : "");
    }
    printf("]\n");
}

static int cmd_scan(int argc, char **argv)
{
    int band = 0, dwell = 250, passes = 2, json = 0;      // band: 0 = all, 2, 5
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--band") && i + 1 < argc) {
            i++;
            if (!strcmp(argv[i], "2")) band = 2; else if (!strcmp(argv[i], "5")) band = 5; else if (!strcmp(argv[i], "all")) band = 0;
            else { fprintf(E, "awusctl scan: --band must be 2, 5 or all\n"); return 2; }
        } else if (!strcmp(argv[i], "--dwell") && i + 1 < argc) dwell = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--passes") && i + 1 < argc) passes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json")) json = 1;
        else { fprintf(E, "awusctl scan: unknown option %s\n", argv[i]); return 2; }
    }
    if (dwell < 20 || dwell > 5000 || passes < 1 || passes > 50) { fprintf(E, "awusctl scan: bad --dwell (20-5000) or --passes (1-50)\n"); return 2; }
    int list[N24 + N5], nl = 0;
    if (band != 5) for (int i = 0; i < N24; i++) list[nl++] = chan24[i];
    if (band != 2) for (int i = 0; i < N5; i++) list[nl++] = chan5[i];

    rtl_t r = {0};
    char b[160];
    const char *step;
    r.verbose = 1;                                          // register log goes to /tmp/awusctl.log
    if (rtl_bringup(&r, list[0], &step, b, sizeof b)) { fprintf(E, "awusctl: bring-up failed at %s: %s\n", step, b); return 1; }
    if (rtl_set_monitor(&r)) { fprintf(E, "awusctl: set_monitor failed\n"); rtl_close(&r); return 1; }
    r.verbose = 0;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    sa[0] = 0x02; for (int i = 1; i < 6; i++) sa[i] = rand() & 0xFF;     // locally-administered, random, ours only
    for (int i = 0; i < 6; i++) rtl_w8(&r, 0x0610 + i, sa[i]);

    for (int p = 0; p < passes; p++) {
        for (int i = 0; i < nl; i++) {
            int ch = list[i];
            if ((p || i) && rtl_set_channel(&r, ch, 1)) { fprintf(E, "awusctl: set_channel %d failed\n", ch); rtl_close(&r); return 1; }
            if (!is_dfs(ch)) send_wildcard_probe(&r);
            long t0 = now_ms();
            while (now_ms() - t0 < dwell) {
                int n = rtl_rx_poll(&r, on_frame, NULL, 20);
                if (n < 0) { fprintf(E, "awusctl: rx error %d\n", n); rtl_close(&r); return 1; }
            }
        }
        // return to the first channel for the next pass
        if (p + 1 < passes && rtl_set_channel(&r, list[0], 1)) { fprintf(E, "awusctl: set_channel failed\n"); rtl_close(&r); return 1; }
    }
    rtl_close(&r);
    if (dropped) fprintf(E, "awusctl: %d network(s) not listed (table full)\n", dropped);
    qsort(aps, naps, sizeof aps[0], cmp_rssi);
    if (json) print_json(); else print_table();
    return 0;
}

static volatile sig_atomic_t stop_req;
static void on_sig(int s) { (void)s; stop_req = 1; }

static int cmd_join(int argc, char **argv)
{
    const char *ssid = NULL, *key_env = NULL; uint8_t bssid[6]; int have_b = 0, ch = 0, hidden = 0, keyid = 0;
    link_sec_t sec = LINK_SEC_AUTO;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--ssid") && i + 1 < argc) ssid = argv[++i];
        else if (!strcmp(argv[i], "--bssid") && i + 1 < argc)
            have_b = sscanf(argv[++i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) == 6;
        else if (!strcmp(argv[i], "--ch") && i + 1 < argc) ch = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hidden")) hidden = 1;
        else if (!strcmp(argv[i], "--key-env") && i + 1 < argc) key_env = argv[++i];
        else if (!strcmp(argv[i], "--wep-keyid") && i + 1 < argc) keyid = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sec") && i + 1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v, "auto")) sec = LINK_SEC_AUTO; else if (!strcmp(v, "open")) sec = LINK_SEC_OPEN;
            else if (!strcmp(v, "wep")) sec = LINK_SEC_WEP; else if (!strcmp(v, "wep-shared")) sec = LINK_SEC_WEP_SHARED;
            else if (!strcmp(v, "wpa")) sec = LINK_SEC_WPA; else if (!strcmp(v, "wpa2")) sec = LINK_SEC_WPA2;
            else { fprintf(E, "awusctl join: --sec must be auto, open, wep, wep-shared, wpa or wpa2\n"); return 2; }
        } else { fprintf(E, "awusctl join: unknown or incomplete option %s\n", argv[i]); return 2; }
    }
    if (!ssid || !*ssid || strlen(ssid) > 32) { fprintf(E, "awusctl join: --ssid S (1-32 bytes) is required\n"); return 2; }
    if (ch < 0 || ch > 165) { fprintf(E, "awusctl join: bad --ch\n"); return 2; }
    const char *key = NULL;
    if (key_env) {
        key = getenv(key_env);
        if (!key || !*key) { fprintf(E, "awusctl join: environment variable %s is empty or unset\n", key_env); return 2; }
    }
    if ((sec == LINK_SEC_WPA || sec == LINK_SEC_WPA2 || sec == LINK_SEC_WEP || sec == LINK_SEC_WEP_SHARED) && !key) {
        fprintf(E, "awusctl join: --sec %s needs --key-env VAR\n", link_sec_str(sec)); return 2;
    }
    if (sec == LINK_SEC_OPEN) key = NULL;
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
    link_cfg_t cfg = { .ssid = ssid, .bssid = have_b ? bssid : NULL, .channel = ch, .hidden = hidden, .sec = sec, .key = key, .wep_keyid = keyid };
    int rc = 1;
    if (link_join(&r, &cfg, &L)) { fprintf(E, "join FAIL %s %s\n", L.fail_step, L.fail_reason); goto out; }
    char ips[20], gws[20];
    link_ipstr(ips, sizeof ips, L.n.lease.ip); link_ipstr(gws, sizeof gws, L.n.lease.gw);
    link_ping_t pr;
    int prc = link_ping(&L, L.n.lease.gw, 6, &pr);
    if (prc) { fprintf(E, "join FAIL ping %s (ip=%s gw=%s)\n", prc > 0 ? "no_reply_to_first_echo" : "deauthenticated_or_stopped", ips, gws); goto out; }
    fprintf(E, "join OK sec=%s pairwise=%s group=%s ch=%d ip=%s gw=%s ping %d/%d loss %d%% avg_rtt %ldms\n",
            link_sec_str(L.sec), link_cipher_str(L.pw_cipher), link_cipher_str(L.grp_cipher), L.s.channel, ips, gws,
            pr.recv, pr.sent, pr.sent ? 100 - 100 * pr.recv / pr.sent : 100, pr.avg_rtt_ms);
    rc = pr.recv == pr.sent ? 0 : 3;
out:
    if (L.s.associated) link_leave(&L);
    rtl_close(&r);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "scan") && strcmp(argv[1], "join"))) {
        fprintf(stderr, "usage: awusctl scan [--band 2|5|all] [--dwell MS] [--passes N] [--json]\n"
                        "       awusctl join --ssid S [--bssid B] [--ch N] [--hidden] [--sec open|wep|wep-shared|wpa|wpa2|auto]\n"
                        "                    [--key-env VAR] [--wep-keyid N]\n"
                        "  join: associate, DHCP, ping the gateway 6 times, leave. No root needed. The passphrase or WEP key\n"
                        "  comes from the environment variable VAR only. Example:\n"
                        "    MYPSK=... awusctl join --ssid HomeNet --ch 36 --key-env MYPSK\n");
        return 2;
    }
    E = fdopen(dup(2), "w");
    if (!E || !freopen("/tmp/awusctl.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0);
    int rc = !strcmp(argv[1], "join") ? cmd_join(argc - 2, argv + 2) : cmd_scan(argc - 2, argv + 2);
    fflush(E);
    return rc;
}
