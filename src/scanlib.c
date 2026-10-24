// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// scanlib: channel-hopping scan with Beacon / Probe Response collection, shared by `awusctl scan` (direct mode) and awusd.
// Hops channels (2.4 GHz 1-13; 5 GHz 36-64, 100-144, 149-165) allowed by the country (NULL = all), collects Beacons and
// Probe Responses and keeps one row per BSSID: SSID, BSSID, channel (from the frame's own DS/HT element), RSSI, security.
// Passive on DFS channels (52-144). On every other channel it sends ONE broadcast wildcard Probe Request per dwell
// (what any station does). No deauth/disassoc frames exist here; nothing is ever sent to a named network.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rtl.h"
#include "phy.h"
#include "rx.h"
#include "tx.h"
#include "scanlib.h"
#include "country.h"
#include "link.h"

static const int chan24[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static const int chan5[]  = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};
#define N24 (int)(sizeof(chan24)/sizeof(chan24[0]))
#define N5  (int)(sizeof(chan5)/sizeof(chan5[0]))
#define now_ms link_now_ms

int scan_is_hidden(const scan_ap_t *a)
{
    if (!a->has_ssid || a->ssid_len == 0) return 1;
    for (int i = 0; i < a->ssid_len; i++) if (a->ssid[i]) return 0;
    return 1;                    // all-zero SSID of any length is how APs hide it
}


static void classify(const scan_t *s, scan_entry_t *e)
{
    int c = s->country[0] ? country_chan(s->country, e->channel) : CC_OK;
    e->allowed = c != CC_BLOCKED;
    e->dfs = c == CC_DFS;
}

static void on_frame(void *ud, const rtl_frame_t *f)
{
    scan_t *S = ud;
    if (f->crc_err || !f->has_fcs || f->len < 24 + 12 + 4) return;
    int sub = f->data[0] & 0xFC;
    if (sub != 0x80 && sub != 0x50) return;            // beacon / probe response
    const uint8_t *bssid = f->data + 16;
    scan_ap_t a;
    if (scan_parse_beacon(f->data + 24, f->len - 24 - 4, &a)) return;
    scan_entry_t *e = NULL;
    for (int i = 0; i < S->n; i++) if (!memcmp(S->aps[i].bssid, bssid, 6)) { e = &S->aps[i]; break; }
    if (!e) {
        if (S->n >= SCAN_MAX_APS) { S->dropped++; return; }
        e = &S->aps[S->n++];
        memset(e, 0, sizeof *e);
        memcpy(e->bssid, bssid, 6);
        e->ap = a;
    } else if (scan_is_hidden(&e->ap) && !scan_is_hidden(&a)) {
        e->ap = a;               // a Probe Response revealed the SSID of a hidden network
    } else if (!e->ap.rsn && !e->ap.wpa1 && (a.rsn || a.wpa1)) {
        e->ap = a;               // keep the richest copy
    }
    e->channel = a.channel ? a.channel : (e->ap.channel ? e->ap.channel : f->channel);
    if (f->rssi_valid) { e->rssi_sum += f->rssi_dbm; e->rssi_n++; }
    if (sub == 0x50) e->seen_probe_resp = 1;
    classify(S, e);
}

static int send_wildcard_probe(rtl_t *r, const uint8_t *sa)
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

int scan_rssi(const scan_entry_t *e) { return e->rssi_n ? (int)(e->rssi_sum / e->rssi_n) : 0; }

static int cmp_rssi(const void *x, const void *y)
{
    const scan_entry_t *a = x, *b = y;
    int ra = a->rssi_n ? scan_rssi(a) : -999, rb = b->rssi_n ? scan_rssi(b) : -999;
    return rb - ra;
}

void scan_sort(scan_t *s) { qsort(s->aps, s->n, sizeof s->aps[0], cmp_rssi); }

void scan_reset(scan_t *s, const char *country)
{
    memset(s, 0, sizeof *s);
    if (country && *country) snprintf(s->country, sizeof s->country, "%s", country);
}

int scan_run(rtl_t *r, scan_t *s, int band, int dwell, int passes, volatile int *abort)
{
    int list[N24 + N5], nl = 0;
    if (band != 5) for (int i = 0; i < N24; i++) list[nl++] = chan24[i];
    if (band != 2) for (int i = 0; i < N5; i++) list[nl++] = chan5[i];
    s->sa[0] = 0x02; for (int i = 1; i < 6; i++) s->sa[i] = rand() & 0xFF;     // locally-administered, random, ours only
    for (int i = 0; i < 6; i++) rtl_w8(r, 0x0610 + i, s->sa[i]);
    for (int p = 0; p < passes; p++) {
        for (int i = 0; i < nl; i++) {
            int ch = list[i];
            if (abort && *abort) return 1;
            if ((p || i || r->channel != ch) && rtl_set_channel(r, ch, 1)) return -1;
            // listen everywhere (receiving is harmless), but only transmit on channels the country allows without radar rules
            if (!is_dfs(ch) && (!s->country[0] || country_chan(s->country, ch) == CC_OK)) send_wildcard_probe(r, s->sa);
            long t0 = now_ms();
            while (now_ms() - t0 < dwell) {
                if (abort && *abort) return 1;
                int n = rtl_rx_poll(r, on_frame, s, 20);
                if (n < 0) return -1;
            }
        }
    }
    return 0;
}

static void phy_str(const scan_entry_t *e, char *b, size_t n)
{
    const scan_ap_t *a = &e->ap;
    char h[24] = "";
    if (a->ht) { snprintf(h + strlen(h), sizeof h - strlen(h), "n"); if (a->nss) snprintf(h + strlen(h), sizeof h - strlen(h), "%d", a->nss); }
    if (a->vht) snprintf(h + strlen(h), sizeof h - strlen(h), "%sac", h[0] ? "/" : "");
    if (a->he)  snprintf(h + strlen(h), sizeof h - strlen(h), "%sax", h[0] ? "/" : "");
    if (!h[0]) snprintf(h, sizeof h, "legacy");
    snprintf(b, n, "%g %s", a->max_rate / 2.0, h);
}

void scan_row(const scan_entry_t *e, scan_row_t *w)
{
    memset(w, 0, sizeof *w);
    w->hidden = scan_is_hidden(&e->ap);
    if (w->hidden) strcpy(w->ssid, "<hidden>"); else ssid_text(&e->ap, 0, w->ssid, sizeof w->ssid);
    ssid_text(&e->ap, 1, w->ssid_json, sizeof w->ssid_json);
    snprintf(w->bssid, sizeof w->bssid, "%02x:%02x:%02x:%02x:%02x:%02x", e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5]);
    w->channel = e->channel; w->rssi = scan_rssi(e);
    scan_security_str(&e->ap, w->security, sizeof w->security);
    scan_cipher_str(&e->ap, w->cipher, sizeof w->cipher);
    phy_str(e, w->phy, sizeof w->phy);
    w->wps = e->ap.wps; w->allowed = e->allowed; w->dfs = e->dfs;
    w->ht = e->ap.ht; w->vht = e->ap.vht; w->he = e->ap.he; w->streams = e->ap.nss; w->max_rate = e->ap.max_rate / 2.0;
}

void scan_print_table(FILE *o, const scan_row_t *rows, int n)
{
    fprintf(o, "%-24s %-17s %3s %5s  %-20s %-9s %-3s %-14s %s\n", "SSID", "BSSID", "CH", "RSSI", "SECURITY", "CIPHER", "WPS", "LEGACY(Mb/s) PHY", "COUNTRY");
    for (int i = 0; i < n; i++) {
        const scan_row_t *w = &rows[i];
        fprintf(o, "%-24s %-17s %3d %5d  %-20s %-9s %-3s %-14s %s\n", w->ssid, w->bssid, w->channel, w->rssi, w->security, w->cipher,
                w->wps ? "yes" : "no", w->phy, w->allowed ? (w->dfs ? "dfs" : "ok") : "BLOCKED");
    }
    fprintf(o, "%d network(s)\n", n);
}

void scan_print_json(FILE *o, const scan_row_t *rows, int n)
{
    fprintf(o, "[\n");
    for (int i = 0; i < n; i++) {
        const scan_row_t *w = &rows[i];
        fprintf(o, "  {\"ssid\": \"%s\", \"hidden\": %s, \"bssid\": \"%s\", \"channel\": %d, "
               "\"band\": \"%s\", \"rssi\": %d, \"security\": \"%s\", \"cipher\": \"%s\", \"wps\": %s, "
               "\"max_rate_mbps\": %g, \"ht\": %s, \"vht\": %s, \"he\": %s, \"streams\": %d, "
               "\"allowed\": %s, \"dfs\": %s}%s\n",
               w->hidden ? "" : w->ssid_json, w->hidden ? "true" : "false", w->bssid,
               w->channel, w->channel > 14 ? "5GHz" : "2.4GHz", w->rssi, w->security, w->cipher,
               w->wps ? "true" : "false", w->max_rate, w->ht ? "true" : "false",
               w->vht ? "true" : "false", w->he ? "true" : "false", w->streams,
               w->allowed ? "true" : "false", w->dfs ? "true" : "false", i + 1 < n ? "," : "");
    }
    fprintf(o, "]\n");
}
