// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Stage 3 CLI: power on, firmware, PHY/MAC init, monitor-mode capture to pcap.
//   monitor [-c CH] [-t SECONDS] [-o out.pcap] [--hop | --hop5 | --hopall] [-v]
//   --hop    2.4 GHz channels 1..13
//   --hop5   5 GHz channels 36,40,44,48,52..64,100..144,149..165 (includes DFS; passive only, no TX scheduled there)
//   --hopall 2.4 GHz + 5 GHz
// Prints one final line: STAGE3 OK frames=N beacons=B ssids=a,b,c  |  STAGE3 FAIL <step> <reason>
// Register log: /tmp/monitor.log
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rtl.h"
#include "phy.h"
#include "mac.h"
#include "rx.h"
#include "bringup.h"
#include "pcap.h"

#define MAX_SSIDS 64
static char ssids[MAX_SSIDS][33];
static int nssid;
static unsigned long nframes, nbeacons, nfcs;
static rtl_pcap_t pc;
static int have_pcap;
static unsigned long per_chan[200];

static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }

// Hop lists. 5 GHz: UNII-1 (36-48), UNII-2/2e (52-64, 100-144, all DFS), UNII-3 (149-165).
static const int chan24[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static const int chan5[]  = {36,40,44,48,52,56,60,64,
                             100,104,108,112,116,120,124,128,132,136,140,144,
                             149,153,157,161,165};
#define N24 (int)(sizeof(chan24)/sizeof(chan24[0]))
#define N5  (int)(sizeof(chan5)/sizeof(chan5[0]))

static void add_ssid(const uint8_t *s, int n)
{
    char b[33]; int k = 0;
    for (int i = 0; i < n && i < 32; i++) b[k++] = (s[i] >= 32 && s[i] < 127) ? s[i] : '?';
    b[k] = 0;
    if (!k) return;
    for (int i = 0; i < nssid; i++) if (!strcmp(ssids[i], b)) return;
    if (nssid < MAX_SSIDS) strcpy(ssids[nssid++], b);
}

static void on_frame(void *ud, const rtl_frame_t *f)
{
    (void)ud;
    if (f->crc_err || f->len < 10) return;
    nframes++;
    nfcs += f->has_fcs;
    if (f->channel > 0 && f->channel < 200) per_chan[f->channel]++;
    if (have_pcap) rtl_pcap_write(&pc, f);
    if (f->len >= 40 && (f->data[0] & 0xFC) == 0x80) {                         // mgmt, subtype 8 = beacon
        nbeacons++;
        const uint8_t *p = f->data + 36;
        const uint8_t *end = f->data + f->len - (f->has_fcs ? 4 : 0);
        while (p + 2 <= end && p + 2 + p[1] <= end) {
            if (p[0] == 0) { add_ssid(p + 2, p[1]); break; }
            p += 2 + p[1];
        }
    }
}

static int fail(rtl_t *r, const char *step, const char *why)
{
    printf("STAGE3 FAIL %s %s\n", step, why);
    fprintf(stderr, "STAGE3 FAIL %s %s\n", step, why);
    rtl_close(r);
    return 1;
}

int main(int argc, char **argv)
{
    int ch = 6, secs = 10, hop = 0, hop5 = 0, hopall = 0;
    const char *out = NULL;
    rtl_t r = {0};
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) ch = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) secs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--hop")) hop = 1;
        else if (!strcmp(argv[i], "--hop5")) hop5 = 1;
        else if (!strcmp(argv[i], "--hopall")) hopall = 1;
        else if (!strcmp(argv[i], "-v")) r.verbose = 2;
    }
    int anyhop = hop || hop5 || hopall;
    int hoplist[N24 + N5], nhop = 0, dwell_ms = 200;
    if (hopall) { for (int i = 0; i < N24; i++) hoplist[nhop++] = chan24[i]; for (int i = 0; i < N5; i++) hoplist[nhop++] = chan5[i]; dwell_ms = 250; }
    else if (hop5) { for (int i = 0; i < N5; i++) hoplist[nhop++] = chan5[i]; dwell_ms = 250; }
    else if (hop) { for (int i = 0; i < N24; i++) hoplist[nhop++] = chan24[i]; dwell_ms = 200; }

    if (!freopen("/tmp/monitor.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!r.verbose) r.verbose = 1;       // log every register access

    int e;
    char b[96];
    const char *step;
    if (rtl_bringup(&r, anyhop ? hoplist[0] : ch, &step, b, sizeof b)) return fail(&r, step, b);
    if ((e = rtl_set_monitor(&r))) { snprintf(b, sizeof b, "error %d", e); return fail(&r, "set_monitor", b); }

    if (out) {
        if (rtl_pcap_open(&pc, out)) return fail(&r, "pcap_open", out);
        have_pcap = 1;
    }
    long t0 = now_ms(), tch = t0;
    int idx = 0;
    int cur = anyhop ? hoplist[0] : ch;
    if (r.verbose < 2) r.verbose = 0;
    fprintf(stderr, "STEP capture channel=%d secs=%d hop=%d hop5=%d hopall=%d nhop=%d dwell_ms=%d\n", cur, secs, hop, hop5, hopall, nhop, dwell_ms);
    while (now_ms() - t0 < secs * 1000L) {
        int n = rtl_rx_poll(&r, on_frame, NULL, 50);
        if (n < 0) { r.verbose = 1; snprintf(b, sizeof b, "rx error %d", n); if (have_pcap) rtl_pcap_close(&pc); return fail(&r, "rx", b); }
        if (anyhop && now_ms() - tch >= dwell_ms) {
            idx = (idx + 1) % nhop;
            cur = hoplist[idx];
            if (rtl_set_channel(&r, cur, 1)) { r.verbose = 1; if (have_pcap) rtl_pcap_close(&pc); return fail(&r, "hop", "set_channel"); }
            tch = now_ms();
        }
    }
    if (have_pcap) rtl_pcap_close(&pc);
    fprintf(stderr, "rx stats: transfers=%lu bytes=%lu frames=%lu c2h=%lu bad_desc=%lu crc_err=%lu\n", rtl_rx_stats.transfers,
            rtl_rx_stats.bytes, rtl_rx_stats.frames, rtl_rx_stats.c2h, rtl_rx_stats.bad_desc, rtl_rx_stats.crc_err);
    fprintf(stderr, "frames with valid trailing FCS: %lu of %lu\n", nfcs, nframes);
    for (int c = 1; c < 200; c++) if (per_chan[c]) fprintf(stderr, "  ch %d: %lu frames\n", c, per_chan[c]);

    char list[512] = "";
    for (int i = 0; i < nssid && i < 10; i++) { if (i) strcat(list, ","); strcat(list, ssids[i]); }
    char line[768];
    if (nframes == 0) snprintf(line, sizeof line, "STAGE3 FAIL rx no frames (transfers=%lu bytes=%lu, see /tmp/monitor.log)", rtl_rx_stats.transfers, rtl_rx_stats.bytes);
    else snprintf(line, sizeof line, "STAGE3 OK frames=%lu beacons=%lu ssids=%s", nframes, nbeacons, list);
    puts(line);
    fprintf(stderr, "%s\n", line);
    rtl_close(&r);
    return nframes ? 0 : 1;
}
