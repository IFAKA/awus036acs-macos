// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Stage 4 CLI: bring up the chip, set channel, send crafted 802.11 frames.
//   inject [-c CH] [--rate N (Mbps, 1 2 5 11 6 9 12 18 24 36 48 54; 5=5.5)] [-n COUNT] [--probe] [-i MS] [--rx SECS] [-v]
// Prints one final line: STAGE4 OK sent=N  |  STAGE4 FAIL <step> <reason>.  Register log: /tmp/inject.log
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rtl.h"
#include "phy.h"
#include "mac.h"
#include "rx.h"
#include "tx.h"
#include "bringup.h"

static int fail(rtl_t *r, const char *step, const char *why)
{
    printf("STAGE4 FAIL %s %s\n", step, why);
    fprintf(stderr, "STAGE4 FAIL %s %s\n", step, why);
    rtl_close(r);
    return 1;
}

static unsigned long nrx;
static void on_frame(void *ud, const rtl_frame_t *f) { (void)ud; (void)f; nrx++; }

static int build_probe_req(uint8_t *p, const uint8_t *sa, const char *ssid)
{
    int n = 0, sl = strlen(ssid);
    p[n++] = 0x40; p[n++] = 0x00;                   // frame control: probe request
    p[n++] = 0; p[n++] = 0;                         // duration
    memset(p + n, 0xFF, 6); n += 6;                 // DA broadcast
    memcpy(p + n, sa, 6); n += 6;                   // SA
    memset(p + n, 0xFF, 6); n += 6;                 // BSSID wildcard
    p[n++] = 0; p[n++] = 0;                         // seq ctl (hardware fills)
    p[n++] = 0; p[n++] = sl; memcpy(p + n, ssid, sl); n += sl;                 // SSID
    static const uint8_t rates[] = {1, 8, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24,   // supported rates
                                    50, 4, 0x30, 0x48, 0x60, 0x6C};                        // extended rates
    memcpy(p + n, rates, sizeof rates); p[n] = 1; n += sizeof rates;
    p[n - 16] = 1;                                  // (id 1, len 8)
    return n;
}

int main(int argc, char **argv)
{
    int ch = 6, rate = 10, count = 5, probe = 1, interval = 100, rxsecs = 0;
    rtl_t r = {0};
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) ch = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rate") && i + 1 < argc) { double m = atof(argv[++i]); rate = (int)(m * 10 + 0.5); }
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-i") && i + 1 < argc) interval = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rx") && i + 1 < argc) rxsecs = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--probe")) probe = 1;
        else if (!strcmp(argv[i], "-v")) r.verbose = 2;
    }
    if (!freopen("/tmp/inject.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!r.verbose) r.verbose = 1;
    (void)probe;

    char b[160];
    const char *step;
    if (rtl_bringup(&r, ch, &step, b, sizeof b)) return fail(&r, step, b);
    int e;
    if ((e = rtl_set_monitor(&r))) { snprintf(b, sizeof b, "error %d", e); return fail(&r, "set_monitor", b); }
    if (r.verbose < 2) r.verbose = 0;

    srand(time(NULL) ^ getpid());
    uint8_t sa[6] = {0x02, rand() & 0xFF, rand() & 0xFF, rand() & 0xFF, rand() & 0xFF, rand() & 0xFF};
    char ssid[48];
    snprintf(ssid, sizeof ssid, "RTLMAC-TEST-%08x", (unsigned)(((unsigned)rand() << 16) ^ (unsigned)rand()));
    printf("ssid=%s sa=%02x:%02x:%02x:%02x:%02x:%02x ch=%d rate=%d.%d Mbps\n", ssid, sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], ch, rate / 10, rate % 10);
    fprintf(stderr, "ssid=%s\n", ssid);
    fflush(stdout);

    uint8_t fr[128];
    int len = build_probe_req(fr, sa, ssid);
    uint32_t txd0 = rtl_r32(&r, 0x0210);
    fprintf(stderr, "before: TXDMA_STATUS=0x%08X FIFOPAGE=0x%08X RQPN=0x%08X\n", txd0, rtl_r32(&r, 0x0230), rtl_r32(&r, 0x0200));
    int sent = 0;
    for (int i = 0; i < count; i++) {
        int rc = rtl_tx_frame(&r, fr, len, rate, 0);
        if (rc) { snprintf(b, sizeof b, "frame %d: tx rc=%d (see /tmp/inject.log)", i, rc); return fail(&r, "tx", b); }
        sent++;
        // drain the bulk-IN pipe for chip TX reports (C2H) and anything received
        long end = interval;
        while (end > 0) { int w = end > 20 ? 20 : end; int n = rtl_rx_poll(&r, on_frame, NULL, w); if (n < 0) break; end -= w; }
    }
    for (int k = 0; k < 10; k++) rtl_rx_poll(&r, on_frame, NULL, 30);
    fprintf(stderr, "after: TXDMA_STATUS=0x%08X FIFOPAGE=0x%08X RQPN=0x%08X\n", rtl_r32(&r, 0x0210), rtl_r32(&r, 0x0230), rtl_r32(&r, 0x0200));
    fprintf(stderr, "tx stats: submitted=%lu completed=%lu failed=%lu ccx=%lu ok=%lu retry_over=%lu life_over=%lu; c2h=%lu\n",
            rtl_tx_stats.submitted, rtl_tx_stats.completed, rtl_tx_stats.failed, rtl_tx_stats.ccx, rtl_tx_stats.ccx_ok,
            rtl_tx_stats.ccx_retry_over, rtl_tx_stats.ccx_life_over, rtl_rx_stats.c2h);
    printf("tx: usb_completed=%lu chip_tx_reports=%lu (ok=%lu retry_over=%lu) c2h=%lu\n", rtl_tx_stats.completed, rtl_tx_stats.ccx,
           rtl_tx_stats.ccx_ok, rtl_tx_stats.ccx_retry_over, rtl_rx_stats.c2h);
    if (rxsecs) {
        nrx = 0;
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        do { rtl_rx_poll(&r, on_frame, NULL, 50); clock_gettime(CLOCK_MONOTONIC, &t1); } while (t1.tv_sec - t0.tv_sec < rxsecs);
        printf("rx after tx: %lu frames in %d s\n", nrx, rxsecs);
    }
    char line[96];
    snprintf(line, sizeof line, "STAGE4 OK sent=%d", sent);
    puts(line); fprintf(stderr, "%s\n", line);
    rtl_close(&r);
    return 0;
}
