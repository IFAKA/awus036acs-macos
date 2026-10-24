// Injection statistics test (like `aireplay-ng -9`), restricted to the user's own AP only.
// Sends directed Probe Requests to BSSID aa:bb:cc:dd:ee:ff (SSID MyNetwork) at four rates and counts
// Probe Responses addressed back to us; also sends ONE broadcast (wildcard SSID) probe and counts distinct
// APs that answer it (ordinary passive-looking 802.11 behaviour: any AP answers a broadcast probe from anyone).
// No deauth/disassoc frames exist in this file and none are sent. Only aa:bb:cc:dd:ee:ff is ever a destination.
//   injtest [-c CHANNEL] [-n COUNT]
// Prints a table and: INJTEST OK 1M=a/30 6M=b/30 24M=c/30 54M=d/30 bcast_aps=N   (OK if best rate >= 80%)
//                   or INJTEST WEAK ... (same fields) if not.
// Log: /tmp/injtest.log
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

#define TARGET_SSID "MyNetwork"
static const uint8_t TARGET_BSSID[6] = {0xca, 0x33, 0x74, 0xbe, 0x45, 0x52};
static const uint8_t BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static uint8_t sa[6];
static int got_resp;                 // directed-test: did we see a Probe Response addressed to us from the target?
static int got_resp_rssi;
static uint8_t bcast_aps[64][6];      // distinct BSSIDs seen answering the broadcast probe
static int n_bcast_aps;

static long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000L + t.tv_nsec / 1000000L; }

// Probe Request subtype 4 (0x40), header: FC(2) DUR(2) A1/DA(6) A2/SA(6) A3/BSSID(6) SEQ(2) = 24 bytes,
// then SSID element + a basic Supported Rates element (both normal, unencrypted management content).
static int build_probe_req(uint8_t *f, const uint8_t *da, const uint8_t *bssid, const char *ssid)
{
    int n = 0;
    f[n++] = 0x40; f[n++] = 0x00;          // FC: mgmt, subtype 4 (probe request)
    f[n++] = 0x00; f[n++] = 0x00;          // duration
    memcpy(f + n, da, 6); n += 6;          // addr1 (DA)
    memcpy(f + n, sa, 6); n += 6;          // addr2 (SA, our own random locally-administered MAC)
    memcpy(f + n, bssid, 6); n += 6;       // addr3 (BSSID)
    f[n++] = 0x00; f[n++] = 0x00;          // seq/frag (hardware overwrites seq via HWSEQ_EN)
    int sl = (int)strlen(ssid);
    f[n++] = 0x00; f[n++] = (uint8_t)sl;   // SSID element
    memcpy(f + n, ssid, sl); n += sl;
    static const uint8_t rates[] = {0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24}; // 1,2,5.5,11,6,9,12,18 (basic marked by caller's AP, not us)
    f[n++] = 0x01; f[n++] = sizeof rates;  // Supported Rates element
    memcpy(f + n, rates, sizeof rates); n += sizeof rates;
    return n;
}

static void on_directed(void *ud, const rtl_frame_t *f)
{
    (void)ud;
    if (f->len < 24 || !f->has_fcs) return;
    if ((f->data[0] & 0xFC) != 0x50) return;           // mgmt subtype 5 = probe response
    if (memcmp(f->data + 4, sa, 6)) return;            // DA must be us
    if (memcmp(f->data + 16, TARGET_BSSID, 6)) return; // only count our own AP's reply
    got_resp = 1;
    got_resp_rssi = f->rssi_dbm;
}

static void on_bcast(void *ud, const rtl_frame_t *f)
{
    (void)ud;
    if (f->len < 24 || !f->has_fcs) return;
    if ((f->data[0] & 0xFC) != 0x50) return;
    if (memcmp(f->data + 4, sa, 6)) return;
    const uint8_t *bssid = f->data + 16;
    for (int i = 0; i < n_bcast_aps; i++) if (!memcmp(bcast_aps[i], bssid, 6)) return;
    if (n_bcast_aps < 64) memcpy(bcast_aps[n_bcast_aps++], bssid, 6);
}

// One probe/listen round. rate in rtl_tx_frame units. retries = hw retry limit for unicast (ignored for broadcast).
// Returns 1 if a matching response was captured within the listen window, else 0.
static int one_round(rtl_t *r, const uint8_t *da, int rate, int retries, rtl_frame_cb cb, int listen_ms)
{
    uint8_t fr[64];
    int len = build_probe_req(fr, da, memcmp(da, BCAST, 6) ? TARGET_BSSID : BCAST, TARGET_SSID);
    int rc = rtl_tx_frame(r, fr, len, rate, retries);
    if (rc) { fprintf(stderr, "tx rc=%d rate=%d\n", rc, rate); return -1; }
    long t0 = now_ms();
    int before = got_resp;
    while (now_ms() - t0 < listen_ms) rtl_rx_poll(r, cb, NULL, 15);
    return got_resp && !before ? 1 : (got_resp ? 1 : 0);
}

static int run_rate(rtl_t *r, const char *name, int rate, int n)
{
    int hits = 0;
    for (int i = 0; i < n; i++) {
        got_resp = 0;
        int ok = one_round(r, TARGET_BSSID, rate, 3, on_directed, 60);
        if (ok > 0) hits++;
        usleep(20000);   // 20 ms gap between probes, be a polite single station
    }
    printf("%-6s %2d/%-2d  (%d%%)\n", name, hits, n, hits * 100 / n);
    fflush(stdout);
    return hits;
}

int main(int argc, char **argv)
{
    int ch = 7, n = 30;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) ch = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) n = atoi(argv[++i]);
    }
    rtl_t r = {0};
    if (!freopen("/tmp/injtest.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    r.verbose = 1;
    char b[160];
    const char *step;
    if (rtl_bringup(&r, ch, &step, b, sizeof b)) { printf("INJTEST FAIL %s %s\n", step, b); return 1; }
    if (rtl_set_monitor(&r)) { printf("INJTEST FAIL set_monitor\n"); return 1; }
    r.verbose = 0;

    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    sa[0] = 0x02; for (int i = 1; i < 6; i++) sa[i] = rand() & 0xFF;   // locally-administered, random, ours only
    for (int i = 0; i < 6; i++) rtl_w8(&r, 0x0610 + i, sa[i]);        // REG_MACID: hardware ACKs replies to us

    printf("injtest: sa=%02x:%02x:%02x:%02x:%02x:%02x target=%02x:%02x:%02x:%02x:%02x:%02x ssid=%s ch=%d n=%d\n",
           sa[0], sa[1], sa[2], sa[3], sa[4], sa[5],
           TARGET_BSSID[0], TARGET_BSSID[1], TARGET_BSSID[2], TARGET_BSSID[3], TARGET_BSSID[4], TARGET_BSSID[5],
           TARGET_SSID, ch, n);
    printf("tx power index: default 0x%02X\n", RTL_TXPWR_DEFAULT);
    printf("%-6s %-8s\n", "rate", "hits");

    int h1  = run_rate(&r, "1M",  10, n);
    int h6  = run_rate(&r, "6M",  60, n);
    int h24 = run_rate(&r, "24M", 240, n);
    int h54 = run_rate(&r, "54M", 540, n);

    // Broadcast (wildcard SSID) probe: ordinary behaviour any AP in range performs for any station that asks.
    got_resp = 0; n_bcast_aps = 0;
    uint8_t fr[64];
    int len = build_probe_req(fr, BCAST, BCAST, "");
    int rc = rtl_tx_frame(&r, fr, len, 60, 0);   // broadcast: no HW retries
    if (rc) fprintf(stderr, "bcast tx rc=%d\n", rc);
    long t0 = now_ms();
    while (now_ms() - t0 < 500) rtl_rx_poll(&r, on_bcast, NULL, 25);
    printf("bcast probe: %d distinct AP(s) answered\n", n_bcast_aps);
    for (int i = 0; i < n_bcast_aps; i++)
        fprintf(stderr, "  bcast AP %d: %02x:%02x:%02x:%02x:%02x:%02x\n", i,
                bcast_aps[i][0], bcast_aps[i][1], bcast_aps[i][2], bcast_aps[i][3], bcast_aps[i][4], bcast_aps[i][5]);

    printf("tx: usb_completed=%lu chip_tx_reports=%lu ok=%lu retry_over=%lu\n",
           rtl_tx_stats.completed, rtl_tx_stats.ccx, rtl_tx_stats.ccx_ok, rtl_tx_stats.ccx_retry_over);

    int best = h1; if (h6 > best) best = h6; if (h24 > best) best = h24; if (h54 > best) best = h54;
    const char *verdict = (best * 100 / n) >= 80 ? "OK" : "WEAK";
    printf("INJTEST %s 1M=%d/%d 6M=%d/%d 24M=%d/%d 54M=%d/%d bcast_aps=%d\n",
           verdict, h1, n, h6, n, h24, n, h54, n, n_bcast_aps);
    rtl_close(&r);
    return strcmp(verdict, "OK") == 0 ? 0 : 1;
}
