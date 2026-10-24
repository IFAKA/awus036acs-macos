// Stage 4 closed-loop check: send an 802.11 Authentication request (open system, seq 1) to our own AP and
// wait for its Authentication response. A response proves TX reached the air and was understood.
//   authtest BSSID CHANNEL   (e.g. authtest aa:bb:cc:dd:ee:ff 7)
// Prints one final line: STAGE4 OK auth_resp status=N rssi=D | STAGE4 FAIL <step> <reason>. Log: /tmp/authtest.log
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

static uint8_t sa[6], bssid[6];
static int got, status = -1, rssi;

static void on_frame(void *ud, const rtl_frame_t *f)
{
    (void)ud;
    if (f->len < 30 || !f->has_fcs) return;
    // mgmt (type 0), subtype 11 = authentication; DA at +4, SA at +10
    if ((f->data[0] & 0xFC) != 0xB0) return;
    if (memcmp(f->data + 4, sa, 6) || memcmp(f->data + 10, bssid, 6)) return;
    got = 1;
    status = f->data[24 + 4] | (f->data[24 + 5] << 8);
    rssi = f->rssi_dbm;
}

int main(int argc, char **argv)
{
    if (argc < 3 || sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6) {
        fprintf(stderr, "usage: authtest BSSID CHANNEL\n");
        return 2;
    }
    int ch = atoi(argv[2]);
    rtl_t r = {0};
    if (!freopen("/tmp/authtest.log", "w", stderr)) return 2;
    setvbuf(stderr, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    r.verbose = 1;
    char b[160];
    const char *step;
    if (rtl_bringup(&r, ch, &step, b, sizeof b)) { printf("STAGE4 FAIL %s %s\n", step, b); return 1; }
    if (rtl_set_monitor(&r)) { printf("STAGE4 FAIL set_monitor\n"); return 1; }
    r.verbose = 0;

    srand(time(NULL) ^ getpid());
    sa[0] = 0x02; for (int i = 1; i < 6; i++) sa[i] = rand() & 0xFF;
    // Program our MAC address so the hardware ACKs the AP's reply (REG_MACID 0x0610).
    for (int i = 0; i < 6; i++) rtl_w8(&r, 0x0610 + i, sa[i]);

    uint8_t fr[30] = {0xB0, 0x00, 0, 0};            // auth, no flags
    memcpy(fr + 4, bssid, 6); memcpy(fr + 10, sa, 6); memcpy(fr + 16, bssid, 6);
    fr[24] = 0; fr[25] = 0;                         // algorithm: open system
    fr[26] = 1; fr[27] = 0;                         // transaction sequence 1
    fr[28] = 0; fr[29] = 0;                         // status 0
    printf("sa=%02x:%02x:%02x:%02x:%02x:%02x bssid=%s ch=%d\n", sa[0], sa[1], sa[2], sa[3], sa[4], sa[5], argv[1], ch);

    for (int attempt = 0; attempt < 5 && !got; attempt++) {
        int rc = rtl_tx_frame(&r, fr, sizeof fr, 10, 7);
        if (rc) { printf("STAGE4 FAIL tx rc=%d\n", rc); return 1; }
        for (int w = 0; w < 10 && !got; w++) rtl_rx_poll(&r, on_frame, NULL, 30);
    }
    printf("tx: usb_completed=%lu chip_tx_reports=%lu ok=%lu retry_over=%lu\n",
           rtl_tx_stats.completed, rtl_tx_stats.ccx, rtl_tx_stats.ccx_ok, rtl_tx_stats.ccx_retry_over);
    if (got) printf("STAGE4 OK auth_resp status=%d rssi=%d\n", status, rssi);
    else printf("STAGE4 FAIL no_auth_response (TX not proven)\n");
    rtl_close(&r);
    return !got;
}
