// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Bench tool for ad-hoc networks, no daemon: ibsstool create SSID CH SECS | join SSID CH SECS.
// Prints the beacon engine registers and the chip's transmitted-beacon counter. Log: /tmp/ibsstool.log
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rtl.h"
#include "phy.h"
#include "mac.h"
#include "bringup.h"
#include "ibss.h"

int main(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: ibsstool create|join SSID CH SECS\n"); return 2; }
    int join = !strcmp(argv[1], "join"), ch = atoi(argv[3]), secs = atoi(argv[4]);
    if (!freopen("/tmp/ibsstool.log", "w", stderr)) return 2;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    rtl_t r = {0}; char b[160]; const char *step;
    if (rtl_bringup(&r, ch, &step, b, sizeof b)) { printf("FAIL %s %s\n", step, b); return 1; }
    rtl_set_monitor(&r);
    ibss_t c; memset(&c, 0, sizeof c);
    snprintf(c.ssid, sizeof c.ssid, "%s", argv[2]); c.channel = ch; c.no_probe_resp = getenv("IBSS_NO_PROBE_RESP") != NULL;
    if (join) {
        ibss_peer_t pe;
        int f = ibss_find(&r, ch, argv[2], 6000, &pe);
        if (f <= 0) { printf("FAIL no IBSS named that heard on channel %d\n", ch); rtl_close(&r); return 1; }
        memcpy(c.bssid, pe.bssid, 6); c.join = 1; c.privacy = pe.privacy;
        printf("found bssid %02x:%02x:%02x:%02x:%02x:%02x rssi %d\n", pe.bssid[0], pe.bssid[1], pe.bssid[2], pe.bssid[3], pe.bssid[4], pe.bssid[5], pe.rssi);
    }
    char err[120] = "";
    if (ibss_start(&r, &c, err, sizeof err)) { printf("FAIL start: %s\n", err); rtl_close(&r); return 1; }
    printf("up: bssid %02x:%02x:%02x:%02x:%02x:%02x mac %02x:%02x:%02x:%02x:%02x:%02x ch %d\n", c.bssid[0], c.bssid[1], c.bssid[2], c.bssid[3], c.bssid[4], c.bssid[5],
           c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5], ch);
    printf("regs: CR=%08x BCN_CTRL=%02x TXQ422=%02x TDECTRL=%08x BCN_INT=%04x\n", rtl_r32(&r, 0x100), rtl_r8(&r, 0x550), rtl_r8(&r, 0x422), rtl_r32(&r, 0x208), rtl_r16(&r, 0x554));
    fflush(stdout);
    uint32_t tsf0 = rtl_r32(&r, 0x560);
    for (int i = 0; i < secs; i++) {
        ibss_tick(&r, &c, 1000);
        printf("t=%2ds beacons_ok=%lu err=%lu dma=%lu tsf=%u probe_req=%lu probe_resp=%lu bcn_heard=%lu peers=%d\n", i + 1, c.beacons_ok, c.beacons_err, c.beacons_dma, rtl_r32(&r, 0x560) - tsf0, c.probe_req, c.probe_resp, c.bcn_heard, c.npeers);
        fflush(stdout);
    }
    ibss_stop(&r, &c);
    rtl_close(&r);
    return 0;
}
