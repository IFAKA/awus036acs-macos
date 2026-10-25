// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// scanlib: channel-hopping scan (Beacons + Probe Responses), shared by `awusctl scan` (direct mode) and awusd.
// Hops the 2.4 GHz (1-13) and 5 GHz (36-64, 100-144, 149-165) channels, keeps one entry per BSSID, and marks each as
// allowed / blocked / DFS for the country (empty = no filter). It only listens on blocked and DFS channels (and on 52-144);
// elsewhere it sends ONE broadcast wildcard Probe Request per dwell (what any station does). No deauth/disassoc frames exist here; nothing is ever sent to a named network.
// scan_row_t is the display form of one entry; the daemon sends rows over the socket and the client prints them.
#ifndef SCANLIB_H
#define SCANLIB_H
#include <stdio.h>
#include <stdint.h>
#include "rtl.h"
#include "scanparse.h"
#include "wps.h"

#define SCAN_MAX_APS 256

typedef struct {
    uint8_t bssid[6];
    scan_ap_t ap;
    int channel;                 // true primary channel (IE) or, failing that, the channel we heard it on
    long rssi_sum; int rssi_n;
    int seen_probe_resp;
    int allowed;                 // channel allowed by the country (1) or blocked (0)
    int dfs;                     // channel is DFS in that country
    wps_ap_info_t wps;           // WSC element of the LATEST Beacon / Probe Response (wps.present = 0 if none): WPS state, locked, button window
} scan_entry_t;

typedef struct {
    scan_entry_t aps[SCAN_MAX_APS];
    int n, dropped;
    uint8_t sa[6];               // random locally-administered source address used for probe requests
    char country[3];             // "" = no filter
} scan_t;

typedef struct {
    char ssid[200];              // display text (control bytes -> '?')
    char ssid_json[400];         // JSON-escaped
    int hidden;
    char bssid[18];
    int channel, rssi;
    char security[64], cipher[32], phy[48];
    int wps, allowed, dfs;
    int ht, vht, he, streams;
    double max_rate;
} scan_row_t;

void scan_reset(scan_t *s, const char *country);
// Scan. band 0 = both, 2, 5. The radio must be up and in monitor mode. Returns 0, 1 if *abort became nonzero, -1 USB error.
int  scan_run(rtl_t *r, scan_t *s, int band, int dwell_ms, int passes, volatile int *abort);
void scan_sort(scan_t *s);                       // strongest first
int  scan_rssi(const scan_entry_t *e);           // average dBm (0 if none)
void scan_row(const scan_entry_t *e, scan_row_t *row);
void scan_print_table(FILE *o, const scan_row_t *rows, int n);
void scan_print_json(FILE *o, const scan_row_t *rows, int n);
int  scan_is_hidden(const scan_ap_t *a);
#endif
