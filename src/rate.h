// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// rate: a small transmit rate adaptation loop. The chip reports the outcome of about a quarter of the frames (C2H TX
// report: final rate, retry count, delivered or not). Each report scores the rate it was sent at; the loop steps down
// when the current rate keeps failing and probes one step up now and then. Pure logic, no USB: tested in test_rate.c.
#ifndef RATE_H
#define RATE_H
#include <stdint.h>

#define RATE_MAX 16

typedef struct {
    int n;                      // rungs in the ladder, slowest first (each a rate code, see caps.h)
    int code[RATE_MAX];         // rate code the TX path takes
    int hw[RATE_MAX];           // matching hardware rate code as seen in TX reports
    int score[RATE_MAX];        // exponential average of delivery quality, 0..1000
    int cnt[RATE_MAX];          // reports seen since the rung became current / probe
    int cur;                    // rung in use
    int probe;                  // rung being probed, -1 = none
    int tick;                   // frames picked, spaces the probes
    long last_probe_ms, backoff_ms;
    unsigned long downs, ups;   // step counts (for logs)
} rate_ctl_t;

void rate_init(rate_ctl_t *rc, int n, const int *codes, const int *hw, int start);
// Rate code for the next frame: the current rung, or the probe rung for one frame in four while probing.
int  rate_pick(rate_ctl_t *rc, long now_ms);
// Feed one TX report. Returns 1 when the current rung changed.
int  rate_report(rate_ctl_t *rc, int hw_rate, int retries, int ok, long now_ms);
#endif
