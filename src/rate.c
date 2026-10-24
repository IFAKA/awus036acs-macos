// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <string.h>
#include "rate.h"

#define DOWN_BELOW   550     // step down when the average quality of the current rung falls under this
#define UP_ABOVE     880     // probe upward only while the current rung is better than this
#define PROBE_OK     800     // a probe must score at least this to be adopted
#define MIN_REPORTS  8
#define PROBE_EVERY_MS 2000
#define BACKOFF_MAX_MS 16000

void rate_init(rate_ctl_t *rc, int n, const int *codes, const int *hw, int start)
{
    memset(rc, 0, sizeof *rc);
    if (n > RATE_MAX) n = RATE_MAX;
    rc->n = n;
    for (int i = 0; i < n; i++) { rc->code[i] = codes[i]; rc->hw[i] = hw[i]; rc->score[i] = 900; }
    rc->cur = start < 0 ? 0 : start >= n ? n - 1 : start;
    rc->probe = -1;
    rc->backoff_ms = PROBE_EVERY_MS;
}

int rate_pick(rate_ctl_t *rc, long now)
{
    if (rc->n == 0) return 0;
    if (rc->probe < 0 && rc->cur < rc->n - 1 && rc->score[rc->cur] >= UP_ABOVE && rc->cnt[rc->cur] >= MIN_REPORTS
        && now - rc->last_probe_ms >= rc->backoff_ms) {
        rc->probe = rc->cur + 1; rc->cnt[rc->probe] = 0; rc->score[rc->probe] = 900; rc->last_probe_ms = now;
    }
    if (rc->probe >= 0 && (rc->tick++ & 3) == 0) return rc->code[rc->probe];
    return rc->code[rc->cur];
}

static int find(const rate_ctl_t *rc, int hw)
{
    for (int i = 0; i < rc->n; i++) if (rc->hw[i] == hw) return i;
    return -1;
}

int rate_report(rate_ctl_t *rc, int hw_rate, int retries, int ok, long now)
{
    int i = find(rc, hw_rate);
    if (i < 0) return 0;
    int sample = ok ? 1000 / (retries + 1) : 0;
    rc->score[i] = rc->cnt[i] ? (rc->score[i] * 7 + sample) / 8 : sample;
    if (rc->cnt[i] < 1000) rc->cnt[i]++;
    if (i == rc->probe && rc->cnt[i] >= MIN_REPORTS) {
        if (rc->score[i] >= PROBE_OK) { rc->cur = i; rc->ups++; rc->backoff_ms = PROBE_EVERY_MS; rc->probe = -1; return 1; }
        rc->probe = -1; rc->backoff_ms = rc->backoff_ms * 2 > BACKOFF_MAX_MS ? BACKOFF_MAX_MS : rc->backoff_ms * 2;
        rc->last_probe_ms = now;
        return 0;
    }
    if (i == rc->cur && rc->cnt[i] >= MIN_REPORTS && rc->score[i] < DOWN_BELOW && rc->cur > 0) {
        rc->cur--; rc->downs++; rc->probe = -1; rc->cnt[rc->cur] = 0; rc->score[rc->cur] = 800;
        rc->last_probe_ms = now; rc->backoff_ms = PROBE_EVERY_MS;
        return 1;
    }
    return 0;
}
