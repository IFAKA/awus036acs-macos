// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos. Unit test for rate.c (step down on failures, probe up when the link is good, back off after a failed probe).
#include <stdio.h>
#include "rate.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static const int codes[4] = {1000, 1001, 1002, 1003}, hw[4] = {12, 13, 14, 15};

int main(void)
{
    rate_ctl_t rc;
    rate_init(&rc, 4, codes, hw, 3);
    long t = 0;
    CHECK(rate_pick(&rc, t) == 1003);
    for (int i = 0; i < 20; i++) rate_report(&rc, 15, 0, 1, t += 10);          // clean link: stays on top
    CHECK(rc.cur == 3 && rc.downs == 0);
    for (int i = 0; i < 10; i++) rate_report(&rc, 15, 4, 0, t += 10);          // top rate fails: steps down
    CHECK(rc.cur == 2 && rc.downs >= 1);
    for (int i = 0; i < 40; i++) rate_report(&rc, 14, 0, 1, t += 10);          // lower rate is clean
    CHECK(rc.cur == 2);
    // probing: after the backoff the next pick may return the higher rate, a good probe is adopted
    t += 3000;
    int seen_probe = 0;
    for (int i = 0; i < 8; i++) if (rate_pick(&rc, t) == 1003) seen_probe = 1;
    CHECK(seen_probe && rc.probe == 3);
    for (int i = 0; i < 9; i++) rate_report(&rc, 15, 0, 1, t += 10);
    CHECK(rc.cur == 3 && rc.probe == -1 && rc.ups == 1);
    // failed probe: stays, backs off
    for (int i = 0; i < 10; i++) rate_report(&rc, 15, 5, 0, t += 10);
    CHECK(rc.cur == 2);
    long b0 = rc.backoff_ms;
    for (int i = 0; i < 40; i++) rate_report(&rc, 14, 0, 1, t += 10);
    t += 3000; for (int i = 0; i < 8; i++) rate_pick(&rc, t);
    CHECK(rc.probe == 3);
    for (int i = 0; i < 9; i++) rate_report(&rc, 15, 7, 0, t += 10);
    CHECK(rc.cur == 2 && rc.probe == -1 && rc.backoff_ms > b0);
    // never below the bottom, unknown rates ignored
    rate_ctl_t lo; rate_init(&lo, 2, codes, hw, 0);
    for (int i = 0; i < 30; i++) rate_report(&lo, 12, 7, 0, t += 10);
    CHECK(lo.cur == 0 && rate_pick(&lo, t) == 1000);
    CHECK(rate_report(&lo, 99, 0, 1, t) == 0);
    printf(fails ? "test_rate FAILED\n" : "test_rate OK\n");
    return fails != 0;
}
