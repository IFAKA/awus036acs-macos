// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos. Unit test for the pure bench helpers.
#include <stdio.h>
#include <string.h>
#include "bench.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void)
{
    uint8_t p[1600]; uint16_t dp; uint32_t seq, src; size_t pl;
    size_t n = bench_udp_build(p, 0xC0A80196, 0xC0A801E4, 40000, BENCH_PORT, 0x01020304, 1400);
    CHECK(n == 1428);
    CHECK(net_cksum(p, 20) == 0);
    CHECK(bench_udp_parse(p, n, &dp, &seq, &pl, &src) == 0);
    CHECK(dp == BENCH_PORT && seq == 0x01020304 && pl == 1400 && src == 0xC0A80196);
    CHECK(bench_udp_parse(p, 20, &dp, &seq, &pl, &src) == -1);       // too short
    p[9] = 1; CHECK(bench_udp_parse(p, n, &dp, &seq, &pl, &src) == -1);   // not UDP
    p[9] = 17; p[24] = 0xFF; CHECK(bench_udp_parse(p, n, &dp, &seq, &pl, &src) == -1);   // UDP length larger than the packet
    CHECK(bench_udp_build(p, 1, 2, 3, 4, 7, 8) == 36);
    CHECK(bench_mbps(1250000, 1000) > 9.99 && bench_mbps(1250000, 1000) < 10.01);
    CHECK(bench_mbps(5, 0) == 0);
    CHECK(bench_find_peer(0x7F000001, 0xFF000000) != 1);
    printf(fails ? "test_bench FAILED\n" : "test_bench OK\n");
    return fails != 0;
}
