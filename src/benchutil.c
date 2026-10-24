// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include "bench.h"

size_t bench_udp_build(uint8_t *p, uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, uint32_t seq, size_t pl)
{
    size_t tl = 20 + 8 + pl;
    memset(p, 0, tl);
    p[0] = 0x45; p[2] = tl >> 8; p[3] = tl; p[4] = seq >> 8; p[5] = seq; p[6] = 0x40; p[8] = 64; p[9] = 17;
    p[12] = src >> 24; p[13] = src >> 16; p[14] = src >> 8; p[15] = src;
    p[16] = dst >> 24; p[17] = dst >> 16; p[18] = dst >> 8; p[19] = dst;
    uint16_t c = net_cksum(p, 20); p[10] = c >> 8; p[11] = c;
    p[20] = sport >> 8; p[21] = sport; p[22] = dport >> 8; p[23] = dport; p[24] = (8 + pl) >> 8; p[25] = 8 + pl;
    if (pl >= 4) { p[28] = seq >> 24; p[29] = seq >> 16; p[30] = seq >> 8; p[31] = seq; }
    for (size_t i = 4; i < pl; i++) p[28 + i] = (uint8_t)(0x30 + (i & 15));
    return tl;
}

int bench_udp_parse(const uint8_t *p, size_t len, uint16_t *dport, uint32_t *seq, size_t *pl, uint32_t *src)
{
    if (len < 28 || (p[0] >> 4) != 4 || p[9] != 17) return -1;
    size_t ihl = (p[0] & 15) * 4, tl = p[2] << 8 | p[3];
    if (ihl < 20 || tl > len || tl < ihl + 8) return -1;
    size_t ul = (p[ihl + 4] << 8 | p[ihl + 5]);
    if (ul < 8 || ihl + ul > tl) return -1;
    *dport = p[ihl + 2] << 8 | p[ihl + 3];
    *pl = ul - 8;
    *seq = *pl >= 4 ? (uint32_t)p[ihl + 8] << 24 | p[ihl + 9] << 16 | p[ihl + 10] << 8 | p[ihl + 11] : 0;
    *src = (uint32_t)p[12] << 24 | p[13] << 16 | p[14] << 8 | p[15];
    return 0;
}

double bench_mbps(unsigned long long bytes, long ms) { return ms > 0 ? (double)bytes * 8.0 / 1000.0 / (double)ms : 0; }

uint32_t bench_find_peer(uint32_t ip, uint32_t mask)
{
    struct ifaddrs *ifa, *a;
    uint32_t found = 0;
    if (getifaddrs(&ifa)) return 0;
    for (a = ifa; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET || (a->ifa_flags & IFF_LOOPBACK)) continue;
        if (!strncmp(a->ifa_name, "utun", 4)) continue;
        uint32_t x = ntohl(((struct sockaddr_in *)a->ifa_addr)->sin_addr.s_addr);
        if (x != ip && (x & mask) == (ip & mask)) { found = x; break; }
    }
    freeifaddrs(ifa);
    return found;
}

