// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_net6.c - IPv6 stack tests with a fake router: addresses, checksum, RS, RA/SLAAC/RDNSS, NS/NA, echo, ping. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "net6.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static const uint8_t MAC[6] = {0x00, 0xc0, 0xca, 0x12, 0x34, 0x56};
static const uint8_t RMAC[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
static uint8_t RLL[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x20, 0x30, 0xff, 0xfe, 0x40, 0x50, 0x60};

static struct { uint8_t mac[6]; uint8_t pkt[1500]; size_t len; int n; } sent;
static int tun_n;
static void tx(void *c, const uint8_t m[6], const uint8_t *p, size_t l) { (void)c; memcpy(sent.mac, m, 6); memcpy(sent.pkt, p, l); sent.len = l; sent.n++; }
static void totun(void *c, const uint8_t *p, size_t l) { (void)c; (void)p; (void)l; tun_n++; }
static const n6_ops_t OPS = { NULL, tx, totun };

static void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = (uint8_t)v; }

/* build an IPv6+ICMPv6 packet with a correct checksum */
static size_t mk(uint8_t *o, const uint8_t *src, const uint8_t *dst, int hop, int type, const uint8_t *body, size_t bl)
{
    memset(o, 0, 44); o[0] = 0x60; wr16(o + 4, (uint16_t)(4 + bl)); o[6] = 58; o[7] = (uint8_t)hop;
    memcpy(o + 8, src, 16); memcpy(o + 24, dst, 16);
    o[40] = (uint8_t)type; if (bl) memcpy(o + 44, body, bl);
    wr16(o + 42, n6_icmp_cksum(src, dst, o + 40, 4 + bl));
    return 44 + bl;
}

static size_t mk_ra(uint8_t *o, const uint8_t *dst, int with_rdnss, int plen)
{
    uint8_t b[256]; size_t n = 0;
    memset(b, 0, sizeof b);
    b[0] = 64; b[1] = 0; wr16(b + 2, 1800); n = 12;               /* cur hop limit, flags, router lifetime, reachable, retrans */
    b[n] = 1; b[n + 1] = 1; memcpy(b + n + 2, RMAC, 6); n += 8;     /* SLLA */
    b[n] = 5; b[n + 1] = 1; wr32(b + n + 4, 1500); n += 8;          /* MTU */
    b[n] = 3; b[n + 1] = 4; b[n + 2] = (uint8_t)plen; b[n + 3] = 0xc0; wr32(b + n + 4, 86400); wr32(b + n + 8, 14400);
    b[n + 16] = 0x20; b[n + 17] = 0x01; b[n + 18] = 0x0d; b[n + 19] = 0xb8; b[n + 20] = 0; b[n + 21] = 1; b[n + 22] = 0; b[n + 23] = 2; n += 32;
    if (with_rdnss) {                                              /* RDNSS: length 3 = 8 header + one 16-byte address */
        b[n] = 25; b[n + 1] = 3; wr32(b + n + 4, 600);
        b[n + 8] = 0x20; b[n + 9] = 0x01; b[n + 23] = 0x88; n += 24;
    }
    return mk(o, RLL, dst, 255, 134, b + 0, n);
}

int main(void)
{
    n6_t n; uint8_t pk[1500]; size_t l;
    static const uint8_t ALLN[16] = {0xff, 2, [15] = 1};

    /* addresses */
    n6_init(&n, MAC);
    const uint8_t want_ll[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0xc0, 0xca, 0xff, 0xfe, 0x12, 0x34, 0x56};
    CHECK(!memcmp(n.ll, want_ll, 16));
    uint8_t sn[16], mm[6];
    n6_solicited_node(sn, want_ll); n6_mcast_mac(mm, sn);
    CHECK(sn[0] == 0xff && sn[1] == 2 && sn[11] == 1 && sn[12] == 0xff && sn[13] == 0x12 && sn[15] == 0x56);
    CHECK(mm[0] == 0x33 && mm[1] == 0x33 && mm[2] == 0xff && mm[3] == 0x12 && mm[5] == 0x56);

    /* checksum: a built packet verifies to 0; a flipped bit does not */
    l = mk(pk, RLL, want_ll, 255, 128, (const uint8_t *)"abcdefgh", 8);
    CHECK(n6_icmp_cksum(RLL, want_ll, pk + 40, l - 40) == 0);
    pk[46] ^= 1; CHECK(n6_icmp_cksum(RLL, want_ll, pk + 40, l - 40) != 0);

    /* router solicitation: sent at once, again after 4 s, at most 3 times, never after an RA */
    n6_tick(&n, 1000, &OPS);
    CHECK(sent.n == 1 && sent.len >= 48 && sent.pkt[40] == 133 && sent.pkt[7] == 255 && !memcmp(sent.pkt + 24, "\xff\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\x02", 16));
    CHECK(sent.mac[0] == 0x33 && sent.mac[5] == 0x02 && n6_icmp_cksum(n.ll, sent.pkt + 24, sent.pkt + 40, sent.len - 40) == 0);
    n6_tick(&n, 2000, &OPS); CHECK(sent.n == 1);
    n6_tick(&n, 5100, &OPS); CHECK(sent.n == 2);
    n6_tick(&n, 9200, &OPS); CHECK(sent.n == 3);
    n6_tick(&n, 13300, &OPS); CHECK(sent.n == 3);

    /* RA: bad hop limit and bad checksum are ignored */
    l = mk_ra(pk, ALLN, 1, 64);
    pk[7] = 64; n6_rx(&n, pk, l, 14000, &OPS); CHECK(n.ra_count == 0);
    pk[7] = 255; pk[43] ^= 0xff; n6_rx(&n, pk, l, 14000, &OPS); CHECK(n.ra_count == 0);
    l = mk_ra(pk, ALLN, 1, 64);
    n6_rx(&n, pk, l, 14000, &OPS);
    CHECK(n.ra_count == 1 && n.has_router && !memcmp(n.router, RLL, 16) && n.has_router_mac && !memcmp(n.router_mac, RMAC, 6));
    CHECK(n.router_lifetime_s == 1800 && n.mtu == 1500 && n.prefix_len == 64 && n.valid_s == 86400 && n.preferred_s == 14400);
    CHECK(n.has_gua && n.gua[0] == 0x20 && n.gua[1] == 1 && n.gua[3] == 0xb8 && n.gua[7] == 2 && !memcmp(n.gua + 8, n.ll + 8, 8));
    CHECK(n.ndns == 1 && n.dns_lifetime_s == 600);
    int before = sent.n; n6_tick(&n, 30000, &OPS); CHECK(sent.n == before);       /* no more RS once an RA arrived */
    /* a /48 prefix is not used for SLAAC */
    { n6_t m; n6_init(&m, MAC); l = mk_ra(pk, ALLN, 0, 48); n6_rx(&m, pk, l, 0, &OPS); CHECK(m.ra_count == 1 && !m.has_gua); }
    /* a truncated option list does not crash or give an address */
    { n6_t m; n6_init(&m, MAC); l = mk_ra(pk, ALLN, 0, 64); for (size_t k = 1; k < l; k++) { pk[4] = 0; pk[5] = 0; n6_rx(&m, pk, k, 0, &OPS); } CHECK(1); }

    /* neighbour solicitation for our link-local from the router: answered with a solicited+override NA to the router's MAC */
    uint8_t body[28]; memset(body, 0, sizeof body); memcpy(body + 4, n.ll, 16); body[20] = 1; body[21] = 1; memcpy(body + 22, RMAC, 6);
    l = mk(pk, RLL, n.ll, 255, 135, body, sizeof body);
    sent.n = 0; n6_rx(&n, pk, l, 15000, &OPS);
    CHECK(sent.n == 1 && sent.pkt[40] == 136 && sent.pkt[44] == 0x60 && !memcmp(sent.pkt + 48, n.ll, 16) && !memcmp(sent.mac, RMAC, 6));
    CHECK(sent.pkt[64] == 2 && !memcmp(sent.pkt + 66, MAC, 6) && !memcmp(sent.pkt + 24, RLL, 16) && n6_icmp_cksum(sent.pkt + 8, sent.pkt + 24, sent.pkt + 40, sent.len - 40) == 0);
    /* NS for somebody else's address, and an NS from the unspecified address (DAD), get no answer */
    uint8_t other[16]; memcpy(other, n.ll, 16); other[15] ^= 1;
    memcpy(body + 4, other, 16); l = mk(pk, RLL, n.ll, 255, 135, body, sizeof body);
    sent.n = 0; n6_rx(&n, pk, l, 15000, &OPS); CHECK(sent.n == 0);
    memcpy(body + 4, n.ll, 16); { uint8_t z[16] = {0}; l = mk(pk, z, n.ll, 255, 135, body, 20); n6_rx(&n, pk, l, 15000, &OPS); CHECK(sent.n == 0); }
    /* NS for our SLAAC address too */
    memcpy(body + 4, n.gua, 16); l = mk(pk, RLL, n.gua, 255, 135, body, sizeof body);
    sent.n = 0; n6_rx(&n, pk, l, 15000, &OPS); CHECK(sent.n == 1 && !memcmp(sent.pkt + 8, n.gua, 16));

    /* echo request from the router -> echo reply with the same data */
    uint8_t eb[4 + 16]; wr16(eb, 7); wr16(eb + 2, 9); for (int i = 0; i < 16; i++) eb[4 + i] = (uint8_t)i;
    l = mk(pk, RLL, n.ll, 64, 128, eb, sizeof eb);
    sent.n = 0; n6_rx(&n, pk, l, 16000, &OPS);
    CHECK(sent.n == 1 && sent.pkt[40] == 129 && !memcmp(sent.pkt + 44, eb, sizeof eb) && !memcmp(sent.mac, RMAC, 6) && n6_icmp_cksum(n.ll, RLL, sent.pkt + 40, sent.len - 40) == 0);

    /* our ping to the router: goes straight out (MAC known from the RA's SLLA), reply is matched by id/seq */
    sent.n = 0;
    CHECK(n6_ping(&n, RLL, 0x6a77, 3, 20000, &OPS) == 0);
    CHECK(sent.n == 1 && sent.pkt[40] == 128 && !memcmp(sent.mac, RMAC, 6) && !memcmp(sent.pkt + 8, n.ll, 16));
    wr16(eb, 0x6a77); wr16(eb + 2, 2);                                   /* wrong sequence */
    l = mk(pk, RLL, n.ll, 64, 129, eb, sizeof eb); n6_rx(&n, pk, l, 20007, &OPS); CHECK(!n.ping_got);
    wr16(eb + 2, 3); l = mk(pk, RLL, n.ll, 64, 129, eb, sizeof eb); n6_rx(&n, pk, l, 20007, &OPS);
    CHECK(n.ping_got == 1 && n.ping_rtt_ms == 7);

    /* an unknown on-link neighbour: the ping waits, an NS goes to the solicited-node group, the NA releases it */
    uint8_t peer[16]; memcpy(peer, n.ll, 16); peer[15] = 0x77; peer[14] = 0x11;
    sent.n = 0; CHECK(n6_ping(&n, peer, 0x6a77, 4, 21000, &OPS) == 0);
    CHECK(sent.n == 1 && sent.pkt[40] == 135 && sent.mac[0] == 0x33 && sent.mac[2] == 0xff && n.pend_len > 0);
    const uint8_t PMAC[6] = {2, 3, 4, 5, 6, 7};
    memset(body, 0, sizeof body); body[0] = 0x60; memcpy(body + 4, peer, 16); body[20] = 2; body[21] = 1; memcpy(body + 22, PMAC, 6);
    l = mk(pk, peer, n.ll, 255, 136, body, sizeof body);
    sent.n = 0; n6_rx(&n, pk, l, 21003, &OPS);
    CHECK(sent.n == 1 && sent.pkt[40] == 128 && !memcmp(sent.mac, PMAC, 6) && n.pend_len == 0);
    /* a pending packet is dropped after 3 s */
    uint8_t peer2[16]; memcpy(peer2, peer, 16); peer2[15] = 0x78;
    n6_ping(&n, peer2, 1, 1, 30000, &OPS); CHECK(n.pend_len > 0); n6_tick(&n, 33500, &OPS); CHECK(n.pend_len == 0);

    /* garbage never crashes: short packets, wrong length, wrong version */
    for (size_t k = 0; k < 60; k++) { memset(pk, 0xa5, sizeof pk); n6_rx(&n, pk, k, 0, &OPS); }
    l = mk(pk, RLL, n.ll, 255, 128, eb, sizeof eb); pk[0] = 0x40; n6_rx(&n, pk, l, 0, &OPS);
    l = mk(pk, RLL, n.ll, 255, 128, eb, sizeof eb); wr16(pk + 4, 2000); n6_rx(&n, pk, l, 0, &OPS);

    /* non-ICMP packet for us goes up to the tun; for another host it does not */
    uint8_t udp[48]; memset(udp, 0, sizeof udp); udp[0] = 0x60; wr16(udp + 4, 8); udp[6] = 17; udp[7] = 64; memcpy(udp + 8, RLL, 16); memcpy(udp + 24, n.ll, 16);
    tun_n = 0; n6_rx(&n, udp, 48, 0, &OPS); CHECK(tun_n == 1);
    memcpy(udp + 24, other, 16); n6_rx(&n, udp, 48, 0, &OPS); CHECK(tun_n == 1);

    /* tx from the tun to an off-link address goes to the router's MAC */
    uint8_t out[48]; memset(out, 0, sizeof out); out[0] = 0x60; wr16(out + 4, 8); out[6] = 17; out[7] = 64; memcpy(out + 8, n.gua, 16);
    out[24] = 0x26; out[25] = 0x06; out[39] = 1;
    sent.n = 0; CHECK(n6_tx_ip(&n, out, 48, 40000, &OPS) == 0 && sent.n == 1 && !memcmp(sent.mac, RMAC, 6));
    { n6_t m; n6_init(&m, MAC); CHECK(n6_tx_ip(&m, out, 48, 0, &OPS) == -1); }          /* no router yet */

    printf("net6: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
