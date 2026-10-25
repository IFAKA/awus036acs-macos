// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* net6.h - the IPv6 side of the userspace stack: a link-local address from the MAC (EUI-64), neighbour discovery
 * (answer Neighbor Solicitations, resolve with our own), Router Solicitation / Router Advertisement parsing for SLAAC
 * (global address, prefix, router, RDNSS DNS servers, MTU), ICMPv6 echo (reply, and our own ping). Pure functions over
 * byte buffers like net.c: no sockets, no clocks (time is passed in). Addresses are 16 bytes, network order. Duplicate
 * address detection is not done (the EUI-64 address is unique as long as the MAC is). */
#ifndef NET6_H
#define NET6_H
#include <stddef.h>
#include <stdint.h>

#define N6_NBR_SLOTS 8
#define N6_MAX_DNS   3
#define N6_PEND_MAX  1500

typedef struct {
    void *ctx;
    /* an IPv6 packet (header + payload) for the given destination MAC; the caller adds LLC/SNAP */
    void (*tx)(void *ctx, const uint8_t dst_mac[6], const uint8_t *ip6, size_t len);
    /* an IPv6 packet addressed to us that the stack does not answer itself (for the utun); may be NULL */
    void (*to_tun)(void *ctx, const uint8_t *ip6, size_t len);
} n6_ops_t;

typedef struct { uint8_t a[16]; uint8_t mac[6]; int valid; } n6_nbr_t;

typedef struct {
    uint8_t mac[6], ll[16];
    uint8_t gua[16]; int has_gua;                 /* SLAAC address: advertised /64 prefix + our EUI-64 interface id */
    uint8_t prefix[16]; int prefix_len; uint32_t valid_s, preferred_s;
    uint8_t router[16]; uint8_t router_mac[6]; int has_router, has_router_mac; uint16_t router_lifetime_s;
    uint8_t dns[N6_MAX_DNS][16]; int ndns; uint32_t dns_lifetime_s;
    uint32_t mtu;
    n6_nbr_t nbr[N6_NBR_SLOTS]; int nbr_next;
    unsigned ra_count;
    /* router solicitation timer */
    uint64_t t_rs; int rs_sent;
    /* one packet waiting for neighbour resolution */
    uint8_t pend[N6_PEND_MAX]; size_t pend_len; uint8_t pend_dst[16]; uint64_t pend_t;
    /* our own ping */
    uint8_t ping_dst[16]; uint16_t ping_id, ping_seq; int ping_got; uint64_t ping_t; long ping_rtt_ms;
} n6_t;

void n6_init(n6_t *n, const uint8_t mac[6]);
/* helpers (exposed for tests) */
void n6_eui64_ll(uint8_t out[16], const uint8_t mac[6]);                 /* fe80::<EUI-64> */
void n6_solicited_node(uint8_t out[16], const uint8_t addr[16]);         /* ff02::1:ffXX:XXXX */
void n6_mcast_mac(uint8_t mac[6], const uint8_t addr[16]);               /* 33:33:<last 4 bytes> */
uint16_t n6_icmp_cksum(const uint8_t src[16], const uint8_t dst[16], const uint8_t *icmp, size_t len);   /* value to store (0 over a valid message) */
/* Send a Router Solicitation (to ff02::2) now. */
void n6_send_rs(n6_t *n, uint64_t now, const n6_ops_t *ops);
/* Retries the Router Solicitation (3 tries, 4 s apart) until a Router Advertisement arrived. Call about every 500 ms. */
void n6_tick(n6_t *n, uint64_t now, const n6_ops_t *ops);
/* Feed one IPv6 packet (LLC/SNAP already removed). Garbage is ignored. */
void n6_rx(n6_t *n, const uint8_t *pkt, size_t len, uint64_t now, const n6_ops_t *ops);
/* Send an IPv6 packet from the tun (resolves the next hop: the router for off-link, the neighbour for on-link
 * link-local). 0 = sent or queued, -1 = rejected. */
int  n6_tx_ip(n6_t *n, const uint8_t *pkt, size_t len, uint64_t now, const n6_ops_t *ops);
/* Our own ICMPv6 echo request. Resolves the neighbour first when needed. n->ping_got becomes 1 when the reply arrives. */
int  n6_ping(n6_t *n, const uint8_t dst[16], uint16_t id, uint16_t seq, uint64_t now, const n6_ops_t *ops);
int  n6_nbr_lookup(const n6_t *n, const uint8_t addr[16], uint8_t mac[6]);
#endif
