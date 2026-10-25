// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* net6.c - see net6.h */
#include <string.h>
#include "net6.h"

#define ICMP6_ECHO_REQ 128
#define ICMP6_ECHO_REP 129
#define ICMP6_RS 133
#define ICMP6_RA 134
#define ICMP6_NS 135
#define ICMP6_NA 136
#define RS_RETRY_MS 4000
#define RS_MAX 3
#define PEND_MAX_AGE_MS 3000

static const uint8_t ALL_ROUTERS[16] = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = (uint8_t)v; }
static int is_ll(const uint8_t *a) { return a[0] == 0xfe && (a[1] & 0xc0) == 0x80; }
static int is_unspec(const uint8_t *a) { static const uint8_t z[16] = {0}; return !memcmp(a, z, 16); }
static int is_mcast(const uint8_t *a) { return a[0] == 0xff; }

void n6_eui64_ll(uint8_t o[16], const uint8_t m[6])
{
    memset(o, 0, 16);
    o[0] = 0xfe; o[1] = 0x80;
    o[8] = m[0] ^ 0x02; o[9] = m[1]; o[10] = m[2]; o[11] = 0xff; o[12] = 0xfe; o[13] = m[3]; o[14] = m[4]; o[15] = m[5];
}

void n6_solicited_node(uint8_t o[16], const uint8_t a[16])
{
    memset(o, 0, 16);
    o[0] = 0xff; o[1] = 0x02; o[11] = 0x01; o[12] = 0xff; o[13] = a[13]; o[14] = a[14]; o[15] = a[15];
}

void n6_mcast_mac(uint8_t m[6], const uint8_t a[16]) { m[0] = m[1] = 0x33; memcpy(m + 2, a + 12, 4); }

uint16_t n6_icmp_cksum(const uint8_t src[16], const uint8_t dst[16], const uint8_t *icmp, size_t len)
{
    uint32_t s = 0;
    for (int i = 0; i < 16; i += 2) s += rd16(src + i) + rd16(dst + i);
    s += (uint32_t)(len >> 16) + (uint32_t)(len & 0xffff) + 58;
    for (size_t i = 0; i + 1 < len; i += 2) s += rd16(icmp + i);
    if (len & 1) s += (uint32_t)icmp[len - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

void n6_init(n6_t *n, const uint8_t mac[6])
{
    memset(n, 0, sizeof *n);
    memcpy(n->mac, mac, 6);
    n6_eui64_ll(n->ll, mac);
}

/* ---- neighbour cache ---- */
static void nbr_learn(n6_t *n, const uint8_t a[16], const uint8_t mac[6])
{
    for (int i = 0; i < N6_NBR_SLOTS; i++)
        if (n->nbr[i].valid && !memcmp(n->nbr[i].a, a, 16)) { memcpy(n->nbr[i].mac, mac, 6); return; }
    int s = n->nbr_next++ % N6_NBR_SLOTS;
    memcpy(n->nbr[s].a, a, 16); memcpy(n->nbr[s].mac, mac, 6); n->nbr[s].valid = 1;
}

int n6_nbr_lookup(const n6_t *n, const uint8_t a[16], uint8_t mac[6])
{
    for (int i = 0; i < N6_NBR_SLOTS; i++)
        if (n->nbr[i].valid && !memcmp(n->nbr[i].a, a, 16)) { memcpy(mac, n->nbr[i].mac, 6); return 0; }
    return -1;
}

/* ---- packet building ---- */
/* IPv6 header (40 bytes) + ICMPv6 body (type, code, body...). Returns total length. */
static size_t build_icmp(uint8_t *o, const uint8_t src[16], const uint8_t dst[16], int hop, int type, const uint8_t *body, size_t blen)
{
    size_t il = 4 + blen;
    memset(o, 0, 40);
    o[0] = 0x60; wr16(o + 4, (uint16_t)il); o[6] = 58; o[7] = (uint8_t)hop;
    memcpy(o + 8, src, 16); memcpy(o + 24, dst, 16);
    o[40] = (uint8_t)type; o[41] = 0; o[42] = o[43] = 0;
    if (blen) memcpy(o + 44, body, blen);
    wr16(o + 42, n6_icmp_cksum(src, dst, o + 40, il));
    return 40 + il;
}

static const uint8_t *src_for(const n6_t *n, const uint8_t dst[16]) { return (!is_ll(dst) && !is_mcast(dst) && n->has_gua) ? n->gua : n->ll; }

static void send_ns(n6_t *n, const uint8_t target[16], const n6_ops_t *ops)
{
    uint8_t body[4 + 16 + 8], pkt[40 + 4 + sizeof body], dst[16], mac[6];
    memset(body, 0, sizeof body);
    memcpy(body + 4, target, 16);
    body[20] = 1; body[21] = 1; memcpy(body + 22, n->mac, 6);          /* source link-layer address option */
    n6_solicited_node(dst, target); n6_mcast_mac(mac, dst);
    size_t l = build_icmp(pkt, n->ll, dst, 255, ICMP6_NS, body, sizeof body);
    ops->tx(ops->ctx, mac, pkt, l);
}

void n6_send_rs(n6_t *n, uint64_t now, const n6_ops_t *ops)
{
    uint8_t body[4 + 8], pkt[40 + 4 + sizeof body], mac[6];
    memset(body, 0, sizeof body);
    body[4] = 1; body[5] = 1; memcpy(body + 6, n->mac, 6);
    n6_mcast_mac(mac, ALL_ROUTERS);
    size_t l = build_icmp(pkt, n->ll, ALL_ROUTERS, 255, ICMP6_RS, body, sizeof body);
    ops->tx(ops->ctx, mac, pkt, l);
    n->t_rs = now; n->rs_sent++;
}

void n6_tick(n6_t *n, uint64_t now, const n6_ops_t *ops)
{
    if (n->ra_count == 0 && n->rs_sent < RS_MAX && (n->rs_sent == 0 || now - n->t_rs >= RS_RETRY_MS)) n6_send_rs(n, now, ops);
    if (n->pend_len && now - n->pend_t >= PEND_MAX_AGE_MS) n->pend_len = 0;
}

static void flush_pend(n6_t *n, const n6_ops_t *ops)
{
    uint8_t mac[6];
    if (!n->pend_len) return;
    const uint8_t *hop = n->pend_dst;
    if (n6_nbr_lookup(n, hop, mac)) return;
    ops->tx(ops->ctx, mac, n->pend, n->pend_len);
    n->pend_len = 0;
}

/* next hop for a destination: itself when link-local (or the router's own address), else the default router */
static const uint8_t *next_hop(const n6_t *n, const uint8_t dst[16])
{
    if (is_ll(dst)) return dst;
    return n->has_router ? n->router : NULL;
}

static int send_resolved(n6_t *n, const uint8_t *pkt, size_t len, const uint8_t *hop, uint64_t now, const n6_ops_t *ops)
{
    uint8_t mac[6];
    if (len > N6_PEND_MAX) return -1;
    if (n->has_router_mac && n->has_router && !memcmp(hop, n->router, 16)) memcpy(mac, n->router_mac, 6);
    else if (n6_nbr_lookup(n, hop, mac)) {
        memcpy(n->pend, pkt, len); n->pend_len = len; memcpy(n->pend_dst, hop, 16); n->pend_t = now;
        send_ns(n, hop, ops);
        return 0;
    }
    ops->tx(ops->ctx, mac, pkt, len);
    return 0;
}

int n6_tx_ip(n6_t *n, const uint8_t *pkt, size_t len, uint64_t now, const n6_ops_t *ops)
{
    if (len < 40 || (pkt[0] >> 4) != 6) return -1;
    if (is_mcast(pkt + 24)) {                                   /* multicast: map to the group MAC */
        uint8_t mac[6]; n6_mcast_mac(mac, pkt + 24);
        ops->tx(ops->ctx, mac, pkt, len);
        return 0;
    }
    const uint8_t *hop = next_hop(n, pkt + 24);
    if (!hop) return -1;
    return send_resolved(n, pkt, len, hop, now, ops);
}

int n6_ping(n6_t *n, const uint8_t dst[16], uint16_t id, uint16_t seq, uint64_t now, const n6_ops_t *ops)
{
    uint8_t body[4 + 32], pkt[40 + 4 + sizeof body];
    for (int i = 0; i < 32; i++) body[4 + i] = (uint8_t)(0x20 + i);
    wr16(body, id); wr16(body + 2, seq);
    const uint8_t *hop = next_hop(n, dst);
    if (!hop) return -1;
    size_t l = build_icmp(pkt, src_for(n, dst), dst, 64, ICMP6_ECHO_REQ, body, sizeof body);
    memcpy(n->ping_dst, dst, 16); n->ping_id = id; n->ping_seq = seq; n->ping_got = 0; n->ping_t = now;
    return send_resolved(n, pkt, l, hop, now, ops);
}

/* ---- receive ---- */
static int mine(const n6_t *n, const uint8_t *a) { return !memcmp(a, n->ll, 16) || (n->has_gua && !memcmp(a, n->gua, 16)); }

static void handle_ra(n6_t *n, const uint8_t *src, const uint8_t *icmp, size_t il)
{
    if (il < 16 || !is_ll(src)) return;
    uint16_t life = rd16(icmp + 6);
    n->ra_count++;
    memcpy(n->router, src, 16); n->router_lifetime_s = life; n->has_router = life != 0;
    size_t i = 16;
    while (i + 2 <= il) {
        size_t ol = (size_t)icmp[i + 1] * 8;
        if (ol == 0 || i + ol > il) break;                       /* malformed option list: stop, keep what we have */
        const uint8_t *o = icmp + i;
        switch (o[0]) {
        case 1: if (ol >= 8) { memcpy(n->router_mac, o + 2, 6); n->has_router_mac = 1; nbr_learn(n, src, o + 2); } break;
        case 3: if (ol == 32 && o[2] == 64 && (o[3] & 0x40)) {   /* prefix information, on-link/autonomous, /64 only */
                    uint32_t v = rd32(o + 4), p = rd32(o + 8);
                    if (v && p <= v && !is_ll(o + 16) && !is_mcast(o + 16) && !is_unspec(o + 16)) {
                        memcpy(n->prefix, o + 16, 16); memset(n->prefix + 8, 0, 8); n->prefix_len = 64;
                        n->valid_s = v; n->preferred_s = p;
                        memcpy(n->gua, n->prefix, 8); memcpy(n->gua + 8, n->ll + 8, 8); n->has_gua = 1;
                    }
                } break;
        case 5: if (ol >= 8) n->mtu = rd32(o + 4); break;
        case 25: if (ol >= 24 && (ol - 8) % 16 == 0) {           /* RDNSS: reserved(2) lifetime(4) addresses */
                    n->dns_lifetime_s = rd32(o + 4);
                    n->ndns = 0;
                    for (size_t k = 8; k + 16 <= ol && n->ndns < N6_MAX_DNS; k += 16) memcpy(n->dns[n->ndns++], o + k, 16);
                } break;
        }
        i += ol;
    }
}

void n6_rx(n6_t *n, const uint8_t *p, size_t len, uint64_t now, const n6_ops_t *ops)
{
    if (len < 40 || (p[0] >> 4) != 6) return;
    size_t pl = rd16(p + 4);
    if (pl + 40 > len) return;
    const uint8_t *src = p + 8, *dst = p + 24;
    if (p[6] != 58) {                                           /* not ICMPv6: pass up when it is for us */
        if ((mine(n, dst) || dst[0] == 0xff) && ops->to_tun) ops->to_tun(ops->ctx, p, 40 + pl);
        return;
    }
    if (pl < 4) return;
    const uint8_t *ic = p + 40;
    if (n6_icmp_cksum(src, dst, ic, pl) != 0) return;
    int type = ic[0];
    if (type == ICMP6_RA) {
        if (p[7] != 255 || ic[1] != 0) return;                  /* hop limit 255 proves it came from the link */
        handle_ra(n, src, ic, pl);
        flush_pend(n, ops);
    } else if (type == ICMP6_NS) {
        if (p[7] != 255 || ic[1] != 0 || pl < 24 || is_mcast(ic + 8)) return;
        if (!mine(n, ic + 8) || is_unspec(src)) return;          /* not for us, or duplicate address detection: no answer */
        uint8_t mac[6]; int have = 0;
        for (size_t i = 24; i + 8 <= pl && ic[i + 1]; i += (size_t)ic[i + 1] * 8)
            if (ic[i] == 1 && ic[i + 1] == 1) { memcpy(mac, ic + i + 2, 6); have = 1; break; }
        if (have) nbr_learn(n, src, mac);
        else if (n6_nbr_lookup(n, src, mac) == 0) have = 1;
        if (!have) return;
        uint8_t body[4 + 16 + 8], pkt[40 + 4 + sizeof body];
        memset(body, 0, sizeof body);
        body[0] = 0x60;                                          /* solicited + override */
        memcpy(body + 4, ic + 8, 16);
        body[20] = 2; body[21] = 1; memcpy(body + 22, n->mac, 6);
        size_t l = build_icmp(pkt, ic + 8, src, 255, ICMP6_NA, body, sizeof body);
        ops->tx(ops->ctx, mac, pkt, l);
    } else if (type == ICMP6_NA) {
        if (p[7] != 255 || ic[1] != 0 || pl < 24) return;
        for (size_t i = 24; i + 8 <= pl && ic[i + 1]; i += (size_t)ic[i + 1] * 8)
            if (ic[i] == 2 && ic[i + 1] == 1) { nbr_learn(n, ic + 8, ic + i + 2); break; }
        flush_pend(n, ops);
    } else if (type == ICMP6_ECHO_REQ) {
        if (!mine(n, dst) || pl < 8) return;
        uint8_t mac[6];
        if (n6_nbr_lookup(n, src, mac)) {
            if (n->has_router_mac && n->has_router && !memcmp(src, n->router, 16)) memcpy(mac, n->router_mac, 6);
            else return;                                         /* unknown neighbour: the sender will solicit us first */
        }
        uint8_t pkt[1500];
        if (pl - 4 > sizeof pkt - 44) return;
        size_t l = build_icmp(pkt, dst, src, 64, ICMP6_ECHO_REP, ic + 4, pl - 4);
        ops->tx(ops->ctx, mac, pkt, l);
    } else if (type == ICMP6_ECHO_REP) {
        if (pl >= 8 && !memcmp(src, n->ping_dst, 16) && rd16(ic + 4) == n->ping_id && rd16(ic + 6) == n->ping_seq && !n->ping_got) {
            n->ping_got = 1; n->ping_rtt_ms = (long)(now - n->ping_t);
        } else if (ops->to_tun && mine(n, dst)) ops->to_tun(ops->ctx, p, 40 + pl);
    } else if (mine(n, dst) || dst[0] == 0xff) {
        if (ops->to_tun) ops->to_tun(ops->ctx, p, 40 + pl);
    }
}
