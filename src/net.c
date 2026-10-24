/* net.c - LLC/SNAP, ARP, DHCP client, IP tx queue. See net.h. */
#include "net.h"
#include <string.h>

static const uint8_t BCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t ZERO6[6] = {0};
static const uint8_t SNAP[6]  = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00};

#define DHCP_RETRY_MS  4000
#define DHCP_MAX_TRIES 3
#define ARP_RETRY_MS   1000
#define TXQ_MAX_AGE_MS 5000
#define HOSTNAME       "awus036acs"

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p)
{ return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v)
{ p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = (uint8_t)v; }

static uint32_t sum_words(const uint8_t *p, size_t len, uint32_t s)
{
    while (len > 1) { s += rd16(p); p += 2; len -= 2; }
    if (len) s += (uint32_t)p[0] << 8;
    return s;
}
static uint16_t fold(uint32_t s)
{
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
uint16_t net_cksum(const uint8_t *p, size_t len) { return fold(sum_words(p, len, 0)); }

/* ---------------- LLC/SNAP ---------------- */
int net_llc_parse(const uint8_t *p, size_t len, uint16_t *et,
                  const uint8_t **payload, size_t *plen)
{
    if (!p || len < NET_LLC_LEN || memcmp(p, SNAP, 6) != 0) return -1;
    *et = rd16(p + 6); *payload = p + NET_LLC_LEN; *plen = len - NET_LLC_LEN;
    return 0;
}
size_t net_llc_build(uint8_t *out, size_t cap, uint16_t et,
                     const uint8_t *payload, size_t plen)
{
    if (cap < NET_LLC_LEN || plen > cap - NET_LLC_LEN) return 0;
    memcpy(out, SNAP, 6); wr16(out + 6, et);
    if (plen) memmove(out + NET_LLC_LEN, payload, plen);
    return NET_LLC_LEN + plen;
}

/* ---------------- ARP ---------------- */
void net_arp_build(uint8_t o[NET_ARP_LEN], uint16_t op, const uint8_t sha[6],
                   uint32_t spa, const uint8_t tha[6], uint32_t tpa)
{
    wr16(o, 1); wr16(o + 2, NET_ETH_IP); o[4] = 6; o[5] = 4; wr16(o + 6, op);
    memcpy(o + 8, sha, 6); wr32(o + 14, spa);
    memcpy(o + 18, tha, 6); wr32(o + 24, tpa);
}
int net_arp_parse(const uint8_t *p, size_t len, net_arp_t *a)
{
    if (!p || len < NET_ARP_LEN) return -1;
    if (rd16(p) != 1 || rd16(p + 2) != NET_ETH_IP || p[4] != 6 || p[5] != 4) return -1;
    a->op = rd16(p + 6);
    if (a->op != 1 && a->op != 2) return -1;
    memcpy(a->sha, p + 8, 6);  a->spa = rd32(p + 14);
    memcpy(a->tha, p + 18, 6); a->tpa = rd32(p + 24);
    return 0;
}

static void send_frame(const net_ops_t *ops, const uint8_t dst[6],
                       const uint8_t *buf, size_t len)
{ if (ops && ops->tx) ops->tx(ops->ctx, dst, buf, len); }

static void send_arp(const net_t *n, const net_ops_t *ops, uint16_t op,
                     const uint8_t *tha, uint32_t tpa, const uint8_t *dst)
{
    uint8_t body[NET_ARP_LEN], f[NET_LLC_LEN + NET_ARP_LEN];
    net_arp_build(body, op, n->mac, n->configured ? n->lease.ip : 0,
                  tha, tpa);
    size_t l = net_llc_build(f, sizeof f, NET_ETH_ARP, body, sizeof body);
    send_frame(ops, dst, f, l);
}

int net_arp_lookup(const net_t *n, uint32_t ip, uint8_t mac[6])
{
    for (int i = 0; i < NET_ARP_SLOTS; i++)
        if (n->arp[i].valid && n->arp[i].ip == ip) {
            memcpy(mac, n->arp[i].mac, 6); return 0;
        }
    return -1;
}
static void arp_learn(net_t *n, uint32_t ip, const uint8_t mac[6])
{
    if (ip == 0 || !memcmp(mac, ZERO6, 6) || !memcmp(mac, BCAST, 6) || (mac[0] & 1)) return;
    for (int i = 0; i < NET_ARP_SLOTS; i++)
        if (n->arp[i].valid && n->arp[i].ip == ip) {
            memcpy(n->arp[i].mac, mac, 6); return;
        }
    net_arp_entry_t *e = &n->arp[n->arp_next];
    n->arp_next = (n->arp_next + 1) % NET_ARP_SLOTS;
    e->ip = ip; memcpy(e->mac, mac, 6); e->valid = 1;
}
void net_arp_request(net_t *n, uint32_t ip, const net_ops_t *ops)
{ send_arp(n, ops, 1, ZERO6, ip, BCAST); }

/* ---------------- IPv4 helpers ---------------- */
/* Returns header length if a sane IPv4 packet, else 0. */
static size_t ip_check(const uint8_t *p, size_t len, size_t *total)
{
    if (len < 20 || (p[0] >> 4) != 4) return 0;
    size_t ihl = (size_t)(p[0] & 15) * 4, tl = rd16(p + 2);
    if (ihl < 20 || ihl > len || tl < ihl || tl > len) return 0;
    *total = tl;
    return ihl;
}

/* ---------------- DHCP ---------------- */
int net_dhcp_parse(const uint8_t *p, size_t len, net_dhcp_msg_t *m)
{
    size_t tl, ihl = p ? ip_check(p, len, &tl) : 0;
    if (!ihl || p[9] != 17) return -1;
    if (net_cksum(p, ihl) != 0) return -1;
    if (rd16(p + 6) & 0x3fff) return -1;                 /* fragment */
    if (tl - ihl < 8 + 240) return -1;
    const uint8_t *u = p + ihl;
    size_t ul = rd16(u + 4);
    if (rd16(u) != 67 || rd16(u + 2) != 68 || ul < 8 + 240 || ul > tl - ihl) return -1;
    if (rd16(u + 6) != 0) {
        uint32_t s = sum_words(p + 12, 8, 0);
        s += 17 + (uint32_t)ul;
        s = sum_words(u, ul, s);
        if (fold(s) != 0) return -1;
    }
    const uint8_t *d = u + 8; size_t dl = ul - 8;
    if (d[0] != 2 || d[1] != 1 || d[2] != 6) return -1;
    if (rd32(d + 236) != 0x63825363u) return -1;
    memset(m, 0, sizeof *m);
    m->xid = rd32(d + 4); m->yiaddr = rd32(d + 16);
    memcpy(m->chaddr, d + 28, 6);
    size_t i = 240;
    while (i < dl) {
        uint8_t c = d[i];
        if (c == 0) { i++; continue; }
        if (c == 255) break;
        if (i + 1 >= dl) return -1;
        size_t l = d[i + 1];
        if (i + 2 + l > dl) return -1;                   /* truncated option */
        const uint8_t *v = d + i + 2;
        switch (c) {
        case 53: if (l == 1) m->type = v[0]; break;
        case 1:  if (l == 4) { m->mask = rd32(v); m->has_mask = 1; } break;
        case 3:  if (l >= 4) { m->router = rd32(v); m->has_router = 1; } break;
        case 6:  for (size_t k = 0; k + 4 <= l && m->ndns < 4; k += 4)
                     m->dns[m->ndns++] = rd32(v + k);
                 break;
        case 51: if (l == 4) { m->lease = rd32(v); m->has_lease = 1; } break;
        case 54: if (l == 4) { m->server_id = rd32(v); m->has_server_id = 1; } break;
        }
        i += 2 + l;
    }
    return m->type ? 0 : -1;
}

/* Build LLC + IPv4 + UDP 68->67 + BOOTP request. Returns frame length. */
static size_t build_dhcp(net_t *n, uint8_t *out, size_t cap, uint8_t type,
                         uint32_t ciaddr, uint32_t reqip, uint32_t srvid, uint16_t secs)
{
    uint8_t buf[NET_LLC_LEN + 20 + 8 + 320];
    if (cap < sizeof buf) return 0;
    memset(buf, 0, sizeof buf);
    memcpy(buf, SNAP, 6); wr16(buf + 6, NET_ETH_IP);
    uint8_t *ip = buf + NET_LLC_LEN, *u = ip + 20, *d = u + 8;
    d[0] = 1; d[1] = 1; d[2] = 6; d[3] = 0;
    wr32(d + 4, n->xid); wr16(d + 8, secs);
    wr16(d + 10, ciaddr ? 0 : 0x8000);                   /* broadcast flag */
    wr32(d + 12, ciaddr);
    memcpy(d + 28, n->mac, 6);
    wr32(d + 236, 0x63825363u);
    uint8_t *o = d + 240;
    *o++ = 53; *o++ = 1; *o++ = type;
    *o++ = 61; *o++ = 7; *o++ = 1; memcpy(o, n->mac, 6); o += 6;
    *o++ = 12; *o++ = (uint8_t)(sizeof HOSTNAME - 1);
    memcpy(o, HOSTNAME, sizeof HOSTNAME - 1); o += sizeof HOSTNAME - 1;
    if (reqip)  { *o++ = 50; *o++ = 4; wr32(o, reqip); o += 4; }
    if (srvid)  { *o++ = 54; *o++ = 4; wr32(o, srvid); o += 4; }
    *o++ = 55; *o++ = 6; *o++ = 1; *o++ = 3; *o++ = 6; *o++ = 15; *o++ = 51; *o++ = 54;
    *o++ = 255;
    size_t dl = (size_t)(o - d);
    if (dl < 300) dl = 300;                              /* BOOTP minimum, zero pad */
    size_t ul = 8 + dl, tl = 20 + ul;
    ip[0] = 0x45; wr16(ip + 2, (uint16_t)tl); wr16(ip + 4, (uint16_t)++n->ip_id);
    ip[8] = 64; ip[9] = 17;
    wr32(ip + 12, ciaddr); wr32(ip + 16, 0xffffffffu);
    wr16(ip + 10, net_cksum(ip, 20));
    wr16(u, 68); wr16(u + 2, 67); wr16(u + 4, (uint16_t)ul);
    uint32_t s = sum_words(ip + 12, 8, 0) + 17 + (uint32_t)ul;
    s = sum_words(u, ul, s);
    uint16_t c = fold(s); if (c == 0) c = 0xffff;
    wr16(u + 6, c);
    size_t tot = NET_LLC_LEN + tl;
    memcpy(out, buf, tot);
    return tot;
}

static void dhcp_send(net_t *n, const net_ops_t *ops, uint8_t type, uint32_t ciaddr,
                      uint32_t reqip, uint32_t srvid, uint64_t now)
{
    uint8_t f[NET_LLC_LEN + 20 + 8 + 320];
    uint16_t secs = 0;
    if (now >= n->t_start) { uint64_t s = (now - n->t_start) / 1000; secs = s > 0xffff ? 0xffff : (uint16_t)s; }
    size_t l = build_dhcp(n, f, sizeof f, type, ciaddr, reqip, srvid, secs);
    n->t_last_tx = now;
    if (l) send_frame(ops, BCAST, f, l);
}

void net_init(net_t *n, const uint8_t mac[6])
{
    memset(n, 0, sizeof *n);
    memcpy(n->mac, mac, 6);
    n->xid_ctr = rd32(mac + 2) ^ 0x5eed1234u;
}

static void lease_lost(net_t *n, const net_ops_t *ops)
{
    if (n->configured) {
        net_lease_t old = n->lease;
        n->configured = 0;
        memset(&n->lease, 0, sizeof n->lease);
        memset(n->arp, 0, sizeof n->arp);
        if (ops && ops->lease) ops->lease(ops->ctx, &old, 0);
    }
}

void net_dhcp_start(net_t *n, uint64_t now, const net_ops_t *ops)
{
    n->xid_ctr = n->xid_ctr * 1664525u + 1013904223u;
    n->xid = n->xid_ctr;
    n->dhcp_state = NET_DHCP_SELECTING;
    n->t_start = now; n->tries = 0;
    dhcp_send(n, ops, DHCP_DISCOVER, 0, 0, 0, now);
}

static void dhcp_rx(net_t *n, const uint8_t *ip, size_t len, uint64_t now,
                    const net_ops_t *ops)
{
    net_dhcp_msg_t m;
    if (n->dhcp_state == NET_DHCP_IDLE || n->dhcp_state == NET_DHCP_BOUND) return;
    if (net_dhcp_parse(ip, len, &m) != 0) return;
    if (m.xid != n->xid || memcmp(m.chaddr, n->mac, 6) != 0) return;

    if (n->dhcp_state == NET_DHCP_SELECTING && m.type == DHCP_OFFER) {
        if (!m.has_server_id || m.yiaddr == 0) return;
        n->offer_ip = m.yiaddr; n->offer_server = m.server_id;
        n->dhcp_state = NET_DHCP_REQUESTING; n->tries = 0;
        dhcp_send(n, ops, DHCP_REQUEST, 0, n->offer_ip, n->offer_server, now);
    } else if ((n->dhcp_state == NET_DHCP_REQUESTING ||
                n->dhcp_state == NET_DHCP_RENEWING) && m.type == DHCP_ACK) {
        if (m.yiaddr == 0 || !m.has_mask) return;
        net_lease_t l; memset(&l, 0, sizeof l);
        l.ip = m.yiaddr; l.mask = m.mask;
        l.gw = m.has_router ? m.router : 0;
        l.ndns = m.ndns; memcpy(l.dns, m.dns, sizeof l.dns);
        l.lease_s = m.has_lease ? m.lease : 3600;
        l.server_id = m.has_server_id ? m.server_id : n->offer_server;
        int changed = !n->configured || n->lease.ip != l.ip || n->lease.gw != l.gw ||
                      n->lease.mask != l.mask;
        n->lease = l; n->configured = 1;
        n->dhcp_state = NET_DHCP_BOUND; n->t_bound = now;
        if (changed) {
            memset(n->arp, 0, sizeof n->arp);
            if (ops && ops->lease) ops->lease(ops->ctx, &n->lease, 1);
            if (l.gw) net_arp_request(n, l.gw, ops);     /* prime gateway cache */
        }
    } else if (m.type == DHCP_NAK &&
               (n->dhcp_state == NET_DHCP_REQUESTING || n->dhcp_state == NET_DHCP_RENEWING)) {
        lease_lost(n, ops);
        net_dhcp_start(n, now, ops);
    }
}

/* ---------------- tx path ---------------- */
static void txq_flush(net_t *n, const net_ops_t *ops)
{
    for (int i = 0; i < NET_TXQ_SLOTS; i++) {
        net_txq_t *q = &n->txq[i];
        uint8_t mac[6], f[NET_MAX_FRAME];
        if (!q->used || net_arp_lookup(n, q->nexthop, mac) != 0) continue;
        size_t l = net_llc_build(f, sizeof f, NET_ETH_IP, q->pkt, q->len);
        q->used = 0;
        if (l) send_frame(ops, mac, f, l);
    }
}

int net_tx_ip(net_t *n, const uint8_t *ip, size_t len, uint64_t now, const net_ops_t *ops)
{
    size_t tl;
    if (!n->configured || !ip || len > NET_MTU || !ip_check(ip, len, &tl)) return -1;
    len = tl;
    uint32_t dst = rd32(ip + 16), L = n->lease.ip, M = n->lease.mask;
    uint8_t mac[6], f[NET_MAX_FRAME];
    if (dst == 0xffffffffu || (M != 0xffffffffu && dst == (L | ~M))) {
        size_t l = net_llc_build(f, sizeof f, NET_ETH_IP, ip, len);
        send_frame(ops, BCAST, f, l);
        return 0;
    }
    uint32_t hop;
    if ((dst & M) == (L & M)) hop = dst;
    else if (n->lease.gw) hop = n->lease.gw;
    else return -1;
    if (net_arp_lookup(n, hop, mac) == 0) {
        size_t l = net_llc_build(f, sizeof f, NET_ETH_IP, ip, len);
        send_frame(ops, mac, f, l);
        return 0;
    }
    /* queue (replace oldest if full), then ARP unless already pending */
    int slot = -1, pending = 0;
    for (int i = 0; i < NET_TXQ_SLOTS; i++) {
        if (n->txq[i].used && n->txq[i].nexthop == hop) pending = 1;
        if (slot < 0 && !n->txq[i].used) slot = i;
    }
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < NET_TXQ_SLOTS; i++) if (n->txq[i].t < n->txq[slot].t) slot = i;
    }
    memcpy(n->txq[slot].pkt, ip, len); n->txq[slot].len = (uint16_t)len;
    n->txq[slot].nexthop = hop; n->txq[slot].t = now; n->txq[slot].used = 1;
    if (!pending) { net_arp_request(n, hop, ops); n->t_last_arp = now; }
    return 0;
}

/* ---------------- rx path ---------------- */
void net_rx(net_t *n, const uint8_t *p, size_t len, uint64_t now, const net_ops_t *ops)
{
    uint16_t et; const uint8_t *pl; size_t pn;
    if (net_llc_parse(p, len, &et, &pl, &pn) != 0) return;
    if (et == NET_ETH_ARP) {
        net_arp_t a;
        if (net_arp_parse(pl, pn, &a) != 0 || !n->configured) return;
        if (a.tpa != n->lease.ip) {
            /* only refresh entries we already hold */
            uint8_t old[6];
            if (a.op == 1 && net_arp_lookup(n, a.spa, old) == 0) arp_learn(n, a.spa, a.sha);
            return;
        }
        if (a.spa == n->lease.ip) return;                /* conflict/gratuitous echo */
        arp_learn(n, a.spa, a.sha);
        if (a.op == 1) send_arp(n, ops, 2, a.sha, a.spa, a.sha);
        txq_flush(n, ops);
    } else if (et == NET_ETH_IP) {
        size_t tl, ihl = ip_check(pl, pn, &tl);
        if (!ihl) return;
        if (pl[9] == 17 && tl >= ihl + 4 && rd16(pl + ihl + 2) == 68) {
            dhcp_rx(n, pl, tl, now, ops);
            return;
        }
        if (!n->configured) return;
        uint32_t dst = rd32(pl + 16);
        if (dst != n->lease.ip && dst != 0xffffffffu &&
            dst != (n->lease.ip | ~n->lease.mask) && (dst >> 28) != 0xE) return;
        if (ops && ops->to_tun) ops->to_tun(ops->ctx, pl, tl);
    }
}

void net_tick(net_t *n, uint64_t now, const net_ops_t *ops)
{
    switch (n->dhcp_state) {
    case NET_DHCP_SELECTING:
        if (now - n->t_last_tx >= DHCP_RETRY_MS)
            dhcp_send(n, ops, DHCP_DISCOVER, 0, 0, 0, now);
        break;
    case NET_DHCP_REQUESTING:
        if (now - n->t_last_tx >= DHCP_RETRY_MS) {
            if (++n->tries >= DHCP_MAX_TRIES) net_dhcp_start(n, now, ops);
            else dhcp_send(n, ops, DHCP_REQUEST, 0, n->offer_ip, n->offer_server, now);
        }
        break;
    case NET_DHCP_BOUND:
        if (n->lease.lease_s != 0xffffffffu &&
            now - n->t_bound >= (uint64_t)n->lease.lease_s * 500) {   /* T1 = lease/2 */
            n->dhcp_state = NET_DHCP_RENEWING;
            n->xid_ctr = n->xid_ctr * 1664525u + 1013904223u; n->xid = n->xid_ctr;
            dhcp_send(n, ops, DHCP_REQUEST, n->lease.ip, 0, 0, now);
        }
        break;
    case NET_DHCP_RENEWING:
        if (now - n->t_bound >= (uint64_t)n->lease.lease_s * 1000) {  /* expired */
            lease_lost(n, ops);
            net_dhcp_start(n, now, ops);
        } else if (now - n->t_last_tx >= 10000) {
            dhcp_send(n, ops, DHCP_REQUEST, n->lease.ip, 0, 0, now);
        }
        break;
    default: break;
    }
    /* ARP retry + age out queued packets */
    int pend = 0;
    for (int i = 0; i < NET_TXQ_SLOTS; i++) {
        net_txq_t *q = &n->txq[i];
        if (!q->used) continue;
        if (now - q->t >= TXQ_MAX_AGE_MS) { q->used = 0; continue; }
        pend = 1;
    }
    if (pend && n->configured && now - n->t_last_arp >= ARP_RETRY_MS) {
        n->t_last_arp = now;
        uint32_t seen[NET_TXQ_SLOTS]; int ns = 0;
        for (int i = 0; i < NET_TXQ_SLOTS; i++) {
            if (!n->txq[i].used) continue;
            int dup = 0;
            for (int j = 0; j < ns; j++) if (seen[j] == n->txq[i].nexthop) dup = 1;
            if (dup) continue;
            seen[ns++] = n->txq[i].nexthop;
            net_arp_request(n, n->txq[i].nexthop, ops);
        }
    }
}
