// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* test_net.c - software-only tests for net.c / tun.c. Prints NET TEST OK. */
#include "net.h"
#include "tun.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define IPA(a,b,c,d) ((uint32_t)(a)<<24|(b)<<16|(c)<<8|(d))
static const uint8_t OUR[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t GWM[6] = {0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5};
static const uint8_t HOSTM[6] = {0x3c, 0x01, 0x02, 0x03, 0x04, 0x05};
static const uint8_t BC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
#define OURIP IPA(192,168,1,50)
#define GWIP  IPA(192,168,1,1)
#define SRVIP GWIP

/* independent checksum: 16-bit words, carry folded after every add */
static uint16_t ref_sum(const uint8_t *p, size_t n, uint32_t acc)
{
    for (size_t i = 0; i < n; i += 2) {
        uint32_t w = (uint32_t)p[i] << 8 | (i + 1 < n ? p[i + 1] : 0);
        acc += w; acc = (acc & 0xffff) + (acc >> 16);
    }
    return (uint16_t)acc;   /* un-complemented; valid packets give 0xffff */
}
static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0]<<24|p[1]<<16|p[2]<<8|p[3]; }
static void put32(uint8_t *p, uint32_t v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }

/* ---- capture ---- */
typedef struct { uint8_t dst[6]; uint8_t b[2048]; size_t len; } cap_t;
static cap_t txs[32]; static int ntx;
static uint8_t tunpk[4][2048]; static size_t tunlen[4]; static int ntun;
static net_lease_t last_lease; static int lease_up = -1, nlease;
static void c_tx(void *c, const uint8_t d[6], const uint8_t *p, size_t l)
{ (void)c; if (ntx < 32 && l <= 2048) { memcpy(txs[ntx].dst, d, 6); memcpy(txs[ntx].b, p, l); txs[ntx].len = l; ntx++; } }
static void c_tun(void *c, const uint8_t *p, size_t l)
{ (void)c; if (ntun < 4 && l <= 2048) { memcpy(tunpk[ntun], p, l); tunlen[ntun++] = l; } }
static void c_lease(void *c, const net_lease_t *l, int up)
{ (void)c; last_lease = *l; lease_up = up; nlease++; }
static net_ops_t OPS = { NULL, c_tx, c_tun, c_lease };
static void reset_cap(void) { ntx = ntun = 0; }

/* ---- verify a client DHCP frame, returns pointer to BOOTP ---- */
static const uint8_t *check_dhcp_frame(const cap_t *f, int type, uint32_t ciaddr, uint32_t *xid)
{
    const uint8_t *b = f->b;
    CHECK(!memcmp(f->dst, BC, 6));
    CHECK(f->len >= 8 + 20 + 8 + 300);
    CHECK(!memcmp(b, "\xAA\xAA\x03\x00\x00\x00\x08\x00", 8));
    const uint8_t *ip = b + 8, *u = ip + 20, *d = u + 8;
    CHECK(ip[0] == 0x45);
    CHECK(be16(ip + 2) == f->len - 8);
    CHECK(ip[9] == 17);
    CHECK(be32(ip + 12) == ciaddr);
    CHECK(be32(ip + 16) == 0xffffffffu);
    CHECK(ref_sum(ip, 20, 0) == 0xffff);                 /* IP checksum */
    CHECK(be16(u) == 68 && be16(u + 2) == 67);
    CHECK(be16(u + 4) == f->len - 8 - 20);
    if (be16(u + 6) != 0) {
        uint32_t acc = ref_sum(ip + 12, 8, 0);
        acc += 17 + be16(u + 4); acc = (acc & 0xffff) + (acc >> 16);
        CHECK(ref_sum(u, be16(u + 4), acc) == 0xffff);   /* UDP checksum */
    }
    CHECK(d[0] == 1 && d[1] == 1 && d[2] == 6 && d[3] == 0);
    *xid = be32(d + 4);
    CHECK(be16(d + 10) == (ciaddr ? 0 : 0x8000));
    CHECK(be32(d + 12) == ciaddr);
    CHECK(be32(d + 16) == 0 && be32(d + 20) == 0 && be32(d + 24) == 0);
    CHECK(!memcmp(d + 28, OUR, 6));
    for (int i = 34; i < 236; i++) if (d[i]) { CHECK(0 && "chaddr pad/sname/file nonzero"); break; }
    CHECK(be32(d + 236) == 0x63825363u);
    /* options */
    size_t dl = be16(u + 4) - 8, i = 240; int seen53 = 0, seen61 = 0, seen12 = 0, seen55 = 0, end = 0;
    while (i < dl) {
        uint8_t c = d[i];
        if (c == 0) { i++; continue; }
        if (c == 255) { end = 1; i++; break; }
        uint8_t l = d[i + 1]; const uint8_t *v = d + i + 2;
        CHECK(i + 2 + l <= dl);
        if (c == 53) { seen53++; CHECK(l == 1 && v[0] == type); }
        if (c == 61) { seen61++; CHECK(l == 7 && v[0] == 1 && !memcmp(v + 1, OUR, 6)); }
        if (c == 12) { seen12++; CHECK(l == 10 && !memcmp(v, "awus036acs", 10)); }
        if (c == 55) { seen55++; int h[256] = {0}; for (int k = 0; k < l; k++) h[v[k]] = 1;
                       CHECK(h[1] && h[3] && h[6] && h[51] && h[54]); }
        if (c == 50) CHECK(type == DHCP_REQUEST && ciaddr == 0 && l == 4);
        i += 2 + l;
    }
    CHECK(end && seen53 == 1 && seen61 == 1 && seen12 == 1 && seen55 == 1);
    for (; i < dl; i++) CHECK(d[i] == 0);                /* padding */
    return d;
}
static int find_opt(const uint8_t *d, size_t dl, uint8_t code, uint8_t *val, size_t *vl)
{
    size_t i = 240;
    while (i < dl) {
        if (d[i] == 0) { i++; continue; }
        if (d[i] == 255) return 0;
        if (d[i] == code) { memcpy(val, d + i + 2, d[i + 1]); *vl = d[i + 1]; return 1; }
        i += 2 + d[i + 1];
    }
    return 0;
}

/* ---- tiny fake DHCP server: builds OFFER/ACK/NAK as LLC frame ---- */
typedef struct { int type; uint32_t xid; uint8_t chaddr[6]; uint32_t yiaddr;
                 uint32_t lease; int bad_trunc; int bad_ipsum; int udp_zero; } srv_t;
static size_t srv_build(uint8_t *o, const srv_t *s)
{
    memset(o, 0, 600);
    memcpy(o, "\xAA\xAA\x03\x00\x00\x00\x08\x00", 8);
    uint8_t *ip = o + 8, *u = ip + 20, *d = u + 8, *p;
    d[0] = 2; d[1] = 1; d[2] = 6;
    put32(d + 4, s->xid); put32(d + 16, s->yiaddr); put32(d + 20, SRVIP);
    memcpy(d + 28, s->chaddr, 6);
    put32(d + 236, 0x63825363u);
    p = d + 240;
    *p++ = 53; *p++ = 1; *p++ = s->type;
    *p++ = 54; *p++ = 4; put32(p, SRVIP); p += 4;
    if (s->type != DHCP_NAK) {
        *p++ = 51; *p++ = 4; put32(p, s->lease); p += 4;
        *p++ = 1; *p++ = 4; put32(p, IPA(255,255,255,0)); p += 4;
        *p++ = 3; *p++ = 4; put32(p, GWIP); p += 4;
        *p++ = 6; *p++ = 8; put32(p, GWIP); put32(p + 4, IPA(8,8,8,8)); p += 8;
    }
    if (s->bad_trunc) { *p++ = 15; *p++ = 40; *p++ = 'x'; }  /* claims 40 bytes, ends */
    else *p++ = 255;
    size_t dl = p - d; if (dl < 300) dl = 300;
    size_t ul = 8 + dl, tl = 20 + ul;
    ip[0] = 0x45; ip[2] = tl >> 8; ip[3] = tl; ip[8] = 64; ip[9] = 17;
    put32(ip + 12, SRVIP); put32(ip + 16, 0xffffffffu);
    u[0] = 0; u[1] = 67; u[2] = 0; u[3] = 68; u[4] = ul >> 8; u[5] = ul;
    uint16_t c = ~ref_sum(ip, 20, 0); ip[10] = c >> 8; ip[11] = c;
    if (s->bad_ipsum) ip[10] ^= 0x55;
    if (!s->udp_zero) {
        uint32_t acc = ref_sum(ip + 12, 8, 0); acc += 17 + ul; acc = (acc & 0xffff) + (acc >> 16);
        c = ~ref_sum(u, ul, acc); if (!c) c = 0xffff; u[6] = c >> 8; u[7] = c;
    }
    return 8 + tl;
}
static void srv_send(net_t *n, int type, uint32_t xid, uint32_t yi, uint32_t lease, uint64_t now)
{
    srv_t s = { type, xid, {0}, yi, lease, 0, 0, 0 };
    memcpy(s.chaddr, OUR, 6);
    uint8_t f[700]; size_t l = srv_build(f, &s);
    net_rx(n, f, l, now, &OPS);
}

static void arp_frame(uint8_t *f, size_t *l, uint16_t op, const uint8_t *sha, uint32_t spa,
                      const uint8_t *tha, uint32_t tpa)
{
    uint8_t b[NET_ARP_LEN]; net_arp_build(b, op, sha, spa, tha, tpa);
    *l = net_llc_build(f, 64, NET_ETH_ARP, b, sizeof b);
}

static uint32_t xid_of_last;
/* run a full exchange, leaving n configured; cap cleared at the end */
static void bring_up(net_t *n, uint64_t t0)
{
    uint32_t x;
    net_init(n, OUR); reset_cap(); lease_up = -1;
    net_dhcp_start(n, t0, &OPS);
    CHECK(ntx == 1);
    check_dhcp_frame(&txs[0], DHCP_DISCOVER, 0, &x);
    srv_send(n, DHCP_OFFER, x, OURIP, 3600, t0 + 10);
    CHECK(ntx == 2);
    srv_send(n, DHCP_ACK, x, OURIP, 3600, t0 + 20);
    xid_of_last = x;
    reset_cap();
}

static void test_llc(void)
{
    uint8_t f[64], pl[5] = {1, 2, 3, 4, 5};
    size_t l = net_llc_build(f, sizeof f, 0x86dd, pl, 5);
    CHECK(l == 13 && !memcmp(f, "\xAA\xAA\x03\x00\x00\x00\x86\xdd\x01\x02\x03\x04\x05", 13));
    uint16_t et; const uint8_t *p; size_t pn;
    CHECK(net_llc_parse(f, l, &et, &p, &pn) == 0 && et == 0x86dd && pn == 5 && !memcmp(p, pl, 5));
    CHECK(net_llc_parse(f, 7, &et, &p, &pn) == -1);
    f[2] = 0; CHECK(net_llc_parse(f, l, &et, &p, &pn) == -1);
    CHECK(net_llc_build(f, 10, 0x800, pl, 5) == 0);
    /* arp body */
    uint8_t a[NET_ARP_LEN]; net_arp_t r;
    net_arp_build(a, 1, OUR, OURIP, (uint8_t[6]){0}, GWIP);
    static const uint8_t exp[28] = {0,1,8,0,6,4,0,1, 2,0x11,0x22,0x33,0x44,0x55, 192,168,1,50,
                                    0,0,0,0,0,0, 192,168,1,1};
    CHECK(!memcmp(a, exp, 28));
    CHECK(net_arp_parse(a, 28, &r) == 0 && r.op == 1 && r.spa == OURIP && r.tpa == GWIP && !memcmp(r.sha, OUR, 6));
    CHECK(net_arp_parse(a, 27, &r) == -1);
    a[7] = 9; CHECK(net_arp_parse(a, 28, &r) == -1);
}

static void test_dhcp(void)
{
    net_t n; uint32_t x, x2;
    net_init(&n, OUR); reset_cap(); lease_up = -1;
    net_dhcp_start(&n, 1000, &OPS);
    CHECK(ntx == 1);
    const uint8_t *d = check_dhcp_frame(&txs[0], DHCP_DISCOVER, 0, &x);
    (void)d;

    /* junk replies that must be ignored */
    { srv_t s = { DHCP_OFFER, x + 1, {0}, OURIP, 3600, 0, 0, 0 }; memcpy(s.chaddr, OUR, 6);
      uint8_t f[700]; size_t l = srv_build(f, &s); net_rx(&n, f, l, 1001, &OPS); CHECK(ntx == 1); }
    { srv_t s = { DHCP_OFFER, x, {1,2,3,4,5,6}, OURIP, 3600, 0, 0, 0 };
      uint8_t f[700]; size_t l = srv_build(f, &s); net_rx(&n, f, l, 1001, &OPS); CHECK(ntx == 1); }
    { srv_t s = { DHCP_OFFER, x, {0}, OURIP, 3600, 0, 1, 0 }; memcpy(s.chaddr, OUR, 6);
      uint8_t f[700]; size_t l = srv_build(f, &s); net_rx(&n, f, l, 1001, &OPS); CHECK(ntx == 1); }
    { srv_t s = { DHCP_OFFER, x, {0}, OURIP, 3600, 1, 0, 0 }; memcpy(s.chaddr, OUR, 6);   /* malformed options */
      uint8_t f[700]; size_t l = srv_build(f, &s); net_rx(&n, f, l, 1001, &OPS);
      CHECK(ntx == 1 && n.dhcp_state == NET_DHCP_SELECTING); }
    CHECK(!n.configured);

    /* retransmit after 4 s, same xid */
    net_tick(&n, 2000, &OPS); CHECK(ntx == 1);
    net_tick(&n, 5000, &OPS); CHECK(ntx == 2);
    check_dhcp_frame(&txs[1], DHCP_DISCOVER, 0, &x2); CHECK(x2 == x);

    /* good offer (UDP checksum 0 variant) -> REQUEST */
    { srv_t s = { DHCP_OFFER, x, {0}, OURIP, 3600, 0, 0, 1 }; memcpy(s.chaddr, OUR, 6);
      uint8_t f[700]; size_t l = srv_build(f, &s); net_rx(&n, f, l, 5100, &OPS); }
    CHECK(ntx == 3);
    const uint8_t *rq = check_dhcp_frame(&txs[2], DHCP_REQUEST, 0, &x2);
    CHECK(x2 == x);
    uint8_t v[16]; size_t vl;
    size_t dl = be16(txs[2].b + 8 + 20 + 4) - 8;
    CHECK(find_opt(rq, dl, 50, v, &vl) && vl == 4 && be32(v) == OURIP);
    CHECK(find_opt(rq, dl, 54, v, &vl) && vl == 4 && be32(v) == SRVIP);

    /* ACK -> configured */
    srv_send(&n, DHCP_ACK, x, OURIP, 3600, 5200);
    CHECK(n.configured && n.dhcp_state == NET_DHCP_BOUND);
    CHECK(nlease == 1 && lease_up == 1);
    CHECK(last_lease.ip == OURIP && last_lease.mask == IPA(255,255,255,0) && last_lease.gw == GWIP);
    CHECK(last_lease.ndns == 2 && last_lease.dns[0] == GWIP && last_lease.dns[1] == IPA(8,8,8,8));
    CHECK(last_lease.lease_s == 3600 && last_lease.server_id == SRVIP);
    /* gateway ARP request was primed */
    CHECK(ntx == 4 && !memcmp(txs[3].dst, BC, 6) && be16(txs[3].b + 6) == 0x0806);
    net_arp_t a; CHECK(net_arp_parse(txs[3].b + 8, txs[3].len - 8, &a) == 0 && a.op == 1 &&
                       a.spa == OURIP && a.tpa == GWIP && !memcmp(a.sha, OUR, 6));
    /* duplicate ACK while bound ignored */
    srv_send(&n, DHCP_ACK, x, OURIP, 3600, 5300); CHECK(nlease == 1);

    /* renew at T1 = 1800 s */
    reset_cap();
    net_tick(&n, 5200 + 1799000, &OPS); CHECK(ntx == 0);
    net_tick(&n, 5200 + 1800000, &OPS); CHECK(ntx == 1 && n.dhcp_state == NET_DHCP_RENEWING);
    const uint8_t *rn = check_dhcp_frame(&txs[0], DHCP_REQUEST, OURIP, &x2);
    CHECK(!find_opt(rn, be16(txs[0].b + 8 + 20 + 4) - 8, 50, v, &vl));
    srv_send(&n, DHCP_ACK, x2, OURIP, 7200, 5200 + 1801000);
    CHECK(n.dhcp_state == NET_DHCP_BOUND && n.lease.lease_s == 7200 && nlease == 1);
    /* renew then lease expiry without answer -> deconfigure + DISCOVER */
    reset_cap();
    uint64_t t1 = 5200 + 1801000;
    net_tick(&n, t1 + 3600000, &OPS); CHECK(ntx == 1 && n.dhcp_state == NET_DHCP_RENEWING);
    net_tick(&n, t1 + 7200000, &OPS);
    CHECK(!n.configured && lease_up == 0 && n.dhcp_state == NET_DHCP_SELECTING);
    CHECK(ntx >= 2); check_dhcp_frame(&txs[ntx - 1], DHCP_DISCOVER, 0, &x2);
    /* NAK during requesting restarts */
    srv_send(&n, DHCP_OFFER, x2, OURIP, 3600, t1 + 7200100);
    reset_cap();
    srv_send(&n, DHCP_NAK, x2, 0, 0, t1 + 7200200);
    CHECK(ntx == 1 && n.dhcp_state == NET_DHCP_SELECTING);
}

static void test_rebind(void)
{
    net_t n; uint32_t x2; uint64_t t0 = 300000, tb = t0 + 20;
    bring_up(&n, t0);                                        /* lease 3600 s bound at tb */
    CHECK(n.renews == 0 && n.rebinds == 0 && !n.rebinding);
    net_tick(&n, tb + 1799999, &OPS); CHECK(ntx == 0);
    net_tick(&n, tb + 1800000, &OPS); CHECK(ntx == 1 && n.dhcp_state == NET_DHCP_RENEWING && !n.rebinding);
    check_dhcp_frame(&txs[0], DHCP_REQUEST, OURIP, &x2);
    net_tick(&n, tb + 1809000, &OPS); CHECK(ntx == 1);
    net_tick(&n, tb + 1810000, &OPS); CHECK(ntx == 2);      /* retransmit every 10 s */
    net_tick(&n, tb + 3149999, &OPS); CHECK(!n.rebinding);
    int before = ntx;
    net_tick(&n, tb + 3150000, &OPS); CHECK(n.rebinding && ntx == before + 1);     /* T2 = 7/8 of 3600 s */
    check_dhcp_frame(&txs[ntx - 1], DHCP_REQUEST, OURIP, &x2);
    srv_send(&n, DHCP_ACK, x2, OURIP, 3600, tb + 3151000);
    CHECK(n.dhcp_state == NET_DHCP_BOUND && n.renews == 1 && n.rebinds == 1 && !n.rebinding);
    /* forced renewal (what `awusctl debug renew` does) */
    reset_cap();
    CHECK(net_dhcp_renew_now(&n, tb + 3152000, &OPS, 0) == 0 && ntx == 1 && n.dhcp_state == NET_DHCP_RENEWING);
    CHECK(net_dhcp_renew_now(&n, tb + 3152001, &OPS, 0) == -1);          /* not BOUND any more */
    check_dhcp_frame(&txs[0], DHCP_REQUEST, OURIP, &x2);
    srv_send(&n, DHCP_ACK, x2, OURIP, 3600, tb + 3153000);
    CHECK(n.dhcp_state == NET_DHCP_BOUND && n.renews == 2 && n.rebinds == 1 && n.configured);
    reset_cap();
    CHECK(net_dhcp_renew_now(&n, tb + 3154000, &OPS, 1) == 0 && n.rebinding);
    srv_send(&n, DHCP_ACK, n.xid, OURIP, 3600, tb + 3155000);
    CHECK(n.renews == 3 && n.rebinds == 2);
}

static void test_arp(void)
{
    net_t n; uint8_t f[64], mac[6]; size_t l;
    bring_up(&n, 100000);
    /* reply from gateway to our priming request */
    arp_frame(f, &l, 2, GWM, GWIP, OUR, OURIP);
    net_rx(&n, f, l, 100030, &OPS);
    CHECK(net_arp_lookup(&n, GWIP, mac) == 0 && !memcmp(mac, GWM, 6));
    CHECK(ntx == 0);
    /* gateway asks for our IP -> unicast reply */
    arp_frame(f, &l, 1, GWM, GWIP, (uint8_t[6]){0}, OURIP);
    net_rx(&n, f, l, 100040, &OPS);
    CHECK(ntx == 1 && !memcmp(txs[0].dst, GWM, 6) && txs[0].len == 8 + 28);
    uint8_t exp[36]; uint8_t body[28];
    net_arp_build(body, 2, OUR, OURIP, GWM, GWIP);
    net_llc_build(exp, sizeof exp, 0x0806, body, 28);
    CHECK(!memcmp(txs[0].b, exp, 36));
    /* request for someone else: silence */
    reset_cap();
    arp_frame(f, &l, 1, HOSTM, IPA(192,168,1,9), (uint8_t[6]){0}, IPA(192,168,1,77));
    net_rx(&n, f, l, 100050, &OPS);
    CHECK(ntx == 0 && net_arp_lookup(&n, IPA(192,168,1,9), mac) == -1);
    /* gateway MAC change is picked up */
    arp_frame(f, &l, 1, HOSTM, GWIP, (uint8_t[6]){0}, OURIP);
    net_rx(&n, f, l, 100060, &OPS);
    CHECK(net_arp_lookup(&n, GWIP, mac) == 0 && !memcmp(mac, HOSTM, 6));
}

static size_t mk_ip(uint8_t *p, uint32_t src, uint32_t dst, size_t payload)
{
    memset(p, 0, 20 + payload);
    p[0] = 0x45; p[2] = (20 + payload) >> 8; p[3] = 20 + payload; p[8] = 64; p[9] = 1;
    put32(p + 12, src); put32(p + 16, dst);
    for (size_t i = 0; i < payload; i++) p[20 + i] = (uint8_t)(i * 7 + 1);
    uint16_t c = ~ref_sum(p, 20, 0); p[10] = c >> 8; p[11] = c;
    return 20 + payload;
}

static void test_tx_rx_ip(void)
{
    net_t n; uint8_t pk[200], f[64], mac[6]; size_t l;
    bring_up(&n, 200000);
    l = mk_ip(pk, OURIP, IPA(8,8,8,8), 32);
    CHECK(net_tx_ip(&n, pk, l, 200100, &OPS) == 0);
    /* queued, ARP for gateway sent */
    CHECK(ntx == 1 && !memcmp(txs[0].dst, BC, 6));
    net_arp_t a; CHECK(net_arp_parse(txs[0].b + 8, txs[0].len - 8, &a) == 0 && a.op == 1 && a.tpa == GWIP);
    /* second packet to the same hop: queued without another ARP */
    uint8_t pk2[200]; size_t l2 = mk_ip(pk2, OURIP, IPA(1,1,1,1), 10);
    CHECK(net_tx_ip(&n, pk2, l2, 200110, &OPS) == 0 && ntx == 1);
    /* resolution flushes both, to the gateway MAC, byte-exact */
    arp_frame(f, &l2, 2, GWM, GWIP, OUR, OURIP);
    net_rx(&n, f, l2, 200200, &OPS);
    CHECK(ntx == 3);
    CHECK(!memcmp(txs[1].dst, GWM, 6) && txs[1].len == 8 + l);
    CHECK(!memcmp(txs[1].b, "\xAA\xAA\x03\x00\x00\x00\x08\x00", 8) && !memcmp(txs[1].b + 8, pk, l));
    CHECK(!memcmp(txs[2].dst, GWM, 6) && !memcmp(txs[2].b + 8, pk2, 30));
    /* now direct */
    reset_cap();
    CHECK(net_tx_ip(&n, pk, l, 200300, &OPS) == 0 && ntx == 1 && !memcmp(txs[0].dst, GWM, 6));
    /* on-link host: ARP for the host itself, not the gateway */
    reset_cap();
    l = mk_ip(pk, OURIP, IPA(192,168,1,77), 8);
    CHECK(net_tx_ip(&n, pk, l, 200400, &OPS) == 0 && ntx == 1);
    CHECK(net_arp_parse(txs[0].b + 8, 28, &a) == 0 && a.tpa == IPA(192,168,1,77));
    /* ARP retry from tick, then timeout drops queue */
    reset_cap();
    net_tick(&n, 200500, &OPS); CHECK(ntx == 0);
    net_tick(&n, 201450, &OPS); CHECK(ntx == 1);
    net_tick(&n, 206000, &OPS);
    reset_cap();
    arp_frame(f, &l2, 2, HOSTM, IPA(192,168,1,77), OUR, OURIP);
    net_rx(&n, f, l2, 206100, &OPS);
    CHECK(ntx == 0 && net_arp_lookup(&n, IPA(192,168,1,77), mac) == 0);
    /* directed broadcast + limited broadcast */
    l = mk_ip(pk, OURIP, IPA(192,168,1,255), 4);
    CHECK(net_tx_ip(&n, pk, l, 206200, &OPS) == 0 && ntx == 1 && !memcmp(txs[0].dst, BC, 6));
    /* rejects */
    CHECK(net_tx_ip(&n, pk, 10, 0, &OPS) == -1);
    CHECK(net_tx_ip(&n, pk, 0, 0, &OPS) == -1);
    pk[0] = 0x65; CHECK(net_tx_ip(&n, pk, l, 0, &OPS) == -1);
    { net_t u; net_init(&u, OUR); l = mk_ip(pk, 1, 2, 4); CHECK(net_tx_ip(&u, pk, l, 0, &OPS) == -1); }

    /* RX: IP packet for us goes to the tun, trailing bytes trimmed */
    reset_cap();
    uint8_t in[300]; size_t il = mk_ip(in + 8, GWIP, OURIP, 40) ;
    memcpy(in, "\xAA\xAA\x03\x00\x00\x00\x08\x00", 8);
    in[8 + il] = 0xee; in[8 + il + 1] = 0xee;           /* padding */
    net_rx(&n, in, 8 + il + 2, 207000, &OPS);
    CHECK(ntun == 1 && tunlen[0] == il && !memcmp(tunpk[0], in + 8, il));
    /* packet for another host is dropped; ethertype ipv6 dropped */
    mk_ip(in + 8, GWIP, IPA(192,168,1,99), 40);
    net_rx(&n, in, 8 + il, 207001, &OPS); CHECK(ntun == 1);
    in[6] = 0x86; in[7] = 0xdd; net_rx(&n, in, 8 + il, 207002, &OPS); CHECK(ntun == 1);
}

static void test_tun(void)
{
    char name[16] = {0};
    int fd = tun_open(name);
    if (fd < 0)
        printf("[tun] tun_open failed: %s (expected EPERM when unprivileged) -- NOT TESTED HERE\n", strerror(errno));
    else {
        printf("[tun] tun_open succeeded unprivileged: %s (closing; tun_configure not run)\n", name);
        uint8_t b[64]; CHECK(tun_read(fd, b, sizeof b) == -1 && errno == EAGAIN);
        close(fd);
    }
    CHECK(tun_read(-1, (uint8_t[4]){0}, 4) == -1);
    CHECK(tun_write(-1, (uint8_t[4]){0x45}, 4) == -1);
    /* argument validation only (no process is spawned for bad input) */
    CHECK(tun_configure("en0", "1.2.3.4", "1.2.3.1", "255.255.255.0") == -1);
    CHECK(tun_configure("utun3", "1.2.3.4; reboot", "1.2.3.1", "255.255.255.0") == -1);
    CHECK(tun_add_host_route("utun3", "default") == -1);
    CHECK(tun_add_host_route("utun3", "0.0.0.0") == -1);
}

/* ---- fuzz ---- */
static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)(rs >> 16); }

static void feed_all(net_t *n, const uint8_t *src, size_t len, uint64_t now)
{
    uint8_t *b = malloc(len ? len : 1);              /* exact size: ASAN sees overreads */
    if (len) memcpy(b, src, len);
    uint16_t et; const uint8_t *p; size_t pn; net_arp_t a; net_dhcp_msg_t m;
    net_llc_parse(b, len, &et, &p, &pn);
    net_arp_parse(b, len, &a);
    net_dhcp_parse(b, len, &m);
    net_rx(n, b, len, now, &OPS);
    net_tx_ip(n, b, len, now, &OPS);
    net_tick(n, now, &OPS);
    free(b);
}

static void test_fuzz(void)
{
    net_t n1, n2; uint8_t buf[700];
    srv_t s = { DHCP_OFFER, 0, {0}, OURIP, 3600, 0, 0, 0 }; memcpy(s.chaddr, OUR, 6);
    uint8_t good_dhcp[700], good_arp[64], good_ip[200]; size_t ld, la, li;
    bring_up(&n2, 300000);
    s.xid = xid_of_last; ld = srv_build(good_dhcp, &s);
    arp_frame(good_arp, &la, 1, GWM, GWIP, (uint8_t[6]){0}, OURIP);
    { uint8_t ip[100]; size_t k = mk_ip(ip, GWIP, OURIP, 50); memcpy(good_ip, "\xAA\xAA\x03\x00\x00\x00\x08\x00", 8); memcpy(good_ip + 8, ip, k); li = 8 + k; }
    net_init(&n1, OUR); reset_cap();
    net_dhcp_start(&n1, 0, &OPS);
    uint64_t now = 1000;
    for (int it = 0; it < 20000; it++) {
        size_t len = rnd() % 320;
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rnd();
        if (rnd() & 1) memcpy(buf, "\xAA\xAA\x03\x00\x00\x00\x08\x00", len < 8 ? len : 8);
        if (rnd() % 4 == 0 && len > 9) { buf[8] = 0x45; buf[17] = 17; }
        now += rnd() % 3000;
        feed_all(&n1, buf, len, now); feed_all(&n2, buf, len, now);
        reset_cap(); ntun = 0;
    }
    /* every truncation + random byte flips of valid frames */
    const uint8_t *goods[3] = { good_dhcp, good_arp, good_ip }; size_t gl[3] = { ld, la, li };
    for (int g = 0; g < 3; g++) {
        for (size_t t = 0; t <= gl[g]; t++) { feed_all(&n1, goods[g], t, now); feed_all(&n2, goods[g], t, now); }
        for (int it = 0; it < 3000; it++) {
            memcpy(buf, goods[g], gl[g]);
            for (int k = 0, c = 1 + rnd() % 4; k < c; k++) buf[rnd() % gl[g]] = (uint8_t)rnd();
            feed_all(&n1, buf, gl[g], now); feed_all(&n2, buf, gl[g], now);
            now += 100;
        }
        reset_cap(); ntun = 0;
    }
    printf("[fuzz] done\n");
}

int main(void)
{
    test_llc(); test_dhcp(); test_rebind(); test_arp(); test_tx_rx_ip(); test_tun(); test_fuzz();
    if (fails) { printf("NET TEST FAILED (%d)\n", fails); return 1; }
    printf("NET TEST OK\n");
    return 0;
}
