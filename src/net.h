// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
/* net.h - framing between decrypted 802.11 data payloads and IP:
 * LLC/SNAP, ARP (with a tiny cache), DHCP client, IP tx queue.
 * Pure functions over byte buffers; no sockets, no threads, no clocks
 * (the caller passes time in milliseconds). IPv4 addresses are uint32_t in
 * host byte order (192.168.1.1 == 0xC0A80101). */
#ifndef NET_H
#define NET_H
#include <stddef.h>
#include <stdint.h>

#define NET_MTU        1500
#define NET_LLC_LEN    8
#define NET_ETH_IP     0x0800
#define NET_ETH_ARP    0x0806
#define NET_ARP_LEN    28
#define NET_ARP_SLOTS  8
#define NET_TXQ_SLOTS  4
#define NET_MAX_FRAME  (NET_LLC_LEN + NET_MTU)

/* ---- LLC/SNAP ---- */
/* Parse AA AA 03 00 00 00 + ethertype. 0 ok, -1 not LLC/SNAP(OUI 0) or short. */
int    net_llc_parse(const uint8_t *p, size_t len, uint16_t *ethertype,
                     const uint8_t **payload, size_t *plen);
/* Returns bytes written, or 0 if cap too small. */
size_t net_llc_build(uint8_t *out, size_t cap, uint16_t ethertype,
                     const uint8_t *payload, size_t plen);

/* ---- ARP body (28 bytes, Ethernet/IPv4) ---- */
typedef struct {
    uint16_t op;                /* 1 request, 2 reply */
    uint8_t  sha[6]; uint32_t spa;
    uint8_t  tha[6]; uint32_t tpa;
} net_arp_t;
void net_arp_build(uint8_t out[NET_ARP_LEN], uint16_t op, const uint8_t sha[6],
                   uint32_t spa, const uint8_t tha[6], uint32_t tpa);
int  net_arp_parse(const uint8_t *p, size_t len, net_arp_t *a); /* 0 / -1 */

/* ---- DHCP message (parsed) ---- */
enum { DHCP_DISCOVER = 1, DHCP_OFFER, DHCP_REQUEST, DHCP_DECLINE, DHCP_ACK,
       DHCP_NAK, DHCP_RELEASE, DHCP_INFORM };
typedef struct {
    uint8_t  type;              /* option 53, 0 if absent */
    uint32_t xid;
    uint8_t  chaddr[6];
    uint32_t yiaddr;
    uint32_t mask;      int has_mask;     /* option 1 */
    uint32_t router;    int has_router;   /* option 3 (first) */
    uint32_t dns[4];    int ndns;         /* option 6 */
    uint32_t lease;     int has_lease;    /* option 51 (seconds) */
    uint32_t server_id; int has_server_id;/* option 54 */
} net_dhcp_msg_t;
/* Parse a full IPv4 packet (header+UDP+BOOTP reply, port 67->68). Verifies IP
 * header checksum and, when nonzero, UDP checksum. 0 ok, -1 reject. */
int net_dhcp_parse(const uint8_t *ip_pkt, size_t len, net_dhcp_msg_t *m);

/* ---- state ---- */
typedef struct {
    uint32_t ip, mask, gw, dns[4]; int ndns;
    uint32_t lease_s, server_id;
} net_lease_t;

typedef struct net_ops {
    void *ctx;
    /* frame to send: dst = final destination MAC, payload = LLC/SNAP + data */
    void (*tx)(void *ctx, const uint8_t dst[6], const uint8_t *payload, size_t len);
    /* IPv4 packet for the tun device */
    void (*to_tun)(void *ctx, const uint8_t *ip_pkt, size_t len);
    /* up=1: configured (l valid); up=0: lease lost/expired */
    void (*lease)(void *ctx, const net_lease_t *l, int up);
} net_ops_t;

enum { NET_DHCP_IDLE, NET_DHCP_SELECTING, NET_DHCP_REQUESTING,
       NET_DHCP_BOUND, NET_DHCP_RENEWING };

typedef struct { uint32_t ip; uint8_t mac[6]; int valid; } net_arp_entry_t;
typedef struct {
    uint8_t  pkt[NET_MTU]; uint16_t len; uint32_t nexthop;
    uint64_t t; int used;
} net_txq_t;

typedef struct {
    uint8_t  mac[6];
    int      dhcp_state;
    uint32_t xid, xid_ctr, ip_id;
    uint32_t offer_ip, offer_server;
    net_lease_t lease; int configured;
    uint64_t t_start, t_bound, t_last_tx, t_last_arp; int tries;
    net_arp_entry_t arp[NET_ARP_SLOTS]; int arp_next;
    net_txq_t txq[NET_TXQ_SLOTS];
} net_t;

void net_init(net_t *n, const uint8_t our_mac[6]);
/* Begin DHCP (sends DISCOVER). Also used to restart. */
void net_dhcp_start(net_t *n, uint64_t now_ms, const net_ops_t *ops);
/* Periodic: DHCP retransmit, renew at T1 (lease/2), expiry, ARP retry, queue age. */
void net_tick(net_t *n, uint64_t now_ms, const net_ops_t *ops);
/* Feed one decrypted data-frame payload (LLC/SNAP + ...). Garbage is ignored. */
void net_rx(net_t *n, const uint8_t *payload, size_t len, uint64_t now_ms,
            const net_ops_t *ops);
/* Wrap an IPv4 packet from the tun. 0 = sent or queued (ARP pending),
 * -1 = rejected (not configured, malformed, too big). */
int  net_tx_ip(net_t *n, const uint8_t *ip_pkt, size_t len, uint64_t now_ms,
               const net_ops_t *ops);
/* ARP cache lookup: 0 found (mac filled), -1 miss. */
int  net_arp_lookup(const net_t *n, uint32_t ip, uint8_t mac[6]);
/* Send an ARP request for ip (e.g. to prime the gateway). */
void net_arp_request(net_t *n, uint32_t ip, const net_ops_t *ops);

/* helper: RFC1071 checksum (returns the complemented sum; 0 over a valid header) */
uint16_t net_cksum(const uint8_t *p, size_t len);
#endif
