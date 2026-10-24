// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Goodput bench, see bench.h.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "bench.h"
#include "tx.h"

typedef struct { unsigned long n, bytes, maxseq; } dcount_t;
static dcount_t dc;
static void on_udp(void *ud, uint16_t dport, const uint8_t *pl, size_t n, uint32_t seq, uint32_t src)
{
    (void)ud; (void)pl; (void)src;
    if (dport != BENCH_PORT) return;
    dc.n++; dc.bytes += n; if (seq > dc.maxseq) dc.maxseq = seq;
}

static int mk_sock(uint32_t bind_ip, int port)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int big = 8 << 20;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    fcntl(s, F_SETFL, O_NONBLOCK);
    if (port) {
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(bind_ip);
        if (bind(s, (struct sockaddr *)&a, sizeof a)) { close(s); return -1; }
    }
    return s;
}

int bench_run(link_t *l, uint32_t peer, int dir, int secs, int payload, int offered, bench_res_t *res)
{
    uint8_t pkt[1600], rb[2048];
    memset(res, 0, sizeof *res);
    if (payload < 16 || payload > 1450) payload = 1400;
    uint32_t me = l->n.lease.ip;
    int s = mk_sock(0, dir == 1 ? BENCH_PORT : 0);
    if (s < 0) return -1;
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET; to.sin_port = htons(BENCH_PORT); to.sin_addr.s_addr = htonl(me);
    l->udp_rx = on_udp; l->udp_ud = NULL;
    memset(&dc, 0, sizeof dc);
    // make sure the ARP entry for the peer exists (uplink) and the path is warm
    if (dir == 1) { net_arp_request(&l->n, peer, &l->ops); }
    for (int i = 0; i < 20; i++) { sta_poll(&l->s, 5, NULL, NULL); }
    uint8_t mac[6];
    for (int i = 0; dir == 1 && net_arp_lookup(&l->n, peer, mac) && i < 50; i++) { sta_poll(&l->s, 20, NULL, NULL); if (i % 10 == 9) net_arp_request(&l->n, peer, &l->ops); }
    rtl_tx_stats_t t0 = rtl_tx_stats;
    long start = link_now_ms(), end = start + secs * 1000L, now;
    unsigned long long rx_bytes_mac = 0; unsigned long sent = 0, recv_mac = 0;
    uint32_t seq = 0;
    double sent_bytes = 0;
    long lasttick = start;
    while ((now = link_now_ms()) < end) {
        if (dir == 1) {
            for (int k = 0; k < 6; k++) {
                size_t n = bench_udp_build(pkt, me, peer, 40000, BENCH_PORT, seq, payload);
                if (net_tx_ip(&l->n, pkt, n, now, &l->ops) == 0) { seq++; sent++; }
            }
            sta_poll(&l->s, 1, NULL, NULL);
            for (;;) { ssize_t g = recv(s, rb, sizeof rb, 0); if (g <= 0) break; rx_bytes_mac += g - 0; recv_mac++; }
        } else {
            double want = (double)offered * 1e6 / 8.0 * (now - start) / 1000.0;     // bytes the Mac should have sent by now
            int budget = 64;
            while (sent_bytes < want && budget-- > 0) {
                uint8_t body[1500];
                memset(body, 0x33, sizeof body); body[0] = seq >> 24; body[1] = seq >> 16; body[2] = seq >> 8; body[3] = seq;
                if (sendto(s, body, payload, 0, (struct sockaddr *)&to, sizeof to) == payload) { seq++; sent++; sent_bytes += payload + 28; }
                else if (errno != ENOBUFS && errno != EAGAIN) break; else break;
            }
            sta_poll(&l->s, 1, NULL, NULL);
        }
        if (now - lasttick > 500) { net_tick(&l->n, now, &l->ops); lasttick = now; }
    }
    long el = link_now_ms() - start;
    // drain
    for (int i = 0; i < 40; i++) { sta_poll(&l->s, 5, NULL, NULL); if (dir == 1) for (;;) { ssize_t g = recv(s, rb, sizeof rb, 0); if (g <= 0) break; rx_bytes_mac += g; recv_mac++; } }
    close(s);
    l->udp_rx = NULL;
    if (dir == 1) { res->recv = recv_mac; res->mbps = bench_mbps(rx_bytes_mac, el); res->offered_mbps = bench_mbps((unsigned long long)sent * payload, el); }
    else { res->recv = dc.n; res->mbps = bench_mbps(dc.bytes, el); res->offered_mbps = bench_mbps((unsigned long long)sent_bytes, el); }
    res->sent = sent;
    res->tx_submitted = rtl_tx_stats.submitted - t0.submitted;
    res->tx_ok = rtl_tx_stats.ccx_ok - t0.ccx_ok;
    res->tx_retry_over = rtl_tx_stats.ccx_retry_over - t0.ccx_retry_over;
    res->rx_rate = l->s.rx_rate;
    res->tx_rate = l->data_rate;
    return 0;
}
