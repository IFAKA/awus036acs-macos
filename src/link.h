// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// link: the reusable station join library. Scan for the AP, authenticate, associate, run the security handshake
// (WPA2-CCMP 4-way + group key), then DHCP. Afterwards the caller pumps it (link_pump) and sends/receives IPv4 through
// the net.c state (l->n) or bridges to a utun. Used by build/wifi and by `awusctl join`. No root needed by itself.
#ifndef LINK_H
#define LINK_H
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include "rtl.h"
#include "sta.h"
#include "wpa.h"
#include "net.h"

typedef enum {
    LINK_SEC_AUTO,          // decide from the AP's own Beacon / Probe Response
    LINK_SEC_OPEN,
    LINK_SEC_WEP,           // WEP 40/104, open-system auth (falls back to shared-key if the AP answers status 13)
    LINK_SEC_WEP_SHARED,    // WEP 40/104, shared-key (challenge) auth
    LINK_SEC_WPA,           // WPA1 (vendor IE), TKIP, PSK
    LINK_SEC_WPA2           // WPA2 (RSN), CCMP preferred, TKIP if that is all the AP has, PSK
} link_sec_t;

#define LINK_CIPHER_NONE 0
#define LINK_CIPHER_WEP  1
#define LINK_CIPHER_TKIP 2
#define LINK_CIPHER_CCMP 3

typedef struct {
    const char *ssid;
    const uint8_t *bssid;   // optional (NULL = any BSSID with that SSID)
    int channel;            // 0 = find it by scanning (2.4 GHz, then 5 GHz; DFS channels passively)
    int hidden;             // SSID is (or may be) hidden: always use directed probes, never trust a Beacon for the SSID
    link_sec_t sec;
    const char *key;        // WPA passphrase, or WEP key: 5/13 ASCII characters or 10/26 hex digits
    int wep_keyid;          // WEP key index 0-3
    int legacy;             // 1 = never use HT/VHT or a radio width above 20 MHz (the safe fallback, --legacy-rates)
    int vht;                // 1 = also negotiate VHT (5 GHz); off by default, see PLAN.md (VHT downlink collapses)
    int max_bw;             // width cap in MHz: 0 = as wide as the AP allows (up to 80), else 20 / 40 / 80
    int hs_rate, data_rate; // TX rates (Mbps*10) for EAPOL and data; 0 = 60 (6 Mbps OFDM)
} link_cfg_t;

#define LINK_PING_MAX 64

typedef struct link {
    rtl_t *r;
    sta_t s;
    wpa_t w;
    net_t n;
    net_ops_t ops;
    link_cfg_t cfg;
    // resolved by the join
    link_sec_t sec;                 // never AUTO after a join attempt got far enough to see the AP
    int pw_cipher, grp_cipher;      // LINK_CIPHER_*
    // output
    FILE *out;                      // progress lines ("assoc aid=..", "handshake ok ..") go here; NULL = silent
    volatile sig_atomic_t *stop;    // optional: join aborts when this becomes nonzero
    char fail_step[32], fail_reason[200];
    long t0;                        // log timestamps are relative to this (ms, monotonic)
    // tun bridge (optional)
    int tun_fd;
    unsigned long st_tun_rx, st_tun_tx, st_tun_drop;
    // optional hook for UDP datagrams addressed to us when there is no tun (used by the bench)
    void (*udp_rx)(void *ud, uint16_t dport, const uint8_t *payload, size_t n, uint32_t seq, uint32_t src);
    void *udp_ud;
    // statistics
    unsigned long st_dec_fail, st_replay, st_dec_ok, st_tx_enc, st_clear_drop, st_no_key;
    // internals (exposed so the CLI tools can print them)
    int hs_rate, data_rate, m1_count, handshake_done, rsn_mismatch, tk_ready;
    long t_assoc, t_m1, t_hs, t_next_null;
    uint64_t tx_pn;
    uint8_t mic_rx[8], mic_tx[8];   // pairwise Michael keys (TKIP only)
    uint64_t rx_pn[16];
    struct { int have; uint8_t tk[16]; uint8_t mic_rx[8]; uint64_t pn; } gk[4];
    tx_plan_t plan;                 // negotiated mode / width / top MCS (MODE_LEGACY until the handshake is done)
    ap_caps_t ap_caps;
    uint32_t lease_ip;
    uint32_t ping_target;
    long ping_sent_at[LINK_PING_MAX]; int ping_got[LINK_PING_MAX]; long ping_rtt[LINK_PING_MAX];
} link_t;

typedef struct { int sent, recv; long first_rtt_ms, avg_rtt_ms; } link_ping_t;

long link_now_ms(void);
// Zero everything, set defaults. Call once before link_join.
void link_init(link_t *l, rtl_t *r);
// Join with up to 3 attempts (1 s apart) on scan/auth/assoc/handshake failures. 0 = joined, DHCP lease in l->n.lease.
// On failure returns -1 and l->fail_step / l->fail_reason say why.
int  link_join(rtl_t *r, const link_cfg_t *cfg, link_t *l);
// One more attempt with the same cfg (fresh state): used to re-join after a deauth. 0 / -1 as above.
int  link_rejoin(link_t *l);
// Receive for ms, run DHCP/ARP timers and keepalives. Returns -1 when the AP deauthenticated us or stop was requested.
int  link_pump(link_t *l, int ms);
// Ping target (host order) `count` times: the first reply is waited for 3 s, the others 1 s.
// 0 = ok, 1 = no reply to the first echo, -1 = deauthenticated / stopped.
int  link_ping(link_t *l, uint32_t target, int count, link_ping_t *res);
// Politely leave: send a Deauthentication (reason 3, station leaving) to the AP we joined.
void link_leave(link_t *l);
// Human text for a security mode / cipher.
const char *link_sec_str(link_sec_t s);
const char *link_cipher_str(int c);
void link_ipstr(char *b, size_t n, uint32_t a);
#endif
