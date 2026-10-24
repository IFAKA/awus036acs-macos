// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// 802.11 station join (probe, open auth, association) and data-frame RX/TX plumbing on top of tx.c / rx.c.
#ifndef STA_H
#define STA_H
#include <stdint.h>
#include "rtl.h"
#include "rx.h"

typedef struct {
    uint8_t mac[6], bssid[6];
    char ssid[33];
    int have_bssid;            // bssid known/required
    int channel;
    // learned from probe response / beacon
    int ap_seen;
    uint16_t ap_cap;
    uint8_t rates[16]; int nrates;      // supported rates IE body (raw, with basic bit)
    uint8_t xrates[16]; int nxrates;    // extended supported rates IE body
    uint8_t rsn[64]; int rsn_len;       // full RSN IE incl. id+len (0 if none)
    uint8_t wpa_ie[96]; int wpa_ie_len; // full WPA1 vendor IE (dd len 00:50:f2:01 ...) incl. id+len (0 if none)
    uint8_t ies[512]; int ies_len;      // raw IE chain of the matched Beacon / Probe Response (for scan_parse_ie)
    int auth_algo;                      // 0 = open system, 1 = shared key (WEP challenge)
    uint8_t wep_key[13]; int wep_key_len, wep_keyid; uint32_t wep_iv;   // WEP key (shared-key auth encrypts the challenge with it)
    int hidden;                         // SSID may be hidden: match only Probe Responses to us (or Beacons of a known BSSID)
    uint8_t sec_ie[96]; int sec_ie_len; // security element (RSN or WPA1) copied into the association request
    int rssi;
    // link health (frames from our AP only): last time any frame was heard, average RSSI (dBm, exponential), last RX rate
    long last_rx_ms; int rssi_avg; unsigned long rssi_n; int rx_rate; unsigned long rx_ap_frames;
    // join result
    int aid, last_status;
    int associated;
    // events
    int deauth_seen, deauth_reason, disassoc_seen, disassoc_reason;
    unsigned long data_rx, prot_rx, prot_extiv, eapol_rx, group_rx;
    int eapol_keyinfo;                  // last EAPOL-Key info (-1 none)
    // internal
    rtl_t *r;
    int rate;                           // mgmt TX rate (Mbps*10)
    long beacon_ms;                     // monotonic time of the last matching Beacon (0 = none), for the DFS transmit gate
    int in_rx;                          // inside sta_poll's receive callbacks: TX must not poll
    int dfs_refused;                    // transmissions refused by the DFS gate since the last scan
    int auth_status, auth_got, auth_rx_algo, assoc_got, assoc_status;   // auth_got = transaction sequence number of the last Authentication frame for us (0 = none)
    uint8_t challenge[128]; int challenge_len;                          // shared-key challenge text from transaction 2
    uint8_t last_hdr_dummy;
    void (*def_cb)(void *ud, const uint8_t *frame, int len, const rtl_frame_t *f);   // used by sta_poll when cb == NULL
    void *def_ud;
} sta_t;

// frame (FCS stripped) is a data frame for us: from-DS from our BSSID, addr1 == our MAC or group. hdr intact.
typedef void (*sta_data_cb)(void *ud, const uint8_t *frame, int len, const rtl_frame_t *f);

// Channel switch (tunes the radio, picks the management rate: 6 Mbps OFDM on 5 GHz) and the DFS rule: see tx_gate in sta.c.
int  sta_set_channel(sta_t *s, int ch);
int  sta_is_dfs(int ch);   // 52-144
void sta_init(sta_t *s, rtl_t *r, const char *ssid, const uint8_t *bssid, int channel);
// Each returns 0 on success, nonzero failure (s->last_status holds the 802.11 status code when the AP refused, else -1 = timeout).
int  sta_scan(sta_t *s, int timeout_ms);
int  sta_auth(sta_t *s);
int  sta_assoc(sta_t *s);
// Process RX for up to ms; delivers matching data frames to cb (may be NULL). Updates counters/deauth state.
void sta_poll(sta_t *s, int ms, sta_data_cb cb, void *ud);
int  sta_send_null(sta_t *s);
// Send a Deauthentication frame to our AP (reason 3 = station is leaving). Best effort; only call for an AP we joined.
int  sta_deauth(sta_t *s, int reason);
// Send a to-DS data frame: dst=DA, payload = LLC/SNAP + packet (or pre-encrypted body incl. CCMP header when prot=1).
int  sta_send_data(sta_t *s, const uint8_t dst[6], const uint8_t *body, int blen, int prot, int rate);
#endif
