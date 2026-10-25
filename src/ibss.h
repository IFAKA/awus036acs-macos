// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Ad-hoc (IBSS) networks: create one (the chip transmits our beacon from the beacon queue every 100 TU), or join one found by
// scanning (adopt its BSSID, beacon with it). Ported from rtl8812au start_create_ibss / issue_beacon (ad-hoc branch) and
// hw_var_set_opmode (_HW_STATE_ADHOC_). Open or WEP-flagged (the privacy bit and key are kept); the data plane (IP over an IBSS,
// WEP data frames) is not built yet: this layer beacons, answers probe requests, and reports the peers it hears.
#ifndef IBSS_H
#define IBSS_H
#include <stddef.h>
#include <stdint.h>
#include "rtl.h"

#define IBSS_MAX_PEERS 16

typedef struct {
    uint8_t bssid[6];
    int channel;
    char ssid[33];
    int privacy;           // capability Privacy bit (WEP)
    int rssi;              // dBm of the last frame (0 = unknown)
    long last_ms;
    uint8_t src[6];        // transmitter of the last beacon
} ibss_peer_t;

typedef struct {
    // configuration (set before ibss_start)
    char ssid[33];
    int channel;
    uint8_t mac[6];        // our address; zero = random locally administered
    uint8_t bssid[6];      // zero = create (random locally administered); non-zero = join this IBSS
    int join;              // 1 = bssid is an existing IBSS
    int no_probe_resp;     // test aid: stay silent on probe requests (prove the beacons alone are heard)
    int privacy;           // announce WEP in the capability field
    uint8_t wep_key[13]; int wep_len;   // WEP key (kept for the data plane, not used on the air yet)
    // state
    int on;
    long started_ms;
    unsigned long beacons_err, beacons_dma;   // chip beacon-error / beacon-DMA interrupt flags seen
    unsigned long beacons_ok;     // beacon transmissions the chip reported (TXBCN OK counter)
    unsigned long probe_resp;     // probe responses we sent
    unsigned long probe_req;      // probe requests we saw for our SSID
    unsigned long bcn_heard;      // beacons of our own BSSID heard from other stations
    ibss_peer_t peers[IBSS_MAX_PEERS]; int npeers;   // other stations / networks heard (see ibss_note)
    uint8_t bcn[256]; int bcn_len;
} ibss_t;

// ---- pure (unit-tested) ----
// A random locally administered unicast address.
void ibss_random_addr(uint8_t a[6], uint32_t (*rnd)(void));
// Build a Beacon (probe_resp = 0, DA ff:ff:ff:ff:ff:ff) or Probe Response (probe_resp = 1, DA = da) for the IBSS in c.
// Timestamp is zero (the chip fills it for beacons). Returns the length (no FCS).
int ibss_build_frame(uint8_t *out, size_t cap, const ibss_t *c, int probe_resp, const uint8_t *da);
// Parse a Beacon / Probe Response: 1 = an IBSS (capability IBSS=1, ESS=0) filled into pe, 0 = anything else.
int ibss_parse(const uint8_t *f, int len, ibss_peer_t *pe);
// Is this frame a Probe Request for our SSID (or the wildcard)?
int ibss_probe_req_for(const uint8_t *f, int len, const char *ssid);

// ---- radio ----
// Bring the IBSS up on the radio: channel, MSR = ad-hoc, BSSID, beacon engine, beacon download. 0 = ok, <0 = step failed
// (reason in err). The beacon then goes out every 100 TU without the host.
int ibss_start(rtl_t *r, ibss_t *c, char *err, size_t en);
// Stop beaconing and go back to the monitor/no-link state.
void ibss_stop(rtl_t *r, ibss_t *c);
// Serve the IBSS for up to ms: receive, answer probe requests, note peers, count transmitted beacons. Returns frames seen, <0 on USB error.
int ibss_tick(rtl_t *r, ibss_t *c, int ms);
// Scan a channel for an IBSS named ssid (any if NULL) for up to ms; fills pe. 1 = found, 0 = none, <0 USB error.
int ibss_find(rtl_t *r, int channel, const char *ssid, int ms, ibss_peer_t *pe);
// Record a heard network / station (exposed for tests).
void ibss_note(ibss_t *c, const ibss_peer_t *pe);
#endif
