// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Beacon / Probe Response parsing for the scan list: pure functions, no I/O, unit-tested (test_scanparse.c).
#ifndef SCANPARSE_H
#define SCANPARSE_H
#include <stdint.h>
#include <stddef.h>

// AKM bits (RSN/WPA authentication and key management)
#define SCAN_AKM_PSK  0x01
#define SCAN_AKM_1X   0x02   // 802.1X / EAP (incl. FT-1X, SHA256, Suite B)
#define SCAN_AKM_SAE  0x04   // WPA3-Personal
#define SCAN_AKM_OWE  0x08   // Enhanced Open
// Pairwise cipher bits
#define SCAN_CIPHER_CCMP 0x01   // CCMP-128 or CCMP-256
#define SCAN_CIPHER_TKIP 0x02
#define SCAN_CIPHER_GCMP 0x04
#define SCAN_CIPHER_WEP  0x08

typedef struct {
    uint8_t ssid[32];
    int ssid_len;
    int has_ssid;          // SSID element present (it may still be empty/zeroed = hidden)
    int channel;           // primary channel from HT Operation, else DS Parameter Set; 0 = neither present
    int privacy;           // capability Privacy bit; scan_parse_beacon() sets it, scan_parse_ie() leaves it 0
    int rsn, wpa1;         // RSN element (id 48) / vendor WPA element (00:50:f2:01) seen
    unsigned rsn_akm, rsn_cipher, wpa_akm, wpa_cipher;
    int wps;               // vendor WPS element (00:50:f2:04) seen
    int max_rate;          // best legacy rate in 500 kb/s units (0 = none listed)
    int ht, vht, he;       // HT / VHT / HE capabilities present
    int nss;               // spatial streams from HT MCS set (0 = unknown)
} scan_ap_t;

// Parse a chain of information elements. Memsets *out first. Truncated elements stop the parse (never overruns).
void scan_parse_ie(const uint8_t *ies, int len, scan_ap_t *out);

// Parse a Beacon/Probe Response body (the bytes after the 24-byte MAC header: timestamp 8, interval 2,
// capability 2, then IEs). Fills the same fields plus privacy. Returns 0, or -1 if too short.
int scan_parse_beacon(const uint8_t *body, int len, scan_ap_t *out);

// Human text. security: "Open", "WEP", "WPA-PSK", "WPA2-PSK", "WPA3-SAE", "WPA2+WPA3-PSK+SAE", "WPA2-802.1X", "OWE"...
void scan_security_str(const scan_ap_t *a, char *buf, size_t n);
// Pairwise ciphers: "CCMP", "TKIP+CCMP", "-" when none/unknown.
void scan_cipher_str(const scan_ap_t *a, char *buf, size_t n);

#endif
