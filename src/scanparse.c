// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Beacon / Probe Response parsing for the scan list. See scanparse.h.
#include <stdio.h>
#include <string.h>
#include "scanparse.h"

static unsigned akm_bit(uint8_t t)
{
    switch (t) {
    case 1: case 3: case 5: case 11: case 12: return SCAN_AKM_1X;
    case 2: case 4: case 6: return SCAN_AKM_PSK;
    case 8: case 9: return SCAN_AKM_SAE;
    case 18: return SCAN_AKM_OWE;
    default: return 0;
    }
}

static unsigned cipher_bit(uint8_t t)
{
    switch (t) {
    case 1: case 5: return SCAN_CIPHER_WEP;
    case 2: return SCAN_CIPHER_TKIP;
    case 4: case 10: return SCAN_CIPHER_CCMP;
    case 8: case 9: return SCAN_CIPHER_GCMP;
    default: return 0;
    }
}

// RSN and WPA1 share one layout: version(2) group(4) pairwise_count(2) pairwise(4 each) akm_count(2) akm(4 each).
// Suites with OUI 00:0f:ac (RSN) or 00:50:f2 (WPA1) are decoded by their type byte.
static void parse_suites(const uint8_t *p, int len, unsigned *cipher, unsigned *akm)
{
    *cipher = *akm = 0;
    if (len < 8) return;
    int off = 2 + 4;                        // skip version + group cipher (the group cipher is not the interesting one)
    int pc = p[off] | p[off + 1] << 8; off += 2;
    if (off + 4 * pc > len) return;
    for (int i = 0; i < pc; i++) *cipher |= cipher_bit(p[off + 4 * i + 3]);
    off += 4 * pc;
    if (pc == 0) *cipher |= cipher_bit(p[5]);          // none listed: pairwise defaults to the group cipher
    if (off + 2 > len) return;
    int ac = p[off] | p[off + 1] << 8; off += 2;
    if (off + 4 * ac > len) return;
    for (int i = 0; i < ac; i++) *akm |= akm_bit(p[off + 4 * i + 3]);
}

void scan_parse_ie(const uint8_t *ies, int len, scan_ap_t *out)
{
    memset(out, 0, sizeof *out);
    int ds_ch = 0, ht_ch = 0;
    for (int i = 0; i + 2 <= len; ) {
        int id = ies[i], l = ies[i + 1];
        if (i + 2 + l > len) break;                     // truncated element
        const uint8_t *d = ies + i + 2;
        switch (id) {
        case 0:
            if (l <= 32) { memcpy(out->ssid, d, l); out->ssid_len = l; out->has_ssid = 1; }
            break;
        case 1: case 50:                                // supported / extended supported rates
            for (int k = 0; k < l; k++) { int rt = d[k] & 0x7F; if (rt > out->max_rate && rt != 0x7F) out->max_rate = rt; }
            break;
        case 3: if (l >= 1) ds_ch = d[0]; break;
        case 45:                                        // HT capabilities: cap(2) ampdu(1) MCS set(16): RX mask bytes first
            if (l >= 7) {
                out->ht = 1;
                int nss = 0;
                for (int k = 0; k < 4; k++) if (d[3 + k]) nss = k + 1;
                out->nss = nss;
            }
            break;
        case 61: if (l >= 1) ht_ch = d[0]; break;       // HT Operation: primary channel
        case 191: out->vht = 1; break;
        case 255: if (l >= 1 && d[0] == 35) out->he = 1; break;   // extension element: HE capabilities
        case 48:
            out->rsn = 1;
            if (l >= 2) parse_suites(d, l, &out->rsn_cipher, &out->rsn_akm);
            break;
        case 221:
            if (l >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2) {
                if (d[3] == 1) { out->wpa1 = 1; parse_suites(d + 4, l - 4, &out->wpa_cipher, &out->wpa_akm); }
                else if (d[3] == 4) out->wps = 1;
            }
            break;
        }
        i += 2 + l;
    }
    out->channel = ht_ch ? ht_ch : ds_ch;
}

int scan_parse_beacon(const uint8_t *body, int len, scan_ap_t *out)
{
    if (len < 12) { memset(out, 0, sizeof *out); return -1; }
    int cap = body[10] | body[11] << 8;
    scan_parse_ie(body + 12, len - 12, out);
    out->privacy = (cap >> 4) & 1;
    return 0;
}

static void cat(char *buf, size_t n, const char *s) { size_t l = strlen(buf); snprintf(buf + l, n - l, "%s", s); }

static void akm_str(unsigned akm, char *buf, size_t n)
{
    int first = 1;
    static const struct { unsigned bit; const char *name; } t[] =
        { {SCAN_AKM_PSK, "PSK"}, {SCAN_AKM_1X, "802.1X"}, {SCAN_AKM_SAE, "SAE"}, {SCAN_AKM_OWE, "OWE"} };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++)
        if (akm & t[i].bit) { if (!first) cat(buf, n, "+"); cat(buf, n, t[i].name); first = 0; }
}

void scan_security_str(const scan_ap_t *a, char *buf, size_t n)
{
    buf[0] = 0;
    if (!n) return;
    if (a->rsn) {
        unsigned k = a->rsn_akm;
        if (k == SCAN_AKM_OWE) { cat(buf, n, "OWE"); return; }
        if (a->wpa1) cat(buf, n, "WPA+");
        if (k & SCAN_AKM_SAE) cat(buf, n, (k & ~SCAN_AKM_SAE) ? "WPA2+WPA3" : "WPA3");
        else cat(buf, n, "WPA2");
        if (k) { cat(buf, n, "-"); akm_str(k, buf, n); }
    } else if (a->wpa1) {
        cat(buf, n, "WPA");
        if (a->wpa_akm) { cat(buf, n, "-"); akm_str(a->wpa_akm, buf, n); }
    } else if (a->privacy) cat(buf, n, "WEP");
    else cat(buf, n, "Open");
}

void scan_cipher_str(const scan_ap_t *a, char *buf, size_t n)
{
    buf[0] = 0;
    if (!n) return;
    unsigned c = a->rsn_cipher | a->wpa_cipher;
    if (!a->rsn && !a->wpa1) c = 0;
    int first = 1;
    static const struct { unsigned bit; const char *name; } t[] =
        { {SCAN_CIPHER_TKIP, "TKIP"}, {SCAN_CIPHER_CCMP, "CCMP"}, {SCAN_CIPHER_GCMP, "GCMP"}, {SCAN_CIPHER_WEP, "WEP"} };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++)
        if (c & t[i].bit) { if (!first) cat(buf, n, "+"); cat(buf, n, t[i].name); first = 0; }
    if (first) cat(buf, n, "-");
}
