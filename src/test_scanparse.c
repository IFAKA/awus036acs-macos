// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Unit test for src/scanparse.c: hand-built information-element chains, no hardware.
#include <stdio.h>
#include <string.h>
#include "scanparse.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static void expect(const char *name, const scan_ap_t *a, const char *sec, const char *cipher)
{
    char s[64], c[64];
    scan_security_str(a, s, sizeof s);
    scan_cipher_str(a, c, sizeof c);
    int ok = !strcmp(s, sec) && !strcmp(c, cipher);
    printf("%-10s sec=%-20s cipher=%-10s %s\n", name, s, c, ok ? "ok" : "FAIL");
    if (!ok) { printf("   wanted sec=%s cipher=%s\n", sec, cipher); fails++; }
}

// common head: SSID "net", rates 1..54 (54 = 0x6C), DS channel 6
#define HEAD 0x00,0x03,'n','e','t', 0x01,0x04,0x82,0x84,0x0C,0x6C, 0x03,0x01,0x06
// RSN: version 1, group CCMP, 1 pairwise CCMP, 1 AKM <type>, caps 0
#define RSN(grp,pw,akm) 0x30,0x14,0x01,0x00, 0x00,0x0F,0xAC,grp, 0x01,0x00, 0x00,0x0F,0xAC,pw, \
                        0x01,0x00, 0x00,0x0F,0xAC,akm, 0x00,0x00

int main(void)
{
    scan_ap_t a;

    static const uint8_t open_[] = { HEAD };
    scan_parse_ie(open_, sizeof open_, &a);
    CHECK(a.has_ssid && a.ssid_len == 3 && !memcmp(a.ssid, "net", 3));
    CHECK(a.channel == 6 && a.max_rate == 54 * 2 && !a.rsn && !a.wpa1 && !a.wps);
    expect("open", &a, "Open", "-");

    static const uint8_t wep[] = { HEAD };
    scan_parse_ie(wep, sizeof wep, &a);
    a.privacy = 1;                                 // capability Privacy bit with no RSN/WPA element
    expect("wep", &a, "WEP", "-");

    static const uint8_t wpa1[] = { HEAD,
        0xDD,0x16, 0x00,0x50,0xF2,0x01, 0x01,0x00, 0x00,0x50,0xF2,0x02, 0x01,0x00, 0x00,0x50,0xF2,0x02,
        0x01,0x00, 0x00,0x50,0xF2,0x02 };                  // WPA1: TKIP/TKIP, AKM type 2 = PSK
    scan_parse_ie(wpa1, sizeof wpa1, &a);
    a.privacy = 1;
    CHECK(a.wpa1 && !a.rsn);
    expect("wpa1-tkip", &a, "WPA-PSK", "TKIP");

    static const uint8_t wpa2[] = { HEAD, RSN(4,4,2),
        0xDD,0x08, 0x00,0x50,0xF2,0x04, 0x10,0x4A,0x00,0x01 };   // + WPS
    scan_parse_ie(wpa2, sizeof wpa2, &a);
    CHECK(a.rsn && a.wps && !a.wpa1);
    expect("wpa2-psk", &a, "WPA2-PSK", "CCMP");

    static const uint8_t wpa3[] = { HEAD, RSN(4,4,8) };
    scan_parse_ie(wpa3, sizeof wpa3, &a);
    expect("wpa3-sae", &a, "WPA3-SAE", "CCMP");

    // transition mode: two AKMs (PSK + SAE)
    static const uint8_t mixed[] = { HEAD,
        0x30,0x18,0x01,0x00, 0x00,0x0F,0xAC,0x04, 0x01,0x00, 0x00,0x0F,0xAC,0x04,
        0x02,0x00, 0x00,0x0F,0xAC,0x02, 0x00,0x0F,0xAC,0x08, 0x80,0x00 };
    scan_parse_ie(mixed, sizeof mixed, &a);
    expect("wpa2+3", &a, "WPA2+WPA3-PSK+SAE", "CCMP");

    static const uint8_t eap[] = { HEAD, RSN(4,4,1) };
    scan_parse_ie(eap, sizeof eap, &a);
    expect("802.1x", &a, "WPA2-802.1X", "CCMP");

    // WPA1 + WPA2 (mixed mode) with TKIP and CCMP pairwise
    static const uint8_t mm[] = { HEAD,
        0x30,0x18,0x01,0x00, 0x00,0x0F,0xAC,0x02, 0x02,0x00, 0x00,0x0F,0xAC,0x04, 0x00,0x0F,0xAC,0x02,
        0x01,0x00, 0x00,0x0F,0xAC,0x02, 0x00,0x00,
        0xDD,0x16, 0x00,0x50,0xF2,0x01, 0x01,0x00, 0x00,0x50,0xF2,0x02, 0x01,0x00, 0x00,0x50,0xF2,0x02,
        0x01,0x00, 0x00,0x50,0xF2,0x02 };
    scan_parse_ie(mm, sizeof mm, &a);
    expect("wpa+wpa2", &a, "WPA+WPA2-PSK", "TKIP+CCMP");

    // 5 GHz: no DS element, HT Operation primary channel 132; HT (2 streams), VHT, HE; hidden SSID (zero-length)
    static const uint8_t ac[] = { 0x00,0x00, 0x01,0x01,0x8C,
        0x2D,0x1A, 0x6F,0x01, 0x17, 0xFF,0xFF,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,
        0x3D,0x16, 132, 0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0xBF,0x0C, 0,0,0,0, 0,0,0,0,0,0,0,0,
        0xFF,0x03, 35, 0,0 };
    scan_parse_ie(ac, sizeof ac, &a);
    CHECK(a.has_ssid && a.ssid_len == 0 && a.channel == 132 && a.ht && a.vht && a.he && a.nss == 2 && a.max_rate == 12);

    // truncated element must stop cleanly without overrun or crash
    static const uint8_t trunc[] = { 0x00,0x03,'a','b','c', 0x30,0x40,0x01 };
    scan_parse_ie(trunc, sizeof trunc, &a);
    CHECK(a.has_ssid && !a.rsn);

    // whole-beacon wrapper: 12 fixed bytes, cap 0x0411 (ESS + Privacy)
    uint8_t body[12 + sizeof wpa2] = {0};
    body[10] = 0x11; body[11] = 0x04;
    memcpy(body + 12, wpa2, sizeof wpa2);
    CHECK(scan_parse_beacon(body, sizeof body, &a) == 0 && a.privacy && a.rsn && a.channel == 6);
    CHECK(scan_parse_beacon(body, 5, &a) == -1);

    printf(fails ? "TEST_SCANPARSE FAIL %d\n" : "TEST_SCANPARSE OK\n", fails);
    return fails != 0;
}
