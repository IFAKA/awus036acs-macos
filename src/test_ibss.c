// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Unit tests of the IBSS frame builder / parser (pure; the radio part is checked on the air by hand).
#include <stdio.h>
#include <string.h>
#include "ibss.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)
static uint32_t seq_rnd(void) { static uint32_t s = 0x01020304; s = s * 1664525u + 1013904223u; return s; }

int main(void)
{
    ibss_t c; memset(&c, 0, sizeof c);
    strcpy(c.ssid, "awus-test-ibss"); c.channel = 11;
    ibss_random_addr(c.mac, seq_rnd); ibss_random_addr(c.bssid, seq_rnd);
    CHECK((c.bssid[0] & 3) == 2 && (c.mac[0] & 3) == 2);
    uint8_t b[256];
    int n = ibss_build_frame(b, sizeof b, &c, 0, NULL);
    CHECK(n > 40 && b[0] == 0x80);
    CHECK(!memcmp(b + 4, "\xff\xff\xff\xff\xff\xff", 6) && !memcmp(b + 10, c.mac, 6) && !memcmp(b + 16, c.bssid, 6));
    CHECK(b[32] == 100 && (b[34] | b[35] << 8) == 0x0002);            // 100 TU, IBSS bit only
    ibss_peer_t pe;
    CHECK(ibss_parse(b, n, &pe) == 1);
    CHECK(!strcmp(pe.ssid, "awus-test-ibss") && pe.channel == 11 && !pe.privacy && !memcmp(pe.bssid, c.bssid, 6));
    // IBSS parameter set IE with ATIM window 0
    int found = 0;
    for (int i = 36; i + 2 <= n; i += 2 + b[i + 1]) if (b[i] == 6) found = (b[i + 1] == 2 && !b[i + 2] && !b[i + 3]);
    CHECK(found);
    c.privacy = 1; n = ibss_build_frame(b, sizeof b, &c, 0, NULL);
    CHECK((b[34] | b[35] << 8) == 0x0012 && ibss_parse(b, n, &pe) && pe.privacy);
    // an infrastructure beacon (ESS) is not an IBSS
    b[34] = 0x11; CHECK(ibss_parse(b, n, &pe) == 0);
    // probe response is addressed
    uint8_t da[6] = {2, 1, 2, 3, 4, 5};
    n = ibss_build_frame(b, sizeof b, &c, 1, da);
    CHECK(b[0] == 0x50 && !memcmp(b + 4, da, 6) && ibss_parse(b, n, &pe));
    // 5 GHz: no DS / ERP elements, OFDM rates only
    c.channel = 36; n = ibss_build_frame(b, sizeof b, &c, 0, NULL);
    int ds = 0; for (int i = 36; i + 2 <= n; i += 2 + b[i + 1]) if (b[i] == 3 || b[i] == 42) ds = 1;
    CHECK(!ds && ibss_parse(b, n, &pe) && pe.channel == 0);
    // probe request matching
    uint8_t pr[64] = {0x40, 0, 0, 0}; pr[24] = 0; pr[25] = 0;
    CHECK(ibss_probe_req_for(pr, 26, "x"));                            // wildcard
    pr[25] = 14; memcpy(pr + 26, "awus-test-ibss", 14);
    CHECK(ibss_probe_req_for(pr, 40, "awus-test-ibss") && !ibss_probe_req_for(pr, 40, "other"));
    // peers table
    ibss_t t; memset(&t, 0, sizeof t); pe.rssi = -40;
    ibss_note(&t, &pe); ibss_note(&t, &pe); CHECK(t.npeers == 1);
    memset(pe.bssid, 9, 6); ibss_note(&t, &pe); CHECK(t.npeers == 2);
    printf(fails ? "IBSS TEST FAILED: %d\n" : "IBSS TEST OK\n", fails);
    return fails != 0;
}
