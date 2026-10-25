// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// wpslink: runs one WPS enrollee registration over the air (or over the sta_io loopback): find the AP on its channel,
// associate OPEN with the WSC association IE (no RSN IE), run EAP-WSC (src/wps.c) over EAPOL data frames, leave, and hand back
// the credential. Does no DHCP and keeps no link. The daemon turns the credential into a saved profile (wpsrun_cred_profile).
#ifndef WPSLINK_H
#define WPSLINK_H
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include "rtl.h"
#include "wps.h"

typedef struct {
    const char *ssid;               // the AP to enrol with (directed probe)
    uint8_t bssid[6];               // required
    int channel;                    // required (the daemon takes it from its scan)
    const char *pin;                // NULL = push button, else 4 or 8 digits
    volatile sig_atomic_t *stop;    // optional abort flag
    FILE *out;                      // progress lines, NULL = silent
    int msg_timeout_ms;             // no frame from the AP for this long -> give up (0 = 10000)
    int session_ms;                 // whole session cap (0 = 120000)
    void (*idle)(void *ud);         // optional, called every ~50 ms while waiting (keeps the daemon socket alive)
    void *idle_ud;
} wpsrun_cfg_t;

typedef struct {
    int ok;                         // 1 = credential received
    char step[24], reason[160];     // on failure: scan / auth / assoc / eap / session ; short text
    int pin_wrong;                  // the AP rejected our PIN (feeds the rate limiter and the message)
    int not_ready;                  // M2D: the registrar is not ready (no button window / PIN not entered)
    int locked;                     // AP setup locked
    wps_fail_t fail; uint16_t cfg_error;
    wps_cred_t cred;                // valid when ok
} wpsrun_res_t;

// 0 = credential received (res->ok), -1 = failed (res->step / res->reason). Secrets in the session are zeroed before return.
int wpsrun(rtl_t *r, const wpsrun_cfg_t *cfg, wpsrun_res_t *res);

// Credential -> profile fields (security word as profile.h knows it, and the key). 0 = ok, -1 = cannot be used (*why = reason).
int wpsrun_cred_profile(const wps_cred_t *c, char *sec, size_t secn, char *key, size_t keyn, const char **why);
#endif
