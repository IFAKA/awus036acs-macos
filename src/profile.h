// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// profile: saved networks (the vendor app's "profiles"). A small in-memory table plus a JSON file store.
// File: {"version":1,"profiles":[{"ssid":"..","security":"wpa2","key":"..","hidden":false,"priority":10,"autojoin":true,
//        "default_route":false}, ...]}. Mode 0600, written atomically (temp file in the same directory, fsync, rename).
// The key is stored in the file in clear text, protected only by the 0600 mode (and root/home directory permissions).
// Keychain was considered and not used: the `security` CLI takes the secret on argv (visible in `ps`) and prompts a GUI
// dialog for a daemon with no login session, which is not robust. Pure code apart from the file functions, unit-tested.
#ifndef PROFILE_H
#define PROFILE_H
#include <stddef.h>

#define PROFILE_MAX 32
#define PROFILE_SEC_LEN 12

typedef struct {
    char ssid[33];
    char security[PROFILE_SEC_LEN];   // "auto", "open", "wep", "wep-shared", "wpa", "wpa2", "sae"
    char key[130];                    // WPA passphrase (8-63) or WEP key; empty for open
    int hidden;
    int priority;                     // higher = preferred by auto-join
    int autojoin;
    int prefer_sae;                   // WPA2/WPA3 transition AP: 1 (default) = join with SAE, 0 = WPA2-PSK
    int default_route;                // route all traffic through the utun (root mode only); default 0
} profile_t;

typedef struct { profile_t p[PROFILE_MAX]; int n; } profiles_t;

// Validate one profile (ssid 1-32 bytes, known security, key length for the security, priority -1000..1000). 0 = ok, else a
// short reason string in *why (static text).
int  profile_check(const profile_t *p, const char **why);
// Insert or replace (same SSID) . 0 = ok, -1 = invalid (see profile_check), -2 = table full.
int  profiles_put(profiles_t *ps, const profile_t *p, const char **why);
// Remove by SSID. 0 = removed, -1 = not found.
int  profiles_remove(profiles_t *ps, const char *ssid);
const profile_t *profiles_find(const profiles_t *ps, const char *ssid);
// Auto-join choice: index of the highest-priority profile with autojoin=1 for which visible(ctx, profile) is nonzero
// (ties: the one added first), or -1. skip_ssid (optional) is passed over (e.g. the one that just failed).
int  profiles_pick(const profiles_t *ps, int (*visible)(void *ctx, const profile_t *p), void *ctx, const char *skip_ssid);

// JSON text <-> table. profiles_to_json returns the length written (always NUL terminated) or -1 if cap is too small.
int  profiles_to_json(const profiles_t *ps, char *out, size_t cap);
// Parse JSON text. Entries that fail profile_check are skipped (counted in *skipped, optional). 0 = ok, -1 = syntax error.
int  profiles_from_json(const char *text, profiles_t *ps, int *skipped);

// File store. load: a missing file is not an error (empty table, returns 0); -1 = unreadable or corrupt.
// save: creates the directory (0700) if needed, writes <path>.tmp with mode 0600, fsync, rename. 0 / -1.
int  profiles_load(const char *path, profiles_t *ps);
int  profiles_save(const char *path, const profiles_t *ps);
#endif
