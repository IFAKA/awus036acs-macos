// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// country: regulatory table for the Wi-Fi channels this driver may use or transmit on. Pure data + lookup, unit-tested.
// The table is a small approximation (written from the public Linux wireless-regdb ranges, not legal advice): it is meant to
// keep the daemon out of channels the user's country does not allow, like the vendor app's country code setting did.
#ifndef COUNTRY_H
#define COUNTRY_H

#define CC_BLOCKED 0   // channel not allowed: never scanned, never joined
#define CC_OK      1   // allowed
#define CC_DFS     2   // allowed, but radar rules apply (we only transmit after hearing the AP's Beacon, see sta.c)

// Is 2-letter code known? ("00" = world-safe default). Case-insensitive.
int  country_known(const char *cc);
// CC_BLOCKED / CC_OK / CC_DFS for channel ch (1-14, 36-165) in country cc. Unknown country = same as "00".
int  country_chan(const char *cc, int ch);
// Normalise to upper case into out[3]. Returns 0 if cc is a known code.
int  country_norm(const char *cc, char out[3]);
// Space-separated list of the known codes (for help text).
const char *country_list(void);
#endif
