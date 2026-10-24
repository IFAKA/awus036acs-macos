// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Shared chip bring-up: open, power on, firmware, MAC/BB/RF init, set channel, sanity readback.
#ifndef BRINGUP_H
#define BRINGUP_H
#include <stddef.h>
#include "rtl.h"

// Returns 0 on success. On failure returns nonzero, *step = failing step name ("open", "power_on", ...)
// and reason (size rn) = human text. Leaves the device open (caller calls rtl_close).
int rtl_bringup(rtl_t *r, int channel, const char **step, char *reason, size_t rn);
#endif
