// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#ifndef RTL_PCAP_H
#define RTL_PCAP_H
#include <stdio.h>
#include "rx.h"

typedef struct { FILE *f; unsigned long n; } rtl_pcap_t;
int  rtl_pcap_open(rtl_pcap_t *p, const char *path);          // 0 = ok
int  rtl_pcap_write(rtl_pcap_t *p, const rtl_frame_t *fr);    // writes one frame with a radiotap header, current time
void rtl_pcap_close(rtl_pcap_t *p);
#endif
