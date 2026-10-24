// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Bulk-IN RX path: split aggregated RX buffers from endpoint 0x84 into 802.11 frames.
#ifndef RX_H
#define RX_H
#include <stdint.h>
#include "rtl.h"

typedef struct {
    const uint8_t *data;   // 802.11 frame (valid only during the callback)
    int len;               // bytes, as delivered by the chip
    int has_fcs;           // 1 if the last 4 bytes are a valid FCS (checked with CRC32)
    int rssi_valid;
    int rssi_dbm;          // from PHY status path A gain: (gain & 0x7F) - 110
    uint8_t rate;          // RX descriptor rate: 0-3 CCK 1/2/5.5/11, 4-11 OFDM 6..54, 12-27 HT MCS0-15, 44+ VHT
    int channel;           // r->channel at receive time
    int crc_err, icv_err;
    int swdec;             // RX desc SWDEC bit: 1 = hardware did NOT decrypt (software must)
    int security;          // RX desc security type field
    int bw;                // 0 = 20, 1 = 40, 2 = 80
} rtl_frame_t;

typedef void (*rtl_frame_cb)(void *ud, const rtl_frame_t *f);

typedef struct {
    unsigned long transfers, bytes, frames, c2h, bad_desc, crc_err;
} rtl_rx_stats_t;
extern rtl_rx_stats_t rtl_rx_stats;

// One (or more) bulk reads, up to timeout_ms total wait for the first data. Returns number of frames delivered
// to cb (>= 0; 0 on timeout), or < 0 on USB error.
int rtl_rx_poll(rtl_t *r, rtl_frame_cb cb, void *ud, int timeout_ms);

#endif
