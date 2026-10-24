// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// USB TX path (injection): 40-byte TX descriptor + 802.11 frame on a bulk OUT endpoint.
// Ported from rtl8812au_xmit.c update_txdesc (MGNT_FRAMETAG branch) and rtl8812a_cal_txdesc_chksum.
#ifndef TX_H
#define TX_H
#include <stdint.h>
#include "rtl.h"

typedef struct {
    unsigned long submitted, completed, failed;
    unsigned long ccx, ccx_ok, ccx_retry_over, ccx_life_over;   // chip TX reports (C2H 0x03) seen by rx.c
    unsigned long ccx_retries;                                  // sum of the retry counts of the reports
    unsigned long ccx_rate_hist[128];                           // reports per final hardware rate code
} rtl_tx_stats_t;
extern rtl_tx_stats_t rtl_tx_stats;
// Called by rx.c for every chip TX report: final hardware rate code, retry count, ok = delivered (0 = retry limit or lifetime over).
extern void (*rtl_tx_report_cb)(void *ud, int hw_rate, int retries, int ok);
extern void *rtl_tx_report_ud;

// Send one raw 802.11 frame (no FCS: hardware appends it). rate = Mbps*10: 10,20,55,110 (CCK), 60,90,120,180,240,360,480,540 (OFDM).
// retries = hardware retry limit (0 = send once; only unicast frames get retried). Returns 0 on success (USB bulk completed
// with all bytes written), <0 on error. Hardware assigns the sequence number.
int rtl_tx_frame(rtl_t *r, const uint8_t *frame, int len, int rate, int retries);

// Send one 802.11 data frame (to-DS, header + body already built by the caller, incl. any software CCMP; the hardware
// does not encrypt: sectype none) on the BE queue / LOW bulk endpoint. Same units and return codes as rtl_tx_frame.
int rtl_tx_data(rtl_t *r, const uint8_t *frame, int len, int rate, int retries);

// Hardware rate code for a rate value (legacy Mbps*10, HT 1000+mcs, VHT 2000+mcs); -1 if unsupported.
int rtl_tx_hw_rate(int rate);

// Build the descriptor only (for debugging): desc must hold 40 bytes. Returns hardware rate code or -1.
int rtl_tx_build_desc(uint8_t *desc, int len, int rate, int retries, int bmc);
#endif
