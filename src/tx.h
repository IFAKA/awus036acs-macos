// USB TX path (injection): 40-byte TX descriptor + 802.11 frame on a bulk OUT endpoint.
// Ported from rtl8812au_xmit.c update_txdesc (MGNT_FRAMETAG branch) and rtl8812a_cal_txdesc_chksum.
#ifndef TX_H
#define TX_H
#include <stdint.h>
#include "rtl.h"

typedef struct {
    unsigned long submitted, completed, failed;
    unsigned long ccx, ccx_ok, ccx_retry_over, ccx_life_over;   // chip TX reports (C2H 0x03) seen by rx.c
} rtl_tx_stats_t;
extern rtl_tx_stats_t rtl_tx_stats;

// Send one raw 802.11 frame (no FCS: hardware appends it). rate = Mbps*10: 10,20,55,110 (CCK), 60,90,120,180,240,360,480,540 (OFDM).
// retries = hardware retry limit (0 = send once; only unicast frames get retried). Returns 0 on success (USB bulk completed
// with all bytes written), <0 on error. Hardware assigns the sequence number.
int rtl_tx_frame(rtl_t *r, const uint8_t *frame, int len, int rate, int retries);

// Build the descriptor only (for debugging): desc must hold 40 bytes. Returns hardware rate code or -1.
int rtl_tx_build_desc(uint8_t *desc, int len, int rate, int retries, int bmc);
#endif
