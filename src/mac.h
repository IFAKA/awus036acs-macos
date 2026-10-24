// MAC init (rtl8812au_hal_init MISC01/MISC02 part, 8821AU path) and monitor-mode RX filter.
#ifndef MAC_H
#define MAC_H
#include "rtl.h"

// Reserved page queues, TX/RX FIFO boundaries, queue priority map, driver info size, interrupt masks,
// WMAC settings, EDCA, retry, burst length, ARFR tables, then enables MAC TX/RX (CR bits 6,7).
// Call after power-on + firmware + PHY_MACConfig table, before the BB/RF tables (rtl_init_phy does this).
int rtl_init_mac(rtl_t *r);

// Promiscuous monitor RCR + RXFLTMAP (all mgt/ctrl/data), PHY status appended. 0 = ok.
int rtl_set_monitor(rtl_t *r);

// Program MAC address + BSSID + station network type. bssid may be NULL (zeros).
int rtl_set_sta_addr(rtl_t *r, const uint8_t mac[6], const uint8_t *bssid);

#endif
