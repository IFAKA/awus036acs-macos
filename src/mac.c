// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// RTL8821AU MAC init after firmware download. Ported from rtl8812au_hal_init (usb_halinit.c), 8821 branches:
// _InitQueueReservedPage_8821AUsb, _InitTxBufferBoundary_8821AUsb, _InitQueuePriority_8812AUsb, _InitPageBoundary,
// _InitDriverInfoSize, _InitInterrupt, _InitNetworkType, _InitWMACSetting, _InitAdaptiveCtrl, _InitEDCA,
// _InitRetryFunction, init_UsbAggregationSetting (RX/TX aggregation compiled out in our reference config -> off),
// _InitBeaconParameters, _InitBurstPktLen.
#include <stdio.h>
#include <unistd.h>
#include "rtl.h"
#include "mac.h"

#define BIT(n) (1u << (n))

#define REG_CR           0x0100
#define REG_TRXDMA_CTRL  0x010C
#define REG_TRXFF_BNDY   0x0114
#define REG_HIMR0        0x00B0
#define REG_HIMR1        0x00B8
#define REG_RQPN         0x0200
#define REG_RQPN_NPQ     0x0214
#define REG_TDECTRL      0x0208
#define REG_BCNQ_BDNY    0x0424
#define REG_MGQ_BDNY     0x0425
#define REG_WMAC_LBK_BF_HD 0x045D
#define REG_RRSR         0x0440
#define REG_RETRY_LIMIT  0x042A
#define REG_HIQ_NO_LMT_EN 0x05A7
#define REG_RCR          0x0608
#define REG_RX_DRVINFO_SZ 0x060F
#define REG_MAR          0x0620
#define REG_RXFLTMAP0    0x06A0
#define REG_RXFLTMAP1    0x06A2
#define REG_RXFLTMAP2    0x06A4
#define REG_RXDMA_PRO    0x0290
#define MACTXEN          BIT(6)
#define MACRXEN          BIT(7)

// 8821: BCNQ pages = 512/256+6 = 8; total = 0xFF-8 = 247; boundary = 248
#define TX_PAGE_BOUNDARY_8821 248
#define TX_TOTAL_PAGE_8821    247
#define RX_DMA_BOUNDARY_8821  (0x3E80 - 1)
#define LD_RQPN BIT(31)

#define QUEUE_EXTRA  0
#define QUEUE_LOW    1
#define QUEUE_NORMAL 2
#define QUEUE_HIGH   3

static int count_out_eps(rtl_t *r)
{
    int n = 0;
    if (!r->h) return 4;
    struct libusb_config_descriptor *cf = NULL;
    if (libusb_get_active_config_descriptor(libusb_get_device(r->h), &cf) < 0) return 4;
    const struct libusb_interface_descriptor *id = &cf->interface[0].altsetting[0];
    for (int i = 0; i < id->bNumEndpoints; i++) {
        uint8_t a = id->endpoint[i].bEndpointAddress;
        if (!(a & 0x80) && (id->endpoint[i].bmAttributes & 3) == 2) n++;
    }
    libusb_free_config_descriptor(cf);
    return n;
}

static int w_check(int *e, int v) { *e |= v; return v; }

int rtl_init_mac(rtl_t *r)
{
    int e = 0, nout = count_out_eps(r);
    if (nout < 2 || nout > 4) nout = 4;
    #define W8(a, v)  w_check(&e, rtl_w8(r, a, v))
    #define W16(a, v) w_check(&e, rtl_w16(r, a, v))
    #define W32(a, v) w_check(&e, rtl_w32(r, a, v))

    // _InitQueueReservedPage_8821AUsb (normal case). TX_SELE: HQ, LQ, NQ, EQ depending on number of OUT endpoints.
    unsigned hq = 0, lq = 0, nq = 0, eq = 0;
    hq = 8; lq = 8;                       // always for >= 2 eps (HQ|NQ for 2 eps; HQ|LQ|NQ for 3; +EQ for 4)
    if (nout == 2) { lq = 0; nq = 0; }    // 2 eps: HQ|NQ, NPQ pages = 0 in the "normal" table
    if (nout == 4) eq = 4;
    unsigned pub = TX_TOTAL_PAGE_8821 - hq - lq - nq - eq;
    W32(REG_RQPN_NPQ, (nq & 0xFF) | ((eq & 0xFF) << 16));
    W32(REG_RQPN, (hq & 0xFF) | ((lq & 0xFF) << 8) | ((pub & 0xFF) << 16) | LD_RQPN);

    // _InitTxBufferBoundary_8821AUsb
    W8(REG_BCNQ_BDNY, TX_PAGE_BOUNDARY_8821);
    W8(REG_MGQ_BDNY, TX_PAGE_BOUNDARY_8821);
    W8(REG_WMAC_LBK_BF_HD, TX_PAGE_BOUNDARY_8821);
    W8(REG_TRXFF_BNDY, TX_PAGE_BOUNDARY_8821);
    W8(REG_TDECTRL + 1, TX_PAGE_BOUNDARY_8821);

    // _InitQueuePriority_8812AUsb: TXDMA queue map (keep low 3 bits of REG_TRXDMA_CTRL)
    {
        unsigned be, bk, vi, vo, mgt, hi;
        if (nout == 4) { be = QUEUE_LOW; bk = QUEUE_LOW; vi = QUEUE_NORMAL; vo = QUEUE_NORMAL; mgt = QUEUE_EXTRA; hi = QUEUE_HIGH; }
        else if (nout == 3) { be = QUEUE_LOW; bk = QUEUE_LOW; vi = QUEUE_NORMAL; vo = QUEUE_HIGH; mgt = QUEUE_HIGH; hi = QUEUE_HIGH; }
        else { be = QUEUE_NORMAL; bk = QUEUE_NORMAL; vi = QUEUE_HIGH; vo = QUEUE_HIGH; mgt = QUEUE_HIGH; hi = QUEUE_HIGH; }
        uint16_t v = rtl_r16(r, REG_TRXDMA_CTRL) & 0x7;
        v |= (vo & 3) << 4 | (vi & 3) << 6 | (be & 3) << 8 | (bk & 3) << 10 | (mgt & 3) << 12 | (hi & 3) << 14;
        W16(REG_TRXDMA_CTRL, v);
        if (nout == 4) W8(REG_HIQ_NO_LMT_EN, 0xFF);
    }

    // _InitPageBoundary_8812AUsb (8821): RX DMA boundary = 0x3E7F at 0x116
    W16(REG_TRXFF_BNDY + 2, RX_DMA_BOUNDARY_8821);

    // _InitDriverInfoSize: 4 * 8 bytes of PHY status
    W8(REG_RX_DRVINFO_SZ, 4);

    // _InitInterrupt: all masked (we only poll the bulk-IN pipe)
    W32(REG_HIMR0, 0);
    W32(REG_HIMR1, 0);

    // _InitNetworkType (NT_LINK_AP = 2 at CR[17:16])
    W32(REG_CR, (rtl_r32(r, REG_CR) & ~0x30000u) | (2u << 16));

    // _InitWMACSetting: RCR set later by rtl_set_monitor; here only the multicast hash + filter map defaults
    W32(REG_MAR, 0xFFFFFFFF); W32(REG_MAR + 4, 0xFFFFFFFF);
    W16(REG_RXFLTMAP1, BIT(10));

    // _InitAdaptiveCtrl: RRSR (keep 1M), SIFS, retry limit
    {
        uint32_t v = rtl_r32(r, REG_RRSR);
        v &= ~0xFFFFFu;
        v |= 0xFFFF1;
        W32(REG_RRSR, v);
        W16(0x0428, 0x1010);                      // REG_SPEC_SIFS (overwritten by EDCA below, as in Linux)
        W16(REG_RETRY_LIMIT, (0x30 << 8) | 0x30); // RL_VAL_STA = 0x30
    }

    // _InitEDCA_8812AUsb
    W16(0x0428, 0x100A);
    W16(0x063A, 0x100A);
    W16(0x0514, 0x100A);
    W16(0x0516, 0x100A);
    W32(0x0508, 0x005EA42B);
    W32(0x050C, 0x0000A44F);
    W32(0x0504, 0x005EA324);
    W32(0x0500, 0x002FA226);
    W8(0x055C, 0x50);
    W8(0x0638, 0x50);

    // _InitRetryFunction
    W8(0x0420, rtl_r8(r, 0x0420) | BIT(7));       // EN_AMPDU_RTY_NEW
    W8(0x0640, 0x80);

    // init_UsbAggregationSetting: compiled out (no CONFIG_USB_RX_AGGREGATION): leave TRXDMA agg bits as set above.

    // _InitBeaconParameters_8812A
    W16(0x0550, 0x1010);                          // BCN_CTRL: DIS_TSF_UDT on both ports
    W8(0x0540, 0x04);                             // TBTT_PROHIBIT setup time
    W8(0x0541, 0x64);                             // hold time (0x64 = 100)
    W8(0x0542, (rtl_r8(r, 0x0542) & 0xF0) | 0x00);
    W8(0x0558, 0x05);                             // DRVERLYINT 5 ms
    W8(0x0559, 0x02);                             // BCNDMATIM 2 ms
    W16(0x0510, 0x4413);                          // BCNTCFG

    // _InitBurstPktLen (8821U: USB2 branch)
    W8(0xF050, 0x01);
    W16(0x0288, 0x7400);
    W8(0x0289, 0xF5);
    W8(0x0456, 0x5E);
    W32(0x0458, 0xFFFFFFFF);
    W8(0x055C, 0x50);
    W8(0x0638, 0x50);
    {
        uint8_t t = rtl_r8(r, 0xFE17);
        uint8_t pro = rtl_r8(r, REG_RXDMA_PRO);
        if (((t >> 4) & 3) == 0) W8(REG_RXDMA_PRO, (uint8_t)((pro | BIT(4) | BIT(3) | BIT(2) | BIT(1)) & ~BIT(5)));
        else                     W8(REG_RXDMA_PRO, (uint8_t)((pro | BIT(5) | BIT(3) | BIT(2) | BIT(1)) & ~BIT(4)));
    }
    W8(REG_TDECTRL, 0x10);
    W8(0x04C7, rtl_r8(r, 0x04C7) | 0x80);
    W8(0x060C, 0x18);
    W8(0x0512, 0x00);
    W16(0x04CA, 0x1F1F);
    W8(0x0420, 0x80);
    W32(0x0460, 0x03087777);
    W8(0x001C, rtl_r8(r, 0x001C) | BIT(5) | BIT(6));
    W32(0x0444, 0x00000010); W32(0x0448, 0xFFFFF000);
    W32(0x044C, 0x00000010); W32(0x0450, 0x003FF000);
    W32(0x048C, 0x00000015); W32(0x0490, 0x003FF000);
    W32(0x0494, 0x00000015); W32(0x0498, 0xFFCFF000);

    // Enable MAC TX/RX after the RX FIFO boundary is set
    W8(REG_CR, rtl_r8(r, REG_CR) | MACTXEN | MACRXEN);
    return e ? -1 : 0;
}

int rtl_set_monitor(rtl_t *r)
{
    int e = 0;
    // AAP | APM | AM | AB | ACRC32 (keep bad-FCS frames out: not set) | AMF | ACF | ADF | HTC_LOC_CTRL |
    // APP_ICV | APP_MIC | APP_PHYST_RXFF. ADD3, APWRMGT too so nothing is filtered by address/power bit.
    uint32_t rcr = BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(4) | BIT(5) | BIT(11) | BIT(12) | BIT(13) |
                   BIT(14) | BIT(29) | BIT(30) | BIT(28) | BIT(31);   // BIT(31) = APPFCS: keep the 4-byte FCS
    e |= rtl_w32(r, REG_RCR, rcr);
    e |= rtl_w16(r, REG_RXFLTMAP0, 0xFFFF);   // management
    e |= rtl_w16(r, REG_RXFLTMAP1, 0xFFFF);   // control
    e |= rtl_w16(r, REG_RXFLTMAP2, 0xFFFF);   // data
    e |= rtl_w32(r, REG_MAR, 0xFFFFFFFF);
    e |= rtl_w32(r, REG_MAR + 4, 0xFFFFFFFF);
    fprintf(stderr, "RCR readback 0x%08X, CR 0x%04X\n", rtl_r32(r, REG_RCR), rtl_r16(r, REG_CR));
    return e ? -1 : 0;
}

// Station state: our MAC (REG_MACID 0x610), BSSID (0x618), network type = station/infrastructure (CR[17:16] = 2).
// RCR is left as set by rtl_set_monitor (software filters), so the hardware still ACKs unicast frames to our MAC.
int rtl_set_sta_addr(rtl_t *r, const uint8_t mac[6], const uint8_t bssid[6])
{
    int e = 0;
    for (int i = 0; i < 6; i++) e |= rtl_w8(r, 0x0610 + i, mac[i]);
    for (int i = 0; i < 6; i++) e |= rtl_w8(r, 0x0618 + i, bssid ? bssid[i] : 0);
    e |= rtl_w32(r, REG_CR, (rtl_r32(r, REG_CR) & ~0x30000u) | (2u << 16));
    return e ? -1 : 0;
}
