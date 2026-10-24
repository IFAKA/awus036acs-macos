// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Card-enable power flow for RTL8821A (USB), then the post-power MAC bring-up that
// rtl8812au_hal_init / _InitPowerOn_8812AU does before firmware download.
#include "rtl.h"
#include <stdio.h>
#include <unistd.h>

#define BIT0 0x01
#define BIT1 0x02
#define BIT2 0x04
#define BIT3 0x08
#define BIT4 0x10
#define BIT5 0x20
#define BIT6 0x40
#define BIT7 0x80

// Masks used by the reference tables.
#define PWR_INTF_SDIO_MSK 0x01
#define PWR_INTF_USB_MSK  0x02
#define PWR_INTF_PCI_MSK  0x04
#define PWR_INTF_ALL_MSK  0x0F
#define PWR_FAB_ALL_MSK   0x0F
#define PWR_CUT_TESTCHIP_MSK 0x01
#define PWR_CUT_A_MSK     0x02
#define PWR_CUT_ALL_MSK   0xFF

enum { PWR_CMD_WRITE = 1, PWR_CMD_POLLING = 2, PWR_CMD_DELAY = 3, PWR_CMD_END = 4 };
enum { PWRSEQ_DELAY_US = 0, PWRSEQ_DELAY_MS = 1 };

// For DELAY: msk = amount, value = unit (as in the reference table).
struct pwr_cmd { uint16_t offset; uint8_t cut, fab, intf, cmd, msk, value; };

#include "pwrseq8821a.h"     // generated: pwr_carddis_to_cardemu[], pwr_cardemu_to_act[]

// Run one table. Same semantics as HalPwrSeqCmdParsing: a command runs only if
// its fab, cut and interface masks all match.
static int run_seq(rtl_t *r, const struct pwr_cmd *t, int n, uint8_t cut_msk, const char *name) {
    for (int i = 0; i < n; i++) {
        const struct pwr_cmd *c = &t[i];
        if (!(c->fab & PWR_FAB_ALL_MSK) || !(c->cut & cut_msk) || !(c->intf & PWR_INTF_USB_MSK))
            continue;
        switch (c->cmd) {
        case PWR_CMD_WRITE: {                  // read-modify-write of one byte
            uint8_t v = rtl_r8(r, c->offset);
            v = (v & ~c->msk) | (c->value & c->msk);
            rtl_w8(r, c->offset, v);
            break;
        }
        case PWR_CMD_POLLING: {                // wait until (reg & msk) == (value & msk)
            int cnt = 0;
            for (;;) {
                uint8_t v = rtl_r8(r, c->offset) & c->msk;
                if (v == (c->value & c->msk)) break;
                if (cnt++ > 5000) {
                    fprintf(stderr, "power seq %s: poll 0x%04x timeout\n", name, c->offset);
                    return -1;
                }
                usleep(10);
            }
            break;
        }
        case PWR_CMD_DELAY:
            if (c->value == PWRSEQ_DELAY_US) usleep(c->msk); else usleep(c->msk * 1000);
            break;
        default: break;
        }
    }
    return 0;
}
#define RUN(t, cut) run_seq(r, t, sizeof(t) / sizeof((t)[0]), cut, #t)

// Reference LLT (TX packet buffer linked list) init, needed before firmware download.
#define REG_LLT_INIT 0x01E0
static int llt_write(rtl_t *r, uint8_t addr, uint8_t data) {
    rtl_w32(r, REG_LLT_INIT, ((uint32_t)addr << 8) | data | (1u << 30));   // op = write
    for (int i = 0; i <= 20; i++) {
        if (((rtl_r32(r, REG_LLT_INIT) >> 30) & 3) == 0) return 0;          // op finished
    }
    return -1;
}
static int llt_init(rtl_t *r, uint8_t bndy) {
    for (int i = 0; i < bndy - 1; i++) if (llt_write(r, i, i + 1)) return -1;
    if (llt_write(r, bndy - 1, 0xFF)) return -1;                            // end of list
    for (int i = bndy; i < 255; i++) if (llt_write(r, i, i + 1)) return -1; // ring for the rest
    return llt_write(r, 255, bndy);
}

// Same as rtl8812au_hw_reset: only needed if firmware from an earlier run is still alive.
static void hw_reset(rtl_t *r) {
    if (!(rtl_r8(r, 0x0080) & BIT7)) return;       // MCUFWDL bit7 = 8051 running RAM code
    fprintf(stderr, "firmware still running from a previous run: resetting chip first\n");
    // 8051 reset (8821): see rtl_fw.c _8051Reset; inline copy
    rtl_w8(r, 0x001C, rtl_r8(r, 0x001C) & ~BIT1);
    rtl_w8(r, 0x001D, rtl_r8(r, 0x001D) & ~BIT0);
    uint8_t t = rtl_r8(r, 0x0003);
    rtl_w8(r, 0x0003, t & ~BIT2);
    rtl_w8(r, 0x001C, rtl_r8(r, 0x001C) & ~BIT1);
    rtl_w8(r, 0x001D, rtl_r8(r, 0x001D) | BIT0);
    rtl_w8(r, 0x0003, t | BIT2);
    rtl_w8(r, 0x0080, 0x00);
    rtl_w32(r, 0x08B4, rtl_r32(r, 0x08B4) | BIT6);        // clock-gate BB before BB reset
    rtl_w8(r, 0x0002, rtl_r8(r, 0x0002) & ~(BIT0 | BIT1)); // reset BB
    rtl_w8(r, 0x001F, 0);                                  // reset RF
    rtl_w16(r, 0x0100, 0);                                 // reset TRX path
    uint8_t v = rtl_r8(r, 0x0005) | BIT1;                  // APS_FSMCO[9]: auto FSM off
    rtl_w8(r, 0x0005, v);
    for (int i = 0; i < 1000 && (rtl_r8(r, 0x0005) & BIT1); i++) usleep(10);
    v = rtl_r8(r, 0x0005) | BIT0;
    rtl_w8(r, 0x0005, v);
    v = rtl_r8(r, 0x0003) & ~(BIT4 | BIT7);
    rtl_w8(r, 0x0003, v);
    rtl_w8(r, 0x0003, v | BIT4 | BIT7);
}

int rtl_power_on(rtl_t *r) {
    // Chip version: REG_SYS_CFG 0xF0.
    uint32_t cfg = rtl_r32(r, 0x00F0);
    int test_chip = (cfg & (1u << 23)) != 0;            // RTL_ID: 1 = test chip, 0 = MP
    r->cut = (cfg >> 12) & 0xF;                         // CHIP_VER_RTL (8821: no +1 as for 8812)
    int vendor = (cfg >> 18) & 3;                       // 0 TSMC, 1 SMIC, 2 UMC
    fprintf(stderr, "SYS_CFG=0x%08X: %s, cut=%d (%c), vendor=%s, rf_type_id=%d\n", cfg,
            test_chip ? "TEST chip" : "MP chip", r->cut, 'A' + r->cut,
            vendor == 0 ? "TSMC" : vendor == 1 ? "SMIC" : "UMC", (cfg >> 27) & 1);
    if ((cfg & 0xFF) == 0xFF && cfg == 0xFFFFFFFF) { fprintf(stderr, "chip not answering\n"); return -1; }
    fprintf(stderr, "decoded: RTL8821A (1T1R, USB) %s\n", test_chip ? "test chip" : "normal chip");

    hw_reset(r);

    // 8821A MP chip uses PWR_CUT_A_MSK, test chip uses PWR_CUT_TESTCHIP_MSK.
    uint8_t cutmsk = test_chip ? PWR_CUT_TESTCHIP_MSK : PWR_CUT_A_MSK;
    // card enable flow = CARDDIS->CARDEMU, then CARDEMU->ACT
    if (RUN(pwr_carddis_to_cardemu, cutmsk)) return -2;
    if (RUN(pwr_cardemu_to_act, cutmsk)) return -3;

    // Enable MAC DMA/WMAC/SCHEDULE/SEC blocks (REG_CR 0x100): HCI_TXDMA|HCI_RXDMA|TXDMA|RXDMA|
    // PROTOCOL|SCHEDULE|ENSEC|CALTMR (32k calibration timer).
    rtl_w16(r, 0x0100, 0x0000);
    uint16_t cr = rtl_r16(r, 0x0100);
    cr |= 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0200 | 0x0400;
    rtl_w16(r, 0x0100, cr);
    fprintf(stderr, "REG_CR now 0x%04X\n", rtl_r16(r, 0x0100));

    // TX page boundary for 8821: 0xFF - (512/256 + 6) + 1 = 248
    if (llt_init(r, 248)) { fprintf(stderr, "LLT init failed\n"); return -4; }
    return 0;
}
