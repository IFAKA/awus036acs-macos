// RTL8821AU MAC / BB / RF / AGC bring-up and channel switching.
// Ported from the Linux rtl8812au driver (reference only):
//   rtl8812au_hal_init (hal/rtl8812a/usb/usb_halinit.c), PHY_MACConfig8812 / PHY_BBConfig8812 / PHY_RFConfig8812 /
//   phy_SwChnl8812 / phy_PostSetBwMode8812 / PHY_SwitchWirelessBand8812 (hal/rtl8812a/rtl8812a_phycfg.c),
//   check_positive + odm_read_and_config_mp_8821a_* (hal/phydm/rtl8821a/halhwimg8821a_*.c).
//
// ASSUMPTIONS (what the Linux driver computes for this adapter; change here if a real-device test says otherwise):
//  * IC = RTL8821A, interface = USB (ODM_ITRF_USB = 0x2), platform = ODM_CE (0x4).
//  * Cut version = r->cut (A=0, B=1, ...), passed straight to the condition check like dm->cut_version.
//    The 8821A tables contain NO cut conditions, so every cut gets the same writes (only the interface/board
//    conditions select anything). Cut still goes through the check so a future table regeneration is right.
//  * board_type = ODM_BOARD_DEFAULT (0): no ext PA/LNA (2G or 5G), no BT-coex bit. package_type = 0.
//    type_glna/gpa/alna/apa = 0. With these the tables resolve to the USB / no-BT / no-ext-PA-LNA branches.
//  * IS_VENDOR_8821A_MP_CHIP = true (normal chip), so the AGC table select is 0xC1C[11:8] (not 0x82C[1:0]).
//  * rf_type = 1T1R, NumTotalRFPath = 1 (path A only). rfe_type handling for 8821 is the phy_SetRFEReg8821 path.
//  * No efuse read yet: crystal cap = 0x20 (Linux default), BB swing = 0 dB (0x200), TX power = fixed index.
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "rtl.h"
#include "phy.h"
#include "tables.h"
#include "mac.h"

// ---- ODM constants used by check_positive ----
#define ODM_PLATFORM_CE    0x04
#define ODM_ITRF_USB       0x02
#define ODM_BOARD_TYPE     0x00   // DEFAULT, see assumptions
#define ODM_PACKAGE_TYPE   0x00
#define COND_ELSE          2
#define COND_ENDIF         3

#define BIT(n) (1u << (n))

// ---------------------------------------------------------------- condition interpreter
static int check_positive(uint8_t cut, uint32_t cond1, uint32_t cond2, uint32_t cond3, uint32_t cond4)
{
    (void)cond3;
    uint32_t board = ODM_BOARD_TYPE;
    uint8_t _board_type = (uint8_t)(((board & BIT(4)) >> 4) << 0 | ((board & BIT(3)) >> 3) << 1 |
                                    ((board & BIT(7)) >> 7) << 2 | ((board & BIT(6)) >> 6) << 3 |
                                    ((board & BIT(2)) >> 2) << 4);
    uint32_t driver1 = (uint32_t)cut << 24 | (ODM_ITRF_USB & 0xF0u) << 16 | (uint32_t)ODM_PLATFORM_CE << 16 |
                       (uint32_t)ODM_PACKAGE_TYPE << 12 | (ODM_ITRF_USB & 0x0Fu) << 8 | _board_type;
    uint32_t driver2 = 0, driver4 = 0;   // type_glna/gpa/alna/apa all 0

    // value-defined fields: package [15:12], cut [27:24]
    if ((cond1 & 0x0000F000) != 0 && (cond1 & 0x0000F000) != (driver1 & 0x0000F000)) return 0;
    if ((cond1 & 0x0F000000) != 0 && (cond1 & 0x0F000000) != (driver1 & 0x0F000000)) return 0;

    cond1 &= 0x00FF0FFF;
    driver1 &= 0x00FF0FFF;
    if ((cond1 & driver1) != cond1) return 0;

    uint32_t bit_mask = 0;
    if ((cond1 & 0x0F) == 0) return 1;           // board type is DONTCARE
    if (cond1 & BIT(0)) bit_mask |= 0x000000FF;  // GLNA
    if (cond1 & BIT(1)) bit_mask |= 0x0000FF00;  // GPA
    if (cond1 & BIT(2)) bit_mask |= 0x00FF0000;  // ALNA
    if (cond1 & BIT(3)) bit_mask |= 0xFF000000;  // APA
    return ((cond2 & bit_mask) == (driver2 & bit_mask)) && ((cond4 & bit_mask) == (driver4 & bit_mask));
}

long rtl_cfg_walk(const uint32_t *tab, size_t nwords, uint8_t cut, rtl_cfg_emit emit, void *ctx, long *n_markers)
{
    int is_matched = 1, is_skipped = 0;
    uint32_t pre_v1 = 0, pre_v2 = 0;
    long emitted = 0, markers = 0;
    for (size_t i = 0; i + 1 < nwords; i += 2) {
        uint32_t v1 = tab[i], v2 = tab[i + 1];
        if (v1 & (BIT(31) | BIT(30))) {
            markers++;
            if (v1 & BIT(31)) {                       // positive condition
                uint8_t c = (uint8_t)((v1 & (BIT(29) | BIT(28))) >> 28);
                if (c == COND_ENDIF) { is_matched = 1; is_skipped = 0; }
                else if (c == COND_ELSE) { is_matched = is_skipped ? 0 : 1; }
                else { pre_v1 = v1; pre_v2 = v2; }    // IF / ELSE IF: remember, decided by the 0x4... line
            } else {                                  // negative condition (bit30): evaluate the remembered IF
                if (!is_skipped) {
                    if (check_positive(cut, pre_v1, pre_v2, v1, v2)) { is_matched = 1; is_skipped = 1; }
                    else { is_matched = 0; is_skipped = 0; }
                } else is_matched = 0;
            }
        } else if (is_matched) {
            if (emit) { int e = emit(ctx, v1, v2); if (e < 0) return e; }
            emitted++;
        }
    }
    if (n_markers) *n_markers = markers;
    return emitted;
}

const uint32_t *rtl_phy_pg(size_t *n_entries)
{
    if (n_entries) *n_entries = rtl_tab_bb_pg_len / 6;
    return rtl_tab_bb_pg;
}

// ---------------------------------------------------------------- BB / RF register access
static unsigned shift_of(uint32_t mask) { unsigned s = 0; while (mask && !(mask & 1)) { mask >>= 1; s++; } return s; }

uint32_t rtl_bb_r32(rtl_t *r, uint16_t addr, uint32_t mask)
{
    return (rtl_r32(r, addr) & mask) >> shift_of(mask);
}

int rtl_bb_w32(rtl_t *r, uint16_t addr, uint32_t mask, uint32_t val)
{
    if (mask != 0xFFFFFFFFu) {
        uint32_t orig = rtl_r32(r, addr);
        val = (orig & ~mask) | ((val << shift_of(mask)) & mask);
    }
    return rtl_w32(r, addr, val);
}

#define R_LSSI_WRITE_A   0xC90   // rA_LSSIWrite_Jaguar: [27:20] rf addr, [19:0] data
#define R_HSSI_READ      0x8B0   // rHSSIRead_Jaguar: [7:0] rf addr to read
#define R_PI_READ_A      0xD04
#define R_SI_READ_A      0xD08
#define R_A_PIMODE       0xC00   // bit 2: path A uses PI mode

uint32_t rtl_rf_r(rtl_t *r, int path, uint8_t reg, uint32_t mask)
{
    if (path != 0) return 0xFFFFFFFFu;
    int pi = (rtl_r32(r, R_A_PIMODE) & 0x4) != 0;
    rtl_bb_w32(r, R_HSSI_READ, 0xFF, reg);
    usleep(20);                                   // 8821: wait before readback (phy_RFSerialRead)
    uint32_t v = rtl_bb_r32(r, pi ? R_PI_READ_A : R_SI_READ_A, 0xFFFFF);
    return (v & mask) >> shift_of(mask);
}

int rtl_rf_w(rtl_t *r, int path, uint8_t reg, uint32_t mask, uint32_t val)
{
    if (path != 0 || mask == 0) return -1;
    mask &= 0xFFFFF;
    uint32_t data;
    if (mask != 0xFFFFF) {
        uint32_t orig = rtl_rf_r(r, path, reg, 0xFFFFF);
        data = (orig & ~mask) | ((val << shift_of(mask)) & mask);
    } else data = val;
    return rtl_w32(r, R_LSSI_WRITE_A, (((uint32_t)reg << 20) | (data & 0xFFFFF)) & 0x0FFFFFFF);
}

// ---------------------------------------------------------------- table writers
static void table_delay(uint32_t a)
{
    switch (a) {
    case 0xFE: case 0xFFE: usleep(50000); break;
    case 0xFD: usleep(5000); break;
    case 0xFC: usleep(1000); break;
    case 0xFB: usleep(50); break;
    case 0xFA: usleep(5); break;
    case 0xF9: usleep(1); break;
    }
}
static int is_delay(uint32_t a) { return a == 0xFE || a == 0xFFE || (a >= 0xF9 && a <= 0xFD); }

static int emit_mac(void *c, uint32_t a, uint32_t d)   // odm_config_mac_8821a: 1-byte write
{ return rtl_w8((rtl_t *)c, (uint16_t)a, (uint8_t)d); }

static int emit_bb(void *c, uint32_t a, uint32_t d)    // odm_config_bb_phy_8821a / _agc_8821a: dword write
{
    if (is_delay(a)) { table_delay(a); return 0; }
    return rtl_w32((rtl_t *)c, (uint16_t)a, d);
}

static int emit_rf_a(void *c, uint32_t a, uint32_t d)  // odm_config_rf_radio_a_8821a -> odm_set_rf_reg(mask 0xFFFFF)
{
    if (is_delay(a)) { table_delay(a); return 0; }
    return rtl_rf_w((rtl_t *)c, 0, (uint8_t)a, 0xFFFFF, d);
}

// ---------------------------------------------------------------- registers used below
#define REG_SYS_FUNC_EN   0x0002
#define REG_RF_CTRL       0x001F
#define REG_MAC_PHY_CTRL  0x002C
#define REG_CR            0x0100
#define REG_RXDMA_PRO     0x0290
#define REG_CCK_CHECK     0x0454
#define REG_TXPKT_EMPTY   0x041A
#define REG_RRSR          0x0440
#define REG_DATA_SC       0x0483
#define REG_WMAC_TRXPTCL  0x0668
#define FEN_BBRSTB        BIT(0)
#define FEN_BB_GLB_RSTN   BIT(1)
#define FEN_USBA          BIT(2)
#define MACTXEN           BIT(6)
#define MACRXEN           BIT(7)

#define RR_RF_CHNLBW      0x18   // RF_CHNLBW_Jaguar
#define BB_OFDMCCKEN      0x808
#define BB_TXPATH         0x80C
#define BB_CCK_RX         0xA04
#define BB_AGC_TXSCALE_A  0xC1C  // also holds the 8821A MP AGC table select in [11:8] and BB swing in [31:21]
#define BB_RFE_PINMUX_A   0xCB0
#define BB_RFE_INV_A      0xCB4

// ---------------------------------------------------------------- PHY_MACConfig8812 + misc MAC init
static int mac_config(rtl_t *r)
{
    long n = rtl_cfg_walk(rtl_tab_mac, rtl_tab_mac_len, r->cut, emit_mac, r, NULL);
    return n < 0 ? -1 : 0;
}

// Tail of rtl8812au_hal_init after the channel switch (MISC11 / MISC21 / MISC31).
static int mac_tail(rtl_t *r)
{
    int e = 0;
    e |= rtl_w8(r, 0x0423, 0xFF);                      // REG_HWSEQ_CTRL: hardware sequence numbers
    e |= rtl_w32(r, 0x04CC, 0x0201FFFF);               // REG_BAR_MODE_CTRL: disable BAR
    e |= rtl_w8(r, 0x0652, 0x00);                      // NAV limit
    e |= rtl_w8(r, 0x04C6, (uint8_t)(rtl_r8(r, 0x04C6) & 0xF7));  // RTS BW depends on CCA
    e |= rtl_w8(r, 0x0421, 0x0F);                      // REG_FWHW_TXQ_CTRL+1: enable Tx report
    e |= rtl_w16(r, 0x04F0, 0x3DF0);                   // REG_TX_RPT_TIME
    e |= rtl_w8(r, 0xFE58, 0x00);                      // REG_USB_HRPWM
    return e ? -1 : 0;
}

// ---------------------------------------------------------------- PHY_BBConfig8812 / PHY_RFConfig8812
int rtl_set_crystal_cap(rtl_t *r, uint8_t cap)
{
    cap &= 0x3F;   // hal_set_crystal_cap, RTL8821: 0x2C[23:12] = cap | cap << 6
    return rtl_bb_w32(r, REG_MAC_PHY_CTRL, 0x00FFF000, (uint32_t)cap | ((uint32_t)cap << 6));
}

static int bb_config(rtl_t *r)
{
    int e = 0;
    uint8_t f = rtl_r8(r, REG_SYS_FUNC_EN);
    f |= FEN_USBA;
    e |= rtl_w8(r, REG_SYS_FUNC_EN, f);
    e |= rtl_w8(r, REG_SYS_FUNC_EN, f | FEN_BB_GLB_RSTN | FEN_BBRSTB);
    e |= rtl_w8(r, REG_RF_CTRL, 0x07);                 // path A RF power on
    e |= rtl_w8(r, 0x0076, 0x07);                      // REG_OPT_CTRL_8812 + 2: path B RF power on (Linux does it for 8821 too)
    if (e) return -1;
    if (rtl_cfg_walk(rtl_tab_bb, rtl_tab_bb_len, r->cut, emit_bb, r, NULL) < 0) return -1;
    if (rtl_cfg_walk(rtl_tab_agc, rtl_tab_agc_len, r->cut, emit_bb, r, NULL) < 0) return -1;
    return rtl_set_crystal_cap(r, 0x20);
}

static int rf_config(rtl_t *r)
{
    return rtl_cfg_walk(rtl_tab_rf_a, rtl_tab_rf_a_len, r->cut, emit_rf_a, r, NULL) < 0 ? -1 : 0;
}

// ---------------------------------------------------------------- TX power
int rtl_set_tx_power(rtl_t *r, uint8_t idx)
{
    // Path A per-rate TX AGC registers (rTxAGC_A_*_JAguar). One index byte replicated into all four rates of each.
    static const uint16_t regs[] = {0xC20, 0xC24, 0xC28, 0xC2C, 0xC30, 0xC34, 0xC38, 0xC3C, 0xC40, 0xC44};
    uint32_t v = (uint32_t)(idx & 0x3F) * 0x01010101u;
    int e = 0;
    for (size_t i = 0; i < sizeof regs / sizeof regs[0]; i++) e |= rtl_w32(r, regs[i], v);
    return e ? -1 : 0;
}

// ---------------------------------------------------------------- band / channel / bandwidth
static int rfe_8821(rtl_t *r, int is_5g)    // phy_SetRFEReg8821 with ExternalLNA_2G = 0
{
    int e = 0;
    if (!is_5g) {
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0xF000, 0x7);
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0xF0, 0x7);
        e |= rtl_bb_w32(r, BB_RFE_INV_A, BIT(20), 0);
        e |= rtl_bb_w32(r, BB_RFE_INV_A, BIT(22), 0);
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0x7, 0x7);
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0x700, 0x7);
    } else {
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0xF000, 0x5);
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0xF0, 0x4);
        e |= rtl_bb_w32(r, BB_RFE_INV_A, BIT(20), 0);
        e |= rtl_bb_w32(r, BB_RFE_INV_A, BIT(22), 0);
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0x7, 0x7);
        e |= rtl_bb_w32(r, BB_RFE_PINMUX_A, 0x700, 0x7);
    }
    return e;
}

// PHY_SwitchWirelessBand8812 for 8821A (path A, no external antenna switch, 1T1R)
static int switch_band(rtl_t *r, int is_5g)
{
    int e = 0;
    if (!is_5g) {
        e |= rtl_bb_w32(r, BB_OFDMCCKEN, 0x30000000, 0x3);      // OFDM + CCK enable
        e |= rfe_8821(r, 0);
        e |= rtl_bb_w32(r, BB_AGC_TXSCALE_A, 0xF00, 0);         // AGC table select (8821A MP chip)
        e |= rtl_bb_w32(r, BB_TXPATH, 0xF0, 0x1);               // workaround: CCK false alarm in scan
        e |= rtl_bb_w32(r, BB_CCK_RX, 0x0F000000, 0x1);
        e |= rtl_w16(r, REG_RRSR, 0x015F);                      // basic rates 1,2,5.5,11,6,12,24 (update_tx_basic_rate 11BG)
        e |= rtl_w8(r, REG_RRSR + 2, (uint8_t)(rtl_r8(r, REG_RRSR + 2) & 0xF0));
        e |= rtl_w8(r, REG_CCK_CHECK, (uint8_t)(rtl_r8(r, REG_CCK_CHECK) & ~BIT(7)));
    } else {
        e |= rfe_8821(r, 1);
        e |= rtl_w8(r, REG_CCK_CHECK, (uint8_t)(rtl_r8(r, REG_CCK_CHECK) | BIT(7)));
        for (int n = 0; n < 50; n++) {                          // wait for TX packet buffers to drain (reg 0x41A bits 5:4)
            if ((rtl_r16(r, REG_TXPKT_EMPTY) & 0x30) == 0x30) break;
            usleep(50);
        }
        e |= rtl_bb_w32(r, BB_OFDMCCKEN, 0x30000000, 0x3);
        e |= rtl_bb_w32(r, BB_AGC_TXSCALE_A, 0xF00, 1);
        e |= rtl_bb_w32(r, BB_TXPATH, 0xF0, 0x0);
        e |= rtl_bb_w32(r, BB_CCK_RX, 0x0F000000, 0xF);
        e |= rtl_w16(r, REG_RRSR, 0x0150);                      // basic rates 6,12,24 (11A: no CCK in 5G)
        e |= rtl_w8(r, REG_RRSR + 2, (uint8_t)(rtl_r8(r, REG_RRSR + 2) & 0xF0));
    }
    // phy_SetBBSwingByBand_8812A: 0xC1C[31:21] = 0x200 (0 dB, efuse swing byte assumed 0)
    e |= rtl_bb_w32(r, BB_AGC_TXSCALE_A, 0xFFE00000, 0x200);
    return e ? -1 : 0;
}

static int channel_valid(int ch)
{
    return (ch >= 1 && ch <= 14) || (ch >= 36 && ch <= 165);
}

// phy_SwChnl8812 (+ phy_SwBand8812) for 8821A path A, then phy_PostSetBwMode8812 for 20 MHz
int rtl_set_channel(rtl_t *r, int channel, int bw20_only)
{
    if (!channel_valid(channel) || !bw20_only) return -1;
    int e = 0;

    // phy_SwBand8812: switch band only if it differs from what 0x454[7] says
    int cur_5g = (rtl_r8(r, REG_CCK_CHECK) & BIT(7)) != 0;
    int want_5g = channel > 14;
    if (cur_5g != want_5g && switch_band(r, want_5g) < 0) return -1;

    // fc_area
    uint32_t fc;
    if (channel >= 36 && channel <= 48) fc = 0x494;
    else if (channel >= 15 && channel <= 35) fc = 0x494;
    else if (channel >= 50 && channel <= 80) fc = 0x453;
    else if (channel >= 82 && channel <= 116) fc = 0x452;
    else if (channel >= 118) fc = 0x412;
    else fc = 0x96A;
    e |= rtl_bb_w32(r, 0x860, 0x1FFE0000, fc);

    // RF_MOD_AG: RF 0x18 bits 18:16 and 9:8
    uint32_t ag;
    if (channel >= 36 && channel <= 80) ag = 0x101;
    else if (channel >= 15 && channel <= 35) ag = 0x101;
    else if (channel >= 82 && channel <= 140) ag = 0x301;
    else if (channel > 140) ag = 0x501;
    else ag = 0x000;
    e |= rtl_rf_w(r, 0, RR_RF_CHNLBW, BIT(18) | BIT(17) | BIT(16) | BIT(9) | BIT(8), ag);
    e |= rtl_rf_w(r, 0, RR_RF_CHNLBW, 0xFF, (uint32_t)channel);
    // (phy_FixSpur_8812A and the APK writes are 8812A / 8821 test-chip only: not applied)

    // phy_PostSetBwMode8812, CHANNEL_WIDTH_20
    uint16_t trx = rtl_r16(r, REG_WMAC_TRXPTCL);
    e |= rtl_w16(r, REG_WMAC_TRXPTCL, trx & 0xFE7F);            // BW bits 8:7 = 0 -> 20 MHz
    e |= rtl_w8(r, REG_DATA_SC, 0);                             // no secondary channel
    e |= rtl_bb_w32(r, 0x8AC, 0x003003C3, 0x00300200);          // RFMOD: 20 MHz
    e |= rtl_bb_w32(r, 0x8C4, BIT(30), 0);
    e |= rtl_bb_w32(r, 0x848, 0x03C00000, 8);                   // L1 peak threshold, 1R
    e |= rtl_rf_w(r, 0, RR_RF_CHNLBW, BIT(11) | BIT(10), 3);    // RF bandwidth = 20 MHz

    // PHY_SetTxPowerLevel8812 replaced by a fixed index for now
    e |= rtl_set_tx_power(r, RTL_TXPWR_DEFAULT);
    if (!e) r->channel = channel;
    return e ? -1 : 0;
}

// ---------------------------------------------------------------- entry point
int rtl_init_phy(rtl_t *r)
{
    if (mac_config(r) < 0) return -1;      // PHY_MACConfig8812
    if (rtl_init_mac(r) < 0) return -2;    // src/mac.c: MISC01/02 (queues, boundaries, EDCA, burst len, CR enable)
    if (bb_config(r) < 0) return -3;       // PHY_BBConfig8812 (BB + AGC tables, crystal cap)
    if (rf_config(r) < 0) return -4;       // PHY_RFConfig8812 (radio A table)
    if (switch_band(r, 0) < 0) return -5;  // PHY_SwitchWirelessBand8812(2.4G), as Linux does for registry channel 1
    if (rtl_set_channel(r, 1, 1) < 0) return -6;
    if (mac_tail(r) < 0) return -7;
    return 0;
}
