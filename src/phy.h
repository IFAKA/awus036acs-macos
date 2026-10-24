// MAC / baseband / RF helpers for the RTL8821AU (0bda:0811). Declared here (not rtl.h) so any stage can use them.
// Everything is path A only (8821A is 1T1R). Ported from the Linux rtl8812au driver (read-only reference).
#ifndef PHY_H
#define PHY_H
#include <stdint.h>
#include <stddef.h>
#include "rtl.h"

// Baseband register (PHY_SetBBReg8812 / PHY_QueryBBReg8812). mask 0xFFFFFFFF = plain 32-bit write/read.
// Otherwise read-modify-write of only the masked bits; val is the field value (not pre-shifted).
int      rtl_bb_w32(rtl_t *r, uint16_t addr, uint32_t mask, uint32_t val);
uint32_t rtl_bb_r32(rtl_t *r, uint16_t addr, uint32_t mask);

// RF register over the baseband serial interface (HSSI). path 0 = A (only path on 8821A).
// rf registers are 20 bits wide: mask 0xFFFFF = plain write.
int      rtl_rf_w(rtl_t *r, int path, uint8_t reg, uint32_t mask, uint32_t val);
uint32_t rtl_rf_r(rtl_t *r, int path, uint8_t reg, uint32_t mask);

// Tune the radio. channel 1-14 (2.4 GHz) or 36-165 (5 GHz). bw20_only must be 1 for now (40/80 MHz not built yet).
// Also switches band when the channel is in another band, and re-applies the TX power index.
// 0 = ok, <0 = error.
int rtl_set_channel(rtl_t *r, int channel, int bw20_only);

// Crystal capacitor trim, 6 bits (Linux default 0x20 when efuse is empty). Writes 0x2C[23:12].
int rtl_set_crystal_cap(rtl_t *r, uint8_t cap);

// Write one TX power index (0..63, 0.5 dB steps) to every rate of path A. rtl_init_phy uses RTL_TXPWR_DEFAULT.
#define RTL_TXPWR_DEFAULT 0x20
int rtl_set_tx_power(rtl_t *r, uint8_t idx);

// ---- table interpreter (exposed for the unit test) ----
// Walk a generated if/else-if/else/endif table (pairs of uint32). Calls emit(ctx, addr, data) for every entry that
// is active for: RTL8821A, USB, cut = `cut`, no ext PA/LNA, no BT, package 0. emit returns 0 or <0 to stop.
// Returns the number of emitted entries, or <0 if emit failed. *n_markers (optional) = number of cond words pairs.
typedef int (*rtl_cfg_emit)(void *ctx, uint32_t addr, uint32_t data);
long rtl_cfg_walk(const uint32_t *tab, size_t nwords, uint8_t cut, rtl_cfg_emit emit, void *ctx, long *n_markers);

// Power-by-rate table (phy_reg_pg): Linux only stores it in RAM to compute per-rate TX power; same here.
// Entries of 6 words: band(0=2.4G,1=5G), path, txnum, regaddr, mask, value.
const uint32_t *rtl_phy_pg(size_t *n_entries);

#endif
