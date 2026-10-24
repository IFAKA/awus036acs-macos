// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include "led.h"

#define REG_LEDCFG2        0x004E
#define REG_GPIO_PIN_CTRL2 0x0060
#define BIT8  (1u << 8)
#define BIT16 (1u << 16)
#define BIT24 (1u << 24)

int led_write(rtl_t *r, int on)
{
    // SwLedOn_8821AU / SwLedOff_8821AU, 8821U branch.
    uint8_t cfg = rtl_r8(r, REG_LEDCFG2) & 0xC0;                 // keep 0x4C[23:22]
    uint32_t g = rtl_r32(r, REG_GPIO_PIN_CTRL2);
    int e = rtl_w8(r, REG_LEDCFG2, cfg);                         // 0x4C[21] = 0
    if (on) g = (g | BIT16) & ~BIT8 & ~BIT24;
    else    g = (g | BIT16 | BIT8) & ~BIT24;
    e |= rtl_w32(r, REG_GPIO_PIN_CTRL2, g);
    return e ? -1 : 0;
}

void led_readback(rtl_t *r, uint8_t *ledcfg2, uint32_t *gpio, int *lit)
{
    uint8_t c = rtl_r8(r, REG_LEDCFG2);
    uint32_t g = rtl_r32(r, REG_GPIO_PIN_CTRL2);
    if (ledcfg2) *ledcfg2 = c;
    if (gpio) *gpio = g;
    if (lit) *lit = (g & BIT16) && !(g & BIT24) && !(g & BIT8);
}

void led_init(led_t *l) { l->mode = LED_OFF; l->on = -1; l->dip_until = l->last_dip = 0; l->phase0 = 0; }

void led_set_mode(led_t *l, led_mode_t m, long now)
{
    if (l->mode == m) return;
    l->mode = m;
    l->phase0 = now;
    l->dip_until = 0;
}

void led_activity(led_t *l, long now)
{
    if (l->mode != LED_SOLID || now - l->last_dip < LED_DIP_MIN_GAP) return;
    l->last_dip = now;
    l->dip_until = now + LED_DIP_MS;
}

int led_want(const led_t *l, long now)
{
    switch (l->mode) {
    case LED_OFF: return 0;
    case LED_SOLID: return now >= l->dip_until;
    case LED_SLOW: return ((now - l->phase0) / LED_SLOW_HALF_MS) % 2 == 0;
    case LED_FAST: return ((now - l->phase0) / LED_FAST_HALF_MS) % 2 == 0;
    }
    return 0;
}

int led_tick(led_t *l, rtl_t *r, long now)
{
    int w = led_want(l, now);
    if (w == l->on) return 0;
    if (led_write(r, w)) return -1;
    l->on = w;
    return 0;
}
