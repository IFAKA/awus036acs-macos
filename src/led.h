// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// led: the adapter's activity LED, ported from ref-rtl8812au/hal/rtl8812a/usb/rtl8812au_led.c (SwLedOn_8821AU /
// SwLedOff_8821AU, the non-minicard branch for an 8821U) and the default blink mode (SW_LED_MODE9, hal_usb_led.c):
//   not linked: slow blink; scanning / joining: fast blink; linked: solid on (a short dip on traffic); radio off: off.
// Register recipe (8821U): LEDCFG2 (0x4E) keep bits 7:6; GPIO_PIN_CTRL_2 (0x60): bit16 = 1 and bit24 = 0 (software
// control of the pin), bit8 = 0 -> LED on, bit8 = 1 -> LED off. The decision function is pure and unit-tested.
#ifndef LED_H
#define LED_H
#include <stdint.h>
#include "rtl.h"

typedef enum { LED_OFF, LED_SOLID, LED_SLOW, LED_FAST } led_mode_t;

#define LED_SLOW_HALF_MS 500    // not linked: 500 ms on, 500 ms off
#define LED_FAST_HALF_MS 100    // scanning / joining: 100 ms on, 100 ms off
#define LED_DIP_MS       60     // linked: LED goes dark this long when traffic is seen
#define LED_DIP_MIN_GAP  400    // ... at most this often

typedef struct {
    led_mode_t mode;
    int on;                     // what we last wrote to the chip (-1 = nothing written yet)
    long dip_until, last_dip;   // ms, monotonic
    long phase0;                // start of the current blink pattern
} led_t;

void led_init(led_t *l);
void led_set_mode(led_t *l, led_mode_t m, long now_ms);
// Traffic seen (linked mode only): schedule one short dip.
void led_activity(led_t *l, long now_ms);
// Pure: should the LED be lit at now_ms?
int  led_want(const led_t *l, long now_ms);
// Write the pin if the wanted state changed. Returns 0 (or -1 on a USB error).
int  led_tick(led_t *l, rtl_t *r, long now_ms);
// Register-level on/off (ported). Exposed for the one-shot "led on|off" debug command.
int  led_write(rtl_t *r, int on);
// Read back: LEDCFG2 (0x4E), GPIO_PIN_CTRL_2 (0x60), and decode "pin is driven on".
void led_readback(rtl_t *r, uint8_t *ledcfg2, uint32_t *gpio, int *lit);
#endif
