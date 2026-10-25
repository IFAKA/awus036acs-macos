// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// Step 1: open the RTL8811AU via libusb, dump endpoints, read a few chip registers.
#include <libusb.h>
#include <stdio.h>
#include <stdint.h>
#include "modeswitch.h"

static libusb_device_handle *h;

static int rd(uint16_t addr, uint8_t *buf, uint16_t len) {
    return libusb_control_transfer(h, 0xC0, 0x05, addr, 0, buf, len, 500);
}

int main(void) {
    libusb_context *c;
    libusb_init(&c);
    h = libusb_open_device_with_vid_pid(c, 0x0bda, 0x0811);
    if (!h) {
        if (modeswitch_scan(NULL) > 0) { fprintf(stderr, "found a Realtek stick in its fake-CD stage and sent the eject; run probe again in a few seconds\n"); return 1; }
        fprintf(stderr, "open failed (not plugged in, or held by another driver)\n"); return 1;
    }
    libusb_device *d = libusb_get_device(h);
    struct libusb_config_descriptor *cfg;
    libusb_get_active_config_descriptor(d, &cfg);
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface_descriptor *id = &cfg->interface[i].altsetting[0];
        printf("iface %d class %02x endpoints %d\n", id->bInterfaceNumber, id->bInterfaceClass, id->bNumEndpoints);
        for (int e = 0; e < id->bNumEndpoints; e++)
            printf("  ep 0x%02x attr %d maxpkt %d\n", id->endpoint[e].bEndpointAddress,
                   id->endpoint[e].bmAttributes & 3, id->endpoint[e].wMaxPacketSize);
    }
    int r = libusb_claim_interface(h, 0);
    printf("claim iface0: %s\n", libusb_error_name(r));
    uint8_t b[4];
    uint16_t regs[] = {0x0000, 0x0004, 0x00F0, 0x00FC};
    for (int i = 0; i < 4; i++) {
        int n = rd(regs[i], b, 4);
        if (n == 4) printf("reg 0x%04x = %02x%02x%02x%02x\n", regs[i], b[3], b[2], b[1], b[0]);
        else printf("reg 0x%04x read failed: %s\n", regs[i], libusb_error_name(n));
    }
    libusb_release_interface(h, 0);
    libusb_close(h);
    libusb_exit(c);
    return 0;
}
