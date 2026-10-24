// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// USB transport for the RTL8821AU: register access through vendor control transfers.
//   read : bmRequestType 0xC0, bRequest 0x05, wValue = register address, wIndex = 0
//   write: bmRequestType 0x40, bRequest 0x05, same wValue/wIndex
// Data is little-endian, which matches the arm64 host, but we still go through byte arrays.
#include "rtl.h"
#include <stdio.h>
#include <string.h>

#define VENQT_READ   0xC0
#define VENQT_WRITE  0x40
#define VENREQ       0x05
#define TIMEOUT_MS   500
#define RETRIES      3          // the Linux driver retries failed vendor requests too

volatile int rtl_usb_dead;
unsigned long rtl_usb_errors;

int rtl_open(rtl_t *r) {
    r->ctx = NULL; r->h = NULL;
    rtl_usb_dead = 0;
    if (libusb_init(&r->ctx) < 0) return -1;
    r->h = libusb_open_device_with_vid_pid(r->ctx, 0x0bda, 0x0811);
    if (!r->h) { libusb_exit(r->ctx); r->ctx = NULL; return -2; }
    if (libusb_claim_interface(r->h, 0) < 0) {
        libusb_close(r->h); libusb_exit(r->ctx); r->h = NULL; r->ctx = NULL; return -3;
    }
    return 0;
}

void rtl_close(rtl_t *r) {
    if (r->h) { libusb_release_interface(r->h, 0); libusb_close(r->h); r->h = NULL; }
    if (r->ctx) { libusb_exit(r->ctx); r->ctx = NULL; }
}

// Read len (1..4) bytes at addr. Returns 0 ok, <0 error.
static int vread(rtl_t *r, uint16_t addr, uint8_t *buf, uint16_t len) {
    int n = -1;
    for (int i = 0; i < RETRIES; i++) {
        n = libusb_control_transfer(r->h, VENQT_READ, VENREQ, addr, 0, buf, len, TIMEOUT_MS);
        if (n == len) return 0;
    }
    fprintf(stderr, "USB read 0x%04x len %u failed: %d (%s)\n", addr, len, n, n < 0 ? libusb_error_name(n) : "short");
    rtl_usb_errors++;
    if (n == LIBUSB_ERROR_NO_DEVICE) rtl_usb_dead = 1;
    return -1;
}

static int vwrite(rtl_t *r, uint16_t addr, const uint8_t *buf, uint16_t len) {
    uint8_t tmp[256];
    if (len > sizeof tmp) return -1;
    memcpy(tmp, buf, len);               // libusb wants a non-const buffer
    int n = -1;
    for (int i = 0; i < RETRIES; i++) {
        n = libusb_control_transfer(r->h, VENQT_WRITE, VENREQ, addr, 0, tmp, len, TIMEOUT_MS);
        if (n == len) return 0;
    }
    fprintf(stderr, "USB write 0x%04x len %u failed: %d (%s)\n", addr, len, n, n < 0 ? libusb_error_name(n) : "short");
    rtl_usb_errors++;
    if (n == LIBUSB_ERROR_NO_DEVICE) rtl_usb_dead = 1;
    return -1;
}

uint8_t rtl_r8(rtl_t *r, uint16_t a) {
    uint8_t b[1] = {0xFF};
    vread(r, a, b, 1);
    if (r->verbose) fprintf(stderr, "R8 0x%04X -> 0x%02X\n", a, b[0]);
    return b[0];
}
uint16_t rtl_r16(rtl_t *r, uint16_t a) {
    uint8_t b[2] = {0xFF, 0xFF};
    vread(r, a, b, 2);
    uint16_t v = b[0] | (b[1] << 8);
    if (r->verbose) fprintf(stderr, "R16 0x%04X -> 0x%04X\n", a, v);
    return v;
}
uint32_t rtl_r32(rtl_t *r, uint16_t a) {
    uint8_t b[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    vread(r, a, b, 4);
    uint32_t v = b[0] | (b[1] << 8) | (b[2] << 16) | ((uint32_t)b[3] << 24);
    if (r->verbose) fprintf(stderr, "R32 0x%04X -> 0x%08X\n", a, v);
    return v;
}
int rtl_w8(rtl_t *r, uint16_t a, uint8_t v) {
    if (r->verbose) fprintf(stderr, "W8 0x%04X <- 0x%02X\n", a, v);
    return vwrite(r, a, &v, 1);
}
int rtl_w16(rtl_t *r, uint16_t a, uint16_t v) {
    uint8_t b[2] = {v & 0xFF, v >> 8};
    if (r->verbose) fprintf(stderr, "W16 0x%04X <- 0x%04X\n", a, v);
    return vwrite(r, a, b, 2);
}
int rtl_w32(rtl_t *r, uint16_t a, uint32_t v) {
    uint8_t b[4] = {v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, v >> 24};
    if (r->verbose) fprintf(stderr, "W32 0x%04X <- 0x%08X\n", a, v);
    return vwrite(r, a, b, 4);
}

// Block write (firmware download). The Linux driver sends 196-byte chunks straight to
// consecutive addresses; the device takes any length on a single request, so no alignment
// fix-up is needed. The caller keeps len <= 196 (we reject longer ones).
int rtl_wblock(rtl_t *r, uint16_t a, const uint8_t *buf, uint16_t len) {
    if (len > 196) return -1;
    if (r->verbose) fprintf(stderr, "WBLOCK 0x%04X <- %u bytes\n", a, len);
    return vwrite(r, a, buf, len);
}
