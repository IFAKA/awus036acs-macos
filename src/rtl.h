// Shared API for the userspace RTL8821AU (0bda:0811) driver. Keep stable: several files depend on it.
#ifndef RTL_H
#define RTL_H
#include <stdint.h>
#include <libusb.h>

typedef struct rtl {
    libusb_context *ctx;
    libusb_device_handle *h;
    int verbose;          // 1 = log every register access to stderr
    uint8_t cut;          // chip cut/version number read at init (A=0, B=1, ...)
    int channel;          // last channel set by rtl_set_channel (0 = none)
} rtl_t;

int      rtl_open(rtl_t *r);            // open 0bda:0811, claim iface 0. 0 = ok, <0 = error
void     rtl_close(rtl_t *r);
uint8_t  rtl_r8 (rtl_t *r, uint16_t addr);
uint16_t rtl_r16(rtl_t *r, uint16_t addr);
uint32_t rtl_r32(rtl_t *r, uint16_t addr);
int      rtl_w8 (rtl_t *r, uint16_t addr, uint8_t v);   // return 0 = ok
int      rtl_w16(rtl_t *r, uint16_t addr, uint16_t v);
int      rtl_w32(rtl_t *r, uint16_t addr, uint32_t v);
int      rtl_wblock(rtl_t *r, uint16_t addr, const uint8_t *buf, uint16_t len); // len <= 196 per call

// stage 2
int rtl_power_on(rtl_t *r);                       // run the card-enable power sequence
int rtl_fw_download(rtl_t *r);                    // load firmware, wait for ready. 0 = ok

// stage 2b: apply MAC / baseband / RF init tables (src/tables.c, generated)
int rtl_init_phy(rtl_t *r);

#endif
