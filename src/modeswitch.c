// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
#include <stdio.h>
#include <string.h>
#include <libusb.h>
#include "modeswitch.h"

// PIDs under which a Realtek Wi-Fi stick shows its driver "disc". 0bda:1a2b is the one usb_modeswitch carries for
// Realtek RTL81xx sticks. Add more only when a unit is seen that really does it.
static const uint16_t driver_cd_pids[] = { 0x1a2b };

ms_action_t modeswitch_decide(uint16_t vid, uint16_t pid, uint8_t dev_class, uint8_t if_class)
{
    if (vid != MODESWITCH_VID || pid == 0x0811) return MS_NONE;
    if (dev_class != USB_CLASS_MASS_STORAGE && if_class != USB_CLASS_MASS_STORAGE) return MS_NONE;
    for (size_t i = 0; i < sizeof driver_cd_pids / sizeof driver_cd_pids[0]; i++)
        if (pid == driver_cd_pids[i]) return MS_EJECT;
    return MS_NONE;
}

void modeswitch_build_cbw(uint8_t cbw[31], uint32_t tag)
{
    memset(cbw, 0, 31);
    memcpy(cbw, "USBC", 4);
    cbw[4] = tag; cbw[5] = tag >> 8; cbw[6] = tag >> 16; cbw[7] = tag >> 24;
    cbw[12] = 0x00;                       // data-out, no data stage
    cbw[14] = 6;                          // CDB length
    cbw[15] = 0x1B;                       // START STOP UNIT
    cbw[19] = 0x02;                       // LoEj=1, Start=0: eject
}

static int eject(libusb_device *dev)
{
    libusb_device_handle *h;
    struct libusb_config_descriptor *cfg;
    if (libusb_open(dev, &h)) return -1;
    int rc = -1;
    if (libusb_get_active_config_descriptor(dev, &cfg)) { libusb_close(h); return -1; }
    int ep_out = -1;
    if (cfg->bNumInterfaces > 0 && cfg->interface[0].num_altsetting > 0) {
        const struct libusb_interface_descriptor *id = &cfg->interface[0].altsetting[0];
        for (int e = 0; e < id->bNumEndpoints; e++) {
            const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
            if ((ed->bmAttributes & 3) == LIBUSB_TRANSFER_TYPE_BULK && !(ed->bEndpointAddress & 0x80)) ep_out = ed->bEndpointAddress;
        }
    }
    if (ep_out >= 0 && libusb_claim_interface(h, 0) == 0) {
        uint8_t cbw[31]; int sent = 0;
        modeswitch_build_cbw(cbw, 0x12345678);
        rc = libusb_bulk_transfer(h, (unsigned char)ep_out, cbw, sizeof cbw, &sent, 1000);
        if (rc == 0 && sent == 31) { uint8_t csw[13]; int got; libusb_bulk_transfer(h, (unsigned char)(ep_out | 0x80), csw, sizeof csw, &got, 500); rc = 0; }
        else rc = -1;
        libusb_release_interface(h, 0);
    }
    libusb_free_config_descriptor(cfg);
    libusb_close(h);
    return rc;
}

int modeswitch_scan(void (*log)(const char *line))
{
    libusb_context *ctx;
    libusb_device **list;
    int n = 0;
    if (libusb_init(&ctx)) return -1;
    ssize_t cnt = libusb_get_device_list(ctx, &list);
    if (cnt < 0) { libusb_exit(ctx); return -1; }
    for (ssize_t i = 0; i < cnt; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) || dd.idVendor != MODESWITCH_VID) continue;
        uint8_t ic = 0;
        struct libusb_config_descriptor *cfg;
        if (libusb_get_active_config_descriptor(list[i], &cfg) == 0) {
            if (cfg->bNumInterfaces > 0 && cfg->interface[0].num_altsetting > 0) ic = cfg->interface[0].altsetting[0].bInterfaceClass;
            libusb_free_config_descriptor(cfg);
        }
        if (modeswitch_decide(dd.idVendor, dd.idProduct, dd.bDeviceClass, ic) != MS_EJECT) continue;
        char b[120];
        int rc = eject(list[i]);
        snprintf(b, sizeof b, "modeswitch: %04x:%04x shows as a mass-storage \"driver CD\": eject %s", dd.idVendor, dd.idProduct, rc ? "failed" : "sent");
        if (log) log(b);
        if (!rc) n++;
    }
    libusb_free_device_list(list, 1);
    libusb_exit(ctx);
    return n;
}
