// SPDX-License-Identifier: GPL-2.0
// Part of awus036acs-macos: a native userspace driver for the RTL8811AU/RTL8821AU
// (Alfa AWUS036ACS) on macOS, derived from aircrack-ng/rtl8812au (GPLv2).
// See LICENSE for the full license text.
// modeswitch: some Realtek Wi-Fi sticks first show up as a fake CD-ROM ("RtWlanDisk" in the vendor package, the same
// idea as usb_modeswitch) carrying the Windows driver, and only turn into the Wi-Fi device after the host ejects that
// "disc" (SCSI START STOP UNIT with LoEj=1). This unit enumerates directly as 0bda:0811 WLAN and never shows the CD
// stage, so this is dormant here; the decision logic is unit-tested, the eject itself has never run on a real stick.
#ifndef MODESWITCH_H
#define MODESWITCH_H
#include <stdint.h>
#include <stddef.h>

#define MODESWITCH_VID 0x0bda
#define USB_CLASS_MASS_STORAGE 8

typedef enum { MS_NONE, MS_EJECT } ms_action_t;

// Pure decision. vid/pid from the device descriptor, dev_class = bDeviceClass, if_class = class of interface 0 (0 if none known).
// MS_EJECT only for Realtek (0bda) that presents mass storage (class 8 on the device or on interface 0) AND whose PID is on
// the known "driver CD" list. The PID list is deliberate: 0bda is also the vendor of the card readers (RTS5xxx), and ejecting
// a user's card reader would be wrong. The Wi-Fi PID itself (0bda:0811) is never switched.
ms_action_t modeswitch_decide(uint16_t vid, uint16_t pid, uint8_t dev_class, uint8_t if_class);
// The 31-byte Bulk-Only Transport command block wrapper carrying SCSI START STOP UNIT, LoEj=1, Start=0 (eject).
void modeswitch_build_cbw(uint8_t cbw[31], uint32_t tag);
// Walk the USB bus; eject every device modeswitch_decide() flags. Returns how many were ejected, or -1 on libusb failure.
// `log` (may be NULL) receives one line per decision. The device re-enumerates by itself a moment later.
int modeswitch_scan(void (*log)(const char *line));
#endif
