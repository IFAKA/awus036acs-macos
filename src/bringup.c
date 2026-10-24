#include <stdio.h>
#include "rtl.h"
#include "phy.h"
#include "bringup.h"

#define FAILE(s, e) do { *step = (s); snprintf(reason, rn, "error %d", (e)); return 1; } while (0)

int rtl_bringup(rtl_t *r, int channel, const char **step, char *reason, size_t rn)
{
    int e;
    if ((e = rtl_open(r))) FAILE("open", e);
    if ((e = rtl_power_on(r))) FAILE("power_on", e);
    if ((e = rtl_fw_download(r))) FAILE("fw_download", e);
    fprintf(stderr, "STEP init_phy\n");
    if ((e = rtl_init_phy(r))) FAILE("init_phy", e);
    if ((e = rtl_set_channel(r, channel, 1))) FAILE("set_channel", e);
    uint32_t rf18 = rtl_rf_r(r, 0, 0x18, 0xFFFFF);
    fprintf(stderr, "SANITY RF 0x18 = 0x%05X (channel byte 0x%02X, want 0x%02X)\n", rf18, rf18 & 0xFF, channel);
    fprintf(stderr, "SANITY BB 0x808=0x%08X 0xC1C=0x%08X 0x860=0x%08X CR=0x%04X\n", rtl_r32(r, 0x808), rtl_r32(r, 0xC1C),
            rtl_r32(r, 0x860), rtl_r16(r, 0x100));
    if ((rf18 & 0xFF) != (uint32_t)channel) {
        *step = "rf_readback";
        snprintf(reason, rn, "RF 0x18 readback 0x%05X does not match channel", rf18);
        return 1;
    }
    return 0;
}
