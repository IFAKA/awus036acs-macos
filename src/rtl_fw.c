// Firmware download for RTL8821A, mirroring FirmwareDownload8812 and helpers.
#include "rtl.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>

extern const uint8_t fw8821a[];
extern const size_t fw8821a_len;

#define REG_SYS_FUNC_EN 0x0002
#define REG_RSV_CTRL    0x001C
#define REG_MCUFWDL     0x0080
#define MCUFWDL_EN      0x01          // bit0: download enable
#define MCUFWDL_RDY     0x02          // bit1: image loaded, ready to run
#define FWDL_CHKSUM_RPT 0x04          // bit2: checksum OK report
#define WINTINI_RDY     0x40          // bit6: firmware booted and ready
#define FW_START_ADDRESS 0x1000
#define PAGE_SIZE_FW     4096
#define MAX_BLOCK        196

static long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

// Reset the 8051 and its IO wrapper (8821 variant of _8051Reset8812).
static void reset_8051(rtl_t *r) {
    uint8_t t = rtl_r8(r, REG_RSV_CTRL);
    rtl_w8(r, REG_RSV_CTRL, t & ~0x02);
    t = rtl_r8(r, REG_RSV_CTRL + 1);
    rtl_w8(r, REG_RSV_CTRL + 1, t & ~0x01);
    uint8_t f = rtl_r8(r, REG_SYS_FUNC_EN + 1);
    rtl_w8(r, REG_SYS_FUNC_EN + 1, f & ~0x04);          // 8051 off
    t = rtl_r8(r, REG_RSV_CTRL);
    rtl_w8(r, REG_RSV_CTRL, t & ~0x02);
    t = rtl_r8(r, REG_RSV_CTRL + 1);
    rtl_w8(r, REG_RSV_CTRL + 1, t | 0x01);             // enable MCU IO wrapper
    rtl_w8(r, REG_SYS_FUNC_EN + 1, f | 0x04);           // 8051 on
}

static void fwdl_enable(rtl_t *r, int on) {
    uint8_t t = rtl_r8(r, REG_MCUFWDL);
    if (on) {
        rtl_w8(r, REG_MCUFWDL, t | MCUFWDL_EN);
        t = rtl_r8(r, REG_MCUFWDL + 2);
        rtl_w8(r, REG_MCUFWDL + 2, t & 0xF7);            // hold 8051 in reset
    } else {
        rtl_w8(r, REG_MCUFWDL, t & 0xFE);
    }
}

// Write one buffer (<= 4096) to the 0x1000 window: 196-byte blocks, then 8-byte, then 1-byte.
static int block_write(rtl_t *r, const uint8_t *p, uint32_t size) {
    uint32_t n1 = size / MAX_BLOCK, rem1 = size % MAX_BLOCK, off = 0;
    for (uint32_t i = 0; i < n1; i++, off += MAX_BLOCK)
        if (rtl_wblock(r, FW_START_ADDRESS + off, p + off, MAX_BLOCK)) return -1;
    uint32_t n2 = rem1 / 8, rem2 = rem1 % 8;
    for (uint32_t i = 0; i < n2; i++, off += 8)
        if (rtl_wblock(r, FW_START_ADDRESS + off, p + off, 8)) return -1;
    for (uint32_t i = 0; i < rem2; i++, off++)
        if (rtl_w8(r, FW_START_ADDRESS + off, p[off])) return -1;
    return 0;
}

static int write_fw(rtl_t *r, const uint8_t *p, uint32_t size) {
    uint32_t pages = size / PAGE_SIZE_FW, rem = size % PAGE_SIZE_FW;
    for (uint32_t pg = 0; pg <= pages; pg++) {
        uint32_t len = pg < pages ? PAGE_SIZE_FW : rem;
        if (!len) break;
        // MCUFWDL+2 low 3 bits select which 4K page the 0x1000 window maps to
        uint8_t v = (rtl_r8(r, REG_MCUFWDL + 2) & 0xF8) | (pg & 7);
        rtl_w8(r, REG_MCUFWDL + 2, v);
        if (block_write(r, p + pg * PAGE_SIZE_FW, len)) return -1;
    }
    return 0;
}

int rtl_fw_download(rtl_t *r) {
    const uint8_t *buf = fw8821a;
    uint32_t len = (uint32_t)fw8821a_len;
    uint16_t sig = buf[0] | (buf[1] << 8);
    fprintf(stderr, "fw: ver=%u subver=%u sig=0x%04X len=%u\n",
            buf[4] | (buf[5] << 8), buf[6], sig, len);
    if ((sig & 0xFFF0) == 0x2100) { buf += 32; len -= 32; }   // skip 32-byte header

    // If the 8051 is running RAM code (leftover from a previous run), reset it first.
    if (rtl_r8(r, REG_MCUFWDL) & 0x80) {
        rtl_w8(r, REG_MCUFWDL, 0x00);
        reset_8051(r);
    }

    fwdl_enable(r, 1);
    long start = now_ms();
    int ok = -1, tries = 0;
    while (tries++ < 3 || now_ms() - start < 500) {
        rtl_w8(r, REG_MCUFWDL, rtl_r8(r, REG_MCUFWDL) | FWDL_CHKSUM_RPT);   // clear old report
        if (write_fw(r, buf, len)) continue;
        // poll checksum report
        long t0 = now_ms(); int cnt = 0; uint32_t v;
        do { cnt++; v = rtl_r32(r, REG_MCUFWDL); if (v & FWDL_CHKSUM_RPT) break; usleep(1000); }
        while (now_ms() - t0 < 50 || cnt < 5);
        fprintf(stderr, "fw: checksum report %s, REG_MCUFWDL=0x%08X\n",
                (v & FWDL_CHKSUM_RPT) ? "OK" : "FAIL", v);
        if (v & FWDL_CHKSUM_RPT) { ok = 0; break; }
    }
    fwdl_enable(r, 0);
    if (ok) { fprintf(stderr, "fw: checksum never OK\n"); return -1; }

    // Free to go: set MCUFWDL_RDY, clear WINTINI_RDY, reset 8051 so it boots the image.
    uint32_t v = rtl_r32(r, REG_MCUFWDL);
    v |= MCUFWDL_RDY; v &= ~WINTINI_RDY;
    rtl_w32(r, REG_MCUFWDL, v);
    reset_8051(r);
    long t0 = now_ms(); int cnt = 0;
    do { cnt++; v = rtl_r32(r, REG_MCUFWDL); if (v & WINTINI_RDY) break; usleep(1000); }
    while (now_ms() - t0 < 200 || cnt < 10);
    fprintf(stderr, "fw: ready poll %s after %ld ms, REG_MCUFWDL=0x%08X\n",
            (v & WINTINI_RDY) ? "OK" : "FAIL", now_ms() - t0, v);
    return (v & WINTINI_RDY) ? 0 : -2;
}
