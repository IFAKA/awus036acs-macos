#include <stdio.h>
#include <string.h>
#include "tx.h"

#define TXDESC_SIZE 40
#define QSLT_MGNT   0x12
#define QSLT_BE     0x00
#define RATEID_B    8
#define RATEID_G    7
#define MGMT_MACID  1

rtl_tx_stats_t rtl_tx_stats;

static void set_bits(uint8_t *d, int byteoff, int lo, int n, uint32_t v)
{
    uint32_t w = d[byteoff] | d[byteoff + 1] << 8 | d[byteoff + 2] << 16 | (uint32_t)d[byteoff + 3] << 24;
    uint32_t m = (n == 32 ? 0xFFFFFFFFu : ((1u << n) - 1)) << lo;
    w = (w & ~m) | ((v << lo) & m);
    d[byteoff] = w; d[byteoff + 1] = w >> 8; d[byteoff + 2] = w >> 16; d[byteoff + 3] = w >> 24;
}

static int hw_rate(int rate)
{
    switch (rate) {
    case 10: return 0x00; case 20: return 0x01; case 55: return 0x02; case 110: return 0x03;
    case 60: return 0x04; case 90: return 0x05; case 120: return 0x06; case 180: return 0x07;
    case 240: return 0x08; case 360: return 0x09; case 480: return 0x0A; case 540: return 0x0B;
    }
    return -1;
}

static int build_desc(uint8_t *d, int len, int rate, int retries, int bmc, int qsel)
{
    int hr = hw_rate(rate);
    if (hr < 0) return -1;
    memset(d, 0, TXDESC_SIZE);
    // dword 0
    set_bits(d, 0, 0, 16, len);
    set_bits(d, 0, 16, 8, TXDESC_SIZE);               // OFFSET: payload starts after the descriptor
    set_bits(d, 0, 24, 1, bmc);
    set_bits(d, 0, 26, 1, 1);                         // LAST_SEG
    set_bits(d, 0, 27, 1, 1);                         // FIRST_SEG
    set_bits(d, 0, 31, 1, 1);                         // OWN
    // dword 1
    set_bits(d, 4, 0, 7, MGMT_MACID);
    set_bits(d, 4, 8, 5, qsel);
    if (qsel != QSLT_MGNT) set_bits(d, 8, 16, 1, 1);   // AGG_BREAK for data
    set_bits(d, 4, 16, 5, rate <= 110 ? RATEID_B : RATEID_G);
    // dword 2: SPE_RPT -> ask the chip for a C2H TX report
    set_bits(d, 8, 19, 1, 1);
    // dword 3
    set_bits(d, 12, 8, 1, 1);                         // USE_RATE
    set_bits(d, 12, 10, 1, 1);                        // DISABLE_FB (fixed rate)
    // dword 4
    set_bits(d, 16, 0, 7, hr);                        // TX_RATE
    set_bits(d, 16, 17, 1, 1);                        // RETRY_LIMIT_ENABLE
    set_bits(d, 16, 18, 6, retries & 0x3F);           // DATA_RETRY_LIMIT
    // dword 8: HWSEQ_EN (+32 bit 15): hardware assigns the sequence number
    set_bits(d, 32, 15, 1, 1);
    // checksum: xor of the first 16 16-bit words with the checksum field cleared
    uint16_t c = 0;
    for (int i = 0; i < 16; i++) c ^= d[2 * i] | d[2 * i + 1] << 8;
    set_bits(d, 28, 0, 16, c);
    return hr;
}

int rtl_tx_build_desc(uint8_t *d, int len, int rate, int retries, int bmc)
{
    return build_desc(d, len, rate, retries, bmc, QSLT_MGNT);
}

// Bulk OUT endpoint for the MGT queue: Linux (typical, non wifi_spec) uses RtOutPipe[3] with 4 OUT endpoints
// (in descriptor order 0x05 HIGH, 0x06 NORMAL, 0x08 LOW, 0x09 EXTRA), RtOutPipe[0] otherwise.
static int out_ep(rtl_t *r, int data)
{
    uint8_t eps[8]; int n = 0;
    struct libusb_config_descriptor *cf = NULL;
    if (libusb_get_active_config_descriptor(libusb_get_device(r->h), &cf) < 0) return -1;
    const struct libusb_interface_descriptor *id = &cf->interface[0].altsetting[0];
    for (int i = 0; i < id->bNumEndpoints && n < 8; i++) {
        uint8_t a = id->endpoint[i].bEndpointAddress;
        if (!(a & 0x80) && (id->endpoint[i].bmAttributes & 3) == 2) eps[n++] = a;
    }
    libusb_free_config_descriptor(cf);
    if (n == 0) return -1;
    if (data) return n >= 3 ? eps[2] : eps[n - 1];   // BE -> LOW queue (see mac.c queue map)
    return n >= 4 ? eps[3] : eps[0];
}

static int tx_common(rtl_t *r, const uint8_t *frame, int len, int rate, int retries, int data)
{
    static uint8_t buf[TXDESC_SIZE + 8 + 2400];
    if (len < 10 || len > 2300) return -2;
    int ep = out_ep(r, data);
    if (ep < 0) return -3;
    int bmc = frame[4] & 1;                           // addr1 group bit
    int pad = ((TXDESC_SIZE + len) % 512 == 0);       // avoid a bulk size that needs a zero-length packet (Linux pads 8 bytes)
    if (build_desc(buf, len, rate, retries, bmc, data ? QSLT_BE : QSLT_MGNT) < 0) return -4;
    if (pad) {
        // PKT_OFFSET = 1 (8-byte units of padding) at dword1 bits 24..28, then recompute checksum
        set_bits(buf, 4, 24, 5, 1);
        set_bits(buf, 28, 0, 16, 0);
        uint16_t c = 0;
        for (int i = 0; i < 16; i++) c ^= buf[2 * i] | buf[2 * i + 1] << 8;
        set_bits(buf, 28, 0, 16, c);
        memset(buf + TXDESC_SIZE, 0, 8);
    }
    int off = TXDESC_SIZE + (pad ? 8 : 0);
    memcpy(buf + off, frame, len);
    int total = off + len, done = 0;
    rtl_tx_stats.submitted++;
    int rc = libusb_bulk_transfer(r->h, ep, buf, total, &done, 1000);
    if (rc == LIBUSB_ERROR_PIPE) libusb_clear_halt(r->h, ep);
    if (rc < 0 || done != total) {
        rtl_tx_stats.failed++;
        fprintf(stderr, "tx: bulk OUT ep 0x%02X failed rc=%d (%s) wrote %d of %d\n", ep, rc, rc < 0 ? libusb_error_name(rc) : "short", done, total);
        return rc < 0 ? rc : -5;
    }
    rtl_tx_stats.completed++;
    if (r->verbose > 1) fprintf(stderr, "tx: ep 0x%02X wrote %d bytes (frame %d)\n", ep, done, len);
    return 0;
}

int rtl_tx_frame(rtl_t *r, const uint8_t *frame, int len, int rate, int retries)
{
    return tx_common(r, frame, len, rate, retries, 0);
}

int rtl_tx_data(rtl_t *r, const uint8_t *frame, int len, int rate, int retries)
{
    return tx_common(r, frame, len, rate, retries, 1);
}
