#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rx.h"
#include "tx.h"

#define RX_EP        0x84
#define RXBUF_SIZE   (32 * 1024)
#define RXDESC_SIZE  24

rtl_rx_stats_t rtl_rx_stats;

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
#define BITS(w, lo, n) (((w) >> (lo)) & ((1u << (n)) - 1))

static uint32_t crc_tab[256];
static void crc_init(void)
{
    if (crc_tab[1]) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_tab[i] = c;
    }
}
static int fcs_ok(const uint8_t *p, int len)
{
    if (len < 8) return 0;
    uint32_t c = 0xFFFFFFFFu;
    for (int i = 0; i < len - 4; i++) c = crc_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return ~c == le32(p + len - 4);
}

static int parse_buf(rtl_t *r, const uint8_t *buf, int len, rtl_frame_cb cb, void *ud)
{
    int n = 0;
    crc_init();
    while (len >= RXDESC_SIZE) {
        uint32_t d0 = le32(buf), d2 = le32(buf + 8), d3 = le32(buf + 12), d4 = le32(buf + 16);
        int pkt_len = BITS(d0, 0, 14), drv = BITS(d0, 16, 4) * 8, shift = BITS(d0, 24, 2), physt = BITS(d0, 26, 1);
        int total = RXDESC_SIZE + drv + shift + pkt_len;
        if (pkt_len == 0 || total > len) {
            rtl_rx_stats.bad_desc++;
            if (r->verbose)
                fprintf(stderr, "rx: bad desc pkt_len=%d drv=%d shift=%d total=%d remain=%d d0=%08X\n", pkt_len, drv, shift, total, len, d0);
            break;
        }
        if (BITS(d2, 28, 1)) {                    // RPT_SEL: C2H / firmware report, not a received frame
            rtl_rx_stats.c2h++;
            const uint8_t *c = buf + RXDESC_SIZE + drv + shift;   // [id][seq][payload]
            if (r->verbose || getenv("C2HDBG")) {
                fprintf(stderr, "c2h: len=%d", pkt_len);
                for (int i = 0; i < pkt_len && i < 16; i++) fprintf(stderr, " %02X", c[i]);
                fputc('\n', stderr);
            }
            if (pkt_len >= 8 && c[0] == 0x03) {              // C2H_CCX_TX_RPT
                rtl_tx_stats.ccx++;
                if (c[2] & 0x80) rtl_tx_stats.ccx_retry_over++;
                else if (c[2] & 0x40) rtl_tx_stats.ccx_life_over++;
                else rtl_tx_stats.ccx_ok++;
            }
        } else {
            rtl_frame_t f;
            memset(&f, 0, sizeof f);
            f.data = buf + RXDESC_SIZE + drv + shift;
            f.len = pkt_len;
            f.crc_err = BITS(d0, 14, 1);
            f.icv_err = BITS(d0, 15, 1);
            f.rate = BITS(d3, 0, 7);
            f.bw = BITS(d4, 4, 2);
            f.channel = r->channel;
            f.has_fcs = fcs_ok(f.data, f.len);
            if (physt && drv >= 8) {
                const uint8_t *ps = buf + RXDESC_SIZE;
                f.rssi_valid = 1;
                f.rssi_dbm = (int)(ps[0] & 0x7F) - 110;
            }
            if (getenv("RXDBG") && rtl_rx_stats.frames < 400) {
                fprintf(stderr, "rxdbg: fc=%02X%02X len=%d d3=%08X d4=%08X physt=%d drv=%d ps=", f.data[0], f.data[1], pkt_len, d3, d4, physt, drv);
                for (int i = 0; physt && i < drv && i < 16; i++) fprintf(stderr, "%02X", buf[RXDESC_SIZE + i]);
                fputc('\n', stderr);
            }
            rtl_rx_stats.frames++;
            if (f.crc_err) rtl_rx_stats.crc_err++;
            if (cb) cb(ud, &f);
            n++;
        }
        int adv = (total + 7) & ~7;
        buf += adv; len -= adv;
    }
    return n;
}

int rtl_rx_poll(rtl_t *r, rtl_frame_cb cb, void *ud, int timeout_ms)
{
    static uint8_t buf[RXBUF_SIZE];
    int got = 0;
    int xfer = 0;
    int rc = libusb_bulk_transfer(r->h, RX_EP, buf, sizeof buf, &xfer, timeout_ms > 0 ? timeout_ms : 1);
    if (rc == LIBUSB_ERROR_TIMEOUT && xfer == 0) return 0;
    if (rc < 0 && rc != LIBUSB_ERROR_TIMEOUT && rc != LIBUSB_ERROR_OVERFLOW) {
        fprintf(stderr, "rx: bulk read error %d (%s)\n", rc, libusb_error_name(rc));
        if (rc == LIBUSB_ERROR_PIPE) libusb_clear_halt(r->h, RX_EP);
        return rc;
    }
    rtl_rx_stats.transfers++;
    rtl_rx_stats.bytes += xfer;
    if (r->verbose > 1 || rtl_rx_stats.transfers <= 5)
        fprintf(stderr, "rx: transfer %lu: %d bytes, first dwords %08X %08X %08X %08X\n", rtl_rx_stats.transfers, xfer,
                xfer >= 4 ? le32(buf) : 0, xfer >= 8 ? le32(buf + 4) : 0, xfer >= 12 ? le32(buf + 8) : 0, xfer >= 16 ? le32(buf + 12) : 0);
    got = parse_buf(r, buf, xfer, cb, ud);
    return got;
}
